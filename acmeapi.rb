class AcmeApi
	require 'json'
	require 'net/https'
	require "helper"

	def initialize(accountkey,acmedirUri=nil,proxy=nil,log=nil)
		@accountkey=accountkey
		if acmedirUri == nil
			@acmedirUri=URI "https://acme-v01.api.letsencrypt.org/directory"
		else
			@acmedirUri=acmedirUri
		end
		if log == nil
			@log=Logger.new(STDOUT)
		else
			@log=log
		end
		@proxy=proxy
		@acmeApiCalls={}
	end

	# All requests have the same main structure
	def mainRequestData
		{
			"header" => {
				"alg"=>"RS256",
				"jwk" => Helper.Pkey2Jwk( @accountkey.public_key )
			},
			"protected" => Helper.base64encode( {"nonce"=>@nonce}.to_json ),
			"payload" =>  nil,
			"signature" => nil
		}
	end

	def newRegistration(domain)
		data = mainRequestData
		data["payload"] = Helper.base64encode( {
			"resource" => "new-reg",
			"contact" => ["mailto:cert-admin@"+domain],
			"agreement" => "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"
		}.to_json )
		data["signature"] = Helper.base64encode @accountkey.sign(OpenSSL::Digest::SHA256.new, data["protected"]+"."+data["payload"])
		return data.to_json
	end

	def newAuthorisation(domain)
		data = mainRequestData
		data["payload"] = Helper.base64encode( {
			"resource" => "new-authz",
			"identifier" => {"type"=>"dns","value"=>domain}
		}.to_json )
		data["signature"] = Helper.base64encode @accountkey.sign(OpenSSL::Digest::SHA256.new, data["protected"]+"."+data["payload"])
		return data.to_json  
	end

	def newCertificate(csr)
		data = mainRequestData
		data["payload"] = Helper.base64encode( {
			"resource" => "new-cert",
			"csr" => Helper.base64encode(csr.to_der)
		}.to_json )
		data["signature"] = Helper.base64encode @accountkey.sign(OpenSSL::Digest::SHA256.new, data["protected"]+"."+data["payload"])
		return data.to_json
	end

	def connect
		proxy_host=nil
		proxy_port=nil
		if @proxy != nil
			proxy_host=@proxy.host
			proxy_port=@proxy.port
		end
		Net::HTTP.start(@acmedirUri.host, @acmedirUri.port, proxy_host, proxy_port, :use_ssl => @acmedirUri.scheme == 'https', :verify_mode => OpenSSL::SSL::VERIFY_NONE  ) do |http|
			response = yield http
			@log.debug "Request return with code : "+response.code
			@log.debug "Response data : '"+response.body+"'"
		end
	end

	def loadAcmeDirectory
		@log.info("Get ACME Directory")
		connect do |http|
			req = Net::HTTP::Get.new @acmedirUri.path
			response = http.request req
			@nonce=response["Replay-Nonce"]
			if response.code.to_i == 200
				@log.info("ACME Directory successfull received.")
				 JSON.parse(response.body).each do |k,v|
					 @acmeApiCalls[k]=URI v
				 end
			end
			response
		end
	end

	def sendNewRegistration(domain)
		@log.info("Try to Register new ACME Account")
		connect do |http|
			req = Net::HTTP::Post.new @acmeApiCalls["new-reg"].path
			req.body = newRegistration domain
			response = http.request req
			@nonce=response["Replay-Nonce"]
			result = JSON.parse(response.body)
			@log.info(result["detail"])
			response
		end
	end

	def sendNewAuthorisation(domain)
		@log.info("Send new authorisation for domain : "+domain)
		connect do |http|
			req = Net::HTTP::Post.new @acmeApiCalls["new-authz"].path
			req.body = newAuthorisation domain
			response = http.request req
			@nonce=response["Replay-Nonce"]
			result = JSON.parse(response.body)
			puts result
			response
		end
	end
end
