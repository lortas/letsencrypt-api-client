class AcmeApi
	require 'json'
	require 'net/https'
	require "helper"

	def initialize(accountkey,acmedirUri=nil,proxy=nil,log=nil)
		@accountkey=accountkey
		if acmedirUri == nil
			@acmedirUri=URI "https://acme-v02.api.letsencrypt.org/directory"
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
		@accountpubkey=Helper.Pkey2Jwk( @accountkey.public_key )
		@accountpubkeySha256 = Helper.base64encode OpenSSL::Digest.digest("SHA256",@accountpubkey.to_json)
		@orders={}
		@accountid=nil
	end

	def accountpubkeySha256
		@accountpubkeySha256
	end

	# All requests have the same main structure
	def mainRequestData
		data={
			"protected"=>{ "alg"=>"RS256", "nonce"=>@nonce },
			"payload"=>{},
			"signature"=>""
		}
		if @accountid
			data["protected"]["kid"]=@accountid.to_s
		else
			data["protected"]["jwk"]=@accountpubkey
		end
		return data
	end

	def signRequestData(data)
		sdata={}
		vals=[]
		["protected","payload"].each do |k|
			val=data[k]
			if val==nil
				sdata[k]=""
				@log.debug "signing: #{k} = \"\""
			else
				val=val.to_json
				@log.debug "signing: #{k} = #{val}"
				sdata[k]=Helper.base64encode val
			end
			vals << sdata[k]
		end
		b64data=vals.join(".")
		@log.debug "signingdata: "+b64data
		sdata["signature"]=Helper.base64encode @accountkey.sign(OpenSSL::Digest::SHA256.new, b64data)
		return sdata.to_json
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
			@nonce=response["replay-nonce"]
			responseCode=response.code.to_i
			@log.debug "Request return with code : "+responseCode.to_s
			@log.debug "Response header : "+response.to_hash.to_json
			if response.body
				if responseCode >= 400
					@log.warn "Response body : "+response.body
					raise Exception.new "http request returned bad: "+responseCode.to_s
				else
					@log.debug "Response body : "+response.body
				end
			end
		end
	end

	def loadAcmeDirectory
		@log.info("Get ACME Directory")
		connect do |http|
			req = Net::HTTP::Get.new @acmedirUri.path
			response = http.request req
			if response.code.to_i == 200
				@log.info("ACME Directory successfull received.")
				JSON.parse(response.body).each do |k,v|
					if k == "meta"
						@acmeApiCalls[k]=v
					else
						@acmeApiCalls[k]=URI v
					end
				end
			end
			response
		end
	end

	def getObject(uri,payload={})
		@log.info("Get Object at "+uri.to_s)
		result={}
		connect do |http|
			req = Net::HTTP::Post.new uri.path
			data = mainRequestData
			if payload==nil
				data["payload"]=nil
			else
				data["payload"].merge!(payload)
			end
			data["protected"]["url"]=uri.to_s
			req["Content-Type"]="application/jose+json"
			req.body = signRequestData(data)
			response = http.request req
			result[:header]={}
			response.to_hash.each do |key,val|
				if val.is_a?(Array) &&  val.size==1
					result[:header][key]=val.first
				else
					result[:header][key]=val
				end
			end
			result[:code]=response.code
			result[:body]=response.body
			result[:body]=JSON.parse(result[:body]) if result[:body]
			response
		end
		return result
	end

	def sendNewRegistration(contactEmailAddress)
		@log.info("Try to Register new ACME Account")
		result=getObject( @acmeApiCalls["newAccount"] , {
			"contact"=>["mailto:"+contactEmailAddress],
			"termsOfServiceAgreed"=>true,
			"onlyReturnExisting"=>false,
			"externalAccountBinding"=>false
		})
		p result
		@accountid=URI result[:header]["location"]
		@log.info "Account ID : "+@accountid.to_s
	end

	def newOrder(domains)
		@log.info("Create new order for domains : "+domains.to_json)
		result=getObject( @acmeApiCalls["newOrder"] , {"identifiers"=>domains.map{|domain|{"type"=>"dns","value"=>domain}}} )
		@orders[result[:header]["location"]]=result[:body]
		return result[:body]
	end

	def getAuthorization(url)
		return getObject(URI(url),nil)[:body]
	end

	def getURI(uri)
		@log.info("get URI")
		result=nil
		connect do |http|
			@log.debug uri
			response = http.request Net::HTTP::Get.new uri
			result=response.body
			response
		end
		return result
	end

	def requestNewNonce
		@log.info("Ask for a new nonce")
		getURI @acmeApiCalls["newNonce"].path
		@log.info("Our nonce is:"+@nonce)
	end
end
