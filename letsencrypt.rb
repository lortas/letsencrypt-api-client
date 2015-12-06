#!/usr/bin/env ruby
require 'optparse'
require 'logger'
require 'json'
require 'openssl'
require 'base64'
require 'net/https'

# Logger
log = Logger.new(STDOUT)
log.progname = "letsencrypt"

# Insert local path to library path list
$:.unshift File.dirname(__FILE__)

# Default Values
$VERBOSE=false
accountKeyFile=nil
csrFilename=nil
acmedirUri=URI "https://acme-v01.api.letsencrypt.org/directory"
proxy=nil

# Opt parsing
optparse = OptionParser.new do |opts|
	opts.banner = "Usage: letsencrypt.rb [options]"
	opts.on( '-v', '--verbose', 'Enable verbosity. Default is off.' ) do |verbose|
		$VERBOSE = true
	end
	opts.on( '-k', '--accountKey FILE', 'File where the private key for the ACME account is stored' ) do |f|
		accountKeyFile = f
	end
	opts.on( '-c', '--csr FILE', 'File where the certificate signing request (csr) is stored' ) do |f|
		csrFilename = f
	end
	opts.on( '-u', '--letsencryptDirectoryUrl URL', 'URL where the ACME Let\'s encrypt Directory is located.' ) do |f|
		acmedirUri=URI f
	end
	opts.on( '-p', '--proxy URL', 'URL of the Proxy to use to access ACME URLs.' ) do |f|
		proxy=URI f
	end
end

# ACME use a modified variant of base64 encoding.
#  - It has no padding equal-symbols at the end
#  - It uses "_" for "/"
#  - It uses "-" for "+"
def base64encode(data)
	return Base64.strict_encode64( data ).sub(/=*$/,"").tr("/+","_-")
end

# All requests have the same main structure
def mainRequestData(publicKey,nonce)
	header = {
		"alg"=>"RS256",
		"jwk" => Pkey2Jwk( publicKey )
	}
	protected = base64encode( {"nonce"=>nonce}.to_json )  
	data = {
		"header" => header,
		"protected" => protected,
		"payload" =>  nil,
		"signature" => nil
	}
	return data
end

def newRegistration(key,domain,nonce)
	data = mainRequestData(key.public_key,nonce)
	data["payload"] = base64encode( {
		"resource" => "new-reg",
		"contact" => ["mailto:cert-admin@"+domain],
		"agreement" => "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"
	}.to_json )
	data["signature"] = base64encode key.sign(OpenSSL::Digest::SHA256.new, data["protected"]+"."+data["payload"])
	return data.to_json
end

def newAuthorised(key,domain,nonce)
	data = mainRequestData(key.public_key,nonce)
	data["payload"] = base64encode( {
		"resource" => "new-authz",
		"identifier" => {"type"=>"dns","value"=>domain}
	}.to_json )
	data["signature"] = base64encode key.sign(OpenSSL::Digest::SHA256.new, data["protected"]+"."+data["payload"])
	return data.to_json  
end

def numberToBase64(number)
	hex = number.to_s(16)
	if hex.length%2 == 1
		hex = "0"+hex
	end
	bin = [hex].pack("H*")
	return base64encode bin
end

def Pkey2Jwk( key )
	result = {}
	if key.is_a? OpenSSL::PKey::RSA
		result["kty"]="RSA"
	elsif key.is_a?OpenSSL::PKey::EC
		result["kty"]="EC"
	else
		result["kty"]="UNKNOWN"
	end
	params=key.params
	[["n","n"],["e","e"],["d","d"],["p","p"],["q","q"],["dp","dmp1"],["dq","dmq1"],["qi","iqmp"]].each do |v|
		p=params[v[1]]
		if !( p==nil or p == 0 )
			result[v[0]]=numberToBase64 p
		end
	end
	return result
end

optparse.parse!

accountKey=nil
if accountKeyFile == nil
	log.error "You did not specify the filename of your account key"
	exit
else
	begin
		accountKey = OpenSSL::PKey.read File.new accountKeyFile
	rescue StandardError => e
		log.error "Could not read your account key from : "+accountKeyFile
		exit
	end
end
csr=nil
if csrFilename == nil
	log.error "You did not specify the filename of your certificate signing request."
	exit
else
	begin
		csr=File.read csrFilename
	rescue StandardError => e
		log.error "Could not read your certificate signing request from : "+csrFilename
		exit
	end
end
proxy_host=nil
proxy_port=nil
if proxy != nil
	proxy_host=proxy.host
	proxy_port=proxy.port
end
acmeApiCalls={}
nonce=""
log.info("Get ACME Directory")
Net::HTTP.start(acmedirUri.host, acmedirUri.port, proxy_host, proxy_port, :use_ssl => acmedirUri.scheme == 'https', :verify_mode => OpenSSL::SSL::VERIFY_NONE  ) do |http|
	req = Net::HTTP::Get.new acmedirUri.path
	response = http.request req
	nonce=response["Replay-Nonce"]
	if response.code.to_i == 200
		log.info("ACME Directory successfull received.")
		 JSON.parse(response.body).each do |k,v|
			 acmeApiCalls[k]=URI v
		 end
	end
end

log.info("Try to Register new ACME Account")
Net::HTTP.start(acmeApiCalls["new-reg"].host, acmeApiCalls["new-reg"].port, proxy_host, proxy_port, :use_ssl => acmeApiCalls["new-reg"].scheme == 'https', :verify_mode => OpenSSL::SSL::VERIFY_NONE  ) do |http|
	req = Net::HTTP::Post.new acmeApiCalls["new-reg"].path
	req.body = newRegistration(accountKey,"lortas.de",nonce)
	response = http.request req
	nonce=response["Replay-Nonce"]
	result = JSON.parse(response.body)
	log.info(result["detail"])
end

Net::HTTP.start(acmeApiCalls["new-authz"].host, acmeApiCalls["new-authz"].port, proxy_host, proxy_port, :use_ssl => acmeApiCalls["new-authz"].scheme == 'https', :verify_mode => OpenSSL::SSL::VERIFY_NONE  ) do |http|
	req = Net::HTTP::Post.new acmeApiCalls["new-authz"].path
	req.body = newAuthorised(accountKey,"lortas.de",nonce)
	response = http.request req
	nonce=response["Replay-Nonce"]
	result = JSON.parse(response.body)
	puts result
end
