#!/usr/bin/env ruby
require 'optparse'
require 'logger'
require 'openssl'

# Logger
log = Logger.new(STDOUT)
log.progname = "letsencrypt"

# Insert local path to library path list
$:.unshift File.dirname(__FILE__)

require "helper"
require "acmeapi"

# Default Values
$VERBOSE=false
acmedirUri=URI "https://acme-v01.api.letsencrypt.org/directory"
proxy=nil
challengeTokenFolder="."
accountKeyFile=nil
csrFilename=nil
certFilename=nil

if ENV[acmedirUri.scheme+"_proxy"]
	proxy=URI ENV[acmedirUri.scheme+"_proxy"]
end

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
	opts.on( '-o', '--cer FILE', 'File where the certificate will be stored into' ) do |f|
		certFilename = f
	end
	opts.on( '-u', '--letsencryptDirectoryUrl URL', 'URL where the ACME Let\'s encrypt Directory is located. Default : "'+acmedirUri.to_s+'"' ) do |f|
		acmedirUri=URI f
	end
	opts.on( '-p', '--proxy URL', 'URL of the Proxy to use to access ACME URLs. Default : "'+((proxy==nil)?String.new():proxy.to_s)+'"' ) do |f|
		proxy=URI f
	end
	opts.on( '-f', '--challengeTokenFolder DIR', 'Path to the folder where the challenge toke shouls be stored. Default : "'+challengeTokenFolder+'"' ) do |f|
		challengeTokenFolder = f.sub(/\/*$/,"")
	end
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
		csr = OpenSSL::X509::Request.new File.read csrFilename
	rescue StandardError => e
		log.error "Could not read your certificate signing request from : "+csrFilename
		exit
	end
end

validetedchallenges=[]
acmeapi=AcmeApi.new accountKey,acmedirUri,proxy,log
acmeapi.loadAcmeDirectory
Helper.getDomainsFromCsr(csr).each do |domain|
	acmeapi.sendNewRegistration domain
	challenges=acmeapi.sendNewAuthorisation domain
	challenges.each do |challenge|
		# we want to use the token as file name
		# never trust forgin data. so we ensure that there is no bad character
		token=challenge["token"].tr("/","")
		case challenge["type"]
		when "http-01"
			f=File.new(challengeTokenFolder+"/"+token,"w")
			f.chmod(0644)
			f << token
			f << "."
			f << acmeapi.accountpubkeySha256
			f.close
			result=acmeapi.sendHttp01Challenge challenge
			while result["status"] == "pending"
				sleep 1
				result=acmeapi.getURI challenge["uri"]
			end
			File.unlink f
			if result["status"] == "valid"
				log.info "Challange is valid."
				validetedchallenges << challenge
			else
				log.error "Challenge is "+result["status"]+": "+result["error"]["detail"]
			end
		else
			log.info "Challenge type '"+challenge["type"]+"' not implemented."
		end
	end
end

#TODO: CSR should only be sent if ensured that all CSR-Domains are valided.
result=acmeapi.sendCsr csr
if result==nil
	log.error "FAIL!"
else
	if certFilename==nil
		puts result.to_pem
	else
		f=File.new(certFilename,"w")
		f<<result.to_pem
		f.close
	end
end
