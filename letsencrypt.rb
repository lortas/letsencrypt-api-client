#!/usr/bin/env ruby
require 'optparse'
require 'logger'
require 'openssl'

# Logger
log = Logger.new(STDOUT)
log.progname = "letsencrypt"
log.level = Logger::INFO


# Insert local path to library path list
$:.unshift File.dirname(__FILE__)

require "helper"
require "acmeapi"

# Default Values
$VERBOSE=false
acmedirUri=URI "https://acme-v01.api.letsencrypt.org/directory"
proxy=nil
useHttps=false
challengeTokenFolder=nil
accountKeyFile=nil
accountEmailAddr=nil
csrFilename=nil
certFilename=nil
renewalTime = nil

if ENV[acmedirUri.scheme+"_proxy"]
	proxy=URI ENV[acmedirUri.scheme+"_proxy"]
end

# Opt parsing
optparse = OptionParser.new do |opts|
	opts.banner = "Usage: letsencrypt.rb [options]"
	opts.on( '-v', '--verbose', 'Enable verbosity. Default is off.' ) do |verbose|
		$VERBOSE = true
		log.level=Logger::DEBUG
	end
	opts.on( '-q', '--quiet', 'Be more quiet.' ) do |verbose|
		$VERBOSE = false
		log.level=Logger::WARN
	end
	opts.on( '-s', '--useHttps', 'Instead of httpi, use https (tcp/443) for certificate challenge. Useful if you do not have a web server listen on tcp/80.' ) do |verbose|
		useHttps=true
	end
	opts.on( '-k', '--accountKey FILE', 'File where the private key for the ACME account is stored' ) do |f|
		accountKeyFile = f
	end
	opts.on( '-e', '--accountEmail EMAIL', 'E-mail address used for the ACME account is stored. Default : cert-admin@[doamin]' ) do |f|
		accountEmailAddr = f
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
	opts.on( '-f', '--challengeTokenFolder DIR', 'Path to the folder where the challenge toke shouls be stored.' ) do |f|
		challengeTokenFolder = f.sub(/\/*$/,"")
	end
	opts.on( '-r', '--renewalTime DAYS', 'The amount of day until the old certificates expiration date is still okay. If the certificate expiration date is more then DAYS in the future, no certificate renewal will be performed. Default behaviour is to perform always a certificate request.' ) do |f|
		renewalTime = Time::now + ( 60 * 60 * 24 * f.to_i )
	end
end

optparse.parse!

if renewalTime!=nil and certFilename!=nil and File.exists?(certFilename)
	oldcert = OpenSSL::X509::Certificate.new File.read certFilename
	expiry=oldcert.not_after
	if expiry > renewalTime
		log.info "The expiration date '"+expiry.to_s+"' of the current certificate is to far in the future. Do not perform a certificate request to replace this certificate."
		exit
	end
end

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

csrDomains=Helper.getDomainsFromCsr csr
if csrDomains.size <1
	log.error "Cound not find any domain within your certificate signing request."
	exit
end
if accountEmailAddr==nil
	accountEmailAddr="cert-admin@"+csrDomains[0]
end

log.info "It seems that we do have everything to ask for our certificate. Let's start."

acmeapi=AcmeApi.new accountKey,acmedirUri,proxy,log
acmeapi.loadAcmeDirectory
acmeapi.sendNewRegistration accountEmailAddr
allChallengesAreApproved=true
csrDomains.each do |domain|
	challengesAreApproved=false
	challenges=acmeapi.sendNewAuthorisation domain
	challenges.each do |challenge|
		oneChallengeIsApproved=false
		# we want to use the token as file name
		# never trust foreign data. so we ensure that there is no bad character
		token=challenge["token"]
		unless Helper.testForNonBase64UrlChars token
			log.error "The challenge token '"+token+"' has non Base64Url characters. Skip this challenge."
			next
		end
		case challenge["type"]
		when "http-01","tls-sni-01"
			protocol=(challenge["type"]=="http-01")?"http":"https"
			if (protocol=="http" and useHttps) or (protocol=="https" and !useHttps)
				log.debug "Skipping '"+challenge["type"]+"'-challenge. We do not want to do an "+protocol+" based challenge."
				next
			end
			log.debug "Starting '"+challenge["type"]+"'-challenge. This is an "+protocol+" based challenge."
			keyAuthorization=token+"."+acmeapi.accountpubkeySha256
			if challengeTokenFolder==nil
				print "==== manual '"+protocol+"' based challenge ====\n"
				print "The following link need to deliver the following content.\n"
				print " - URL:     "+protocol+"://"+domain+"/.well-known/acme-challenge/"+token+"\n"
				print " - Content: "+keyAuthorization+"\n\n"
				print "This may be done by the following steps:\n"
				print "1. Open a (remote) console to/on the system, whose IP address is resolving to the DNS entry '"+domain+"'.\n"
				print "2. Ensure that you have running a web server daemon listening on tcp/"
				print (protocol=="http")?"80":"443"
				print " and accessible from the internet.\n"
				print "3. Change your current working directory to the DocumentRoot of the domain '"+domain+"'.\n"
				print "4. Ensure that the following folder '.well-known/acme-challenge' exists ( mkdir -p .well-known/acme-challenge ).\n"
				print "5. Change your current working directory to the folder above ( cd .well-known/acme-challenge ).\n"
				print "6. Execute: echo -n '"+keyAuthorization+"' > '"+token+"'\n"
				print "7. Ensure that the new file is world-readable ( chmod +r '"+token+"' )\n"
				print "8. Hit Enter if you have performed all steps above. "
				gets
			else
				f=File.new(challengeTokenFolder+"/"+token,"w")
				f.chmod(0644)
				f << keyAuthorization
				f.close
			end
			result=acmeapi.sendChallenge challenge
			while result["status"] == "pending"
				sleep 1
				result=acmeapi.getURI challenge["uri"]
			end
			if challengeTokenFolder==nil
				print "You now can remove any folder and file created above.\nHit Enter to continue. "
				gets
			else
				File.unlink challengeTokenFolder+"/"+token
			end
			if result["status"] == "valid"
				log.info "Challenge is valid."
				oneChallengeIsApproved=true
			else
				detail=""
				if result["error"]
					detail=result["error"]["detail"]
				elsif result["detail"]
					detail=result["detail"]
				end
				log.warn "Challenge is "+result["status"].to_s+": "+detail
			end
		else
			log.info "Challenge type '"+challenge["type"]+"' not implemented."
		end
		if oneChallengeIsApproved
			challengesAreApproved=true
		end
	end
	unless challengesAreApproved
		allChallengesAreApproved=false
		log.error "Could not perform at least one approved challenge for the domain '"+domain+"'."
	end
end

unless allChallengesAreApproved
	log.error "Not all needed challenges were approved to be valid. We need at least one approved challenge for each domain noted within the certificate signing request file. Please consider the log entries to determine which challenge failed."
	exit
end

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
