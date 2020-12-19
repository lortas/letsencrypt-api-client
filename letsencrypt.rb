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
acmedirUri=URI "https://acme-v02.api.letsencrypt.org/directory"
proxy=nil
useHttps=false
challengeTokenFolder=nil
accountKeyFile=nil
accountEmailAddr=nil
csrFilename=nil
certFilename=nil
chainFilename=nil
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
	opts.on( '-n', '--chain FILE', 'File where the CA certificate(s) will be stored into' ) do |f|
		chainFilename = f
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
acmeapi.requestNewNonce
acmeapi.sendNewRegistration accountEmailAddr
order=acmeapi.newOrder csrDomains
placedtoken=[]
while ! order["authorizations"].empty?
	done=[]
	order["authorizations"].each do |authorization|
		authObject=acmeapi.getAuthorization authorization
		domain=authObject["identifier"]["value"]
		challenges=authObject["challenges"].select{|c| c["type"]=="http-01" && c["status"]=="pending" }
		if challenges.empty?
			done << authorization
		else
			challenges.each do |challenge|
				protocol="http"
				token=challenge["token"]
				keyAuthorization=token+"."+acmeapi.accountpubkeySha256
				if placedtoken.include? token
					sleep 60
				else
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
					placedtoken << token
				end
				acmeapi.getObject(URI challenge["url"])
			end
		end
	end
	done.each{ |authorization| order["authorizations"].delete authorization }
end
if challengeTokenFolder==nil
	print "You now can remove any folder and file created above.\nHit Enter to continue. "
	gets
else
	placedtoken.each do |token|
		File.unlink challengeTokenFolder+"/"+token
	end
end
finalize=acmeapi.getObject( URI(order["finalize"]) , {"csr"=>Helper.base64encode(csr.to_der)} )
chain=acmeapi.getURI URI finalize[:body]["certificate"]
# We just assume that the first certificate is the client certificate and not one of the CA certificates
certificate=chain.slice!(/-----BEGIN CERTIFICATE-----(.|\n|\r)*?-----END CERTIFICATE-----/)
chain.strip!

if certFilename==nil
	puts certificate
	puts chain
else
	f=File.new(certFilename,"w")
	f.puts certificate
	# if no chain file defined, we append the chain to the cert file
	unless chainFilename==nil
		f.close
		f=File.new(chainFilename,"w")
	end
	f.puts chain
	f.close
end
