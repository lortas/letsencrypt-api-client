#!/usr/bin/env ruby
require 'optparse'
require 'logger'
require 'json'
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

acmeapi=AcmeApi.new accountKey,acmedirUri,proxy,log
acmeapi.loadAcmeDirectory
acmeapi.sendNewRegistration "lortas.de"
challenges = acmeapi.sendNewAuthorisation "lortas.de"
challenges.each do |challenge|
	token=challenge["token"].tr("/","")
	keyauth=token+"."+acmeapi.accountpubkeySha256
	case challenge["type"]
	when "http-01"
		f=File.new(challengeTokenFolder+"/"+token,"w")
		f.chmod(0644)
		f << keyauth
		f.close
		acmeapi.sendHttp01Challenge challenge
		File.unlink f
	else
		log.info "Challenge type '"+challenge["type"]+"' not implemented."
	end
end
