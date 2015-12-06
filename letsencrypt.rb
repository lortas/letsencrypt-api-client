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
accountKeyFile=nil
csrFilename=nil
acmedirUri=nil
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

acmeapi=AcmeApi.new accountKey,acmedirUri,proxy,log
acmeapi.loadAcmeDirectory
acmeapi.sendNewRegistration("lortas.de")
