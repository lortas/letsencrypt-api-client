# letsencrypt-api-client
Independent command line client for the "Let’s Encrypt" (ACME) API. It is for people who want to generate certificate signing requests on their own and like to have little bit more control over the signing process.

example usage

openssl genrsa -out account.key 4096

openssl genrsa -out domain.key 4096

openssl req -new -sha256 -key domain.key -subj "/CN=www.example.org" -out domain.csr
oder
openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:example.org,DNS:www.example.org")) > domain.csr

./letsencrypt.rb -k account.key -c domain.csr
