# letsencrypt-api-client
Independent command line client for the "Let’s Encrypt" (ACME) API. It is for people who want to generate certificate signing requests on their own and like to have little bit more control over the signing process.

This client was inspired by https://github.com/diafygi/gethttpsforfree and has a similar intension. So the same note applies here too:

> This tool is for people who know how to generate certificate signing requests (CSRs)! If you are not familiar with how to do this, please use the official Let's Encrypt client that can automatically issue and install certificates for you. This tool is designed for people who know what they are doing and just want to get their free certificate.

You can use this tool in two ways

 1. Within your server scripts, to automatically get a new certificate when your previous one will expire soon.
 2. On a client system, to get manual a new certificate, that will be placed on the server by your one.
 3. And any kind in between.

## precondition
 * You need Ruby >1.9
 * You may need ruby-json, in case it is not within your standard "libruby" distribution package
 * You need write access into the folder <code>/.well-known/acme-challenge/</code> on your web-root where your domain is hosted.

## example usage

First you need an identity, also called 'account key'. This is a RSA key, which can be generated with the following command
<pre><code>openssl genrsa -out account.key 4096</code></pre>

Then you need a key for your domain you want a certificate for
<pre><code>openssl genrsa -out domain.key 4096</code></pre>

You can generate the certificate signing request file with one of the following commands
<pre><code>
openssl req -new -sha256 -key domain.key -subj "/CN=www.example.org" -out domain.csr
openssl req -new -sha256 -key domain.key -subj "/CN=www.example.org" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:example.org,DNS:www2.example.org")) > domain.csr
openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:example.org,DNS:www.example.org,DNS:www2.example.org")) > domain.csr
</code></pre>

And finally run the command
<pre><code>./letsencrypt.rb -k account.key -c domain.csr -f /var/www/htdocs/.well-known/acme-challenge -o domain.cer -r 20</code></pre>

You may use the command without '-f', but then you have to put the challenge file by your own. This is useful if you do not want (or have doubts about) to run this command on your server.

Here is an example for a cron file <code>/etc/cron.weekly/updateLetsencrypt</code>
<pre><code>
if [ `stat --format=%Y /etc/ssl/private/example_org.key` -le $(( `date +%s` - 31630000 )) ]
then
    openssl genrsa -out /etc/ssl/private/example_org.key 4096
fi
openssl req -new -sha256 -key /etc/ssl/private/example_org.key -subj "/CN=example.org" > /etc/ssl/example_org.csr
/opt/letsencrypt-api-client/letsencrypt.rb -q -k /etc/ssl/private/letsencrypt_account.key -e cert-admin@example.org -c /etc/ssl/example_org.csr -f /var/www/htdocs/.well-known/acme-challenge/ -o /etc/ssl/certs/example_org.pem -r 20
rm /etc/ssl/example_org.csr
</code></pre>
