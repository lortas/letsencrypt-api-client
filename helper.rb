module Helper
	require 'openssl'
	module_function

	# ACME use a modified variant of base64 encoding.
	#  - It has no padding equal-symbols at the end
	#  - It uses "_" for "/"
	#  - It uses "-" for "+"
	def base64encode(data)
		return [data].pack("m0").sub(/=*$/,"").tr("/+","_-")
	end

	def testForNonBase64UrlChars(string)
		i=string.index(/[^-_0-9A-Za-z]/)
		return i==nil
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
		keydata = {}
		if key.is_a? OpenSSL::PKey::RSA
			keydata["kty"]="RSA"
		elsif key.is_a?OpenSSL::PKey::EC
			keydata["kty"]="EC"
		else
			keydata["kty"]="UNKNOWN"
		end
		params=key.params
		[["n","n"],["e","e"],["d","d"],["p","p"],["q","q"],["dp","dmp1"],["dq","dmq1"],["qi","iqmp"]].each do |v|
			p=params[v[1]]
			if !( p==nil or p == 0 )
				keydata[v[0]]=numberToBase64 p
			end
		end

		# Since Ruby 1.9 the hash entry order is defined by it insert order
		# We need the hash entries sorted in lexicographical order.
		result={}
		keydata.keys.sort.each do |k|
			result[k]=keydata[k]
		end
		return result
	end

	def getDomainsFromCsr(csr)
		domains={}
		csr.subject.to_a.each do |e|
			if e[0] == "CN"
				domains[e[1]]=true
			end
		end
		csr.attributes.each do |attributeListByType|
			attributeListByType.value.each do |attributes|
				attributes.each do |i|
					if i.is_a? OpenSSL::ASN1::Sequence
						ary = Asn1SequenceToArray i
						if ary.size==2 and ary[0].is_a? OpenSSL::ASN1::ObjectId and ary[0].value=="subjectAltName"
							Asn1OctetStringToArray(ary[1]).each do |v|
								if v[0] == 130
									# Domain Name
									domains[v[1]]=true
								elsif v[0] == 135
									# IPv4 Address
									ip=v[1].chars.map{|x| x.ord.to_s}.join(".")
									domains[ip]=true
								else
									# unknown Type
									p v
									domains[v[1]]=true
								end
							end
						end
					end
				end
			end
		end
		return domains.keys.sort
	end

	def Asn1SequenceToArray(seq)
		ret=[]
		seq.each { |e| ret << e }
		return ret
	end

	def Asn1OctetStringToArray(o)
		ret=[]
		b=[]
		o.value.bytes.each{|i| b<<i}
		#skip the first two unknown bytes
		unknown = b.slice!(0,2)
		while b.size>0
			tag=b.slice!(0)
			length=b.slice!(0)
			value=b.slice!(0,length).map{|c| c.chr}.join
			ret << [tag,value]
		end
		return ret
	end

	def splitPems(data)
		result=[]
		while e=data.sub!(/-----BEGIN ([A-Z][A-Z ]*)-----[\n\r]+.*?\n-----END \1-----[\n\r]*/,"")
			result << e
		end
		return result
	end

	def buildcertchain(chain)
		certificates={}
		while certificate=chain.slice!(/-----BEGIN CERTIFICATE-----(.|\n|\r)*?-----END CERTIFICATE-----/)
			chain.strip!
			c=OpenSSL::X509::Certificate.new certificate
			h=c.subject.hash
			if certificates.key? h
				certificates[h] << c.to_pem
			else
				certificates[h] = [c.to_pem]
			end
		end

		notdone=true
		while notdone
			newcerts=[]
			certificates.each_pair do |subject_hash,certs|
				certs.each do |certificate|
					c=OpenSSL::X509::Certificate.new certificate
					next if c.issuer.hash == subject_hash
					Dir["/etc/ssl/certs/"+c.issuer.hash.to_s(16)+".*"].each do |cafile|
						cacert=File.read(cafile).strip
						newcerts << OpenSSL::X509::Certificate.new(cacert).to_pem
					end
				end
			end
			notdone=false
			newcerts.each do |certificate|
				c=OpenSSL::X509::Certificate.new certificate
				h=c.subject.hash
				if certificates.key? h
					unless certificates[h].include?( c.to_pem )
						notdone=true
						certificates[h] << c.to_pem
					end
				else
					notdone=true
					certificates[h] = [c.to_pem]
				end
				certificates[h].uniq!
			end
		end

		# Convert all PEMs to certificate object
		certificates.each_value{|certs| certs.map!{|c| OpenSSL::X509::Certificate.new c}}

		# Get a list off all issuers
		all_issuers=[]
		certificates.each_value do |certs|
			all_issuers  += certs.map{|c| c.issuer.hash}.uniq
		end
		all_issuers.uniq!
		# Search for certificate which are not an issuer
		non_issuers=certificates.keys.select{|subj| ! all_issuers.include?(subj) }

		chains=[]
		non_issuers.each do |issuer|
			chains+=certificates[issuer].map{|c|[c]}
			certificates.delete issuer
		end

		notdone=true
		while notdone
			newchains=[]
			notdone=false
			chains.each do |chain|
				h=chain.last.issuer.hash
				if (h!=chain.last.subject.hash) and certificates.key?(h)
					certificates[h].each do |cert|
						newchains << chain.clone.append(cert)
					end
					notdone=true
				else
					newchains << chain
				end
			end
			chains=newchains
		end

		return [
			chains.map{|chain| chain.shift.to_pem}.uniq.map{|c| OpenSSL::X509::Certificate.new c}.map{|c| "subject="+c.subject.to_s+"\nissuer="+c.issuer.to_s+"\nnot_before="+c.not_before.to_s+"\nnot_after="+c.not_after.to_s+"\n"+c.to_pem}.join,
			chains.flatten.map{|c| c.to_pem}.uniq.map{|c| OpenSSL::X509::Certificate.new c}.select{|c| c.subject.hash!=c.issuer.hash}.map{|c| "subject="+c.subject.to_s+"\nissuer="+c.issuer.to_s+"\nnot_before="+c.not_before.to_s+"\nnot_after="+c.not_after.to_s+"\n"+c.to_pem}.join
		]
	end
end
