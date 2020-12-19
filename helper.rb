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
								domains[v[1]]=true
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
end
