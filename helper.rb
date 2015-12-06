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
end
