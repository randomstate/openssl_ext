require "./src/openssl_ext"

key = OpenSSL::PKey::EC.new 256

pkey = OpenSSL::PKey.read(key.public_key.to_pem)

puts key.to_pem
puts pkey.to_pem

