require "../src/openssl_ext"

key_pem = File.read("server_key.pem")
cert_pem = File.read("server_cert.pem")

cert = OpenSSL::X509::Certificate.from_pem cert_pem
key = OpenSSL.parse_pkey(key_pem)

puts "PrivateKey :\n" + key.to_pem + "\n"
puts "PublicKey :\n#{key.public_key.to_pem}" if key.public_key.to_pem == cert.public_key.to_pem
