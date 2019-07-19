require "../src/openssl_ext"

pkey = OpenSSL::EC.new(521)
cert = OpenSSL::X509::Certificate.new

name = OpenSSL::X509::Name.new
name.add_entry "DC", "crystal-lang.org"
name.add_entry "CN", "RootCA"
name.add_entry "OU", "Crystal"
name.add_entry "O", "Github"

cert.version = 2
cert.serial = 1_i64
cert.subject = OpenSSL::X509::Name.parse "DC=crystal-lang.org/OU=Crystal/O=Github/CN=My RootCA"
cert.issuer = cert.subject
cert.public_key = pkey.public_key
cert.not_before = OpenSSL::ASN1::Time.days_from_now(0)
cert.not_after = OpenSSL::ASN1::Time.days_from_now(365 * 10)

ef = OpenSSL::X509::ExtensionFactory.new
ef.subject_certificate = cert
ef.issuer_certificate = cert

cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
cert.add_extension(ef.create_extension("keyUsage", "keyCertSign, cRLSign", true))
cert.add_extension(ef.create_extension("subjectKeyIdentifier", "hash", false))
cert.add_extension(ef.create_extension("authorityKeyIdentifier", "keyid:always", false))

cert.sign(pkey, OpenSSL::Digest::SHA512.new)

#File.write "root_ca-cert.pem", cert.to_pem
#File.write "root_ca-key.pem", pkey.to_pem

puts cert.to_pem
puts pkey.to_pem

puts cert.public_key.to_pem

