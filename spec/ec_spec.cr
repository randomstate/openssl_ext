require "./spec_helper"

require "spec"
require "../src/openssl_ext/pkey/ec"

describe OpenSSL::PKey::EC do
  describe "instantiating and generate a key" do
    it "can instantiate and generate for a given key size" do
      pkey = OpenSSL::PKey::EC.new(384)
      pkey.private?.should be_true
      pkey.public?.should be_false

      pkey.public_key.public?.should be_true
    end
    it "can export to PEM format" do
      pkey = OpenSSL::PKey::EC.new(384)
      pkey.private?.should be_true

      pem = pkey.to_pem
      is_empty = "-----BEGIN EC PRIVATE KEY-----\n-----END EC PRIVATE KEY-----\n" == pem

      pem.should contain("BEGIN EC PRIVATE KEY")
      is_empty.should be_false
    end
    it "can export to DER format" do
      pkey = OpenSSL::PKey::EC.new(384)
      pkey.private?.should be_true
      pem = pkey.to_pem
      der = pkey.to_der

      pkey = OpenSSL::PKey::EC.new(der)
      pkey.to_pem.should eq pem
      pkey.to_der.should eq der
    end
    it "can instantiate with a PEM encoded key" do
      pem = OpenSSL::PKey::EC.new(384).to_pem
      pkey = OpenSSL::PKey::EC.new(pem)

      pkey.to_pem.should eq pem
    end
    it "can instantiate with a DER encoded key" do
      der = OpenSSL::PKey::EC.new(384).to_der
      pkey = OpenSSL::PKey::EC.new(der)

      pkey.to_der.should eq der
    end
  end
  describe "encrypting / decrypting" do
    it "should be able to sign and verify data" do
      ec = OpenSSL::PKey::EC.new(384)
      sha256 = OpenSSL::Digest.new("sha256")
      data = "my test data"
      sha256.update(data)
      digest = sha256.final
      signature = ec.ec_sign(digest)

      ec.ec_verify(digest, signature).should be_true
    end
  end
end
