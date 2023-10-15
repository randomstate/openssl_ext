require "./spec_helper"

require "spec"
require "../src/openssl_ext/pkey/ec"
require "base64"

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

  describe "groups and points" do
    it "should be able to generate a matter verifier", focus: true do
      passcode = 20202021_u32
      io = IO::Memory.new
      io.write_bytes(passcode, IO::ByteFormat::LittleEndian)

      salt = Base64.decode "U1BBS0UyUCBLZXkgU2FsdA=="
      iterations = 1000

      # "prime256v1" or "secp256r1" are aliases for "P-256"
      curve = OpenSSL::PKey::EC.generate("P-256")
      group = curve.group
      point = group.generator
      ws_length = group.baselen + 8
      nist256p_order = group.order

      ws = OpenSSL::PKCS5.pbkdf2_hmac(io.to_slice, salt, iterations, OpenSSL::Algorithm::SHA256, ws_length * 2)
      w0 = OpenSSL::BN.from_bin(ws[0, ws_length]).to_big % nist256p_order
      w1 = OpenSSL::BN.from_bin(ws[ws_length, ws_length]).to_big % nist256p_order

      point = point.mul(w1)

      w0_bytes = OpenSSL::BN.new(w0).to_bin
      point_bytes = point.uncompressed_bytes

      output = w0_bytes + point_bytes
      output.should eq Base64.decode("uWFwqugDNGiEck/po7KHwwMwwqZgN10XuyBajPGuyzUEV/iree4lOrao5GuwnlQ65CJzbeUB49s31EH+NEkg0JVI5MGCQGMMT/SRPFNRODm3wH/MBiehuFc6FJ/NH6Rmzw==")
    end
  end
end
