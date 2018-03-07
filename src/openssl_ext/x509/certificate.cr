module OpenSSL::X509
  class Certificate
    class CertificateError < OpenSSL::Error; end

    def self.new(pem : String)
      io = IO::Memory.new(pem)
      bio = OpenSSL::GETS_BIO.new(io)
      x509 = LibCrypto.pem_read_bio_x509(bio, nil, nil, nil)

      raise CertificateError.new "Could not read PEM" unless x509
      new x509
    end

    def to_pem(io)
      bio = OpenSSL::GETS_BIO.new(io)
      cert_pointer = self.to_unsafe_pointer
      raise CertificateError.new "Could not convert to PEM" unless LibCrypto.pem_write_bio_x509(bio, cert_pointer)
    end

    def to_pem
      io = IO::Memory.new
      to_pem(io)
      io.to_s
    end

    def public_key
      RSA.new(LibCrypto.x509_get_public_key(self), false)
    end

    def to_unsafe_pointer
      pointerof(@cert)
    end
  end
end
