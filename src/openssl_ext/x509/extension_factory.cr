module OpenSSL::X509
  class ExtensionFactory
    getter issuer_cert
    getter subject_cert

    def initialize
      @ctx = LibCrypto::X509V3_CTX.new
      raise Error.new("X509V3_CTX.new") unless @ctx
    end

    def initialize(@ctx : LibCrypto::X509V3_CTX)
      raise Error.new "Invalid X509V3_CTX" unless @ctx
    end

    def create_extension(oid : String, value : String, critical = false) : Extension
      LibCrypto.x509v3_set_ctx(self, self.issuer_cert, self.subject_cert, nil, nil, 0)
      Extension.new(self, oid, value, critical)
    end

    def subject_certificate=(cert : Certificate)
      self.subject_cert = cert
      @ctx.subject_cert = cert.as Void*
    end

    def issuer_certificate=(cert : Certificate)
      self.issuer_cert = cert
      @ctx.issuer_cert = cert.as Void*
    end

    def finalize
      LibCrypto.openssl_free(self)
    end

    def to_unsafe
      pointerof(@ctx)
    end
  end
end
