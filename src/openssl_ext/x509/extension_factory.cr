module OpenSSL::X509
  class ExtensionFactory
    def initialize
      @ctx = LibCrypto::X509V3_CTX.new
      raise Error.new("X509V3_CTX.new") unless @ctx
    end

    def initialize(@ctx : LibCrypto::X509V3_CTX)
      raise Error.new "Invalid X509V3_CTX" unless @ctx
    end

    def create_extension(oid : String, value : String, critical = false) : Extension
      LibCrypto.x509v3_set_ctx(self, @ctx.issuer_cert, @ctx.subject_cert, nil, nil, 0)
      Extension.new(self, oid, value, critical)
    end

    def subject_certificate=(cert : Certificate)
      @ctx.subject_cert = cert
    end

    def issuer_certificate=(cert : Certificate)
      @ctx.issuer_cert = cert
    end

    def finalize
      LibCrypto.openssl_free(self)
    end

    def to_unsafe
      pointerof(@ctx)
    end
  end
end
