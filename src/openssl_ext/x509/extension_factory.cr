module OpenSSL::X509
  class ExtensionFactory
    getter issuer_cert
    getter subject_cert

    def initialize
      @ctx = LibCrypto::X509V3_CTX.new
      raise Error.new("X509V3_CTX.new") if @ctx.null?
    end

    def initialize(@ctx : LibCrypto::X509V3_CTX*)
      raise Error.new "Invalid X509V3_CTX" if @ctx.null?
    end

    def create_extension(oid : String, value : String, critical = false) : Extension
      LibCrypto.x509v3_set_ctx(pointerof(@ctx), self.issuer_cert, self.subject_cert, nil, nil, 0)
      Extension.new(pointerof(@ctx), oid, value, critical)
    end

    def subject_certificate=(cert : Certificate)
      self.subject_cert = cert
    end

    def issuer_certificate=(cert : Certificate)
      self.issuer_cert = cert
    end

    def finalize
      LibCrypto.openssl_free(@ctx)
    end

    def to_unsafe
      @ctx
    end
  end
end
