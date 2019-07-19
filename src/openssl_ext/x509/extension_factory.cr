module OpenSSL::X509
  class ExtensionFactory
    getter issuer_cert : Certificate
    getter subject_cert : Certificate

    def initialize
      @ctx = LibCrypto::X509V3_CTX.new
      raise Error.new("X509V3_CTX.new") unless @ctx

      @issuer_cert = uninitialized Certificate
      @subject_cert = uninitialized Certificate
    end

    def initialize(@ctx : LibCrypto::X509V3_CTX)
      raise Error.new "Invalid X509V3_CTX" unless @ctx

      @issuer_cert = uninitialized Certificate
      @subject_cert = uninitialized Certificate
    end

    def create_extension(oid : String, value : String, critical = false) : Extension
      LibCrypto.x509v3_set_ctx(self, @issuer_cert, @subject_cert, nil, nil, 0)
      Extension.new(self, oid, value, critical)
    end

    def subject_certificate=(subject : Certificate)
      @subject_cert = subject
    end

    def issuer_certificate=(issuer : Certificate)
      @issuer_cert = issuer
    end

    def to_unsafe
      pointerof(@ctx)
    end
  end
end
