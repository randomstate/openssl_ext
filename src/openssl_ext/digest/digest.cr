require "digest"
require "digest/*"

class Digest
  macro def_digest_classes(names)
    {% for name in names %}
      class {{name.id}} < ::OpenSSL::Digest
        extend ClassMethods

        def initialize
          super("{{name.id}}")
        end

        protected def initialize(ctx : LibCrypto::EVP_MD_CTX)
          super("{{name.id}}", ctx)
        end

        def dup
          self.class.new(dup_ctx)
        end
      end
    {% end %}
  end

  def_digest_classes %w(DSS DSS1 MD2 MD4 MD5 MDC2 RIPEMD160 SHA SHA1 SHA224 SHA256 SHA384 SHA512)
end
