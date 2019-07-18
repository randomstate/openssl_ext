module OpenSSL
  class Digest
    macro def_digest_classes(names)
      {% for name in names %}
        class {{name.id}} < Digest
          def self.new
            new("{{name.id}}", new_evp_mt_ctx("{{name.id}}"))
          end
        end
      {% end %}
    end

    def_digest_classes %w(DSS DSS1 MD2 MD4 MD5 MDC2 RIPEMD160 SHA SHA1 SHA224 SHA256 SHA384 SHA512)
  end
end
