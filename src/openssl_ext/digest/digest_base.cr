module OpenSSL
  module DigestBase
    def self.hexdump(digest)
      String.build do |buffer|
        digest.each do |i|
          buffer.printf("%02x", i)
        end
      end
    end
  end
end
