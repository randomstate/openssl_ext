require "random/secure"
require "openssl/cipher"

class OpenSSL::Cipher
  def to_unsafe
    cipher
  end
end
