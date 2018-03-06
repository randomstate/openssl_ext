require "random/secure"
require "openssl"

class OpenSSL::Cipher
  def to_unsafe
    cipher
  end
end
