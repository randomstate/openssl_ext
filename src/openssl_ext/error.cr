module OpenSSL
  class Error < Exception
    getter err
    getter err_msg = ""

    def initialize(msg = nil)
      unless (err = @err = LibCrypto.get_error) == 0
        @err_msg = String.new(LibCrypto.err_error_string(err, nil))
        msg = msg ? "#{msg}: #{@err_msg}" : @err_msg
      end
      super(msg)
    end
  end
end
