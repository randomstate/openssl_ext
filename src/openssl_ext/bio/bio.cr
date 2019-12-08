module OpenSSL
  class BioError < Error; end
end

struct OpenSSL::GETS_BIO
  GETS_BIO = begin
    crystal_bio = OpenSSL::BIO::CRYSTAL_BIO
    bgets = LibCrypto::BioMethodGets.new do |bio, buffer, len|
      io = Box(IO).unbox(BIO.get_data(bio))
      io.flush

      position = io.pos

      line = io.gets(len, false)

      if line.nil?
        return 0
      end

      io.seek(position)
      bytes = io.read(Slice.new(buffer, line.bytesize)).to_i

      bytes -= 1 unless bytes == 1
      bytes
    end
    {% if compare_versions(LibCrypto::OPENSSL_VERSION, "1.1.0") >= 0 %}
      LibCrypto.BIO_meth_set_gets(crystal_bio, bgets)
    {% else %}
      crystal_bio.value.bgets = bgets
    {% end %}
    crystal_bio
  end

  @boxed_io : Void*

  def initialize(@io : IO)
    @bio = LibCrypto.BIO_new(GETS_BIO)

    # We need to store a reference to the box because it's
    # stored in `@bio.value.ptr`, but that lives in C-land,
    # not in Crystal-land.
    @boxed_io = Box(IO).box(io)

    BIO.set_data(@bio, @boxed_io)
  end

  getter io

  def to_unsafe
    @bio
  end
end
