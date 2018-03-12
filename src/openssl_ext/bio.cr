struct OpenSSL::GETS_BIO
  GETS_BIO = begin
    crystal_bio = OpenSSL::BIO::CRYSTAL_BIO
    crystal_bio.bgets = LibCrypto::BioMethodGets.new do |bio, buffer, len|
      io = Box(IO).unbox(bio.value.ptr)
      io.flush

      position = io.pos

      line = io.gets(len, false)

      if line.nil?
        return 0
      end

      io.seek(position)
      bytes = io.read(Slice.new(buffer, line.bytesize)).to_i

      bytes - 1
    end
    crystal_bio
  end

  @boxed_io : Void*

  def initialize(@io : IO)
    @bio = LibCrypto.bio_new(pointerof(GETS_BIO))

    # We need to store a reference to the box because it's
    # stored in `@bio.value.ptr`, but that lives in C-land,
    # not in Crystal-land.
    @boxed_io = Box(IO).box(io)
    @bio.value.ptr = @boxed_io
  end

  getter io

  def to_unsafe
    @bio
  end
end
