require "./point"

class OpenSSL::PKey::EC::Group
  def initialize(ec : EC)
    @internal = true
    @group = LibCrypto.ec_key_get0_group(LibCrypto.evp_pkey_get1_ec_key(ec))
  end

  @internal : Bool
  @group : LibCrypto::EC_GROUP

  def to_unsafe
    @group
  end

  def finalize
    LibCrypto.ec_group_free(self) unless @internal
  end

  def degree
    LibCrypto.ec_group_get_degree self
  end

  def generator : Point
    Point.new self, generator: true
  end

  def point : Point
    Point.new self
  end
end
