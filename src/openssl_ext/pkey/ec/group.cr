require "./point"
require "big"

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

  def baselen
    degree // 8
  end

  def generator : Point
    Point.new self, generator: true
  end

  def point : Point
    Point.new self
  end

  def order : BigInt
    bn = BN.new
    success = LibCrypto.ec_group_get_order(self, bn, Pointer(Void).null)
    raise "failed to get order" if success.zero?
    bn.to_big
  end
end
