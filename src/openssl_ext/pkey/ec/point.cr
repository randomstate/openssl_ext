require "big"

class OpenSSL::PKey::EC::Point
  def initialize(group : EC::Group, generator : Bool = false)
    @internal = generator
    if generator
      @point = LibCrypto.ec_group_get0_generator(group)
    else
      @point = LibCrypto.ec_point_new(group)
    end
    @group = group
  end

  def initialize(group : EC::Group, point : EC::Point)
    @internal = false
    @group = group
    @point = LibCrypto.ec_point_dup(point, group)
  end

  @internal : Bool
  @point : Pointer(LibCrypto::EcPoint)
  getter group : EC::Group

  def to_unsafe
    @point
  end

  def finalize
    LibCrypto.ec_point_free(self) unless @internal
  end

  def dup
    self.class.new(group, self)
  end

  def mul(integer : Int) : EC::Point
    num = BN.new(integer)
    result = EC::Point.new(group)
    success = LibCrypto.ec_point_mul(group, result, Pointer(LibCrypto::Bignum).null, self, pointerof(num), Pointer(Void).null)
    result
  end
end
