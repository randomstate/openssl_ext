require "openssl"

lib LibCrypto
  struct EvpPKey
    type : LibC::Int
    save_type : LibC::Int
    references : LibC::Int
    ameth : EVP_PKEY_ASN1_method
    engine : Engine
    pkey : EVP_PKEY_KEY
    save_parameters : LibC::Int
    attributes : StackStX509Attribute*
  end

  struct StackStX509Attribute
    stack : Stack
  end

  struct Stack
    num : LibC::Int
    data : LibC::Char**
    sorted : LibC::Int
    num_alloc : LibC::Int
    comp : (Void*, Void* -> LibC::Int)
  end

  struct Dsa
    pad : LibC::Int
    version : LibC::Long
    write_params : LibC::Int
    p : Bignum*
    q : Bignum*
    g : Bignum*
    pub_key : Bignum*
    priv_key : Bignum*
    kinv : Bignum*
    r : Bignum*
    flags : LibC::Int
    method_mont_p : BnMontCtx*
    references : LibC::Int
    ex_data : CryptoExData
    meth : DsaMethod*
    engine : Engine
  end

  struct Bignum
    d : LibC::ULong*
    top : LibC::Int
    dmax : LibC::Int
    neg : LibC::Int
    flags : LibC::Int
  end

  struct BnMontCtx
    ri : LibC::Int
    rr : Bignum
    n : Bignum
    ni : Bignum
    n0 : LibC::ULong[2]
    flags : LibC::Int
  end

  struct CryptoExData
    sk : StackVoid*
    dummy : LibC::Int
  end

  struct DsaMethod
    name : LibC::Char*
    dsa_do_sign : (UInt8*, LibC::Int, Dsa* -> DsaSig*)
    dsa_sign_setup : (Dsa*, BnCtx, Bignum**, Bignum** -> LibC::Int)
    dsa_do_verify : (UInt8*, LibC::Int, DsaSig*, Dsa* -> LibC::Int)
    dsa_mod_exp : (Dsa*, Bignum*, Bignum*, Bignum*, Bignum*, Bignum*, Bignum*, BnCtx, BnMontCtx* -> LibC::Int)
    bn_mod_exp : (Dsa*, Bignum*, Bignum*, Bignum*, Bignum*, BnCtx, BnMontCtx* -> LibC::Int)
    init : (Dsa* -> LibC::Int)
    finish : (Dsa* -> LibC::Int)
    flags : LibC::Int
    app_data : LibC::Char*
    dsa_paramgen : (Dsa*, LibC::Int, UInt8*, LibC::Int, LibC::Int*, LibC::ULong*, BnGencb* -> LibC::Int)
    dsa_keygen : (Dsa* -> LibC::Int)
  end

  struct StackVoid
    stack : Stack
  end

  struct DsaSig
    r : Bignum*
    s : Bignum*
  end

  struct BnGencb
    ver : LibC::UInt
    arg : Void*
    cb : BnGencbCb
  end

  struct Dh
    pad : LibC::Int
    version : LibC::Int
    p : Bignum*
    g : Bignum*
    length : LibC::Long
    pub_key : Bignum*
    priv_key : Bignum*
    flags : LibC::Int
    method_mont_p : BnMontCtx*
    q : Bignum*
    j : Bignum*
    seed : UInt8*
    seedlen : LibC::Int
    counter : Bignum*
    references : LibC::Int
    ex_data : CryptoExData
    meth : DhMethod*
    engine : Engine
  end

  struct DhMethod
    name : LibC::Char*
    generate_key : (Dh* -> LibC::Int)
    compute_key : (UInt8*, Bignum*, Dh* -> LibC::Int)
    bn_mod_exp : (Dh*, Bignum*, Bignum*, Bignum*, Bignum*, BnCtx, BnMontCtx* -> LibC::Int)
    init : (Dh* -> LibC::Int)
    finish : (Dh* -> LibC::Int)
    flags : LibC::Int
    app_data : LibC::Char*
    generate_params : (Dh*, LibC::Int, LibC::Int, BnGencb* -> LibC::Int)
  end

  struct Rsa
    pad : LibC::Int
    version : LibC::Long
    meth : RsaMethod*
    engine : Engine
    n : Bignum*
    e : Bignum*
    d : Bignum*
    p : Bignum*
    q : Bignum*
    dmp1 : Bignum*
    dmq1 : Bignum*
    iqmp : Bignum*
    ex_data : CryptoExData
    references : LibC::Int
    flags : LibC::Int
    _method_mod_n : BnMontCtx*
    _method_mod_p : BnMontCtx*
    _method_mod_q : BnMontCtx*
    bignum_data : LibC::Char*
    blinding : BnBlinding
    mt_blinding : BnBlinding
  end

  struct RsaMethod
    name : LibC::Char*
    rsa_pub_enc : (LibC::Int, UInt8*, UInt8*, Rsa*, LibC::Int -> LibC::Int)
    rsa_pub_dec : (LibC::Int, UInt8*, UInt8*, Rsa*, LibC::Int -> LibC::Int)
    rsa_priv_enc : (LibC::Int, UInt8*, UInt8*, Rsa*, LibC::Int -> LibC::Int)
    rsa_priv_dec : (LibC::Int, UInt8*, UInt8*, Rsa*, LibC::Int -> LibC::Int)
    rsa_mod_exp : (Bignum*, Bignum*, Rsa*, BnCtx -> LibC::Int)
    bn_mod_exp : (Bignum*, Bignum*, Bignum*, Bignum*, BnCtx, BnMontCtx* -> LibC::Int)
    init : (Rsa* -> LibC::Int)
    finish : (Rsa* -> LibC::Int)
    flags : LibC::Int
    app_data : LibC::Char*
    rsa_sign : (LibC::Int, UInt8*, LibC::UInt, UInt8*, LibC::UInt*, Rsa* -> LibC::Int)
    rsa_verify : (LibC::Int, UInt8*, LibC::UInt, UInt8*, LibC::UInt, Rsa* -> LibC::Int)
    rsa_keygen : (Rsa*, LibC::Int, Bignum*, BnGencb* -> LibC::Int)
  end

  union EVP_PKEY_KEY
    ptr : LibC::Char*
    rsa : Rsa*
    dsa : Dsa*
    dh : Dh*
    ec : Void*
  end

  union BnGencbCb
    cb_1 : (LibC::Int, LibC::Int, Void* -> Void)
    cb_2 : (LibC::Int, LibC::Int, BnGencb* -> LibC::Int)
  end

  enum Padding
    PKCS1_PADDING      = 1
    SSLV23_PADDING     = 2
    NO_PADDING         = 3
    PKCS1_OAEP_PADDING = 4
    X931_PADDING       = 5
    PKCS1_PSS_PADDING  = 6
  end

  BIO_CTRL_RESET = 1

  NID_rsaEncryption        =   6
  NID_dsa                  = 116
  NID_X9_62_id_ecPublicKey = 408

  EVP_PKEY_NONE = NID_undef
  EVP_PKEY_RSA  = NID_rsaEncryption
  EVP_PKEY_DSA  = NID_dsa
  EVP_PKEY_EC   = NID_X9_62_id_ecPublicKey

  alias PasswordCallback = (LibC::Char*, LibC::Int, LibC::Int, Void*) -> LibC::Int

  type EVP_PKEY_ASN1_method = Void*
  type Engine = Void*
  type BnCtx = Void*
  type BnBlinding = Void*

  alias ASN1_TIME = Void*

  fun obj_txt2nid = OBJ_txt2nid(s : UInt8*) : Int32
  fun asn1_dup = ASN1_dup(i2d : Void*, d2i_of_void : Void*, x : Void*) : Void*
  fun asn1_time_free = ASN1_TIME_free(t : ASN1_TIME)

  fun bignum_new = BN_new : Bignum*
  fun set_bignum_from_decimal = BN_dec2bn(a : Bignum**, str : LibC::Char*) : LibC::Int

  fun bio_s_mem = BIO_s_mem : BioMethod*
  fun bio_new = BIO_new(type : BioMethod*) : Bio*
  fun bio_free = BIO_free(bio : Bio*) : LibC::Int
  fun bio_free_all = BIO_free_all(bio : Bio*)
  fun bio_read = BIO_read(bio : Bio*, data : LibC::Char*, len : LibC::Int) : LibC::Int
  fun bio_write = BIO_write(bio : Bio*, data : LibC::Char*, len : LibC::Int) : LibC::Int
  fun bio_set_data = BIO_set_data(bio : Bio*, data : Void*)
  fun bio_get_data = BIO_get_data(bio : Bio*) : Void*
  fun bio_set_init = BIO_set_init(bio : Bio*, init : LibC::Int)
  fun bio_set_shutdown = BIO_set_shutdown(bio : Bio*, shut : LibC::Int)
  fun bio_ctrl = BIO_ctrl(bio : Bio*, cmd : LibC::Int, larg : LibC::Long, parg : Void*) : LibC::Long

  fun evp_pkey_new = EVP_PKEY_new : EvpPKey*
  fun evp_pkey_free = EVP_PKEY_free(pkey : EvpPKey*)
  fun evp_pkey_size = EVP_PKEY_size(pkey : EvpPKey*) : LibC::Int
  fun evp_pkey_bits = EVP_PKEY_bits(pkey : EvpPKey*) : LibC::Int
  fun evp_pkey_get1_rsa = EVP_PKEY_get1_RSA(pkey : EvpPKey*) : Rsa*
  fun evp_pkey_set1_rsa = EVP_PKEY_set1_RSA(pkey : EvpPKey*, key : Rsa*) : LibC::Int
  fun evp_pkey_assign = EVP_PKEY_assign(pkey : EvpPKey*, type : LibC::Int, key : Void*) : LibC::Int

  fun rsa_new = RSA_new : Rsa*
  fun rsa_public_key_dup = RSAPublicKey_dup(rsa : Rsa*) : Rsa*
  fun rsa_blinding_on = RSA_blinding_on(rsa : Rsa*, ctx : BnCtx) : LibC::Int
  fun rsa_blinding_off = RSA_blinding_off(rsa : Rsa*)
  fun rsa_generate_key_ex = RSA_generate_key_ex(rsa : Rsa*, bits : LibC::Int, e : Bignum*, cb : BnGencb*) : LibC::Int
  fun rsa_private_encrypt = RSA_private_encrypt(flen : LibC::Int, from : UInt8*, to : UInt8*, rsa : Rsa*, padding : LibC::Int) : LibC::Int
  fun rsa_public_encrypt = RSA_public_encrypt(flen : LibC::Int, from : UInt8*, to : UInt8*, rsa : Rsa*, padding : LibC::Int) : LibC::Int
  fun rsa_private_decrypt = RSA_private_decrypt(flen : LibC::Int, from : UInt8*, to : UInt8*, rsa : Rsa*, padding : LibC::Int) : LibC::Int
  fun rsa_public_decrypt = RSA_public_decrypt(flen : LibC::Int, from : UInt8*, to : UInt8*, rsa : Rsa*, padding : LibC::Int) : LibC::Int

  fun pem_read_bio_private_key = PEM_read_bio_PrivateKey(bp : Bio*, x : EvpPKey**, cb : (LibC::Char*, LibC::Int, LibC::Int, Void* -> LibC::Int), u : Void*) : EvpPKey*
  fun pem_read_bio_public_key = PEM_read_bio_PUBKEY(bp : Bio*, x : EvpPKey**, cb : (LibC::Char*, LibC::Int, LibC::Int, Void* -> LibC::Int), u : Void*) : EvpPKey*
  fun pem_write_bio_rsa_private_key = PEM_write_bio_RSAPrivateKey(bp : Bio*, x : Rsa*, enc : EVP_MD*, kstr : UInt8*, klen : LibC::Int, cb : (LibC::Char*, LibC::Int, LibC::Int, Void* -> LibC::Int), u : Void*) : LibC::Int
  fun pem_write_bio_rsa_public_key = PEM_write_bio_RSAPublicKey(bp : Bio*, x : Rsa*) : LibC::Int
  fun pem_write_bio_pkcs8_private_key = PEM_write_bio_PKCS8PrivateKey(bp : Bio*, x : EvpPKey*, enc : EVP_CIPHER*, kstr : LibC::Char*, klen : LibC::Int, cb : (LibC::Char*, LibC::Int, LibC::Int, Void* -> LibC::Int), u : Void*) : LibC::Int
  fun pem_write_bio_public_key = PEM_write_bio_PUBKEY(bp : Bio*, x : EvpPKey*) : LibC::Int

  fun d2i_private_key_bio = d2i_PrivateKey_bio(bp : Bio*, a : EvpPKey**) : EvpPKey*
  fun i2d_private_key = i2d_PrivateKey(a : EvpPKey*, pp : UInt8**) : LibC::Int
  fun i2d_public_key = i2d_PublicKey(a : EvpPKey*, pp : UInt8**) : LibC::Int

  OPENSSL_EC_EXPLICIT_CURVE = 0x000
  OPENSSL_EC_NAMED_CURVE    = 0x001

  alias EcKey = Void*
  alias EC_GROUP = Void*

  fun ec_key_new = EC_KEY_new : EcKey
  fun ec_key_free = EC_KEY_free(key : EcKey)
  fun ec_key_generate_key = EC_KEY_generate_key(key : EcKey) : Int32
  fun ec_key_new_by_curve_name = EC_KEY_new_by_curve_name(nid : Int32) : EcKey
  fun ec_key_print = EC_KEY_print(bio : Bio*, key : EcKey, off : Int32) : Int32
  fun ec_key_set_asn1_flag = EC_KEY_set_asn1_flag(eckey : EcKey, asn1_flag : Int32)
  fun ec_key_get0_group = EC_KEY_get0_group(key : EcKey) : EC_GROUP
  fun ec_key_set_group = EC_KEY_set_group(key : EcKey, group : EC_GROUP) : Int32
  fun ec_curve_nist2nid = EC_curve_nist2nid(s : UInt8*) : LibC::Int
  fun evp_pkey_get1_ec_key = EVP_PKEY_get1_EC_KEY(pkey : EvpPKey*) : EcKey
  fun i2d_ecprivatekey = i2d_ECPrivateKey(key : EcKey, out : UInt8**) : Int32
  fun i2d_ec_pubkey = i2d_EC_PUBKEY(key : EcKey, out : UInt8**) : Int32
  fun d2i_ecprivatekey = d2i_ECPrivateKey(key : EcKey*, out : UInt8**, length : Int64) : EcKey
  fun d2i_ec_pubkey = d2i_EC_PUBKEY(key : EcKey*, out : UInt8**, length : Int64) : EcKey
  fun i2d_ecprivatekey_bio = i2d_ECPrivateKey_bio(bio : Bio*, key : EcKey) : Int32
  fun i2d_ec_pubkey_bio = i2d_EC_PUBKEY_bio(bio : Bio*, key : EcKey) : Int32
  fun d2i_ecprivatekey_bio = d2i_ECPrivateKey_bio(bio : Bio*, key : EcKey*) : EcKey
  fun d2i_ec_pubkey_bio = d2i_EC_PUBKEY_bio(bio : Bio*, key : EcKey*) : EcKey
  fun ecdsa_size = ECDSA_size(eckey : EcKey) : Int32
  fun ecdsa_sign = ECDSA_sign(type : Int32, dgst : UInt8*, dgstlen : Int32, sig : UInt8*, siglen : UInt32*, eckey : EcKey) : Int32
  fun ecdsa_verify = ECDSA_verify(type : Int32, dgst : UInt8*, dgstlen : Int32, sig : UInt8*, siglen : UInt32, eckey : EcKey) : Int32
  fun ec_group_get_curve_name = EC_GROUP_get_curve_name(group : EC_GROUP) : Int32
  fun ec_group_set_asn1_flag = EC_GROUP_set_asn1_flag(group : EC_GROUP, flag : Int32)
  fun pem_read_bio_ecprivatekey = PEM_read_bio_ECPrivateKey(bio : Bio*, key : EcKey*, cb : PasswordCallback, user_data : Void*) : EcKey
  fun pem_write_bio_ecprivatekey = PEM_write_bio_ECPrivateKey(bio : Bio*, key : EcKey, enc : EVP_CIPHER*,
                                                              kstr : UInt8*, klen : Int32, cb : PasswordCallback, user_data : Void*) : Int32
  fun pem_read_bio_ec_pubkey = PEM_read_bio_EC_PUBKEY(bio : Bio*, key : EcKey*, cb : PasswordCallback, user_data : Void*) : EcKey
  fun pem_write_bio_ec_pubkey = PEM_write_bio_EC_PUBKEY(bio : Bio*, key : EcKey) : Int32

  # Adding x509 Capabilities
  fun x509_name_print_ex = X509_NAME_print_ex(bio : Bio*, name : X509_NAME, indent : Int32, flags : LibC::ULong) : LibC::Int
  fun x509_gmtime_adj = X509_gmtime_adj(t : ASN1_TIME, adj : Int64) : ASN1_TIME
  fun pem_read_bio_x509 = PEM_read_bio_X509(bp : Bio*, x : X509, cb : (LibC::Char*, LibC::Int, LibC::Int, Void* -> LibC::Int), u : Void*) : X509
  fun pem_write_bio_x509 = PEM_write_bio_X509(bp : Bio*, x : X509) : LibC::Int
  fun x509_get_public_key = X509_get_pubkey(x : X509) : EvpPKey*
  fun evp_sign_final = EVP_SignFinal(ctx : EVP_MD_CTX, md : UInt8*, s : LibC::UInt*, pkey : EvpPKey*) : LibC::Int
  fun evp_verify_final = EVP_VerifyFinal(ctx : EVP_MD_CTX, sigbuf : UInt8*, siglen : LibC::UInt, pkey : EvpPKey*) : LibC::Int
end
