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

  type EVP_PKEY_ASN1_method = Void*
  type Engine = Void*
  type BnCtx = Void*
  type BnBlinding = Void*

  fun bignum_new = BN_new : Bignum*
  fun set_bignum_from_decimal = BN_dec2bn(a : Bignum**, str : LibC::Char*) : LibC::Int

  fun evp_pkey_new = EVP_PKEY_new : EvpPKey*
  fun evp_pkey_free = EVP_PKEY_free(pkey : EvpPKey*)
  fun evp_pkey_size = EVP_PKEY_size(pkey : EvpPKey*) : LibC::Int
  fun evp_pkey_get1_rsa = EVP_PKEY_get1_RSA(pkey : EvpPKey*) : Rsa*
  fun evp_pkey_set1_rsa = EVP_PKEY_set1_RSA(pkey : EvpPKey*, key : Rsa*) : LibC::Int

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
  fun pem_write_bio_rsa_private_key = PEM_write_bio_RSAPrivateKey(bp : Bio*, x : Rsa*, enc : EVP_MD*, kstr : UInt8*, klen : LibC::Int, cb : (LibC::Char*, LibC::Int, LibC::Int, Void* -> LibC::Int), u : Void*) : LibC::Int
  fun pem_write_bio_rsa_public_key = PEM_write_bio_RSAPublicKey(bp : Bio*, x : Rsa*) : LibC::Int
  fun pem_write_bio_pkcs8_private_key = PEM_write_bio_PKCS8PrivateKey(bp : Bio*, x : EvpPKey*, enc : EVP_CIPHER*, kstr : LibC::Char*, klen : LibC::Int, cb : (LibC::Char*, LibC::Int, LibC::Int, Void* -> LibC::Int), u : Void*) : LibC::Int
  fun pem_write_bio_public_key = PEM_write_bio_PUBKEY(bp : Bio*, x : EvpPKey*) : LibC::Int

  fun d2i_private_key_bio = d2i_PrivateKey_bio(bp : Bio*, a : EvpPKey**) : EvpPKey*
  fun i2d_private_key = i2d_PrivateKey(a : EvpPKey*, pp : UInt8**) : LibC::Int
  fun i2d_public_key = i2d_PublicKey(a : EvpPKey*, pp : UInt8**) : LibC::Int

  # Adding x509 Capabilities
  fun pem_read_bio_x509 = PEM_read_bio_X509(bp : Bio*, x : X509**, cb : (LibC::Char*, LibC::Int, LibC::Int, Void* -> LibC::Int), u : Void*) : X509
  fun pem_write_bio_x509 = PEM_write_bio_X509(bp : Bio*, x : X509*) : LibC::Int
  fun x509_get_public_key = X509_get_pubkey(x : X509) : EvpPKey*
  fun evp_sign_final = EVP_SignFinal(ctx : EVP_MD_CTX, md : UInt8*, s : LibC::UInt*, pkey : EvpPKey*) : LibC::Int
  fun evp_verify_final = EVP_VerifyFinal(ctx : EVP_MD_CTX, sigbuf : UInt8*, siglen : LibC::UInt, pkey : EvpPKey*) : LibC::Int
end
