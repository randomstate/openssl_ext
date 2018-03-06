# openssl_rsa

RSA C Bindings for Crystal

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  openssl_rsa:
    github: randomstate/openssl_rsa.cr
```

## Usage

```crystal
require "openssl_rsa"
```

See `spec/rsa_spec.cr` for usage in depth.
The bindings closely follows the API for https://ruby-doc.org/stdlib-2.4.0/libdoc/openssl/rdoc/OpenSSL/PKey/RSA.html

**Encoding with a passphrase is not yet supported as OpenSSL fails silently without any errors (in order to fix).**


## Contributors

- [cimrie](https://github.com/cimrie) Connor Imrie - creator, maintainer
