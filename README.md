# Sign with PKCS#12
Sign any text using a PKCS#12 file (containing key and certificate)

## Help
```
signer --pkcs12 <pkcs12_file> [options]
--pkcs12 path       pkcs12 file path
--password passw    pkcs12 password (optional)
--digest            display digest (SHA256)
--sign              display signature (SHA256, RSA PKCS1 padding)
--verify            once sign done, display verify from public key
--digest-sign       display digest and sign via EVP_DigestSign
--display-all       display all things above
```

## Build

Using CMake, configure the project and assign OpenSSL in the cache. 

Note : use vcpkg to get OpenSSL and ZLIB easily.

Build on linux (Clang 10) ans Windows (MSVC 19.27.29111.0)
