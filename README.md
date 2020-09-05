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

## Note

The PKCS#12 test file password is **1234**

## Example 
```
> echo Hello world | sign-with-pkcs12.exe --pkcs12 .\test_file\pkcs12.p12 --password 1234 --display-all
Digest: 4L+7DC0oD8hjE6yYjmtTFdKleEQzXPYhRrZbamKCB3U=
Sign: rI08MXyflRr4qhm8EsZajpKmww+tRnawP4CTnGIfZiBr0Gx4/ieMQAwkpBVklvSOW7BCleWuFio+6rkX/0VNVBtIl07JbPuKOdorQ8pDWOLB59YGcWEx8R1ni3UEUPUIXiywR4qeqyFoSXFu48ABw8liBlJS6s+3CmNf7KH9O2+/Rwr3LcSi9EB3ZBimBB/DvObW0PU6OkbVc0yOOikQ3kBJOydmNAzBZCdO9AzuqOqkiS9iyUZWr9h3adWr9Q9VDvoqS48fP6B47Hthw7XrCqO1fiwGiT2RwdEjMs8WT2b360sfiMGgeE35IgOzboq2bvGvBtyoSlUZfI8pKQwGXw==
Verify: OK
Digest sign: rI08MXyflRr4qhm8EsZajpKmww+tRnawP4CTnGIfZiBr0Gx4/ieMQAwkpBVklvSOW7BCleWuFio+6rkX/0VNVBtIl07JbPuKOdorQ8pDWOLB59YGcWEx8R1ni3UEUPUIXiywR4qeqyFoSXFu48ABw8liBlJS6s+3CmNf7KH9O2+/Rwr3LcSi9EB3ZBimBB/DvObW0PU6OkbVc0yOOikQ3kBJOydmNAzBZCdO9AzuqOqkiS9iyUZWr9h3adWr9Q9VDvoqS48fP6B47Hthw7XrCqO1fiwGiT2RwdEjMs8WT2b360sfiMGgeE35IgOzboq2bvGvBtyoSlUZfI8pKQwGXw==
```
