Values are provided as ASCII strings, but MUST be converted into binary in the obvious way.
For example:

* "`\.//^\`" in hexadecimal is "`5c2e2f2f5e5c`"
* "`QSF-MLKEM768-P256-HMACSHA256`" in hexadecimal is "`5153462d4d4c4b454d3736382d503235362d484d4143534841323536`"


| Composite KEM Algorithm                       | Label (string)                       |
| --------------------------------------------- | ------------------------------------ |
| id-MLKEM768-RSA2048-HMAC-SHA256               | `QSF-MLKEM768-RSAOAEP2048-HMACSHA256 ` |
| id-MLKEM768-RSA3072-HMAC-SHA256               | `QSF-MLKEM768-RSAOAEP3072-HMACSHA256 ` |
| id-MLKEM768-RSA4096-HMAC-SHA256               | `QSF-MLKEM768-RSAOAEP4096-HMACSHA256 ` |
| id-MLKEM768-X25519-SHA3-256                   | `\.//^\                              ` |
| id-MLKEM768-ECDH-P256-HMAC-SHA256             | `QSF-MLKEM768-P256-HMACSHA256        ` |
| id-MLKEM768-ECDH-P384-HMAC-SHA256             | `QSF-MLKEM768-P384-HMACSHA256        ` |
| id-MLKEM768-ECDH-brainpoolP256r1-HMAC-SHA256  | `QSF-MLKEM768-BP256-HMACSHA256       ` |
| id-MLKEM1024-RSA3072-HMAC-SHA512              | `QSF-MLKEM1024-RSAOAEP3072-HMACSHA512` |
| id-MLKEM1024-ECDH-P384-HMAC-SHA512            | `QSF-MLKEM1024-P384-HMACSHA512       ` |
| id-MLKEM1024-ECDH-brainpoolP384r1-HMAC-SHA512 | `QSF-MLKEM1024-BP384-HMACSHA512      ` |
| id-MLKEM1024-X448-SHA3-256                    | `QSF-MLKEM1024-X448-SHA3256          ` |
| id-MLKEM1024-ECDH-P521-HMAC-SHA512            | `QSF-MLKEM1024-P521-HMACSHA512       ` |
