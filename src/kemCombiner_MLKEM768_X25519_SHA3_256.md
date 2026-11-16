Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
7cfeecea076323d6bf08a046a483eec9500fac17cd34e6a73ffd21126e054e34

tradSS:
99701e0007aa3fc6259b219b4c321895597cecdb6676f9bcd1f038eb137fa070

tradCT:
e0923e7f074df8b5abb70b5180df48d6c35a226b649d6b5b02db2d48fe003d19

tradPK:
deb4ff2116d137d59143e69eb413b9050b279b83e0c1c21f8f257ef8293ad726

Label:  5c2e2f2f5e5c

        (ascii: "\.//^\")


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Label

Combined KDF Input: 7cfeecea076323d6bf08a046a483eec9500fac17cd34e6a
73ffd21126e054e3499701e0007aa3fc6259b219b4c321895597cecdb6676f9bcd1
f038eb137fa070e0923e7f074df8b5abb70b5180df48d6c35a226b649d6b5b02db2
d48fe003d19deb4ff2116d137d59143e69eb413b9050b279b83e0c1c21f8f257ef8
293ad7265c2e2f2f5e5c


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss:
7cbf305947d0a755ba3b618ec4553c28f1931258c42e097f8924bb2f6eda4970
