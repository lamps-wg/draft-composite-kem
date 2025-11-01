Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
d4dc3f9fe2e2cc227a7c02ff52cf0e32a8b1ee7616f3a9b5e0dfb3e9ef31986f

tradSS:
bb55e07e4a68b6087078681ab5547cde537bf1de422f89eb7ccd0dbfd58a1903

tradCT:
b2608b176034413b41900d7f2c556110f8981891f63b0bd71388cdedcec20b11

tradPK:
e69089a334e0cadf2f004ffedb79878e446c9c6dee1e69cfa9fe85ade0975006

Label:  5c2e2f2f5e5c

        (ascii: "\.//^\")


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Label

Combined KDF Input: d4dc3f9fe2e2cc227a7c02ff52cf0e32a8b1ee7616f3a9b
5e0dfb3e9ef31986fbb55e07e4a68b6087078681ab5547cde537bf1de422f89eb7c
cd0dbfd58a1903b2608b176034413b41900d7f2c556110f8981891f63b0bd71388c
dedcec20b11e69089a334e0cadf2f004ffedb79878e446c9c6dee1e69cfa9fe85ad
e09750065c2e2f2f5e5c


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss:
09266b1ad41a6a18989abf5e3fcbb8cf733be540be26bbf4c307a3bfe2316cec
