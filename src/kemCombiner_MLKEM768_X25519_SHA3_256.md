Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
b191c0384d3a5c3921fd2fe63fdb87a9156d3e73efb9c5ebf0e2cc00a2087643

tradSS:
e8247eb791cc06cb8e50d404058c820ad1b44e02d39b855c041a03cf03ebe44a

tradCT:
6da0261f94959c4da892dbaf5680af92d962b0b59befae895f44b95bdcbbae1e

tradPK:
c5c26f76e6232e48aa2d1a87ced73f275a4031cdf83aff90c26d036d12611977

Label:  5c2e2f2f5e5c

        (ascii: "\.//^\")


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Label

Combined KDF Input: b191c0384d3a5c3921fd2fe63fdb87a9156d3e73efb9c5e
bf0e2cc00a2087643e8247eb791cc06cb8e50d404058c820ad1b44e02d39b855c04
1a03cf03ebe44a6da0261f94959c4da892dbaf5680af92d962b0b59befae895f44b
95bdcbbae1ec5c26f76e6232e48aa2d1a87ced73f275a4031cdf83aff90c26d036d
126119775c2e2f2f5e5c


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss:
ff15da0b25b55c8971b5e088cd4fba3e6f90c848cb9c068c24ac701e487eb9c4
