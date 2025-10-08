Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
596056880b0bf653cbfb0564699b312051cc7151185e5c368e9e1ac2e3d48315

tradSS:
9f5b87a25df11f9765b463091a08df19e0b714e53372e65b32ebba6035311361

tradCT:
8fee01a0aed0a39c6d52dc7df81269fd8715c7e7b1da4e4cbf5c32a7fbc50942

tradPK:
06b2deebdb7dc94964f91ab65ca9e44c1090b505703243dca62f8aba6d1cec6a

Label:  5c2e2f2f5e5c

        (ascii: "\.//^\")


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Label

Combined KDF Input: 596056880b0bf653cbfb0564699b312051cc7151185e5c3
68e9e1ac2e3d483159f5b87a25df11f9765b463091a08df19e0b714e53372e65b32
ebba60353113618fee01a0aed0a39c6d52dc7df81269fd8715c7e7b1da4e4cbf5c3
2a7fbc5094206b2deebdb7dc94964f91ab65ca9e44c1090b505703243dca62f8aba
6d1cec6a5c2e2f2f5e5c


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss:
dd50a7611a9b502a047e756ff8c9e782353ecfc46921f2244559a61d133892f4
