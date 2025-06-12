Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
542aba637e129ef540743b8420edb78b26e492af2a496f31d33138a5402239c3

tradSS:
8af825f1d07ad0b3bff6856a6f7aaa706eb1db11b6a7d2c44dfb06d041e7e261

tradCT:
1c5e3c085e7180ffe732c67b94f0d408e524af9dc2954e5ceea1fdfc03a76247

tradPK:
0cf7344981ef158017db99cce88de79194f0bf8ebc128d462b1f6a89b34fce7c

Domain:  060b6086480186fa6b50050235


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Domain

Combined KDF Input: 542aba637e129ef540743b8420edb78b26e492af2a496f31d3
3138a5402239c38af825f1d07ad0b3bff6856a6f7aaa706eb1db11b6a7d2c44dfb06d0
41e7e2611c5e3c085e7180ffe732c67b94f0d408e524af9dc2954e5ceea1fdfc03a762
470cf7344981ef158017db99cce88de79194f0bf8ebc128d462b1f6a89b34fce7c060b
6086480186fa6b50050235


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss: 1fa931e383cd072d5df88a42865f1e2c14acac1c2820cfcf76fbbcd2444aadbd
