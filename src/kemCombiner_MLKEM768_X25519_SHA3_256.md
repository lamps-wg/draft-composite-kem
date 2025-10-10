Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
866f5a3f16ff8bebbcc1637dbba46813ddd818bd9bb357a2d5efe4c794c02381

tradSS:
a4a3bc91159618edc0dd67ac2535b9a0e22026af2664da1debb536a5dfc33c11

tradCT:
5e389a03f3dab351b9d66c3600246511da711f47a4fd43cb99100de3cc401a6d

tradPK:
ab0928f58ca15dcd23fbdbefd06047a07fe22f5716d96ff88e590bc34fbc8d7e

Label:  5c2e2f2f5e5c

        (ascii: "\.//^\")


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Label

Combined KDF Input: 866f5a3f16ff8bebbcc1637dbba46813ddd818bd9bb357a
2d5efe4c794c02381a4a3bc91159618edc0dd67ac2535b9a0e22026af2664da1deb
b536a5dfc33c115e389a03f3dab351b9d66c3600246511da711f47a4fd43cb99100
de3cc401a6dab0928f58ca15dcd23fbdbefd06047a07fe22f5716d96ff88e590bc3
4fbc8d7e5c2e2f2f5e5c


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss:
6aeb7e3a99d6fa73f296866c3695d3b591d197973b68c018aa22072de23b2a08
