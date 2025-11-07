Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
fdbab9b807a578e5601f98db3c803f7e2e5e85b80add50ac59dd6f50b38c1372

tradSS:
1bc5516686552096ae4deb8186e69d30473298f8f5b926d5d9cc1510ac1c954b

tradCT:
ddbc2b6c3de2425d47dae6df9ad1a1c722d4327e61e03ace083f12ea64047a53

tradPK:
28de695b688e0d0612ee1906cf62c6f2eaf70910c3daba5095673629a8b7a418

Label:  5c2e2f2f5e5c

        (ascii: "\.//^\")


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Label

Combined KDF Input: fdbab9b807a578e5601f98db3c803f7e2e5e85b80add50a
c59dd6f50b38c13721bc5516686552096ae4deb8186e69d30473298f8f5b926d5d9
cc1510ac1c954bddbc2b6c3de2425d47dae6df9ad1a1c722d4327e61e03ace083f1
2ea64047a5328de695b688e0d0612ee1906cf62c6f2eaf70910c3daba5095673629
a8b7a4185c2e2f2f5e5c


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss:
f103f16f0d8b9c69be1d1276b30495e991387dcab41eb957f99b34faaded6804
