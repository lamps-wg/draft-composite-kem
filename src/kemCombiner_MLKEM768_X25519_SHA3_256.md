Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
c40c03784030d51cf7fff4364502adf83122bb658fccba8acb780f8bb0111a1a

tradSS:
ad3af2ea79de53b4aca7d7361fb0e113d42859d22f43833118f6a77191be0b51

tradCT:
11736b7b25250305b9d22307a9d9351aaf2a7a808264e106ab721bc0fa0f1671

tradPK:
96560ec1619de5d414ac182b58736b857995ad3e2cf228bfd2f60ae43d892f49

Label:  5c2e2f2f5e5c

        (ascii: "\.//^\")


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Label

Combined KDF Input: c40c03784030d51cf7fff4364502adf83122bb658fccba8
acb780f8bb0111a1aad3af2ea79de53b4aca7d7361fb0e113d42859d22f43833118
f6a77191be0b5111736b7b25250305b9d22307a9d9351aaf2a7a808264e106ab721
bc0fa0f167196560ec1619de5d414ac182b58736b857995ad3e2cf228bfd2f60ae4
3d892f495c2e2f2f5e5c


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss:
903ec1ed0ef9a32ab02f95214e214a435ab2209b6f0d3e0645861e8a4913908d
