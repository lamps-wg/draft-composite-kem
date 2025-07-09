Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
c16afc7df01f411f28577a343668d1fc022bb8738f1237b4e2c8fa9fafe628e0

tradSS:
9fd2d3dcae0cb154bb3edc1f6e4a2275f2c72675b5947b3c063ef7b7e8e41639

tradCT:
acbf2c905bdfae6c1bcdd72efb6b507051c11f6073e3bbabafdc26ee4877b457

tradPK:
431f6bd3bf16532849dbec8d6ccdba02c2a26cb3d0f6adbcf84c5c9043eab120

Domain:  060b6086480186fa6b50050235


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Domain

Combined KDF Input: c16afc7df01f411f28577a343668d1fc022bb8738f1237b4e2
c8fa9fafe628e09fd2d3dcae0cb154bb3edc1f6e4a2275f2c72675b5947b3c063ef7b7
e8e41639acbf2c905bdfae6c1bcdd72efb6b507051c11f6073e3bbabafdc26ee4877b4
57431f6bd3bf16532849dbec8d6ccdba02c2a26cb3d0f6adbcf84c5c9043eab120060b
6086480186fa6b50050235


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss: fb6ae3b70b08c001c433975e587f8c21f757120785d2ab826b91f7e3ff834d4c
