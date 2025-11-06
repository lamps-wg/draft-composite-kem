Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
6d1887359d027ee230ce296ab3713bfbd4f5882f679d6fe6fc1bbd18375a5ccc

tradSS:
581d748b7defafdeed042d4ec30f37f7bb87ab0ed4ef52682ec9a4c0a01eb95a

tradCT:
f1b35d3a8930a2854016f450d5ced88bbef4f06655dba312b01fb316841bee24

tradPK:
1b916c2512566e76b0721bd5b7a4a6d191f49eafdd0fbb04389b7f25f6dd0f7b

Label:  5c2e2f2f5e5c

        (ascii: "\.//^\")


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Label

Combined KDF Input: 6d1887359d027ee230ce296ab3713bfbd4f5882f679d6fe
6fc1bbd18375a5ccc581d748b7defafdeed042d4ec30f37f7bb87ab0ed4ef52682e
c9a4c0a01eb95af1b35d3a8930a2854016f450d5ced88bbef4f06655dba312b01fb
316841bee241b916c2512566e76b0721bd5b7a4a6d191f49eafdd0fbb04389b7f25
f6dd0f7b5c2e2f2f5e5c


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss:
1ff985393d374d1599517e84bfeeb81a222d7d84bf76c2296d6b5d28226c7154
