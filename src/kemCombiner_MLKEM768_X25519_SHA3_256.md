Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
50e8413bab2ad551e46ae9d4c54bbcc6240329f5092af523fc55fac418e6a755

tradSS:
0ec3ce511151647f38e17c6bdcaac66fbfedb9f97fac2c4ac0c17bd7e0efd856

tradCT:
2266687e62f5365be29ed5f8f04019775432fef3be41e68cbca15e7cfb8eff58

tradPK:
1a2f275700c9ecfb99c7f099ecbd48ac1e52ce16b113d5e16098e68be2031872

Domain:  060b6086480186fa6b50050235


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Domain

Combined KDF Input: 50e8413bab2ad551e46ae9d4c54bbcc6240329f5092af523fc
55fac418e6a7550ec3ce511151647f38e17c6bdcaac66fbfedb9f97fac2c4ac0c17bd7
e0efd8562266687e62f5365be29ed5f8f04019775432fef3be41e68cbca15e7cfb8eff
581a2f275700c9ecfb99c7f099ecbd48ac1e52ce16b113d5e16098e68be2031872060b
6086480186fa6b50050235


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss: 1e28799aae5528414775bca59b21d2dd1055df3cda35f0316f7e6740d4ff1c0a
