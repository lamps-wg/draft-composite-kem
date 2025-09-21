Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
6f3a03c01ee644a579f2f19b4a8ab18bd1c3566d53734f36e44f006a28ea663f

tradSS:
5aef32a7787f0f7529f3d48688b29a2cdf30623f878bb8d2ce4d18d88e207905

tradCT:
2c29e1fd91da87318c386e0efdbd1407d3a2d50f86dd3192e509d3c4625fe321

tradPK:
104a34c97d422f68e1ffe75c6384ea6d485d910c4d737d08f8ddd47c372d3330

Label:  5c2e2f2f5e5c

        (ascii: "\.//^\")


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Label

Combined KDF Input: 6f3a03c01ee644a579f2f19b4a8ab18bd1c3566d53734f3
6e44f006a28ea663f5aef32a7787f0f7529f3d48688b29a2cdf30623f878bb8d2ce
4d18d88e2079052c29e1fd91da87318c386e0efdbd1407d3a2d50f86dd3192e509d
3c4625fe321104a34c97d422f68e1ffe75c6384ea6d485d910c4d737d08f8ddd47c
372d33305c2e2f2f5e5c


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss:
fb87fe95b58c0f0a88da73bc5d8375b8a5bcf24ed1fa7ad35d717f014d087913
