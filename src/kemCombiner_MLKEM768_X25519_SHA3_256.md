Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
461b74b074818906edcd2fd976008caca5247f496670ae86e34abe35e62a7ae1

tradSS:
4c62bd6d6f76294f3c14d7e79dbf56e4bf82cb1fb803accfaf2a59c1663a8843

tradCT:
0ec7210a4aa22bb75af9243f95a6ccf857e872efbe5e77e8e917b56178fa473f

tradPK:
1e9d4f72d56cef589864e102c6d6fa86cd3ac5163839556f7555ad083f37b03b

Label:  5c2e2f2f5e5c

        (ascii: "\.//^\")


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Label

Combined KDF Input: 461b74b074818906edcd2fd976008caca5247f496670ae8
6e34abe35e62a7ae14c62bd6d6f76294f3c14d7e79dbf56e4bf82cb1fb803accfaf
2a59c1663a88430ec7210a4aa22bb75af9243f95a6ccf857e872efbe5e77e8e917b
56178fa473f1e9d4f72d56cef589864e102c6d6fa86cd3ac5163839556f7555ad08
3f37b03b5c2e2f2f5e5c


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss:
21ee673fdeac21dd78ef13bc8432a50c0ac31893cbe97d14c0e82f5fe4a28d98
