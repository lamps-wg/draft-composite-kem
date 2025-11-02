Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
f47746bd9d8a6da737eb543702d00ce60f031650389b97ece9ab118f0b1d0d0f

tradSS:
174863c5e361040e201120208179f76f6d618babf3d8c20418557a4c98a85015

tradCT:
082d5eb99812b1e7c6bcc9c7da3466fa8bf0a2dd10a07d7a38ca75f7875bb42e

tradPK:
9e3e05a2bdde3d3b8d2d5257ee0605d59b23466122249431e3d59f24749cd22c

Label:  5c2e2f2f5e5c

        (ascii: "\.//^\")


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Label

Combined KDF Input: f47746bd9d8a6da737eb543702d00ce60f031650389b97e
ce9ab118f0b1d0d0f174863c5e361040e201120208179f76f6d618babf3d8c20418
557a4c98a85015082d5eb99812b1e7c6bcc9c7da3466fa8bf0a2dd10a07d7a38ca7
5f7875bb42e9e3e05a2bdde3d3b8d2d5257ee0605d59b23466122249431e3d59f24
749cd22c5c2e2f2f5e5c


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss:
9f9f6cb45af75f5eb6f3cab2e234b1926c6c01edffd6563bbe01daeae631e627
