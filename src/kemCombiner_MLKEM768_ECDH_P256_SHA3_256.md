Example of id-MLKEM768-ECDH-P256-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
59c899893be215dceec13af76c78db7d816bca5baff4401959773a3eac8b274e

tradSS:
e633bd549a8ba3260d1fea7d4a75ddbbc175ae7a128a6557054d4fa31487d251

tradCT:  04f7dacade2fc1eef5d91c91379c3480cee1e640a93ad60bbb143ff648
fd846a6c7a0626b390d4baebc0a63bcf5fa414ff3425d6656bb4e3d1bcc2f635e4a
282d7

tradPK:  045614f95504123b7df6b6d106eb8855a5e2eb5f3d1f6e903670e9f5de
a47e5b484fb52d94a986ab0ffb4306a7d5ac3b62225a1e7ab0270ec6a06733e9a02
41488

Label:  7c2d28292d7c

        (ascii: "|-()-|")


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Label

Combined KDF Input: 59c899893be215dceec13af76c78db7d816bca5baff4401
959773a3eac8b274ee633bd549a8ba3260d1fea7d4a75ddbbc175ae7a128a655705
4d4fa31487d25104f7dacade2fc1eef5d91c91379c3480cee1e640a93ad60bbb143
ff648fd846a6c7a0626b390d4baebc0a63bcf5fa414ff3425d6656bb4e3d1bcc2f6
35e4a282d7045614f95504123b7df6b6d106eb8855a5e2eb5f3d1f6e903670e9f5d
ea47e5b484fb52d94a986ab0ffb4306a7d5ac3b62225a1e7ab0270ec6a06733e9a0
2414887c2d28292d7c


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss:
76fdce8312cc28ca288f7d372ba2cf1dadc430490956678c4e771c4df6bf4a28
