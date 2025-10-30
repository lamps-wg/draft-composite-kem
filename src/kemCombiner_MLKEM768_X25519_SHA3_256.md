Example of id-MLKEM768-X25519-SHA3-256 Combiner function output.

# Inputs
mlkemSS:
6fc49d3e1bd5823dd145f076155ae20242aee02643e95ddaa006780c6715ac85

tradSS:
c36082f4faeb7d02d0967ea539bce6287f8ba493cfadc2ee459bb7ac539f0809

tradCT:
16a40cc4376979192ea274304ef622d8dc0fec173a9fe0f4cf2d5f5580308e64

tradPK:
8f2151b3c5cfc9bc276d473ef094f60a8f472c3d20e682cd656724c5a5da4644

Label:  5c2e2f2f5e5c

        (ascii: "\.//^\")


# Combined KDF Input:
#  mlkemSS || tradSS || tradCT || tradPK || Label

Combined KDF Input: 6fc49d3e1bd5823dd145f076155ae20242aee02643e95dd
aa006780c6715ac85c36082f4faeb7d02d0967ea539bce6287f8ba493cfadc2ee45
9bb7ac539f080916a40cc4376979192ea274304ef622d8dc0fec173a9fe0f4cf2d5
f5580308e648f2151b3c5cfc9bc276d473ef094f60a8f472c3d20e682cd656724c5
a5da46445c2e2f2f5e5c


# Outputs
# ss = SHA3-256(Combined KDF Input)

ss:
bd85733d101a753775ef7bde15babef79b813a067b845afae09c91d64bc67b73
