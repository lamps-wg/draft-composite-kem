#!/usr/bin/env python3

import generate_test_vectors

import json, base64

from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives import hashes, serialization
from pyasn1.codec.der.encoder import encode as der_encode

from kyber_py.ml_kem import ML_KEM_768



# from https://github.com/cfrg/draft-irtf-cfrg-concrete-hybrid-kems/blob/main/test-vectors.json
# retrieved 2025-08-28

jsonstr = '''{"qsf_p256_mlkem768_shake256_sha3256": [
    {
      "seed": "0101010101010101010101010101010101010101010101010101010101010101",
      "randomness": "6464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464",
      "encapsulation_key": "ec7b50cddc8360f98b189bac73d395ef947b37d8453886a253269f7b18b9eb78c1b63212471a0f979793f9936b3f496f4b5394ea69c2a35729f91c688f6bbbb864cd5e87108676c4014c2ba98204f911becae33a71e832ac012bb827578810955f8c6e2d26c0b17b7ba574990884546ba58bf6785721f3854f434cfea602e8595c71642e8d4c70934b7e54c638f5a13e1a136bc86565e6b40abc163ca65650baf953de7bb99b138ac1b695023103c9b417853c9d42e54fdb816174659d85a783e3d4613db1cbbaa63fb667a4a636804b6c4ae821ac5d6556688bab1dc10d6779b485c63c0ddacb91837c4ff3402e6214188072b4186a39c65bde524c683c95d3c8b65e37104f551b6a3602eda50b787182d703ac6a221428b4553e3b99c2b251ef642e31256c329b21d1246a71456fce700d7f50cfe5390a1c37bc133809f102c22914a1402c205c0512b733afeea04411ca5ebb0bca9392b1ee23935eb196024732daa2a1f79358e6e74b73c965a9e74778dc6921442b19328f6216a5e814ccc0639a863a437a614def5a61f38852151011b04a37bbc78c1eba4d8d1b3a1622a0dff74d25c731abb2a5fe5919f835bd3dd97330cbb7dba0b74260c963402160c4017d92256a3713c9e77ea0f4901accbd38715511784c9ec287dd85a769e081854b32aba9322a3840f6065133228c41851afcb40ea509cfbb86145fb8853ce14c649691136b8660b0077f3b2f9da82d483c1414c39a9777665899131a8336fb828480986df102628d10b54239cc20231457d4bbb7016f76029661f14ffd3532e2f8494e1613430730ab915683c3c8c4db2b4373a3057a097e23333605398b15cc4d6ac3fbd0732f21026bb0cd51fb738a740467114e7c66256b830022f28c028392cff8013d617c77a47bbda11c4a522f8f2b49f2822cc06338605671fca4518df9b3c506532c9cca3175330f8733ce11cb3fd8b95239ceebc9483cb68bff43b622911fcf4a9c57c226caa38bf0b081535999f573016b14563ec4826dc281dbabc633868a1d903d59207fc662a293735085c01f40b5b56cbb795ecabfad709d611cac73eaca579768213c18c969c59be58fcef6bdd8a85192907cd0773f81eaa24be07e0d620e9685acb0c6b0f54b47dffb510384241c4b733fe08dacb2852b2b74cc014e974a5e9db35d80d7b83ad31da1487a0170ba7fbc1c551a6f1eecb572084180b256962748d5e3200b731ac7c3928585a153b167c92a48cd91668c773707c054af16aa7bfacaa161a620600e8d08cc97601a53391da0247e5fca60cd1bb65ec0417177a9eb78cde5aa1dfae34e948417b3cc0b223803f5f40e8ae3a382848ff80c4185824076423ae4c137bd30bd81f04095c20a01e0a49f664f8f2b7f6bf6a990993cbc0596a514ccebc578c6418e825903ae11ac52831c6a48c67727409ed7274eea03eef32094271b02d4535563aa4924a2666871a4b690540c78b06043bca31ca4e42a03650ecab74792017217d10615d0acdee124e3222c90d79362207e4f7779e097501cf140b1a3431ee0cf27b23a50373d59976d82b5b1ce165f4aa1361157afad564081c85777584dd6058a1a4663b53234d7264fbac6877351d1928c6780f77d47209337271e305370df9aeffb74d7c75de55c006e2b2a048e3ae3cfd5a5fb7d4d18c612217e2341d498e9f219b1d59300c409c651a110491626b0fcd544b8c53705ba9b8f1e6ebe4c71106cb35df0aad865763e2423b840",
      "decapsulation_key": "0101010101010101010101010101010101010101010101010101010101010101",
      "dk_t": "282ca8885984af2a743ab3ae30fc221767bb7c6c205c46e0447a3607ba79c8fa",
      "ciphertext": "639b91c267be1f9f509e0af149fef93cd34e51a4ac47a61488ed5977a450fba07cf697a3c63c42ce66682caee69193e9f919d59655f89b8a2d182321ccbe7929ffddcd9e137f00494e6dc473a1d27c7e55b5ad7e18ec21c12876a378f7cbab35eafec5147264a3d60209b0e4690e38dfeb2ca87ae8b91099c95812f9bb9bd17fbd570c8f6b5887ab96520081c0526b7b642cf6ed9604df1c24b2b3d06d0fa8b360fc6b354efa3ed83b34846d21f082bb0dd1f68d76a467ba2ad7c4a1657c546bc4cf4c68b5964ca3239be4e63398a01b2c379d2d5adfd5c562fc59e980c76cba1605e1031f8a8262a5a91209bcc94ed461d868ced8f8ff6783f3e538ffd05e892870d16340c62e8ba17dbf42d17d3c83d78e615494e97113bb4cd2b224e021e20808b9e7ec87589fc47954fd391e34d8b1e765ce4eefd56818bb661d96b02e871218d8cd16f59441ca8f6104281fdde280f42332026899e913d8d9d98d9e31e274d7472016f7693e97773e5f334ff4d63f1ce035ca22a6d76f1ee24a37bc50d239587fb8b261f48b7dea75bb7f26f34d45515faad1d7566608530953180ac57aa38198f1e56ded075d3ec4bd9e963da010ff34cdc80349553898f29a25de6f9b75f0c2ec90ba6296aa574a507abc94532bfc1c631e30b96f24faf123e0d52e2f38d6e9a3ab1f9ee03a4068b6e0006397a7e71039ea90671524b3e5c371268a99beae37b3feabaa01e2da65cfe8749d9a8c1706037af5612d46611c7f74863140ddf1bf2ba163be37f5769b1682ab73c32bd4b582617d41573d6cfa1d0dddad52d4e35bcd725f445ba3115f8bdd3d5be551fe4f5e364bc2b3afcee04051a7bb2a951e10ba801042c1910b30cba98217a324be0b2458b5de73e3dc8c6157daf26badbceae13414682c722a73f035856ea4c96432737c96343c6b2b331087e138b833f316675b5cdf988c3079957a3a95aec5be424abc3b6c826d7830724871fae41cc677bf8a5585c55690a002f991a61eaf68cdc6813f9adf47ee3d7c4c23993e4e0bda40c678e8b7cb8c7de733715d14e5eb50bde7b0b4b5c2cee8377f4bab762d042708601b6228b48549b1adc3b900009f93437ece1b66f8a0f34eb3138ccbffe69649551b211024ef97feeca61511ad196f38765b1d44c2a50088189f6fcb6894e9c23b0ab237227b2a7a5f3bd1bfec5668de7179fd42549b48790e7fc1be65d210b8aa7e0820f8c9a14c2e44ab2b6abf306a5d78a370b3ef5738bcdd8e01ed0a36bdb325cbdb6fdd6d81e7c20bd7b8586ccf1188f72792be726f486bb7950b8f3a2d482c870e69a79c0221e9988d65a4da6eac7386b9be0eff31762a04e4abbd3bcd741086d1e56680511db2b1115948b34e3c5c36bd10c01715d2414d6a358d013689114cc8bae472e447ff332d6e9c2c8c7ae1d1fe049556ee9a10dc8e693421efbd8bd33be8c7ab17b217c084f2eb3626695c9a0e33cc14363bfe401eb9596902f15f057b57d25b4e855d1a120847d238a8d6d3252084870c11f217670456092b796aeafabcf7f8370fafa5e8082e16be1c0627800e8c43a48574129e2107395d03221f1da93403b2f9e2f39245d5782131a0a3815911bfaa8d1e2536a1",
      "shared_secret": "d7dd5690bc8262dfe0bd13254dff3220190f2b40ee64bed35466e668b20dbdb0"
    }
    ],
  "qsf_x25519_mlkem768_shake256_sha3256": [
    {
      "seed": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "randomness": "6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f",
      "encapsulation_key": "b3c66fa010a66fc5bcc8ca23c4d9179778a874098393b90df0694b057b559bb4392ac810f363a15ed66961f9a749ac72fce5aaed774220971b6d6222dce553b0675071fa1c75c12a72ac0cdd82c723c34d68c90450f8a5153786467308ee3a4e7c925c647a708c4948ad365e9ab5079bc183fdf6b7cbc83cc772b382168fe3d265a5db4d79259fb9758a17754dd1517f65992dcf8572b8550ddfe1928783bdd4aa7a4bc737270c9f4f60b14d54519da058898a63d321b1efd6209791c58068bcd9072ea06ab50825650f71388943a24001cd85685463db4d4b91c8f7032be9d223076377b608a39d3b05f2434e67f8516e1a1b74a2581628a454217c6f076cb438b81621493db40ad89453c9169be33471bbeb831ca0c3c8e781b3236856b83606511193d67609244de8c99271ea1bda849bf54559512b76818c80ef54247e78cd409357fe0ccce1421c532690ed15a3f930181251259944c33258ba72d25f3a150d00edbac9d9c4ac849c9db84d87e05debfc46c9ba6a94b21272c47d92152f4fb5992f478771c8260a1b050fc3c09f57beb109b4e5657b0a902ed9ec127184c6da05bf8afa0ae05865b7a2cbb10c39ecf5963ebc6d4135a20b30255b5c13f1252c863940a22483ae6870765b412b242fe533ad5b66cfb8e5bc24cbcb5dc2a82d9baf19830b35986b065506578684baf9a8048698b2745bdaf77b07d72d3ab49e46e04a465266b3e267c402aa90dccedf08305804273f81609e8932d89bba3d4b0140fc4a8fb2a49961c0716640c04abdabd4748b2b96bc964928fb6520652e6c539adbe63bec83cf72566f79241a2e413928d921bc8c2fe7c6b1cf875a5589a64d56a4c7576dddc4564fb8b87fe4a01f202f8f8563a9ac6e61e951fa631c6a666872194a16fc5b396cb38d614fd7d585bcbb41e8e405ec410a9b1ace39020723b9277a8b4e63f9082c16c70372059a70b2df297d81cb67a2e1658031ccd5316eefc7b1dd241347f990bca137359b237de59756ac7f6cd4c78e7493e11704ad3284cb620051509fa35b9641e82950f802b2fabd04970c205652ae713f76c2bbc623b94f1ab48cd38188b127e2b7c4cd374b48c163718747099a1a660c9edaba36ee1bb5a71a3b6bc363a7e04f256ab91e509f735c41de6738db31909854afa373045afb0a6ad30fcfba4c80740d4bc4814e54c0d8d190baa62b2ea1469b8022a7466190e78580c0cb7fab140e759e7d982776282fa82044767b7ee9897442148db001148c858a4888ae7b88ceb526076622c5780841a78a33b516660943b62f8bc60e9a6d7507430be85248786bd434b42f08bda4e6a54f3bb6ddf9bcde61b35df76453180952c0a32f202c7dd4861fc686e4b7bd564b5c26203128bb45a947a00d74cc1022856075ae320b3f3ae56be2798e511968dc27732ee8c8a6575dd7c9923a4c2b81991a1e159727b960494c87fe66984f0a77b0374622a70b3ca80773444aee0386f2931a176520b8d55c9ee992929b8b46450c7ac9bece3412924152e98207a995ba501b30938712c0b4010b23c88e4c45ac4438a5029074005323b3a611394da791bbb9dcc79948420417a271a4ae4cfc08c0b8b564d473acc50492f94320a10ea3c41db35af8e3e86fea098fd7be1d8aa638a227903cc2d7b8268f148b7e552019fd7a4fda43737cbba64182f839e08e71d0f3f23ea8c6bed760",
      "decapsulation_key": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "ciphertext": "d3db66a3d01d907f0e81d79ec0d2cf56eaf62d7b516daf22ae8b6bc217c8e5e9b1b566476ab94707effdf1dc9fc3bbb9f89a453bf349979179c3c68c97abf17f6da365acaf44b92130d1dd1b500d633abcc46201524643f36cfd840a1b565deaa30a9e287ff53a7f6dffc563374aba9042f4e51a47b41a95ed42630000a918bb608059365b2d0380a0f9df6cef3b898b8980e6e4ae8d6972652842b54d62a170a1972c381bf65c3b5b4e1e6b7369e8977ee33a539d345a088711fea725a10475c94e35e9f9aaf82f24b77e314465f349a17d10d4d3b546adbebd3c7f1aac3db7c1a115d6d7eb00bb776e5d56fd581b7451eb41c1fa8751a93bbf440ab5755d0df1e8bab1a237541e5b743ec7dec9f4a37784e3e806be86742077e561c22e1c4cd42b18f9f99e5cf7ad1d459fbfb9ff4ab7fc77e13cc3596a2158bc3c7139bfb783d29abb5ec0e96fa7bb9797c3ad01441fb10e40dda1a47dda63113c2488c505c4c9550475ff402b4bd071a9b918106e3d75ab9a627d85ad9286aec4b9b8cd1ee22ac102a568ca94dc9c99afc9d04fb21abf0c70612e88f4efa4474473673040c2d92891ca3652df26693fbfbdbba6357fad6ce230f95ca9b044b88afabc1246ddd6267396b58b3fb8d776fd42d819ee18436c72eee355ceebf402ea47199310d15a681a15128f7da21b559ca18cc3c985e5c4f148fec862aa864f89f0be37a1af1b662b4c0defc051a04e9be8e1d1c94b79b2f471f15da5e00fa477550621d3546d1718b7ccf3f33964e7f7082277d9ed8390d5fd5fce8ab2f306e2c8e042b3f226320fa74259a8aed30a6e95db750205358f7b6d307e41664dd79e5289c7bf79199bbf8ab154d53c295985cd3c678240189add1261c66cae4453252048d8310e72b39a9ddf1bcb2422cb82833c3337bb019e5ebf419f3f20ee0a551e2ee96d5b2abfe5af4c44de678f2bc70e5733c9e221069dc32bec3e9db6cb206117f1ad89ffa57727ed4ce6adfcafba7291b278c219db3e22182a762b7bc33e93a6afe4f72da9eb4be0839ba909ec6b589e969e33bac9fb505cb89dc4c7e60dea51970bdfbd702b252060282707bf172ad4d0d4dbd87e7bfeed153604a2b99679de54826bdfdfa20d809236b74157877b45aafb09559e1078c3b0f76ba563de82ca073ad181b9b7854d97805124f8ae63ddfa77c5b34d99c6a82442823b028abd53d70f2e6956b845416f5c3817aa799d5579d098e0500f9e1b8933a3034696f01532ee3f96387b108442504508f1b3d3177ee34830e9cea8ef0653c545457031a24973ff20d8643abeb2af4b3850dec6cf165e51a00cea0e85032ef51413e060db73440bc28da2bad80aa868e7d68702f4285d08ce7d832fe14b754197b30e745408bdef4a056be619bfcda403923bd824fc9f567d11a31f50d7452a3d527e691194e4fc6b094b46fd7f61eabc3064a250350e5499c647a860a05915cb7e4905ca0a3c6fa365fab1fa8bb0f2aafa7f09429c8794df660b89d78e199116334bad3234c6742562a1209c1a3694cf632449c658f54b085363c509a9d834a6914f78301719",
      "shared_secret": "60447f94b1e3675f09dbc4bc1abe8eafa14aed544547637aa980c3822ddd8578"
    } ] }
    '''

cfrg_test_vectors = json.loads( jsonstr )



def qsf_x25519_mlkem768_shake256_sha3256_keygen(seed):
  """based on https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-05#name-qsf
  def expandDecapsulationKey(seed):
    seed_full = PRG(seed)
    (seed_T, seed_PQ) = split(Group_T.Nseed, KEM_PQ.Nseed, seed)

    dk_T = Group_T.RandomScalar(seed_T)
    ek_T = Group_T.Exp(Group_T.g, dk_T)
    (ek_PQ, dk_PQ) = KEM_PQ.DeriveKeyPair(seed_PQ)
  """

  hashes.SHAKE256(64 + 32)
  digest = hashes.Hash(hashes.SHAKE256(64 + 32))
  digest.update(seed)
  seedExpansion = digest.finalize()
  mlkemSeed = seedExpansion[:64]
  TSeed = seedExpansion[64:]

  dk_T = x25519.X25519PrivateKey.from_private_bytes(TSeed)

  # Serialize the private key into the Composite encoding
  composite_priv_key = mlkemSeed + len(dk_T.public_key().public_bytes_raw()).to_bytes(2, 'little') + \
                                            dk_T.public_key().public_bytes_raw() + dk_T.private_bytes_raw()

  KEM = generate_test_vectors.MLKEM768_X25519_SHA3_256()
  KEM.loadKeyPair(private_bytes=composite_priv_key)

  return KEM


def qsf_p256_mlkem768_shake256_sha3256_keygen(seed, cfrg_dk_t):
  """based on https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-05#name-qsf
  def expandDecapsulationKey(seed):
    seed_full = PRG(seed)
    (seed_T, seed_PQ) = split(Group_T.Nseed, KEM_PQ.Nseed, seed)

    dk_T = Group_T.RandomScalar(seed_T)
    ek_T = Group_T.Exp(Group_T.g, dk_T)
    (ek_PQ, dk_PQ) = KEM_PQ.DeriveKeyPair(seed_PQ)
  """

  hashes.SHAKE256(64 + 32)
  digest = hashes.Hash(hashes.SHAKE256(64 + 32))
  digest.update(seed)
  seedExpansion = digest.finalize()
  mlkemSeed = seedExpansion[:64]
  TSeed = seedExpansion[64:]

  dk_T = ec.derive_private_key(int.from_bytes(TSeed, "big"), ec.SECP256R1())

  # For some reason, Python's routine to export dk_T as PKCS8 is not working,
  # ... but hand-rolling a PKCS8 does work.
  # I'm obviously missing something about how I'm invoking python's dk_T.private_bytes(..) below.
  prk = generate_test_vectors.ECDSAPrivateKey()
  prk['version'] = 1
  prk['privateKey'] = cfrg_dk_t
  prk['parameters'] = generate_test_vectors.ECDSAPrivateKey.parameters.clone(generate_test_vectors.ECDHP256KEM.curveOid)
  der_dt_t = der_encode(prk)

  ek_T_bytes = dk_T.public_key().public_bytes(
                      encoding=serialization.Encoding.X962,
                      format=serialization.PublicFormat.UncompressedPoint
                    )
  

  # This, for whatever reason, does not work
  # Clearly dk_T is correct, because otherwise I would not be able to exract ek_T from it successfully
  # So I suspect there's something up with how Python is re-serializing it to PKCS8

  # Serialize the private key into the Composite encoding
  # composite_priv_key = mlkemSeed + len(ek_T_bytes).to_bytes(2, 'little') + ek_T_bytes + dk_T.private_bytes(
  #                                           encoding=serialization.Encoding.DER,
  #                                           format=serialization.PrivateFormat.PKCS8,
  #                                           encryption_algorithm=serialization.NoEncryption()
  #                                                   )
  
  composite_priv_key = mlkemSeed + len(ek_T_bytes).to_bytes(2, 'little') + ek_T_bytes + der_dt_t

  KEM = generate_test_vectors.MLKEM768_ECDH_P256_SHA3_256()
  KEM.loadKeyPair(private_bytes=composite_priv_key)

  return KEM



# Composite_MLKEM768_X25519 = qsf_x25519_mlkem768_shake256_sha3256_keygen( base64.b16decode(cfrg_test_vectors['qsf_x25519_mlkem768_shake256_sha3256'][0]['seed'].strip(), casefold=True) )

# # MODIFICATION: Need to modify the composite KEM to use the X-Wing domsep value
# Composite_MLKEM768_X25519.domSep = '\\.//^\\'.encode()
# ct = base64.b16decode(cfrg_test_vectors['qsf_x25519_mlkem768_shake256_sha3256'][0]['ciphertext'].strip(), casefold=True)
# ss = Composite_MLKEM768_X25519.decap( ct )

# print("MLKEM768_X25519:")
# print("\tss from CFRG test vectors, and decapsulated ss")
# print("\t"+cfrg_test_vectors['qsf_x25519_mlkem768_shake256_sha3256'][0]['shared_secret'].strip())
# print("\t"+base64.b16encode(ss).decode().lower())




Composite_MLKEM768_P256 = qsf_p256_mlkem768_shake256_sha3256_keygen( base64.b16decode(cfrg_test_vectors['qsf_p256_mlkem768_shake256_sha3256'][0]['seed'].strip(), casefold=True),
                                                                    base64.b16decode(cfrg_test_vectors['qsf_p256_mlkem768_shake256_sha3256'][0]['dk_t'].strip(), casefold=True) )

# MODIFICATION: Need to modify the composite KEM to use the CFRG domsep value
Composite_MLKEM768_P256.label = 'QSF-P256-MLKEM768-SHAKE256-SHA3256'

# MODIFICATION: Need to modify the composite KEM to use SHA3-256
Composite_MLKEM768_P256.kdf = "SHA3-256"

# Hackathon TODO: 
#   * get X-Wing working again
#   * add P384, P521 from CFRG test vectors
#   * perform encap() for x-wing and P256, send to Richard, make sure he can decap()

ct = base64.b16decode(cfrg_test_vectors['qsf_p256_mlkem768_shake256_sha3256'][0]['ciphertext'].strip(), casefold=True)
ss = Composite_MLKEM768_P256.decap( ct )

print("\nMLKEM768_P256:")
print("\tss from CFRG test vectors, and decapsulated ss")
print("\t"+cfrg_test_vectors['qsf_p256_mlkem768_shake256_sha3256'][0]['shared_secret'].strip())
print("\t"+base64.b16encode(ss).decode().lower())

