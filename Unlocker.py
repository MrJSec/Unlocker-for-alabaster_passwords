#Install the following "pip install pycryptodome", "pip install setuptools" and "pip install pyopenssl"
#Created by MrJSec.co.uk
import binascii
import OpenSSL
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

#This is the encrypted key to generate OaepSHA1 key using X509 certificate (pkcs12)
encrypted = binascii.unhexlify("3cf903522e1a3966805b50e7f7dd51dc7969c73cfb1663a75a56ebf4aa4a1849d1949005437dc44b8464dca05680d531b7a971672d87b24b7a6d672d1d811e6c34f42b2f8d7f2b43aab698b537d2df"
                               "2f401c2a09fbe24c5833d2c5861139c4b4d3147abb55e671d0cac709d1cfe86860b6417bf019789950d0bf8d83218a56e69309a2bb17dcede7abfffd065ee0491b379be44029ca4321e60407d44e6e"
                               "381691dae5e551cb2354727ac257d977722188a946c75a295e714b668109d75c00100b94861678ea16f8b79b756e45776d29268af1720bc49995217d814ffd1e4b6edce9ee57976f9ab398f9a8479c"
                               "f911d7d47681a77152563906a2c29c6d12f971")

#pfx certificate store as string to avoid read from file. "server.pfx" (pkcs12)
binpfx = binascii.unhexlify("308209a10201033082096706092a864886f70d010701a082095804820954308209503082040706092a864886f70d010706a08203f8308203f4020100308203ed06092a864886f70d010701301c060a"
                            "2a864886f70d010c0106300e04088372a20f0b7c1f5602020800808203c016674e7e58465d7969e5dd76aa38d8a886ab97a9cee57751509a9db6b9ddff0fce52d50186cd4e61feb0c69b2c37687fb8"
                            "8b3a7d6af5721157c9d001f62cadebbcc91f12442696bf746d3c3b0bf12abff226f06a0f038f7225f0514e8d3c6cea475165f436da1d1ae88a3842913b341122f832ac35173518c689e869aab86e08"
                            "2f84e9659bab4c9737c3549d89032c79082dfb3af2e0efdc70f70960a950487fc45540d4264af28136d3346a3bcbfd97dc75a2887f31d5046a3b5137bbadb49ef7da50357b0e27148139587d3e538b"
                            "c8c9f2b5d5872b356634bba28def9ee6e0816812434b8aea750bb3cc31178847eae650a586a385624c5ad3aa0e625e5cc4087a42534fded12b82d766056260b81df6d1673b4d96e005ef07ba4c273a"
                            "97e9bd0d7b401ce5509858bfed6e56eedf20ddd9906b15da25665284b3c341b8225bb10461e7512094da621558162e6c82cc898153a6ccf8121aae84d6fe5bdfd7fe3e3b6ad8864b04c8843a9e262a"
                            "e82087eca0a7f5416bade4e129f0a18cfda1e83df5c22f9d6ca2f0bcf195cd23623ca86aac786f0030dc9830a0856dbb04e38c2dd1fa9f6f4142acc4e6a5fac043a66dda99a5a036b8e2784a17ccdf"
                            "453086df041621051841bb456919b48f9714ae28b4962311d21774748ad8ed4f663919ce812ab7f80d79561af9d7656170a997dd26d1fb9288c30ec8e4cf3f2a1b3bb57043a394950fe39e4b34f400"
                            "f013c74d6e3af319160480cf22047fd984eb89a453317743e7bc6e2ecdf35ae93b2dbcbf9e700d440b63978c566611baff3af6d6536173183762f6f1258abceb4d8afe377aeafa11336e63bb5c90e2"
                            "b990b0eaca7a00a1af13fb9b45db0953fb525342e45713eec4924abb07ff70ecabec5689856df4a3f6d064932d0f3b13d45693d18a39c86a20a5bc2da6ebf59a22732ab4dc29a2c0480230dfdd6bc1"
                            "593c94f99359b4be22c9ffc9459c4477c4fde72566c543e90654978f381fc2ad3320578582f4a2d8ee606e7aca550f35394ce01223d7965f9986116493463ecb5147454d1d0cb992369125fd1760e8"
                            "8f19657eee44ed1508e49bb818bf9087c972fddc9e2f37f67086e30889c808c620064426971e541203a856ba3a9e7f16b451ac1d920fd46367ebedd0d36d2edde95d1e80b700e79bdf46ed933e0f0e"
                            "fc342dc2d654683bed0c2a5f907008bd20760cb25208bf336b215ca26be45d68a5b3e7eba071ac66f55fe3b00241d401d5b0c324383f8f8d09557414d4f670c4ea3c3fcf5a97b56671fa0a7321b338"
                            "9ca6cd2326ef36c9a4c6f8a0db444573d4cfeb732897f74f112de6c75016c56c52edda83804af0646c263082054106092a864886f70d010701a08205320482052e3082052a30820526060b2a864886"
                            "f70d010c0a0102a08204ee308204ea301c060a2a864886f70d010c0103300e0408e0b82a6d52a90de902020800048204c8cc942ac6e63ed03f3f71634741df0fdd9fce0864326da0c0398ec5b3a0ca"
                            "4bacffa684c398895d4a260d0263abc78c1365ff44c29e39c2f909c9023135779260ed742bacf135fe8cc387babe152689c476779f17e6b475deecabf98e17c7d38c57ae24065fba9d11d2906edf7e"
                            "052daf532e11cfe87827accb717850672fa99f954ed8be0df8d1675b2210128d5bce64fa163be8fca7d54bd16cf66252ffd1d936fa54b0b3140d0ab485cd624f072210adf5cd23751f9ce188f260b7"
                            "85cbb479fd035f4c605a9a79f252d510fbf3b983c1e00922fe31866be14c1e0416a4941c2d91a1038c6062f9e7821499165b748d2f97dc388f7a510f40359b4fb9b788278784e49009014863b095ed"
                            "fd52cef71a318f16d9ff50e4a6f357c0de036f2680cf86265bb94fe8a4ab728d3fb9459acacfa9b8fff7a169678b2f0f9c88091b6aba976f3db2904fc86f991b7e12674912145e89872db58d45fa2c"
                            "990f2c5d6c5408e5d2107422ea26c5ead242725bcdff47f97b5bdbf91f39b8bafde290a964da079f20cb589ed7eb0cac2a8d521a49a47f81991510cad818ee619fe146d89bcfc09a056dab90976bd6"
                            "abe492e55d91c7a9137110c39c7b165deffd981747b7e531dc8286af792d24790df8be9524533ad8d6f7eb1961aaf2b510334595929a3edefada1d2126a935a36d0554018a1f9b9aa5532caeb0331d"
                            "e4b2fb386718d772d04f29e6973149041b1297ac9283f21ed33f6300190aae3b0674ace2184b5c37923939f30a1393bb58007d4eaa3da4ff03313f90555b1552b0492bc7d19155abf89532232e61ab"
                            "5c54e4ea8941e3bc870d844d86b1baf214e3c0dd6234927d6fab2c384d81de0af75c315d8097b03a9d32f4cf41cbac6de0e541e2134ffa3b116804c263b5176b99d38c1295cf01af8155a6ffbffd47"
                            "529685e858dc65bb9255d6b599b16329d6d350898bef9130c29b980849bedd185f011acd1f39f6e264884e3ce009426fadca232876691c20b931871b59758966b50b08f7053b6ad70567335ef9ad11"
                            "ef14fe6b008a348f7121e38bc030895ee82e479572f977c875621000085ed896a007bb245aa78aceb971634a8a612d2168f327f980299849d4963fa5472fde0864a1532d0f9643543eee4b4b784f58"
                            "146246bb9670b76b702573c00d5526b2460ca7adc68481e7e0418e8385a31f889310d3a44956bb3766897f12675321454140ea6f175811b11202494965aa8a54a78bf7410e38c97371ece11d045be3"
                            "eef4ab2c5763a2dd22f422f395057e2df54462c124c82b4eec00c99eaa74d25f1be5e3f61d15e6bf137b288d5f5d13756ebeca4a21e7e3e9c98cc915cf55a04d0eef3458999e0bcae7f2ae8d1c3352"
                            "f07b106aecb582f4bf618436be6b6954ebed6165ec327dead1165de70f73a7dfdec128a4984abc029f934b382b455f36de13a560d7d7e253ddd2a5572d3ff81b05fe51982458bbcb943046b4586583"
                            "f04a18a63ad34068189f01fcc06a930aa531b21f402dd75594cd17f9e5da98643f6eda45168efb58cf2ca3a47638f4f52048c83ca246fdb4957ec1e38becef5b4c273d383c7f8dc0f0497bc1dd2651"
                            "03232981deef3080369bf49468b0f0cfbdc5ebb54d12c4171d81a6f44795e075ed5b6800f2673e05e9d14c6ffc242902b8520b7fcf426819c545ff9c21557ca2766fdd9ba05a5ff71f78ec76bf89e1"
                            "efa0312cde7231bf0e3125302306092a864886f70d01091531160414b1d1e73dcbffbd458b341a6e8aed3549a81077d630313021300906052b0e03021a050004141917ae4109f4ff9dced0d931875f"
                            "e0d076cfd1250408a5d71ac5a6546b6602020800")

#decrypt function
def decrypt(filepath):
    block_size = 16 #Aes block size
    p12 = OpenSSL.crypto.load_pkcs12(binpfx, b'topsecret') #load pfx cetificate from byte array
    privatekey = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, p12.get_privatekey()) #get certificate  private key 
    cipher = PKCS1_OAEP.new(RSA.importKey(privatekey)) #create cypher for decrypt encrypted string to be used in AES decrypt
    key= cipher.decrypt(encrypted) #get encrypted key OAEP RSA
    
    filein = open(filepath, 'rb') #read file to be decrypte
    filein.seek(4) #avoid 4 first byte in the file
    string = filein.read() #store file data in variable to easy access after avoid 4 bytes

    unpad = lambda s : s[:-ord(s[len(s)-1:])] #create lambda to decrypt all file in blocks (size 16 bytes)
    iv = string[:block_size] #get IV from offset 4 (size 16)
    cipher = AES.new(key, AES.MODE_CBC, iv ) #create AES cypher to decrypt the file
    fileout = open(filepath.replace('.wannacookie',''), "wb") #build out file path/name
    fileout.write(unpad(cipher.decrypt(string[block_size:]))) #perform decrypt in each input file date by block of 16 bytes


#Main
try:
  decrypt("alabaster_passwords.elfdb.wannacookie") #just call decrypt using input file path
  print("File Decrypted.")
except Exception as e:
  print("An exception occurred e: " + e ) #show any Exception raised

