import sys
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

suite = CipherSuite.new(KEMId.DHKEM_P256_HKDF_SHA256,
                        KDFId.HKDF_SHA256, AEADId.AES256_GCM)
skr = KEMKey.from_pem(open("recipient.pem").read())
ctx = suite.create_recipient_context(bytes.fromhex(sys.argv[1]), skr)
print(ctx.open(bytes.fromhex(sys.argv[2])))

