from ..lab3_packets import *
from .CertFactory import *
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import hashlib
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from .Engine import *
from playground.common.CipherUtil import *

class PLSProtocol(StackingProtocol):
    ###### init ######
    state = ""
    M1 = b""
    M2 = b""
    M3 = b""
    M4 = b""
    SHA1value = b""
    nonceC = UINT64(0)
    nonceS = UINT64(0)
    pkC = b""
    pkS = b""
    publickey = 0
    Side_Indicator = ""
    logging = False
    count = 0 # record the total incoming Pls data pkt from other side
    PLSTransport = None
    Encryption_Engine = None
    Decryption_Engine = None
    MAC_Engine = None
    Verification_Engine = None

    def authentication(self, certs):
        listCertificates = [getCertFromBytes(certs[0]), getCertFromBytes(certs[1]), getCertFromBytes(CertFactory.getRootCert())]
        verifier = ValidateCertChainSigs(listCertificates)
        if self.logging:
            print("Verification :", verifier)
        if not verifier:
            self.state = "error_state"
            self.send_PlsClose("Certs Verification not pass!")

    def extract_pulickey(self,certs):
        cert_obj = load_pem_x509_certificate(certs[0], default_backend())
        self.publickey = cert_obj.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


    def calc_sha1(self):
        sha1 = hashlib.sha1()
        sha1.update(self.M1 + self.M2 + self.M3 + self.M4)
        self.SHA1value = sha1.digest()

    def send_handshake_done(self):
        outBoundPacket = PlsHandshakeDone.create(self.SHA1value)
        self.transport.write(outBoundPacket.__serialize__())
        # if self.logging:
        #     print("PLS %s Protocol: handshake Done send!" % self.Side_Indicator)

    def send_PlsClose(self, error=None):
        outBoundPacket = PlsClose.create(error)
        self.transport.write(outBoundPacket.__serialize__())
        if self.logging:
            print("\n\n###################################################")
            print("# PLS %s Protocol: !!!!! PlsClose send !!!!" % self.Side_Indicator)
            print("# PLS %s Protocol: error is: %s" % (self.Side_Indicator, error))
            print("###################################################\n\n")

    # handshake done, begin create keys
    def creat_keys(self):
        if self.logging:
            print("PLS %s Protocol: Begin create keys..." % self.Side_Indicator)
        seed = b"PLS1.0" + self.nonceC.to_bytes(8,byteorder='big') + self.nonceS.to_bytes(8,byteorder='big') + self.pkC + self.pkS
        # print(self.nonceC,"\n",self.nonceS,"\n",self.pkC,"\n",self.pkS)
        block_0 = hashlib.sha1(seed).digest()
        block_1 = hashlib.sha1(block_0).digest()
        block_2 = hashlib.sha1(block_1).digest()
        block_3 = hashlib.sha1(block_2).digest()
        block_4 = hashlib.sha1(block_3).digest()
        block = block_0 + block_1 + block_2 + block_3 + block_4
        self.Ekc = block[0:16]
        self.Eks = block[16:32]
        self.IVc = block[32:48]
        self.IVs = block[48:64]
        self.MKc = block[64:80]
        self.MKs = block[80:96]
        if self.logging:
            print("  * Ekc -- %s, len: %d" % (self.Ekc, len(self.Ekc)))
            print("  * Eks -- %s, len: %d" % (self.Eks, len(self.Eks)))
            print("  * IVc -- %s, len: %d" % (self.IVc, len(self.IVc)))
            print("  * IVs -- %s, len: %d" % (self.IVs, len(self.IVs)))
            print("  * MKc -- %s, len: %d" % (self.MKc, len(self.MKc)))
            print("  * MKs -- %s, len: %d\n" % (self.MKs, len(self.MKs)))

        if self.Side_Indicator == "Server":
            self.Encryption_Engine = EncryptionEngine(self.Eks, self.IVs)
            self.Decryption_Engine = DecryptionEngine(self.Ekc, self.IVc)
            self.MAC_Engine = MACEngine(self.MKs)
            self.Verification_Engine = VerificationEngine(self.MKc)
            if self.logging:
                print("PLS %s Protocol: All 4 Engine set up!" % self.Side_Indicator)

        elif self.Side_Indicator == "Client":
            self.Encryption_Engine = EncryptionEngine(self.Ekc, self.IVc)
            self.Decryption_Engine = DecryptionEngine(self.Eks, self.IVs)
            self.MAC_Engine = MACEngine(self.MKc)
            self.Verification_Engine = VerificationEngine(self.MKs)
            if self.logging:
                print("PLS %s Protocol: All 4 Engine set up!" % self.Side_Indicator)

        else:
            # this must be logged even if self.logging == False
            print("\n###########################################################")
            print("########## ERROR: Side Indicator not defined! #############")
            print("###########################################################\n")
