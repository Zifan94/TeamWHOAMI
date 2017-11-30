from ..lab3_packets import *
from ...CertFactory import *
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import hashlib
import string
import random
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

    def CreatePrekey(self):
        md5 = hashlib.md5()
        randomstring = ''.join(random.sample(string.ascii_letters + string.digits, 20))
        print("string:",randomstring)
        md5.update(randomstring.encode('utf-8'))
        return md5.digest()

    def GetCommonName(self,cert):
        commonNameList = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(commonNameList) != 1: return None
        commonNameAttr = commonNameList[0]
        return commonNameAttr.value

    def authentication(self,certs):
        listCertificates = [getCertFromBytes(certs[0]), getCertFromBytes(certs[1]), getCertFromBytes(CertFactory.getRootCert())]
        verifier = True
        #verify whether peeraddress equals commonname
        self.peeraddress = self.transport.get_extra_info("peername")[0]
        print("PeerAddress:",self.peeraddress)

        self.commonname = self.GetCommonName(listCertificates[0])
        if (self.commonname == None) :
            verifier = False
            if self.logging:
                print("PLS %s Protocol: Error: Wrong CommonName!" % self.Side_Indicator)
            self.state = "error_state"
            self.send_PlsClose("Wrong CommonName!")
            return False
        print("CommonName:",self.commonname)

        #if (self.peeraddress != self.commonname) :
        #    verifier = False
        #    if self.logging:
        #        print("PLS %s Protocol: Error: PeerAdress and CommonName not match!" % self.Side_Indicator)
        #    self.state = "error_state"
        #    self.send_PlsClose("PeerAdress and CommonName not match!")
        #    return False
            
        #Make sure that each CA is a prefix of the lower certificate
        self.commonname1 = self.GetCommonName(listCertificates[1])
        self.commonname2 = self.GetCommonName(listCertificates[2])

        print("commom1:",self.commonname1)
        if not self.commonname.startswith(self.commonname1):
            verifier = False
            if self.logging:
                print("PLS %s Protocol: Error: The common name of each successive CA MUST be a prefix of previous certificate, CommonName %s and CommonName1 %s" % (self.Side_Indicator,self.commonname,self.commonname1))
            self.state = "error_state"
            self.send_PlsClose("Prefix not match!")
            return False

        print("commom2:",self.commonname2)
        if not self.commonname1.startswith(self.commonname2):
            verifier = False
            if self.logging:
                print("PLS %s Protocol: Error: The common name of each successive CA MUST be a prefix of previous certificate, CommonName1 %s and CommonName2 %s" % (self.Side_Indicator,self.commonname1,self.commonname2))
            self.state = "error_state"
            self.send_PlsClose("Prefix not match!")
            return False

#You may want to consider some additional checks, such as validity date, issuer name, and so forth.

        for i in range(len(certs) - 1):
            this = listCertificates[i]
            issuer = RSA_SIGNATURE_MAC(listCertificates[i + 1].public_key())
            if not issuer.verify(this.tbs_certificate_bytes, this.signature):
                verifier = False
                break

        if self.logging:
            print("Verification :", verifier)
        if not verifier:
            self.state = "error_state"
            self.send_PlsClose("Certs Verification not pass!")
            return False
        return True

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
