from ..lab3_packets import *
from .CertFactory import *
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import hashlib


class PLSProtocol(StackingProtocol):
    ###### init ######
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

    # TODO with professor's guide
    def extract_pulickey(self,certs):
        self.publickey = CertFactory.getPublicKeyForAddr()
        # self.publickey = b"999" # use mock key for now


    def send_handshake_done(self):
        sha1 = hashlib.sha1()
        sha1.update(self.M1 + self.M2 + self.M3 + self.M4)
        self.SHA1value = sha1.digest()
        outBoundPacket = PlsHandshakeDone.create(self.SHA1value)
        self.transport.write(outBoundPacket.__serialize__())
        if self.logging:
            print("PLS %s Protocol: handshake Done send!" % self.Side_Indicator)

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
        self.Ekc = block[0:15]
        self.Eks = block[16:31]
        self.IVc = block[32:47]
        self.IVs = block[48:63]
        self.MKc = block[64:78]
        self.MKs = block[80:95]
        print(self.Ekc,' ',self.Eks,' ',self.IVc,' ',self.IVs,' ',self.MKc,' ',self.MKs)
