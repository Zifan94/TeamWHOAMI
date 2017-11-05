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
    SHA1value = 0
    nonceC = 0
    nonceS = 0
    pkC = b""
    pkS = b""
    publickey = 0

    # TODO with professor's guide
    def extract_pulickey(self,certs):
        # self.publickey = CertFactory.getPublicKeyForAddr()
        self.publickey = 999 # use mock key for now


    def send_handshake_done(self):
        self.SHA1value = hashlib.sha1(self.M1 + self.M2 + self.M3 + self.M4)
        outBoundPacket = PlsHandshakeDone.create(self.SHA1value)
        self.transport.write(outBoundPacket.__serialize__())

    # handshake done, begin create keys
    def creat_keys(self):
        seed = b"PLS1.0" + self.nonceC + self.nonceS + self.pkC + self.pkS
        block_0 = hashlib.sha1(seed)
        block_1 = hashlib.sha1(block_0)
        block_2 = hashlib.sha1(block_1)
        block_3 = hashlib.sha1(block_2)
        block_4 = hashlib.sha1(block_3)
        self.Ekc = block_4[0:127]
        self.Eks = block_4[128:255]
        self.IVc = block_4[256:383]
        self.IVs = block_4[384:511]
        self.MKc = block_4[512:639]
        self.MKs = block_4[640:767]
