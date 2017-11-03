from ..lab3_packets import *
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import hashlib


class PLSProtocol(StackingProtocol):
    M1 = b"";
    M2 = b"";
    M3 = b"";
    M4 = b"";
    SHA1value = 0;

    def send_handshake_done(self):
        self.SHA1value = hashlib.sha1(self.M1+self.M2+self.M3+self.M4)
        outBoundPacket = PlsHandshakeDone.create(self.SHA1value)
        self.transport.write(outBoundPacket.__serialize__())

    # handshake done, begin create keys
    def creat_keys(self):
        return 0;