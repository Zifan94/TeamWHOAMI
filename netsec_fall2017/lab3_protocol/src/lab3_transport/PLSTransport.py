from playground.network.common import StackingTransport
from ..lab3_protocol import *
from ..lab3_packets import *


class PLSTransport(StackingTransport):
    M2 = b""
    Encryption_Engine = None
    MAC_Engine = None
    logging = True
    Side_Indicator = ""
    count = 0

    def __init__(self, transport):
        super().__init__(transport)

    def close(self):
        if self.logging:
            print("\n##############################################################")
            print("# PLS %s Transport: App layer call PLS Transport.close() #"%(self.Side_Indicator))
        outBoundPacket = PlsClose.create()
        if self.logging:
            print("# PLS %s Transport: Sent PLS_Close packet                #"%(self.Side_Indicator))
            print("##############################################################\n")
        self.lowerTransport().write(outBoundPacket.__serialize__())

    def set_Engine(self, Encryption_Engine, MAC_Engine):
        self.Encryption_Engine = Encryption_Engine
        self.MAC_Engine = MAC_Engine
        if self.logging:
            print("PLS %s Transport: Encryption_Engine set up!"%(self.Side_Indicator))
            print("PLS %s Transport: MAC_Engine set up!"%(self.Side_Indicator))

    def write(self, data):
        C = self.Encryption_Engine.encrypt(data)
        V = self.MAC_Engine.calc_MAC(C)
        outBoundPacket = PlsData.create(Ciphertext = C, Mac = V)
        self.lowerTransport().write(outBoundPacket.__serialize__())
        self.count += 1
        if self.logging:
            print("PLS %s Transport: [%d] PLS data packet written!\n"%(self.Side_Indicator, self.count))