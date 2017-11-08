from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT64, UINT32, UINT16, UINT8, STRING, BUFFER, BOOL, LIST
from playground.network.packet.fieldtypes.attributes import *
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