from . import PLSProtocol
from ..lab3_packets import *
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

import playground
import random


class PLSServerProtocol(PLSProtocol):

    state = "Not_Init_State"

    def __init__(self, Side_Indicator="Server", logging=True):
        if Side_Indicator is not None:  # here we use Side_Indicator to help logging
            self.Side_Indicator = Side_Indicator
        self.logging = logging

        if self.logging:
            print("PLS %s Protocol: Init Compelete..." % (self.Side_Indicator))
        self._deserializer = PacketBaseType.Deserializer()
        super().__init__
        self.transport = None
        self.state = "Initial_State_0"

    def connection_made(self, transport):
        if self.logging:
            print("PLS %s Protocol: Connection Made..." % (self.Side_Indicator))
        self.transport = transport

    def connection_lost(self, exc=None):
        self.higherProtocol().connection_lost(None)
        self.transport = None
        if self.logging:
            print("PLS %s Protocol: Connection Lost..." % (self.Side_Indicator))

    def send_Server_Hello_Packet(self):
            self.nonceS = random.randint(1, 2 ^ 64)
            certs=[] #TODO
            outBoundPacket = PlsHello.create(self.nonceS, certs)
            if self.logging:
                print("PLS Protocol: Server_Hello sent")
            packetBytes = outBoundPacket.__serialize__()
            self.state = "M2"
            self.M2 = packetBytes
            self.transport.write(packetBytes)

    def authentication(self, certs):
        return True;

    def send_key_exchange(self):
        self.transport.write()

    def decrypt_RSA(self,Perkey):
        return 0;

    def data_received(self, data):
        self._deserializer.update(data)
        for packet in self._deserializer.nextPackets():
            if self.logging:
                print()
            if self.transport is None:
                continue
            if False:  # leave here for further use
                if self.logging:
                    print("PLS %s Protocol: TODO" % (self.Side_Indicator))
            else:
                ################# got a Client Hello Packet ###################
                if isinstance(packet,PlsHello):
                    if self.state != "Initial_State_0":
                        if self.logging:
                            print(
                                "PLS %s Protocol: Error: State Error! Expecting Initial_State_0 but getting %s" %
                                (self.Side_Indicator, self.state))
                        self.state = "error_state"
                    else:
                        if self.logging:
                            print("PLS %s Protocol: Pls Hello Received: Nonce = %d" % (self.Side_Indicator, packet.Nonce))
                        self.authentication(packet.Certs)
                        self.M1 = packet.__serialize__()
                        self.send_Server_Hello_Packet()

                ################# got a KeyExchange Packet ######################
                elif isinstance(packet,PlsKeyExchange):
                    if self.state != "M2":
                        if self.logging:
                            print("PLS %s Protocol: Error: State Error! Should be M2 but %s" %(self.Side_Indicator, self.state))
                        self.state = "error_state"
                    else:
                        if self.nouce+1 != packet.NoncePlusOne:
                            self.state = "error_state"
                            if self.logging:
                                print("PLS %s Protocol: Error: Nounce error!" % self.Side_Indicator)
                        self.decrypt_RSA(packet.PreKey)
                        self.state = "M4"
                        self.send_key_exchange()
                        self.send_handshake_done()
                        self.state = "M6"

                ################ got handshakedone Packet #####################
                elif isinstance(packet, PlsHandshakeDone):
                    if self.state != "M6":
                        if self.logging:
                            print("PLS %s Protocol: Error: State Error! Should be M6 but %s" % (
                            self.Side_Indicator, self.state))
                        self.state = "error_state"
                    else:
                        if self.SHA1value != packet.ValidationHash:
                            if self.logging:
                                print("PLS %s Protocol: Error: SHA Error! Except SHA %s, but %s" % (
                                    self.Side_Indicator, self.SHA1value, packet.ValidationHash))
                            self.state = "error_state"
                        else:
                            self.state = "Data_transport"
                            self.creat_keys()
                            if self.logging:
                                print("PLS %s Protocol: HandShake Done!\n" % self.Side_Indicator)