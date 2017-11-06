from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT64, UINT32, UINT16, UINT8, STRING, BUFFER, BOOL, LIST
from .PLSProtocol import *
from ..lab3_packets import *
from .CertFactory import *
from Crypto.Cipher import PKCS1_OAEP
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import base64
import playground
import random
import asyncio


class PLSServerProtocol(PLSProtocol):

    state = "Not_Init_State"

    def __init__(self, Side_Indicator="Server", logging=True):
        if Side_Indicator is not None:  # here we use Side_Indicator to help logging
            self.Side_Indicator = Side_Indicator
        self.logging = logging

        if self.logging:
            print("PLS %s Protocol: Init Compelete..." % (self.Side_Indicator))
        self._deserializer = PacketType.Deserializer()
        super().__init__
        self.transport = None
        self.state = "Initial_State_0"

    def connection_made(self, transport):
        if self.logging:
            print("PLS %s Protocol: Connection Made..." % (self.Side_Indicator))
        self.transport = transport
        self.higherTransport = StackingTransport(self.transport)

    def connection_lost(self, exc=None):
        self.higherProtocol().connection_lost(None)
        self.transport = None
        if self.logging:
            print("PLS %s Protocol: Connection Lost..." % (self.Side_Indicator))

    def send_Server_Hello_Packet(self):
        self.nonceS = random.randint(1, 2 ** 64)
        certs=[] #TODO
        certs.append(CertFactory.getCertsForAddr())
        # certs.append(b"cert server") # use fake cert for now
        outBoundPacket = PlsHello.create(self.nonceS, certs)
        if self.logging:
            print("PLS %s Protocol: 2. Server_Hello sent\n"% (self.Side_Indicator))
        packetBytes = outBoundPacket.__serialize__()
        self.state = "M2"
        self.M2 = packetBytes
        self.transport.write(packetBytes)

    def authentication(self, certs):
        return True;

    def send_key_exchange(self):
        self.pkS = b"hahahahahahaha 123123"
        rsakey = RSA.importKey(self.publickey)
        cipher = PKCS1_OAEP.new(rsakey)
        cipher_text = cipher.encrypt(self.pkS)
        outBoundPacket = PlsKeyExchange.create(cipher_text, self.nonceS + 1)
        packetBytes = outBoundPacket.__serialize__()
        self.state = "M4"
        self.M4 = packetBytes
        self.transport.write(packetBytes)
        if self.logging:
            print("\nPLS %s Protocol: 4. %s_PlsKeyExchange sent\n"%(self.Side_Indicator,self.Side_Indicator))

    def decrypt_RSA(self, Perkey):
        privobj = RSA.importKey(CertFactory.getPrivateKeyForAddr())
        privobj = PKCS1_OAEP.new(privobj)
        self.pkC = privobj.decrypt(Perkey)
        # print(self.pkC)

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
                        self.send_PlsClose("state not match")
                    else:
                        if self.logging:
                            print("PLS %s Protocol: Pls Hello Received: Nonce = %d" % (self.Side_Indicator, packet.Nonce))
                        self.authentication(packet.Certs)
                        self.extract_pulickey(packet.Certs)
                        self.nonceC = packet.Nonce
                        self.M1 = packet.__serialize__()
                        self.send_Server_Hello_Packet()

                ################# got a KeyExchange Packet ######################
                elif isinstance(packet,PlsKeyExchange):
                    if self.state != "M2":
                        if self.logging:
                            print("PLS %s Protocol: Error: State Error! Should be M2 but %s" %(self.Side_Indicator, self.state))
                        self.state = "error_state"
                        self.send_PlsClose("state not match")
                    else:
                        if self.nonceC +1 != packet.NoncePlusOne:
                            if self.logging:
                                print("PLS %s Protocol: Error: Nounce error! Should be %d but %d" % self.Side_Indicator,self.nonceC +1,packet.NoncePlusOne)
                            self.state = "error_state"
                            self.send_PlsClose("Nonce not plus 1")
                        else:
                            self.decrypt_RSA(packet.Pre_Key)
                            self.M3 = packet.__serialize__()
                            self.state = "M4"
                            self.send_key_exchange()
                            self.calc_sha1()
                            # self.send_handshake_done()
                            self.state = "M6"

                ################ got handshakedone Packet #####################
                elif isinstance(packet, PlsHandshakeDone):
                    if self.state != "M6":
                        if self.logging:
                            print("PLS %s Protocol: Error: State Error! Should be M6 but %s" % (
                            self.Side_Indicator, self.state))
                        self.state = "error_state"
                        self.send_PlsClose("state not match")
                    else:
                        if self.SHA1value != packet.ValidationHash:
                            if self.logging:
                                print("PLS %s Protocol: Error: SHA Error! Except SHA %s, but %s" % (
                                    self.Side_Indicator, self.SHA1value, packet.ValidationHash))
                            self.state = "error_state"
                            self.send_PlsClose("SHA not match")
                        else:
                            if self.logging:
                                print("PLS %s Protocol: 6. Pls HandshakeDone sent\n"%(self.Side_Indicator))
                            self.send_handshake_done()
                            self.state = "Data_transport"
                            self.creat_keys()
                            if self.logging:
                                print("\nPLS %s Protocol: ###### HandShake Done! ######\n" % self.Side_Indicator)
                            self.higherProtocol().connection_made(self.higherTransport)

                ################# got a PlsClose Packet ######################
                elif isinstance(packet,PlsClose):
                    if self.logging:
                        print("PLS %s Protocol: Got a PLS Close from other side"% self.Side_Indicator)
                    # self.connection_lost()
