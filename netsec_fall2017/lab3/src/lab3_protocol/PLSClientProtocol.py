from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT64, UINT32, UINT16, UINT8, STRING, BUFFER, BOOL, LIST
from .PLSProtocol import *
from ..lab3_packets import *
from ..lab3_transport import *
from .CertFactory import *
from Crypto.Cipher import PKCS1_OAEP
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import base64
import playground
import random
import asyncio



class PLSClientProtocol(PLSProtocol):

    state = "Not_Init_State"

    def __init__(self, Side_Indicator="Client", logging=True):
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

        self.send_Client_Hello_Packet()

    def send_Client_Hello_Packet(self, callback=None):
        if self.state != "Initial_State_0":
            if self.logging:
                print(
                    "PLS %s Protocol: Error: State Error! Expecting Initial_State_0 but getting %s" %
                    (self.Side_Indicator, self.state))
            self.state = "error_state"
        else:
            self._callback = callback
            self.nonceC = random.randint(1, 2 ** 64)
            certs=[]
            certs.append(CertFactory.getCertsForAddr()) # TODO
            # certs.append(b"cert client") # use fake cert for now
            outBoundPacket = PlsHello.create(self.nonceC, certs)
            if self.logging:
                print("\nPLS %s Protocol: 1. Client_Hello sent"%(self.Side_Indicator))
            packetBytes = outBoundPacket.__serialize__()
            self.state = "M1"
            self.M1 = packetBytes
            self.transport.write(packetBytes)

    def connection_lost(self, exc=None):
        self.higherProtocol().connection_lost(None)
        self.transport = None
        if self.logging:
            print("PLS %s Protocol: Connection Lost..." % (self.Side_Indicator))

    def authentication(self, certs):
        return True;

    def send_key_exchange(self):
        self.pkC = b"This is key??!"
        rsakey = RSA.importKey(self.publickey)
        cipher = PKCS1_OAEP.new(rsakey)
        cipher_text = cipher.encrypt(self.pkC)
        outBoundPacket = PlsKeyExchange.create(cipher_text, self.nonceC+1)
        if self.logging:
            print("\nPLS %s Protocol: 3. %s_PlsKeyExchange sent\n"%(self.Side_Indicator,self.Side_Indicator))
        packetBytes = outBoundPacket.__serialize__()
        self.state = "M3"
        self.M3 = packetBytes
        self.transport.write(packetBytes)

    def decrypt_RSA(self, Perkey):
        privobj = RSA.importKey(CertFactory.getPrivateKeyForAddr())
        privobj = PKCS1_OAEP.new(privobj)
        self.pkS = privobj.decrypt(Perkey)
        # print(self.pkS)


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
                ################# got a Server Hello Packet ###################
                if isinstance(packet, PlsHello):
                    if self.state != "M1":
                        if self.logging:
                            print(
                                "PLS %s Protocol: Error: State Error! Expecting M1 but getting %s" %
                                (self.Side_Indicator, self.state))
                        self.state = "error_state"
                        self.send_PlsClose("state not match")
                    else:
                        if self.logging:
                            print(
                                "PLS %s Protocol: Pls Hello Received: Nonce = %d" % (self.Side_Indicator, packet.Nonce))
                        self.authentication(packet.Certs)
                        self.extract_pulickey(packet.Certs)
                        self.nonceS = packet.Nonce
                        self.M2 = packet.__serialize__()
                        self.send_key_exchange()
                        self.state = "M3"

                ################# got a KeyExchange Packet ######################
                elif isinstance(packet, PlsKeyExchange):
                    if self.state != "M3":
                        if self.logging:
                            print("PLS %s Protocol: Error: State Error! Should be M3 but %s" % (
                            self.Side_Indicator, self.state))
                        self.state = "error_state"
                        self.send_PlsClose("state not match")
                    else:
                        if self.nonceS + 1 != packet.NoncePlusOne:
                            if self.logging:
                                print("PLS %s Protocol: Error: Nounce error!" % self.Side_Indicator)
                            self.state = "error_state"
                            self.send_PlsClose("Nonce not plus 1")
                        else:
                            if self.logging:
                                print("PLS %s Protocol: PlsKeyExchange received"%(self.Side_Indicator))
                            self.decrypt_RSA(packet.Pre_Key)
                            self.M4 = packet.__serialize__()
                            self.state = "M5"
                            self.calc_sha1()
                            self.send_handshake_done()
                            if self.logging:
                                print("PLS %s Protocol: 5. Pls HandshakeDone sent\n"%(self.Side_Indicator))

                ################ got handshakedone Packet #####################
                elif isinstance(packet, PlsHandshakeDone):
                    if self.state != "M5":
                        if self.logging:
                            print("PLS %s Protocol: Error: State Error! Should be M5 but %s" % (
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
                            self.state = "Data_transport"
                            self.creat_keys()
                            if self.logging:
                                print("\nPLS %s Protocol: ###### HandShake Done! ######\n" % self.Side_Indicator)

                            self.PLSTransport = PLSTransport(self.transport)
                            self.PLSTransport.logging = self.logging
                            self.PLSTransport.Side_Indicator = self.Side_Indicator
                            self.PLSTransport.set_Engine(self.Encryption_Engine, self.MAC_Engine)

                            self.higherProtocol().connection_made(self.PLSTransport)

                ################# got a PlsClose Packet ######################
                elif isinstance(packet,PlsData):
                    if self.state != "Data_transport":
                        if self.logging:
                            print("PLS %s Protocol: Error: State Error! Should be Data_transport but %s" % (
                            self.Side_Indicator, self.state))
                        self.state = "error_state"
                        self.send_PlsClose("state not match")
                    else:
                        self.count += 1
                        if self.logging:
                            print("PLS %s Protocol: Got %d PLS Data from other side"% (self.Side_Indicator, self.count))
                        C = packet.Ciphertext
                        V = packet.Mac
                        V_ = self.Verification_Engine.calc_MAC(C)
                        if V == V_: # Verification Success
                            Current_PlainText = self.Decryption_Engine.decrypt(C)
                            self.higherProtocol().data_received(Current_PlainText)
                            if self.logging:
                                print("PLS %s Protocol: Verification Success, passing data up!"% (self.Side_Indicator))

                        else: # V != V_  Verification Fail 
                            if self.logging:
                                print("PLS %s Protocol: Verification Fail !!!!!!!!!!!!!!!!!!!!"% (self.Side_Indicator))
                            self.state = "error_state"
                            self.send_PlsClose("MAC verifiation failed!")


                ################# got a PlsClose Packet ######################
                elif isinstance(packet,PlsClose):
                    if self.logging:
                        print("PLS %s Protocol: Got a PLS Close from other side"% self.Side_Indicator)
                    self.connection_lost()