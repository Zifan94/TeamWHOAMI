from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT16, UINT8, STRING, BUFFER, BOOL
from ..lab2_packets import *
from ..lab2_Util import *
from ..lab2_transport import *
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory

import playground

import random

import asyncio

import time

from collections import OrderedDict

class PEEPServerProtocol(StackingProtocol):
	state = "SYN_ACK_State_0"
	data_chunck_dict = None
	peeptransport = None
	ackRceived = 0
	sequenceNumber = 0

	def __init__(self, logging=True):
		if logging:
			print("PEEP Server Side: Init Compelete...")
		self._deserializer = PacketType.Deserializer()
		super().__init__
		self.transport = None
		self.state = "SYN_ACK_State_0"
		self.logging = logging
		self.data_chunck_dict = {}
		self.ackRceived = 0

	def current_seq_update(self, seq):
		self.sequenceNumber = seq

	def connection_made(self, transport):
		if self.logging:
			print("PEEP Server Side: Connection Made...")
		self.transport = transport

	def connection_lost(self, exc=None):
		self.higherProtocol().connection_lost()
		self.transport = None
		if self.logging:
			print("PEEP Server Side: Connection Lost...")

	def __data_packet_handler(self,packet):
		if self.state != "Transmission_State_2":
			if self.logging:
				print("PEEP Server Side: Error: State Error! Expecting Transmission_State_2 but getting %s" % self.state)
			self.state = "error_state"
		else:
			if self.logging:
				print("PEEP Server Side: Data Chunck reveived: Seq = %d, Checksum = (%d)" % (packet.SequenceNumber, packet.Checksum))

			self.data_chunck_dict.update({packet.SequenceNumber: packet.Data})
			
			#### we need to return ACK when received a packet ###
			print(len(packet.Data))
			outBoundPacket = Util.create_outbound_packet(2, None, packet.SequenceNumber+len(packet.Data))
			packetBytes = outBoundPacket.__serialize__()
			if self.logging:
				print("PEEP Server Side: ACK back <=")
			#####################################################

			self.transport.write(packetBytes)
			self.higherProtocol().data_received(packet.Data)

	def data_received(self, data):
		self._deserializer.update(data)
		for packet in self._deserializer.nextPackets():
			if self.logging:	print()
			if self.transport == None:
				continue

			#Do checksum verification first!
			if (packet.verifyChecksum() == False):
				if self.logging:
					print("PEEP Server side: checksum is bad")
				self.state = "error_state"
			else: # checksum is good, now we look into the packet
				# if self.logging:
				# 	print("PEEP Server side: checksum is good")

				if packet.Type == 0:	# incoming an SYN handshake packet
					if self.state != "SYN_ACK_State_0":
						if self.logging:
							print("PEEP Server Side: Error: State Error! Expecting SYN_ACK_State but getting %s"%self.state)
						self.state = "error_state"
					else:
						self.current_seq_update(random.randint(0, 5000))
						outBoundPacket = Util.create_outbound_packet(1, self.sequenceNumber, packet.SequenceNumber+1)
						if self.logging:
							print("PEEP Server Side: SYN reveived: Seq = %d, Checksum = (%d)"%(packet.SequenceNumber, packet.Checksum))
							print("PEEP Server Side: SYN-ACK sent: Seq = %d, Ack = %d, Checksum = (%d)"%(outBoundPacket.SequenceNumber, outBoundPacket.Acknowledgement, outBoundPacket.Checksum))
						packetBytes = outBoundPacket.__serialize__()
						self.state = "SYN_State_1"
						self.transport.write(packetBytes)

				elif packet.Type == 2:	# incoming an ACK handshake packet
					if self.state != "SYN_State_1" and self.state != "Transmission_State_2" and self.state != "RIP_Received_State_3":
						if self.logging:
							print("PEEP Server Side: Error: State Error! Expecting SYN_State or Transmission_State_2 or RIP_Received_State_3 but getting %s"%self.state)
						self.state = "error_state"

					elif self.state == "SYN_State_1":
						if self.logging:
							print("PEEP Server Side: ACK reveived: Seq = %d, Ack = %d, Checksum = (%d)"%(packet.SequenceNumber,packet.Acknowledgement, packet.Checksum))
							print("PEEP Server Side: CONNECTION ESTABLISHED!")
						self.state = "Transmission_State_2"
						if self.logging:
							print("PEEP Server Side: ### THREE-WAY HANDSHAKE established ###")
							print()
						self.peeptransport = PEEPTransport(self.transport)
						self.peeptransport.logging = self.logging
						self.peeptransport.sequenceNumber = self.sequenceNumber
						self.higherProtocol().connection_made(self.peeptransport)

					elif self.state == "Transmission_State_2" or "RIP_Received_State_3":
						self.peeptransport.ack_received(packet.Acknowledgement)
						self.ackRceived = self.ackRceived+1

				elif packet.Type == 3: # incoming an RIP packet
					if self.state != "Transmission_State_2":
						if self.logging:
							print("PEEP Server Side: Error: State Error! Expecting Transmission_State_2 but getting %s"%self.state)
						self.state = "error_state"
					else:
						outBoundPacket = Util.create_outbound_packet(4, 0, 0) #TODO seq num and ack num
						if self.logging:
							print("PEEP Server Side: RIP reveived: Seq = %d, Ack = %d, Checksum = (%d)"%(packet.SequenceNumber,packet.Acknowledgement, packet.Checksum))
							print("PEEP Server Side: RIP-ACK sent: Seq = %d, Ack = %d, Checksum = (%d)"%(outBoundPacket.SequenceNumber, outBoundPacket.Acknowledgement, outBoundPacket.Checksum))
				
						packetBytes = outBoundPacket.__serialize__()
						self.state = "RIP_Received_State_3"
						self.transport.write(packetBytes)

						if self.logging:
							print("\nPEEP Server Side: Starting sending remaining packets in buffer ...")
						# sending all the cached packets in buffer here
						if self.logging:
							print("\nPEEP Server Side: Finish sending remainng packets in buffer !!!")
						
						# set a timeout here to wait for remaining ACKs to sent back
						# while len(self.peeptransport.PEEPPacketList) > self.ackRceived:
						# 	time.sleep(1)

						# sending RIP to client
						outBoundPacket = Util.create_outbound_packet(3, 0, 0) #TODO seq num and ack num
						if self.logging:
							print("PEEP Server Side: RIP sent: Seq = %d, Ack = %d, Checksum = (%d)"%(outBoundPacket.SequenceNumber,outBoundPacket.Acknowledgement, outBoundPacket.Checksum))
						packetBytes = outBoundPacket.__serialize__()
						# self.state = "RIP_sent_State_4"
						self.transport.write(packetBytes)	


				elif packet.Type == 4: # incoming an RIP-ACK packet
					if self.state != "RIP_Received_State_3": #this should be RIP_sent_State_4 once we figure out the timeout for ack
						if self.logging:
							print("PEEP Server Side: Error: State Error! Expecting RIP_sent_State_4 but getting %s"%self.state)
						self.state = "error_state"
					else:
						self.state = "Closing_State_5"
						if self.logging:
							print("PEEP Server Side: RIP-ACK reveived: Seq = %d, Ack = %d, Checksum = (%d)"%(packet.SequenceNumber,packet.Acknowledgement, packet.Checksum))
							print("\nPEEP Server SIde: Preparing connection lose...")
						self.connection_lost()


				elif packet.Type == 5:	# incomming an Data packet
					self.__data_packet_handler(packet)
				# more packet type implemented here
				else:
					if self.logging:
						print("PEEP Server Side: Error: Unrecognize HandShake Type received!")
					self.state = "error_state"

			if self.transport == None:
				continue
			if self.state == "error_state":
				self.transport.close()