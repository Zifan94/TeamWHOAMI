from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT16, UINT8, STRING, BUFFER, BOOL
from ..lab2_packets import *
from ..lab2_Util import *
from ..lab2_transport import *
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory

import playground

import random

import asyncio

from collections import OrderedDict

class PEEPServerProtocol(StackingProtocol):
	state = "SYN_ACK_State_0"
	data_chunck_dict = None
	peeptransport = None

	def __init__(self, logging=True):
		if logging:
			print("PEEP Server Side: Init Compelete...")
		self._deserializer = PacketType.Deserializer()
		super().__init__
		self.transport = None
		self.state = "SYN_ACK_State_0"
		self.logging = logging
		self.data_chunck_dict = {}

	def connection_made(self, transport):
		if self.logging:
			print("PEEP Server Side: Connection Made...")
		self.transport = transport

	def connection_lost(self, exc=None):
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
				print("PEEP Server Side: Data Chunck reveived: Seq = %d, Ack = %d, Checksum = (%d)" % (packet.SequenceNumber, packet.Acknowledgement, packet.Checksum))
			
			self.data_chunck_dict.update({packet.SequenceNumber: packet.Data})
			self.higherProtocol().data_received(packet.Data)
			
			#### we need to return ACK when received a packet ###
			outBoundPacket = Util.create_outbound_packet(2, packet.SequenceNumber, packet.SequenceNumber)  # TODO: need to specify the seq num and acknoledgement
			packetBytes = outBoundPacket.__serialize__()
			self.transport.write(packetBytes)
			if self.logging:
				print("PEEP Server Side: ACK back <=")
			#####################################################

	def data_received(self, data):
		self._deserializer.update(data)
		for packet in self._deserializer.nextPackets():
			print()
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
						outBoundPacket = Util.create_outbound_packet(1, random.randint(0, 2147483646/2), packet.SequenceNumber+1)
						if self.logging:
							print("PEEP Server Side: SYN reveived: Seq = %d, Checksum = (%d)"%(packet.SequenceNumber, packet.Checksum))
							print("PEEP Server Side: SYN-ACK sent: Seq = %d, Ack = %d, Checksum = (%d)"%(outBoundPacket.SequenceNumber, outBoundPacket.Acknowledgement, outBoundPacket.Checksum))
						packetBytes = outBoundPacket.__serialize__()
						self.state = "SYN_State_1"
						self.transport.write(packetBytes)

				elif packet.Type == 2:	# incoming an ACK handshake packet
					if self.state != "SYN_State_1" and self.state != "Transmission_State_2":
						if self.logging:
							print("PEEP Server Side: Error: State Error! Expecting SYN_State or Transmission_State_2 but getting %s"%self.state)
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
						self.higherProtocol().connection_made(self.peeptransport)

					elif self.state == "Transmission_State_2":
						self.peeptransport.ack_received(packet.Acknowledgement,self.logging)


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