from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT16, UINT8, STRING, BUFFER, BOOL
from ..lab2_packets import *
from ..lab2_Util import *
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory

import playground

import random

import asyncio

class PEEPClientProtocol(StackingProtocol):
	state = "Initial_SYN_State_0"
	TIMEOUTLIMIT = 10
	timeout_flag = True

	def __init__(self, logging=True):
		if logging:
			print("PEEP Client Side: Init Compelete...")
		self._deserializer = PacketType.Deserializer()
		super().__init__
		self.transport = None
		self.state = "Initial_SYN_State_0"
		self.logging = logging

	def connection_made(self, transport):
		if self.logging:
			print("PEEP Client Side: Connection Made...")
		self.transport = transport
		self.send_request_packet()

	def timeout_checker(self):
		if self.state == "SYN_ACK_State_1":
			if self.logging:
				print("PEEP Client Side: Time-out. Close Connection.")
			self.state = "error_state"
			self.transport.close()

	def set_timeout_flag(self, flag): #Only used in UnitTest to turn off timeout_flag
		self.timeout_flag = flag
		if self.logging:
			print("PEEP Client Side: Time-out Flag OFF!")

	def send_request_packet(self, callback=None):
		#print("Client: %s"%self.state)
		if self.state != "Initial_SYN_State_0":
			if self.logging:
				print("PEEP Client Side: Error: State Error! Expecting Initial_SYN_State but getting %s"%self.state)
			self.state = "error_state"
			self.transport.close()
		else:
			self._callback = callback
			outBoundPacket = Util.create_outbound_packet(0, random.randint(0, 2147483646/2))
			if self.logging:
				print("PEEP Client Side: SYN sent: Seq = %d, Checksum = (%d)"%(outBoundPacket.SequenceNumber, outBoundPacket.Checksum))
			packetBytes = outBoundPacket.__serialize__()
			self.state = "SYN_ACK_State_1"
			self.transport.write(packetBytes)

			if self.timeout_flag == True:
				current_time = asyncio.get_event_loop().time()
				asyncio.get_event_loop().call_at(current_time + self.TIMEOUTLIMIT, self.timeout_checker)

	def connection_lost(self, exc=None):
		self.transport = None
		if self.logging:
			print("PEEP Client Side: Connection Lost...")

	def data_received(self, data):
		self._deserializer.update(data)
		for packet in self._deserializer.nextPackets():
			if self.logging:
				print()
			if self.transport == None:
				continue

			 #Do checksum verification first!
			if (packet.verifyChecksum() == False):
				if self.logging:
					print("PEEP Client side: checksum is bad")
				self.state = "error_state"
			else:  # checksum is good, now we look into the packet
				if self.logging:
					print("PEEP Client side: checksum is good")

				if packet.Type == 1:	# incoming an SYN-ACK handshake packet
					if self.state != "SYN_ACK_State_1":
						if self.logging:
							print("PEEP Client Side: Error: State Error! Expecting SYN_ACK_State but getting %s"%self.state)
						self.state = "error_state"
					else:
						outBoundPacket = Util.create_outbound_packet(2, packet.Acknowledgement+1, packet.SequenceNumber+1)
						if self.logging:
							print("PEEP Client Side: SYN-ACK reveived: Seq = %d, Ack = %d, Checksum = (%d)"%(packet.SequenceNumber,packet.Acknowledgement, packet.Checksum))
							print("PEEP Client Side: ACK sent: Seq = %d, Ack = %d, Checksum = (%d)"%(outBoundPacket.SequenceNumber, outBoundPacket.Acknowledgement, outBoundPacket.Checksum))

						packetBytes = outBoundPacket.__serialize__()
						self.state = "Transmission_State_2"
						self.transport.write(packetBytes)
						if self.logging:
							print("PEEP Client Side: ### THREE-WAY HANDSHAKE established ###")
							print()
						higherTransport = StackingTransport(self.transport)
						self.higherProtocol().connection_made(higherTransport)
				else:
					if self.logging:
						print("PEEP Client Side: Error: Unrecognize HandShake Type received!")
					self.state = "error_state"

			if self.transport == None:
				continue
			if self.state == "error_state":
				self.transport.close()


	def callbackForUserVCInput(self):
		answer = input("Client Side: Please input the verification code: ")
		return answer
