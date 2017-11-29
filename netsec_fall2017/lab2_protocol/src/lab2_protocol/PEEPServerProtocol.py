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
	TIMEOUTLIMIT = 1
	data_chunck_dict = None
	peeptransport = None
	seq_expected = 0
	sequenceNumber = 0
	isMock = False
	timeout_flag = True
	outBoundSYNACKPacket_3way_handshake = None

	CONNECTION_LOSE_TIME_LIMIT = 15
	prepare_connection_lose_count_down = False

	def __init__(self, logging=False):
		if logging:
			print("PEEP Server Side: Init Compelete...")
		self._deserializer = PEEPPacket.Deserializer()
		super().__init__
		self.transport = None
		self.state = "SYN_ACK_State_0"
		self.logging = logging
		self.data_chunck_dict = {0: ""}
		self.seq_expected = 0
		self.isMock = False
		self.timeout_flag = True
		self.outBoundSYNACKPacket_3way_handshake = None
		self.CONNECTION_LOSE_TIME_LIMIT = 15
		self.prepare_connection_lose_count_down = False

	def set_mock_flag(self, isMock):
		self.isMock = isMock

	def current_seq_update(self, seq):
		self.sequenceNumber = seq

	def connection_made(self, transport):
		if self.logging:
			print("PEEP Server Side: Connection Made...")
		self.transport = transport

	def connection_lost(self, exc=None):
		if self.isMock == False:
			self.higherProtocol().connection_lost(None)
		self.transport = None
		if self.logging:
			print("PEEP Server Side: Connection Lost...")

	def timeout_checker(self, retrans_packet, wrong_current_state):
		if self.state == wrong_current_state:
			if self.logging:
				if retrans_packet.Type == 1:
					print("PEEP Client Side: Wait for ACK [* Time-out *]. SYN-ACK Retransmitted: Seq = %d, Ack = %d, Checksum = (%d)"%(retrans_packet.SequenceNumber, retrans_packet.Acknowledgement, retrans_packet.Checksum))
				else:
					print("PEEP Client Side: Unconsidered case happened in timeout_checker function [* Time-out *].")

			packetBytes = retrans_packet.__serialize__()
			self.transport.write(packetBytes)
			asyncio.get_event_loop().call_later(self.TIMEOUTLIMIT, self.timeout_checker, retrans_packet, wrong_current_state)


	def set_timeout_flag(self, flag): #Only used in UnitTest to turn off timeout_flag
		self.timeout_flag = flag
		if self.logging:
			if self.timeout_flag == True:
				print("PEEP Server Side: Time-out Flag ON!")
			else:
				print("PEEP Server Side: Time-out Flag OFF!")

	def __data_packet_handler(self,packet):
		if self.state != "Transmission_State_2" or self.peeptransport.receiving_Flag == False:
			if self.logging:
				print("PEEP Server Side: Error: State Error! or Client side already sent RIP so will reject this Packet")
			# self.state = "error_state"
		else:
			if self.logging:
				print("PEEP Server Side: Data Chunck reveived: Seq = %d, Checksum = (%d)" % (packet.SequenceNumber, packet.Checksum))

			if (packet.SequenceNumber + len(packet.Data)) == self.seq_expected:
				self.peeptransport.ack_send_updater(self.seq_expected)

			if packet.SequenceNumber == self.seq_expected:
				self.seq_expected = packet.SequenceNumber+len(packet.Data)
				self.peeptransport.ack_send_updater(self.seq_expected)
				self.data_chunck_dict.update({packet.SequenceNumber: packet.Data})
				self.higherProtocol().data_received(packet.Data)

	def __ack_handler(self,ack):
		self.peeptransport.ack_received(ack)
		# self.ackRceived = self.ackRceived + 1

	def __peeptransport_init(self):
		self.peeptransport = PEEPServerTransport(self.transport)
		self.peeptransport.logging = self.logging
		self.peeptransport.sequenceNumber = self.sequenceNumber
		# self.peeptransport.ack_send_autocheck()
		self.higherProtocol().connection_made(self.peeptransport)

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
				# self.state = "error_state"
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
						self.outBoundSYNACKPacket_3way_handshake = outBoundPacket
						self.transport.write(packetBytes)

						if self.timeout_flag == True:
							asyncio.get_event_loop().call_later(self.TIMEOUTLIMIT, self.timeout_checker, self.outBoundSYNACKPacket_3way_handshake, "SYN_State_1")

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
						self.current_seq_update(packet.Acknowledgement)
						self.seq_expected = packet.SequenceNumber  # not plus 1
						self.__peeptransport_init()

					elif self.state == "Transmission_State_2" or "RIP_Received_State_3":
						self.__ack_handler(packet.Acknowledgement)

				elif packet.Type == 3: # incoming an RIP packet
					if self.state != "Transmission_State_2" and self.state != "RIP_Received_State_3":
						if self.logging:
							print("PEEP Server Side: Error: State Error! Expecting Transmission_State_2 or RIP_Received_State_3 but getting %s"%self.state)
						# self.state = "error_state"
					else:
						self.peeptransport.pass_close = True
						outBoundPacket = Util.create_outbound_packet(4, None, packet.SequenceNumber+1) #TODO seq num and ack num
						if self.logging:
							print("\n-------------PEEP Server Protocol Termination Starts--------------------\n")
							print("PEEP Server Side: RIP reveived: Seq = %d, Checksum = (%d)"%(packet.SequenceNumber, packet.Checksum))
							print("PEEP Server Side: RIP-ACK sent: Ack = %d, Checksum = (%d)"%(outBoundPacket.Acknowledgement, outBoundPacket.Checksum))
				
						packetBytes = outBoundPacket.__serialize__()
						self.state = "RIP_Received_State_3"
						self.transport.write(packetBytes)
						self.transport.write(packetBytes)
						self.transport.write(packetBytes)
						self.transport.write(packetBytes)
						self.transport.write(packetBytes)
						self.transport.write(packetBytes)
						self.transport.write(packetBytes)
						self.transport.write(packetBytes)
						self.transport.write(packetBytes)
						self.transport.write(packetBytes)
						self.transport.write(packetBytes)

						if self.prepare_connection_lose_count_down == False:
							if self.logging:
								print("PEEP Server Side: sent 10 RIP-ACK at once...")
							self.prepare_connection_lose_count_down = True
							# asyncio.get_event_loop().call_later(self.CONNECTION_LOSE_TIME_LIMIT, self.connection_lost, None) 
							self.connection_lost(None)
						

				elif packet.Type == 4: # incoming an RIP-ACK packet
					if self.state == "Transmission_State_2" and self.peeptransport.RIP_SENT_FLAG == True:
						self.peeptransport.RIP_ACK_RECV_FlAG = True
						if self.logging:
							print("PEEP Server Side: RIP-ACK received: Ack = %d, Checksum = (%d)"%(packet.Acknowledgement, packet.Checksum))
						self.connection_lost(None)

				# elif packet.Type == 4: # incoming an RIP-ACK packet
				# 	if self.state != "RIP_sent_State_4": #this should be RIP_sent_State_4 once we figure out the timeout for ack
				# 		if self.logging:
				# 			print("PEEP Server Side: Error: State Error! Expecting RIP_sent_State_4 but getting %s"%self.state)
				# 		self.state = "error_state"
				# 	else:
				# 		self.state = "Closing_State_5"
				# 		if self.logging:
				# 			print("PEEP Server Side: RIP-ACK reveived: Ack = %d, Checksum = (%d)"%(packet.Acknowledgement, packet.Checksum))
				# 			print("\nPEEP Server SIde: Preparing connection lose...")
				# 		self.connection_lost(None)


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
