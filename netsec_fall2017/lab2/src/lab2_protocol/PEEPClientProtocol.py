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

class PEEPClientProtocol(StackingProtocol):
	state = "Initial_SYN_State_0"
	TIMEOUTLIMIT = 1
	timeout_flag = True
	data_chunck_dict = None
	peeptransport = None
	sequenceNumber = 0
	seq_expected = 0
	isMock = False
	outBoundSYNPacket_3way_handshake = None
	outBoundACKPacket_3way_handshake = None

	CONNECTION_LOSE_TIME_LIMIT = 15
	prepare_connection_lose_count_down = False

	def __init__(self, logging=True):
		if logging:
			print("PEEP Client Side: Init Compelete...")
		self._deserializer = PEEPPacket.Deserializer()
		super().__init__
		self.transport = None
		self.state = "Initial_SYN_State_0"
		self.logging = logging
		self.data_chunck_dict = {}
		self.isMock = False
		self.seq_expected = 0
		self.outBoundSYNPacket_3way_handshake = None
		self.outBoundACKPacket_3way_handshake = None
		self.CONNECTION_LOSE_TIME_LIMIT = 15
		self.prepare_connection_lose_count_down = False

	def set_mock_flag(self, isMock):
		self.isMock = isMock

	def current_seq_update(self, seq):
		self.sequenceNumber = seq

	def connection_made(self, transport):
		if self.logging:
			print("PEEP Client Side: Connection Made...")
		self.transport = transport
		self.send_request_packet()

	def timeout_checker(self, retrans_packet, wrong_current_state):
		if self.state == wrong_current_state:
			if self.logging:
				if retrans_packet.Type == 0:
					print("PEEP Client Side: Wait for ACK-SYN [* Time-out *]. SYN Retransmitted: Seq = %d, Checksum = (%d)"%(retrans_packet.SequenceNumber, retrans_packet.Checksum))
				elif retrans_packet.Type == 2:
					print("PEEP Client Side: Wait for the FIRST Data Packet [* Time-out *]. ACK Retransmitted: Seq = %d, Ack = %d, Checksum = (%d)"%(retrans_packet.SequenceNumber, retrans_packet.Acknowledgement, retrans_packet.Checksum))
				else:
					print("PEEP Client Side: Unconsidered case happened in timeout_checker function [* Time-out *].")

			packetBytes = retrans_packet.__serialize__()
			self.transport.write(packetBytes)
			asyncio.get_event_loop().call_later(self.TIMEOUTLIMIT, self.timeout_checker, retrans_packet, wrong_current_state)


	def set_timeout_flag(self, flag): #Only used in UnitTest to turn off timeout_flag
		self.timeout_flag = flag
		if self.logging:
			if self.timeout_flag == True:
				print("PEEP Client Side: Time-out Flag ON!")
			else:
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
			self.current_seq_update(random.randint(0, 5000))
			outBoundPacket = Util.create_outbound_packet(0, self.sequenceNumber)
			if self.logging:
				print("PEEP Client Side: SYN sent: Seq = %d, Checksum = (%d)"%(outBoundPacket.SequenceNumber, outBoundPacket.Checksum))
			packetBytes = outBoundPacket.__serialize__()
			self.state = "SYN_ACK_State_1"
			self.outBoundSYNPacket_3way_handshake = outBoundPacket
			self.transport.write(packetBytes)

			if self.timeout_flag == True:
				asyncio.get_event_loop().call_later(self.TIMEOUTLIMIT, self.timeout_checker, self.outBoundSYNPacket_3way_handshake, "Initial_SYN_State_0")

	def connection_lost(self, exc=None):
		if self.isMock == False:
			self.higherProtocol().connection_lost(None)
		self.transport = None
		if self.logging:
			print("PEEP Client Side: Connection Lost...")

	def __data_packet_handler(self,packet):
		if self.state != "Transmission_State_2" or self.peeptransport.receiving_Flag == False:
			if self.logging:
				print("PEEP Client Side: Error: State Error! or Client side already sent RIP so will reject this Packet")
			# self.state = "error_state"
		else:
			if self.logging:
				print("PEEP Client Side: Data Chunck reveived: Seq = %d, Checksum = (%d)" % (packet.SequenceNumber, packet.Checksum))

			# if packet.Acknowledgement != None:
			# 	self.__ack_handler(packet.Acknowledgement)
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
		self.peeptransport = PEEPClientTransport(self.transport)
		self.peeptransport.logging = self.logging
		self.peeptransport.sequenceNumber = self.sequenceNumber
		# self.peeptransport.ack_send_autocheck()
		self.higherProtocol().connection_made(self.peeptransport)

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
				# self.state = "error_state"
			else:  # checksum is good, now we look into the packet
				# if self.logging:
				# 	print("PEEP Client side: checksum is good")

				if packet.Type == 1:	# incoming an SYN-ACK handshake packet
					if self.state != "SYN_ACK_State_1":
						if self.logging:
							print("PEEP Client Side: Error: State Error! Expecting SYN_ACK_State but getting %s"%self.state)
						self.state = "error_state"
					else:
						self.current_seq_update(packet.Acknowledgement)
						self.seq_expected = packet.SequenceNumber+1
						outBoundPacket = Util.create_outbound_packet(2, self.sequenceNumber, packet.SequenceNumber+1)
						if self.logging:
							print("PEEP Client Side: SYN-ACK reveived: Seq = %d, Ack = %d, Checksum = (%d)"%(packet.SequenceNumber,packet.Acknowledgement, packet.Checksum))
							print("PEEP Client Side: ACK sent: Seq = %d, Ack = %d, Checksum = (%d)"%(outBoundPacket.SequenceNumber, outBoundPacket.Acknowledgement, outBoundPacket.Checksum))

						packetBytes = outBoundPacket.__serialize__()
						self.state = "Transmission_State_2"
						self.outBoundACKPacket_3way_handshake = outBoundPacket
						self.transport.write(packetBytes)
						if self.logging:
							print("PEEP Client Side: ### THREE-WAY HANDSHAKE established ###")
							print()
						self.__peeptransport_init()

				elif packet.Type == 2 and self.state == "Transmission_State_2": # receiving ACK back
					self.__ack_handler(packet.Acknowledgement)


				elif packet.Type == 3: # incoming an RIP packet
					if self.state != "Transmission_State_2" and self.state != "RIP_Received_State_3":
						if self.logging:
							print("PEEP Client Side: Error: State Error! Expecting Transmission_State_2 or RIP_Received_State_3 but getting %s"%self.state)
						# self.state = "error_state"
					else:
						self.peeptransport.pass_close = True
						outBoundPacket = Util.create_outbound_packet(4, None, packet.SequenceNumber+1) #TODO seq num and ack num
						if self.logging:
							print("\n-------------PEEP Client Protocol Termination Starts--------------------\n")
							print("PEEP Client Side: RIP reveived: Seq = %d, Checksum = (%d)"%(packet.SequenceNumber, packet.Checksum))
							print("PEEP Client Side: RIP-ACK sent: Ack = %d, Checksum = (%d)"%(outBoundPacket.Acknowledgement, outBoundPacket.Checksum))
				
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

						if self.prepare_connection_lose_count_down == False:
							if self.logging:
								print("PEEP Client Side: sent 10 RIP-ACK at once...")
							self.prepare_connection_lose_count_down = True
							# asyncio.get_event_loop().call_later(self.CONNECTION_LOSE_TIME_LIMIT, self.connection_lost, None) 
							self.connection_lost(None)
							
				# elif packet.Type == 3: # incoming an RIP packet
				# 	if self.state != "Transmission_State_2":
				# 		if self.logging:
				# 			print("PEEP Client Side: Error: State Error! Expecting Transmission_State_2 but getting %s"%self.state)
				# 		self.state = "error_state"
				# 	else:
				# 		outBoundPacket = Util.create_outbound_packet(4, None, packet.SequenceNumber+1) #TODO seq num and ack num
				# 		if self.logging:
				# 			print("PEEP Client Side: RIP reveived: Seq = %d, Checksum = (%d)"%(packet.SequenceNumber, packet.Checksum))
				# 			print("PEEP Client Side: RIP-ACK sent: Ack = %d, Checksum = (%d)"%(outBoundPacket.Acknowledgement, outBoundPacket.Checksum))
				# 			print("PEEP Client Side: Preparing to lose connection")
				# 		packetBytes = outBoundPacket.__serialize__()
				# 		self.state = "Closing_State_3"
				# 		self.transport.write(packetBytes)
				# 		self.connection_lost(None)

				elif packet.Type == 4: # incoming an RIP-ACK packet
					if self.state == "Transmission_State_2" and self.peeptransport.RIP_SENT_FLAG == True:
						self.peeptransport.RIP_ACK_RECV_FlAG = True
						if self.logging:
							print("PEEP Client Side: RIP-ACK received: Ack = %d, Checksum = (%d)"%(packet.Acknowledgement, packet.Checksum))
						self.connection_lost(None)
							

				elif packet.Type == 5:	# incomming an Data packet
					self.__data_packet_handler(packet)

				# more packet type implemented here
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
