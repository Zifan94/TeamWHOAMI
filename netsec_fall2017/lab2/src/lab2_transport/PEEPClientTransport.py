from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT16, UINT8, STRING, BUFFER, BOOL
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from ..lab2_packets import *
from ..lab2_Util import *
import asyncio

DATA_CHUNK_SIZE = 1024 # use 10 for test!!!
class PEEPClientTransport(StackingTransport):
	# ACK_TIME_INTERVAL = 0.5
	WINDOWS_SIZE = 10
	processing_packet = 0
	TIME_OUT_LIMIE = 1
	CLEAR_BUFFER_TIME_LIMIT = 0.5
	logging = True
	RetransmissionPacketList = {0: ""}
	waitingList = [Util.create_outbound_packet(5)]
	ackList = [0]
	sequenceNumber = 0
	maxAck = 0
	ack_sendflag = False
	outBoundRIPPacket_4way_termination = None
	state = "Transmission_State_2"

	def close(self):
		if self.logging:	print("\n-------------PEEP Client Termination Starts--------------------\n")
		asyncio.get_event_loop().call_later(self.TIME_OUT_LIMIE, self.clear_databuffer_and_send_RIP, self.sequenceNumber)
		# self.clear_databuffer_and_send_RIP(self.sequenceNumber)


	def write(self, data):
		#this will be the data from the upper layer
		size = int(len(data)/DATA_CHUNK_SIZE)
		if len(data)%DATA_CHUNK_SIZE != 0: size+=1
		if self.logging:
			print("\nPEEP Client Transport: data length is [%s], and divided into [%s] PEEP packets"%(len(data), size))

		for i in range(1, size+1):
			if self.logging:
				print("PEEP Client Transport: packing seq = [%s] PEEP packet..." % self.sequenceNumber)
			cur_Data_Chuck = (data[(i-1)*DATA_CHUNK_SIZE : i*DATA_CHUNK_SIZE])
			cur_PEEP_Packet = Util.create_outbound_packet(5, self.sequenceNumber, None, cur_Data_Chuck)
			self.sequenceNumber += len(cur_PEEP_Packet.Data)
			self.window_control(cur_PEEP_Packet)


	def Timeout_checker(self, retrans_packet, wrong_current_state):
		if self.state == wrong_current_state:
			if self.logging:
				if retrans_packet.Type == 3:
					print("PEEP Client Side: Wait for RIP-SYN [* Time-out *]. RIP Retransmitted: Seq = %d Checksum = (%d)"%(retrans_packet.SequenceNumber, retrans_packet.Checksum))
				# elif retrans_packet.Type == 2:
				# 	print("PEEP Client Side: Wait for the FIRST Data Packet [* Time-out *]. ACK Retransmitted: Seq = %d, Ack = %d, Checksum = (%d)"%(retrans_packet.SequenceNumber, retrans_packet.Acknowledgement, retrans_packet.Checksum))
				else:
					print("PEEP Client Side: Unconsidered case happened in Timeout_checker function [* Time-out *].")

			packetBytes = retrans_packet.__serialize__()
			self.lowerTransport().write(packetBytes)
			asyncio.get_event_loop().call_later(self.TIME_OUT_LIMIE, self.Timeout_checker, retrans_packet, wrong_current_state)
	

	def clear_databuffer_and_send_RIP(self, seq):
		if len(self.waitingList) != 1 or len(self.RetransmissionPacketList) != 1:
			if self.logging:	print("PEEP Client Transport: Cleaning data buffer now ......")
			self.clean_waitList()
			self.clean_RetransmissionPacketList()
			asyncio.get_event_loop().call_later(self.CLEAR_BUFFER_TIME_LIMIT, self.clear_databuffer_and_send_RIP, self.sequenceNumber) 
		else:
			cur_RIP_Packet = Util.create_outbound_packet(3, seq)
			if self.logging:
				print("\nPEEP Client Transport: ### Data Buffer is CLEAR ###")
				print("\nPEEP Client Transport: RIP sent: Seq = %d Checksum = (%d)"%(cur_RIP_Packet.SequenceNumber, cur_RIP_Packet.Checksum))
			self.lowerTransport().write(cur_RIP_Packet.__serialize__())
			self.outBoundRIPPacket_4way_termination = cur_RIP_Packet
			asyncio.get_event_loop().call_later(self.TIME_OUT_LIMIE, self.Timeout_checker, self.outBoundRIPPacket_4way_termination, "Transmission_State_2")


	def clean_waitList(self):
		if len(self.waitingList) == 1: 
			if self.logging:
				print("\nPEEP Client Transport: # Wait List is CLEAR! #\n")
			return
		else:
			if self.processing_packet < self.WINDOWS_SIZE:
				self.process_a_waitList_packet()
			# asyncio.get_event_loop().call_later(self.CLEAR_BUFFER_TIME_LIMIT, self.clean_waitList)


	def clean_RetransmissionPacketList(self):
		if len(self.ackList) == 1:
			if self.logging:
				print("\nPEEP Client Transport: # Retransmission Packet List is CLEAR! #\n")
			return
		else:
			self.retransmission_checker(self.ackList[1])
			# asyncio.get_event_loop().call_later(self.CLEAR_BUFFER_TIME_LIMIT, self.clean_RetransmissionPacketList)


	def process_a_waitList_packet(self):
		if (self.processing_packet < self.WINDOWS_SIZE) & (len(self.waitingList) > 1):
			self.processing_packet += 1
			cur_PEEP_Packet = self.waitingList.pop(1)
			ackNumber = cur_PEEP_Packet.SequenceNumber + len(cur_PEEP_Packet.Data)
			self.RetransmissionPacketList.update({ackNumber: cur_PEEP_Packet})
			self.ackList.append(ackNumber)
			if self.logging:
				print("PEEP Client Transport: Seq = [%s] PEEP Packets written!\n" % cur_PEEP_Packet.SequenceNumber)
			self.lowerTransport().write(cur_PEEP_Packet.__serialize__())
			asyncio.get_event_loop().call_later(self.TIME_OUT_LIMIE, self.retransmission_checker, ackNumber)
	

	def window_control(self, packet=None):
		if packet is not None:
			self.waitingList.append(packet)
		self.process_a_waitList_packet()


	def retransmission_checker(self,seq):
		if seq in self.RetransmissionPacketList:
			if self.logging:
				print("PEEP Client Transport: Packets ack = [%s] not received after TIMEOUT, Retransmission...." %seq)
			self.lowerTransport().write(self.RetransmissionPacketList[seq].__serialize__())
			asyncio.get_event_loop().call_later(self.TIME_OUT_LIMIE, self.retransmission_checker, seq)


	def ack_received(self,ack):
		if self.logging:	print("PEEP Client Transport: ACK received, Ack = %d" % ack)
		while (self.ackList[1] < ack):
			del self.RetransmissionPacketList[self.ackList[1]]
			del self.ackList[1]
			self.processing_packet -= 1
			self.window_control()
		if self.ackList[1] == ack:
			del self.RetransmissionPacketList[self.ackList[1]]
			del self.ackList[1]
			self.processing_packet -= 1
			self.window_control()


	def ack_send_check(self):
		if self.ack_sendflag:
			outBoundPacket = Util.create_outbound_packet(2, None, self.maxAck)
			packetBytes = outBoundPacket.__serialize__()
			self.ack_sendflag = False
			self.lowerTransport().write(packetBytes)
			if self.logging:
				print("PEEP Client Transport: ACK back <= ", self.maxAck)


	def ack_send_updater(self, new_ack):
		self.maxAck = max(new_ack, self.maxAck)
		self.ack_sendflag = True
		self.ack_send_check()
