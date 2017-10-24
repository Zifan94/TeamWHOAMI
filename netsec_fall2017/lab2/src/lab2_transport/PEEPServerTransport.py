from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT16, UINT8, STRING, BUFFER, BOOL
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from ..lab2_packets import *
from ..lab2_Util import *
import asyncio

class PEEPServerTransport(StackingTransport):
	DATA_CHUNK_SIZE = 1024 # use 10 for test!!!
	# ACK_TIME_INTERVAL = 0.5
	WINDOWS_SIZE = 5
	processing_packet = 0
	TIME_OUT_LIMIE = 0.5
	CLEAR_BUFFER_TIME_LIMIT = 0.5
	logging = True
	RetransmissionPacketList = {0: ""}
	waitingList = [Util.create_outbound_packet(5)]
	ackList = [0]
	sequenceNumber = 0
	maxAck = 0
	ack_sendflag = False
	RIP_SENT_FLAG = False
	receiving_Flag = True
	pass_close = False
	first_time_close = True
	WAIT_BEFORE_CLOSE = 5
	RIP_ACK_RECV_FlAG = False
	RIP_PKT = None

	def Time(self,index):
		return 0.1+0.1*index

	def close(self):
		if self.pass_close == False:
			if self.first_time_close == True:
				self.first_time_close = False
				if self.logging:	
					print("\nPEEP Server Transport: Let's Wait a little bit before clean buffer\n")
				asyncio.get_event_loop().call_later(self.WAIT_BEFORE_CLOSE, self.close)
			else:
				if self.logging:	
					print("\n-------------PEEP Server Termination Starts--------------------\n")
				asyncio.get_event_loop().call_later(self.TIME_OUT_LIMIE, self.clear_databuffer_and_send_RIP, self.sequenceNumber)
		# else:
		# 	self.lowerTransport.close()


	def write(self, data):
		#this will be the data from the upper layer
		size = int(len(data)/self.DATA_CHUNK_SIZE)
		if len(data)%self.DATA_CHUNK_SIZE != 0: size+=1
		if self.logging:
			print("\nPEEP Server Transport: data length is [%s], and divided into [%s] PEEP packets"%(len(data), size))

		for i in range(1, size+1):
			if self.logging:
				print("PEEP Server Transport: packing seq = [%s] PEEP packet..." % self.sequenceNumber)
			cur_Data_Chuck = (data[(i-1)*self.DATA_CHUNK_SIZE : i*self.DATA_CHUNK_SIZE])
			cur_PEEP_Packet = Util.create_outbound_packet(5, self.sequenceNumber, None, cur_Data_Chuck)
			self.sequenceNumber += len(cur_PEEP_Packet.Data)
			self.window_control(cur_PEEP_Packet)

	
	def clear_databuffer_and_send_RIP(self, seq):
		if self.pass_close == True:
			print("PEEP Server: Pass this phase")
			return
		if len(self.waitingList) != 1 or len(self.RetransmissionPacketList) != 1:
			if self.logging:	print("PEEP Server Transport: Cleaning data buffer now ......")
			self.clean_waitList()
			self.clean_RetransmissionPacketList()
			asyncio.get_event_loop().call_later(self.CLEAR_BUFFER_TIME_LIMIT, self.clear_databuffer_and_send_RIP, self.sequenceNumber) 
		else:
			cur_RIP_Packet = Util.create_outbound_packet(3, seq)
			if self.logging:
				print("\nPEEP Server Transport: ### Data Buffer is CLEAR ###")
				print("\nPEEP Server Transport: RIP sent: Seq = %d Checksum = (%d)"%(cur_RIP_Packet.SequenceNumber, cur_RIP_Packet.Checksum))
			self.lowerTransport().write(cur_RIP_Packet.__serialize__())
			self.RIP_SENT_FLAG = True
			self.receiving_Flag = False
			self.pass_close = True
			self.RIP_PKT = cur_RIP_Packet
			asyncio.get_event_loop().call_later(self.TIME_OUT_LIMIE, self.Timeout_checker, self.RIP_PKT)
			# self.lowerTransport.close()


	def Timeout_checker(self, RIP_packet):
		if self.RIP_ACK_RECV_FlAG == False:
			if self.logging:
				print("\nPEEP Client Side: Wait for RIP-ACK [* Time-out *]. RIP Retransmitted: Seq = %d Checksum =(%d)"%(RIP_packet.SequenceNumber, RIP_packet.Checksum))
			self.lowerTransport().write(RIP_packet.__serialize__())
			asyncio.get_event_loop().call_later(self.TIME_OUT_LIMIE, self.Timeout_checker, self.RIP_PKT)


	def clean_waitList(self):
		if len(self.waitingList) == 1: 
			if self.logging:
				print("\nPEEP Server Transport: # Wait List is CLEAR! #\n")
			return
		else:
			if self.processing_packet < self.WINDOWS_SIZE:
				self.process_a_waitList_packet()
			# asyncio.get_event_loop().call_later(self.CLEAR_BUFFER_TIME_LIMIT, self.clean_waitList)


	def clean_RetransmissionPacketList(self):
		if len(self.ackList) == 1:
			if self.logging:
				print("\nPEEP Server Transport: # Retransmission Packet List is CLEAR! #\n")
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
				print("PEEP Server Transport: Seq = [%s] PEEP Packets written!\n" % cur_PEEP_Packet.SequenceNumber)
			self.lowerTransport().write(cur_PEEP_Packet.__serialize__())
			asyncio.get_event_loop().call_later(self.Time(self.ackList.index(ackNumber)), self.retransmission_checker, ackNumber)
	

	def window_control(self, packet=None):
		if packet is not None:
			self.waitingList.append(packet)
		self.process_a_waitList_packet()


	def retransmission_checker(self,seq):
		if seq in self.RetransmissionPacketList:
			if self.logging:
				print("PEEP Server Transport: Packets ack = [%s] not received after TIMEOUT, Retransmission...." %seq)
			self.lowerTransport().write(self.RetransmissionPacketList[seq].__serialize__())
			asyncio.get_event_loop().call_later(self.Time(self.ackList.index(seq)), self.retransmission_checker, seq)


	def ack_received(self,ack):
		if self.receiving_Flag == False: 
			if self.logging: print("PEEP Client Transport: Ignore a received ACK = %d"% ack)
			return
		if self.logging:	print("PEEP Server Transport: ACK received, Ack = %d" % ack)
		if len(self.ackList) == 1:
			return
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
				print("PEEP Server Transport: ACK back <= ", self.maxAck)


	def ack_send_updater(self, new_ack):
		self.maxAck = max(new_ack, self.maxAck)
		self.ack_sendflag = True
		self.ack_send_check()
