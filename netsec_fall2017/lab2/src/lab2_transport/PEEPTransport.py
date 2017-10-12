from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT16, UINT8, STRING, BUFFER, BOOL
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from ..lab2_packets import *
from ..lab2_Util import *
import asyncio

DATA_CHUNK_SIZE = 10
class PEEPTransport(StackingTransport):
	# ACK_TIME_INTERVAL = 0.5
	WINDOWS_SIZE = 3
	processing_packet = 0
	TIME_OUT_LIMIE = 3
	logging = True
	RetransmissionPacketList = {0: ""}
	waitingList = [Util.create_outbound_packet(5)]
	ackList = [0]
	sequenceNumber = 0
	maxAck = 0
	ack_sendflag = False

	def close(self):
		cur_RIP_Packet = Util.create_outbound_packet(3, 0, 0) #TODO seq num and acknoledgement
		if self.logging:
			print("\n-------------PEEP Termination Starts--------------------\n")
			print("\nPEEP Transport: (THIS SHOULD ON CLIENT SIDE ONLY) RIP sent: Seq = %d, Ack = %d, Checksum = (%d)"%(cur_RIP_Packet.SequenceNumber,cur_RIP_Packet.Acknowledgement, cur_RIP_Packet.Checksum))
		self.lowerTransport().write(cur_RIP_Packet.__serialize__())

	def write(self, data):
		#this will be the data from the upper layer
		size = int(len(data)/DATA_CHUNK_SIZE)
		if len(data)%DATA_CHUNK_SIZE != 0: size+=1
		if self.logging:
			print("\nPEEP Transport: data length is [%s], and divided into [%s] PEEP packets"%(len(data), size))

		for i in range(1, size+1):
			if self.logging:
				print("PEEP Transport: packing seq = [%s] PEEP packet..." % self.sequenceNumber)
			cur_Data_Chuck = (data[(i-1)*DATA_CHUNK_SIZE : i*DATA_CHUNK_SIZE])
			cur_PEEP_Packet = Util.create_outbound_packet(5, self.sequenceNumber, None, cur_Data_Chuck)
			self.sequenceNumber += len(cur_PEEP_Packet.Data)
			self.window_control(cur_PEEP_Packet)

	def clean_databuffer(self):  # send the rest data buffer in the list
		print("TODO: we clear buffer over here")

	def window_control(self, packet=None):
		if packet is not None:
			self.waitingList.append(packet)
		if (self.processing_packet < self.WINDOWS_SIZE) & (len(self.waitingList) > 1):
			self.processing_packet += 1
			cur_PEEP_Packet = self.waitingList.pop(1)
			ackNumber = cur_PEEP_Packet.SequenceNumber + len(cur_PEEP_Packet.Data)
			self.RetransmissionPacketList.update({ackNumber: cur_PEEP_Packet})
			self.ackList.append(ackNumber)
			if self.logging:
				print("PEEP Transport: Seq = [%s] PEEP Packets written!\n" % cur_PEEP_Packet.SequenceNumber)
			self.lowerTransport().write(cur_PEEP_Packet.__serialize__())
			asyncio.get_event_loop().call_later(self.TIME_OUT_LIMIE, self.retransmission_checker, ackNumber)

	def retransmission_checker(self,seq):
		if seq in self.RetransmissionPacketList:
			if self.logging:
				print("PEEP Transport: Packets ack = [%s] not received after TIMEOUT, Retransmission...." %seq)
			self.lowerTransport().write(self.RetransmissionPacketList[seq].__serialize__())
			asyncio.get_event_loop().call_later(self.TIME_OUT_LIMIE, self.retransmission_checker, seq)

	def ack_received(self,ack):
		if self.logging:	print("PEEP Transport: ACK received, Ack = %d" % ack)
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
			if self.logging:
				print("PEEP Transport: ACK back <= ", self.maxAck)
			self.ack_sendflag = False
			self.lowerTransport().write(packetBytes)

	def ack_send_updater(self, new_ack):
		self.maxAck = new_ack
		self.ack_sendflag = True
		self.ack_send_check()


