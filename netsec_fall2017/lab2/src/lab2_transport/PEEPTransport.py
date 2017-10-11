from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT16, UINT8, STRING, BUFFER, BOOL
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from ..lab2_packets import *
from ..lab2_Util import *
import asyncio
import threading
import time

DATA_CHUNK_SIZE = 10
class PEEPTransport(StackingTransport):
	ACK_TIME_INTERVAL = 0.5
	TIME_OUT_LIMIE = 3
	logging = True
	RetransmissionPacketList = {0: ""}
	ackList = [0]
	sequenceNumber = 0
	maxAck = 0
	ack_sendflag = False

	def write(self, data):
		if data == "app_layer_rip_signal":
			cur_RIP_Packet = Util.create_outbound_packet(3, 0, 0) #TODO seq num and acknoledgement
			if self.logging:
				print("\nPEEP Transport: (THIS SHOULD ON CLIENT SIDE ONLY) RIP sent: Seq = %d, Ack = %d, Checksum = (%d)"%(cur_RIP_Packet.SequenceNumber,cur_RIP_Packet.Acknowledgement, cur_RIP_Packet.Checksum))
			self.lowerTransport().write(cur_RIP_Packet.__serialize__())
			return
		#this will be the data from the upper layer
		size = int(len(data)/DATA_CHUNK_SIZE)
		if len(data)%DATA_CHUNK_SIZE != 0: size+=1
		if self.logging:
			print("\nPEEP Transport: data length is [%s], and divided into [%s] PEEP packets"%(len(data), size))

		for i in range(1, size+1):
			if self.logging:
				print("PEEP Transport: packing #%s PEEP packet..."%i)
			cur_Data_Chuck = (data[(i-1)*DATA_CHUNK_SIZE : i*DATA_CHUNK_SIZE])
			cur_PEEP_Packet = Util.create_outbound_packet(5, self.sequenceNumber, None, cur_Data_Chuck)
			self.sequenceNumber = self.sequenceNumber + len(cur_Data_Chuck)
			self.RetransmissionPacketList.update({self.sequenceNumber: cur_PEEP_Packet})
			self.ackList.append(self.sequenceNumber)
			# TODO Windows Control
			self.lowerTransport().write(cur_PEEP_Packet.__serialize__())
			##############TIME_OUT CHECK################
			asyncio.get_event_loop().call_later(self.TIME_OUT_LIMIE, self.retransmission_checker, self.sequenceNumber)
		if self.logging:
			print("PEEP Transport: [%s] PEEP Packets written!\n"%size)

	def clean_databuffer(self):  # send the rest data buffer in the list
		print()

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
		if self.ackList[1] == ack:
			del self.RetransmissionPacketList[self.ackList[1]]
			del self.ackList[1]

	def ack_send_autocheck(self):
		if self.ack_sendflag:
			#### we need to return ACK when received a packet ###
			outBoundPacket = Util.create_outbound_packet(2, None, self.maxAck)
			packetBytes = outBoundPacket.__serialize__()
			if self.logging:
				print("PEEP Transport: ACK back <= ", self.maxAck)
			self.ack_sendflag = False
			self.lowerTransport().write(packetBytes)
			#####################################################11

		asyncio.get_event_loop().call_later(self.ACK_TIME_INTERVAL, self.ack_send_autocheck)

	def ack_send_updater(self, new_ack):
		self.maxAck = new_ack
		self.ack_sendflag = True



