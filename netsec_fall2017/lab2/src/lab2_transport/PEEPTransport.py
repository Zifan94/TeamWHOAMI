from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT16, UINT8, STRING, BUFFER, BOOL
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from ..lab2_packets import *
from ..lab2_Util import *

DATA_CHUNK_SIZE = 10
class PEEPTransport(StackingTransport):
	logging = True
	PEEPPacketList = []

	def write(self, data, logging=True):
		self.logging = logging
		#this will be the data from the upper layer
		size = int(len(data)/DATA_CHUNK_SIZE)
		if len(data)%DATA_CHUNK_SIZE != 0: size+=1
		if self.logging:
			print("\nPEEP Transport: data length is [%s], and divided into [%s] PEEP packets"%(len(data), size))

		CurrentPEEPPacketList = []
		for i in range(1, size+1):
			if self.logging:
				print("PEEP Transport: packing #%s PEEP packet..."%i)
			cur_Data_Chuck = (data[(i-1)*DATA_CHUNK_SIZE : i*DATA_CHUNK_SIZE])
			cur_PEEP_Packet = Util.create_outbound_packet(5, i, 1, cur_Data_Chuck) #TODO seq num and acknoledgement
			CurrentPEEPPacketList.append(cur_PEEP_Packet)
			self.PEEPPacketList.append(cur_PEEP_Packet)
		# #create PEEPPacket
		for pkt in CurrentPEEPPacketList:
			self.lowerTransport().write(pkt.__serialize__())

		if self.logging:
			print("PEEP Transport: [%s] PEEP Packets written!\n"%len(CurrentPEEPPacketList))

		

	def ack_received(self,ack,logging):
		if logging:	print("PEEP Transport: ACK received, Seq = %d" % ack)


