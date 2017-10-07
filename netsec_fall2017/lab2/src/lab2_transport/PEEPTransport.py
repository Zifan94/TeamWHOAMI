from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT16, UINT8, STRING, BUFFER, BOOL
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from ..lab2_packets import *
from ..lab2_Util import *

DATA_CHUNK_SIZE = 10
class PEEPTransport(StackingTransport):
	logging = True

	def write(self, data, logging=True):
		self.logging = logging
		#this will be the data from the upper layer
		size = int(len(data)/DATA_CHUNK_SIZE)
		if len(data)%DATA_CHUNK_SIZE != 0: size+=1
		if self.logging:
			print("\nPEEP Transport: data length is [%s], and divided into [%s] PEEP packets"%(len(data), size))

		PEEPPacketList = []
		for i in range(1, size+1):
			if self.logging:
				print("PEEP Transport: packing #%s PEEP packet..."%i)
			cur_Data_Chuck = (data[(i-1)*DATA_CHUNK_SIZE : i*DATA_CHUNK_SIZE])
			cur_PEEP_Packet = Util.create_outbound_packet(5, i, 1, cur_Data_Chuck) #TODO seq num and acknoledgement
			PEEPPacketList.append(cur_PEEP_Packet)
		# #create PEEPPacket
		for pkt in PEEPPacketList:
			self.lowerTransport().write(pkt.__serialize__())

		if self.logging:
			print("PEEP Transport: [%s] PEEP Packets written!\n"%len(PEEPPacketList))

		# Currently, we write an additional data PEEP Packet with empty Data file as the "END FLAG"!
		# TODO: Will change after we get more infomation on Piazza
		End_Flag_PEEP_Packet = Util.create_outbound_packet(5, 0, 1, b"")
		self.lowerTransport().write(End_Flag_PEEP_Packet.__serialize__())