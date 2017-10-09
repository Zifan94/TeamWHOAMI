from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT16, UINT8, STRING, BUFFER, BOOL
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory
from ..lab2_packets import *
from ..lab2_Util import *

DATA_CHUNK_SIZE = 10
class PEEPTransport(StackingTransport):
	logging = True
	PEEPPacketList = []
	sequenceNumber = 0

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

		CurrentPEEPPacketList = []
		for i in range(1, size+1):
			if self.logging:
				print("PEEP Transport: packing #%s PEEP packet..."%i)
			cur_Data_Chuck = (data[(i-1)*DATA_CHUNK_SIZE : i*DATA_CHUNK_SIZE])
			cur_PEEP_Packet = Util.create_outbound_packet(5, self.sequenceNumber, None, cur_Data_Chuck)
			self.sequenceNumber = self.sequenceNumber+len(cur_Data_Chuck)
			CurrentPEEPPacketList.append(cur_PEEP_Packet)
			self.PEEPPacketList.append(cur_PEEP_Packet)
		# #create PEEPPacket
		for pkt in CurrentPEEPPacketList:
			self.lowerTransport().write(pkt.__serialize__())

		if self.logging:
			print("PEEP Transport: [%s] PEEP Packets written!\n"%len(CurrentPEEPPacketList))

		

	def ack_received(self,ack):
		if self.logging:	print("PEEP Transport: ACK received, Ack = %d" % ack)


