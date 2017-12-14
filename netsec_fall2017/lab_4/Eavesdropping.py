from playground.network.packet import PacketType
import playground
import asyncio



class demuxer(asyncio.Protocol):

	logging = True

	def connectionMade(self):
		pass

	def demux(self, src, srcPort, dst, dstPort, demuxData):
		if logging:	
			print("src: %s, srcPort : %s"%(src,srcPort))
			print("dst: %s, dstPort : %s"%(dst,dstPort))
		deserializer = PacketType.Deserializer()
		deserializer.update(demuxData)
		for packet in deserializer.nextPackets():
			print(packet)

		print("")








if __name__ == '__main__':

	switchAddress = "192.168.200.240"
	switchPort = "9090"

	# switchAddress = "127.0.0.1"
	# switchPort = "43731"

	print("## Starting eavesdropping ##")
	print("## Switch Address: %s ##"%switchAddress)
	print("## Switch Port: %s ##"%switchPort)

	myDemuxer = demuxer()

	loop = asyncio.get_event_loop()

	eavesdrop = playground.network.protocols.switching.PlaygroundSwitchTxProtocol(myDemuxer, "20174.*.*.*")

	coro = asyncio.get_event_loop().create_connection(lambda: eavesdrop, switchAddress, switchPort)
	loop.run_until_complete(coro)
	loop.run_forever()