from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT16, UINT8, STRING, BUFFER, BOOL
from playground.network.packet.fieldtypes.attributes import *
from .VerificationCodeServerProtocol import VerificationCodeServerProtocol
from .VerificationCodeClientProtocol import VerificationCodeClientProtocol
from ..src.lab2_protocol import *
from ..src.lab2_packets import *
from ..src.lab2_Util import *
from playground.asyncio_lib.testing import TestLoopEx
from playground.network.testing import MockTransportToStorageStream as MockTransport
from playground.network.testing import MockTransportToProtocol

import asyncio


def basicUnitTestForUtil(loggingFlag):

	# test for create_outbound_packet()
	packet1 = Util.create_outbound_packet(1, 2, 3, b"data")
	assert packet1.Type == 1
	assert packet1.SequenceNumber == 2
	assert packet1.Acknowledgement == 3
	assert packet1.Data == b"data"
	if loggingFlag == True: print ("- test for Util.create_outbound_packet() SUCCESS")




def basicUnitTestForPEEPPacketPacket(loggingFlag):

	# test for PEEPPacket Serialize Deserialize
	packet1 = Util.create_outbound_packet(1, 1, 1, b"data")
	packet1Bytes = packet1.__serialize__()
	packet1_serialized_deserialized = PEEPPacket.Deserialize(packet1Bytes)
	assert packet1 == packet1_serialized_deserialized
	if loggingFlag == True: print ("- test for PEEPPacket Serialize Deserialize SUCCESS")


	# negative test for PEEPPacket Serialize Deserialize
	packet1 = Util.create_outbound_packet(1, 1, 1, b"data")
	packet1Bytes = packet1.__serialize__()
	packet1_serialized_deserialized = PEEPPacket.Deserialize(packet1Bytes)

	packet2 = Util.create_outbound_packet(1, 2, 1, b"datadata")
	packet2Bytes = packet2.__serialize__()
	packet2_serialized_deserialized = PEEPPacket.Deserialize(packet2Bytes)
	assert packet1_serialized_deserialized != packet2_serialized_deserialized
	if loggingFlag == True: print ("- negative test for PEEPPacket Serialize Deserialize SUCCESS")



	# test for PEEPPacket Optional fields
	packet1 = Util.create_outbound_packet(1, 2, 3)
	packet1Bytes = packet1.__serialize__()
	packet1_serialized_deserialized = PEEPPacket.Deserialize(packet1Bytes)
	assert packet1 == packet1_serialized_deserialized
	if loggingFlag == True: print ("- test for  PEEPPacket Optional fields SUCCESS")





def basicUnitTestForPEEPProtocol(loggingFlag):
	asyncio.set_event_loop(TestLoopEx())
	loop = asyncio.get_event_loop()

	server = PEEPServerProtocol(False)
	client = PEEPClientProtocol(False)

	client.set_timeout_flag(False)
	cTransport, sTransport = MockTransportToProtocol.CreateTransportPair(client, server)

	# test for general connection_made
	client.connection_made(cTransport)
	server.connection_made(sTransport)
	
	if loggingFlag == True: print("- test for general connection_made SUCCESS")
	if loggingFlag == True: print ("")


	# negative test for messing up packet order
	cTransport, sTransport = MockTransportToProtocol.CreateTransportPair(client, server)
	client.connection_made(cTransport)
	server.connection_made(sTransport)

	MockPEEPPacket_SYN = Util.create_outbound_packet(0, 1, 1, b"data")
	packetBytes = MockPEEPPacket_SYN.__serialize__()
	server.state = "SYN_State_1"
	client.state = "SYN_ACK_State_1"
	server.data_received(packetBytes)
	assert server.state == "error_state"
	if loggingFlag == True: print("- negative test for messing up packet order SUCCESS")
	if loggingFlag == True: print ("")

	# # test for client vericifation result (disabled for now because of stacking protocol)
	# cTransport, sTransport = MockTransportToProtocol.CreateTransportPair(client, server)
	# client.connection_made(cTransport)
	# server.connection_made(sTransport)

	# MockPEEPPacket_ACK = Util.create_outbound_packet(2, 1, 1, b"data")
	# packetBytes = MockPEEPPacket_ACK.__serialize__()
	# server.state = "SYN_State_1"
	# client.state = "Transmission_State_2"
	# server.data_received(packetBytes)
	# assert server.state == "Transmission_State_2"
	# assert client.state == "Transmission_State_2"
	# print("- test for client vericifation result SUCCESS")
	# print ("")


def basicUnitTestForAppLayerPacket(loggingFlag):
	
	# test for RequestPacket
	packet1 = RequestPacket()
	packet1.ID = 1
	packet1Bytes = packet1.__serialize__()
	packet1a = RequestPacket.Deserialize(packet1Bytes)
	assert packet1 == packet1a
	if loggingFlag == True: print ("- test for RequestPacket SUCCESS")

	# negative test for RequestPacket
	packet1 = RequestPacket()
	packet1.ID = 1
	packet1Bytes = packet1.__serialize__()
	assert packet1 != packet1Bytes
	if loggingFlag == True: print ("- negative test for RequestPacket SUCCESS")
	if loggingFlag == True: print ("")




	# test for VerificationCodePacket
	packet2 = VerificationCodePacket()
	packet2.ID = 1
	packet2.originalVerificationCode = 447755
	packet2Bytes = packet2.__serialize__()
	packet2a = VerificationCodePacket.Deserialize(packet2Bytes)
	assert packet2 == packet2a
	if loggingFlag == True: print ("- test for VerificationCodePacket SUCCESS")

	# negative test for VerificationCodePacket
	packet2 = VerificationCodePacket()
	packet2.ID = 1
	packet2.originalVerificationCode = 447755
	packet2Bytes = packet2.__serialize__()
	packet2a = VerificationCodePacket.Deserialize(packet2Bytes)
	packet2.originalVerificationCode = 447756
	assert packet2 != packet2a
	if loggingFlag == True: print ("- negative test for VerificationCodePacket SUCCESS")
	if loggingFlag == True: print ("")




	# test for VerifyPacket
	packet3 = VerifyPacket()
	packet3.ID = 1
	packet3.answer = 447755
	packet3Bytes = packet3.__serialize__()
	packet3a = VerifyPacket.Deserialize(packet3Bytes)
	assert packet3 == packet3a
	if loggingFlag == True: print ("- test for VerifyPacket SUCCESS")

	# negative test for VerifyPacket
	packet3 = VerifyPacket()
	packet3.ID = 1
	packet3.answer = 447755
	packet3Bytes = packet3.__serialize__()
	packet3a = VerifyPacket.Deserialize(packet3Bytes)
	packet3.answer = 447754
	assert packet3 != packet3a
	if loggingFlag == True: print ("- negative test for VerifyPacket SUCCESS")
	if loggingFlag == True: print ("")




	# test for ResultPacket
	packet4 = ResultPacket()
	packet4.ID = 1
	packet4.passfail = "pass"
	packet4Bytes = packet4.__serialize__()
	packet4a = ResultPacket.Deserialize(packet4Bytes)
	assert packet4 == packet4a
	if loggingFlag == True: print ("- test for ResultPacket SUCCESS")

	# negative test for ResultPacket
	packet4 = ResultPacket()
	packet4.ID = 1
	packet4.passfail = "pass"
	packet4Bytes = packet4.__serialize__()
	packet4a = ResultPacket.Deserialize(packet4Bytes)
	packet4.passfail = "fail"
	assert packet4 != packet4a
	if loggingFlag == True: print ("- negative test for ResultPacket SUCCESS")
	if loggingFlag == True: print ("")


	# test for HangUpPacket
	packet5 = HangUpPacket()
	packet5.ID = 1
	packet5.hangup = True
	packet5Bytes = packet5.__serialize__()
	packet5a = HangUpPacket.Deserialize(packet5Bytes)
	assert packet5 == packet5a
	if loggingFlag == True: print ("- test for HangUpPacket SUCCESS")

	# negative test for HangUpPacket
	packet5 = HangUpPacket()
	packet5.ID = 1
	packet5.hangup = True
	packet5Bytes = packet5.__serialize__()
	assert packet5 != packet1Bytes
	if loggingFlag == True: print ("- negative test for HangUpPacket SUCCESS")
	if loggingFlag == True: print ("")






	# test for Deserializer
	pktBytes = packet1.__serialize__() + packet2.__serialize__() + packet3.__serialize__() + packet4.__serialize__()
	deserializer = PacketType.Deserializer()
	deserializer.update(pktBytes)
	if loggingFlag == True: print("- Start deserializer process!")
	for packet in deserializer.nextPackets():
		if packet == packet1 : continue
		elif packet == packet2: continue
		elif packet == packet3: continue
		elif packet == packet4: continue
		else: assert 1 == 0
	if loggingFlag == True: print("- test for deserializer SUCCESS")


def basicUnitTestForAppLayerProtocol(loggingFlag):
	asyncio.set_event_loop(TestLoopEx())
	loop = asyncio.get_event_loop()

	server = VerificationCodeServerProtocol(loop, False)
	client = VerificationCodeClientProtocol(1, loop, False)
	cTransport, sTransport = MockTransportToProtocol.CreateTransportPair(client, server)

	# test for general connection_made 
	client.connection_made(cTransport)
	server.connection_made(sTransport)
	if loggingFlag == True: print("- test for general connection_made SUCCESS")
	if loggingFlag == True: print ("")
	
	# test for client verification code length 
	cTransport, sTransport = MockTransportToProtocol.CreateTransportPair(client, server)
	client.connection_made(cTransport)
	server.connection_made(sTransport)

	MockRequestPacket = RequestPacket()
	MockRequestPacket.ID = 1
	packetBytes = MockRequestPacket.__serialize__()
	server.data_received(packetBytes)
	assert len(str(server._verificationCode)) == 6
	if loggingFlag == True: print("- test for client verification code length SUCCESS")
	if loggingFlag == True: print ("")

	# negative test for messing up packet order 
	cTransport, sTransport = MockTransportToProtocol.CreateTransportPair(client, server)
	client.connection_made(cTransport)
	server.connection_made(sTransport)

	MockVerifyPacket = VerifyPacket()
	MockVerifyPacket.ID = 1
	MockVerifyPacket.answer = server._verificationCode
	packetBytes = MockVerifyPacket.__serialize__()
	server.state = "wait_for_verify_packet"
	client.state = "initial_state"
	server.data_received(packetBytes)
	assert client.state == "error_state"
	if loggingFlag == True: print("- negative test for messing up packet order SUCCESS")
	if loggingFlag == True: print ("")

	# test for client vericifation result 
	cTransport, sTransport = MockTransportToProtocol.CreateTransportPair(client, server)
	client.connection_made(cTransport)
	server.connection_made(sTransport)

	MockVerifyPacket = VerifyPacket()
	MockVerifyPacket.ID = 1
	MockVerifyPacket.answer = server._verificationCode
	packetBytes = MockVerifyPacket.__serialize__()
	server.state = "wait_for_verify_packet"
	client.state = "wait_for_result_packet"
	server.data_received(packetBytes)
	assert server._result == "pass"
	if loggingFlag == True: print("- test for client vericifation result SUCCESS")
	if loggingFlag == True: print ("")

	# negative test for client vericifation result
	cTransport, sTransport = MockTransportToProtocol.CreateTransportPair(client, server)
	client.connection_made(cTransport)
	server.connection_made(sTransport)

	MockVerifyPacket = VerifyPacket()
	MockVerifyPacket.ID = 1
	MockVerifyPacket.answer = 0
	packetBytes = MockVerifyPacket.__serialize__()
	server.state = "wait_for_verify_packet"
	client.state = "wait_for_result_packet"
	server.data_received(packetBytes)
	assert server._result == "fail"
	if loggingFlag == True: print("- negative test for client vericifation result SUCCESS")
	if loggingFlag == True: print ("")




if __name__ =="__main__":

	# Each function herer contains a lot of sub-unit-test, and we won't show the result of sub-unit-test here 
	# because there are too many loggings, so we pass in a False parameter into each function below. If Unit Test
	# Failed, you can see the logging and find which function is failed and then pass True into that function instead
	# of False to see all the result of sub-unit-tests of that function. In this way, you can locate the Unit Test failure
	# more efficiently instead of find in a bunch of logging sentences.
	
	print ("=======================================")
	print ("### START BASIC UNIT TEST FOR Util###")
	print ("")
	basicUnitTestForUtil(False) #Set the parameter into True to print the detail result inside this UnitTest
	print("")
	print("")
	print("### ALL UTIL UNIT TEST SUCCESS! ###")
	print("=====================================")

	print ("=======================================")
	print ("### START BASIC UNIT TEST FOR PEEP_Packet PACKET###")
	print ("")
	basicUnitTestForPEEPPacketPacket(False)
	print("")
	print("")
	print("### ALL PEEP_Packet PACKET UNIT TEST SUCCESS! ###")
	print("=====================================")

	print ("==========================================")
	print ("### START BASIC UNIT TEST FOR PEEP_PROTOCOL ###")
	print ("")
	basicUnitTestForPEEPProtocol(False)
	print("")
	print("")
	print("### ALL PEEP_PROTOCOL UNIT TEST SUCCESS! ###")
	print("=======================================")


	print ("==========================================")
	print ("### START BASIC UNIT TEST FOR AppLayer_Packet ###")
	print ("")
	basicUnitTestForAppLayerPacket(False)
	print("")
	print("")
	print("### ALL AppLayer_Packet UNIT TEST SUCCESS! ###")
	print("=======================================")


	print ("==========================================")
	print ("### START BASIC UNIT TEST FOR AppLayer_PROTOCOL ###")
	print ("")
	basicUnitTestForAppLayerProtocol(False)
	print("")
	print("")
	print("### ALL AppLayer_PROTOCOL UNIT TEST SUCCESS! ###")
	print("=======================================")


	print()
	print()
	print()
	print()
	print("*******************************")
	print("*      All Unit Tests         *")
	print("*                             *")
	print("*   ****    *    ****  ****   *")
	print("*   *  *   * *   *     *      *")
	print("*   *  *  *   *  *     *      *")
	print("*   ****  *****  ****  ****   *")
	print("*   *     *   *     *     *   *")
	print("*   *     *   *     *     *   *")
	print("*   *     *   *  ****  ****   *")
	print("*                             *")
	print("*******************************")
	print()
