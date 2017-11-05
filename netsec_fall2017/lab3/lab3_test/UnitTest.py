from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT64, UINT32, UINT16, UINT8, STRING, BUFFER, BOOL, LIST
from playground.network.packet.fieldtypes.attributes import *
# from ..src.lab3_protocol import *
from ..src.lab3_packets import *
from playground.asyncio_lib.testing import TestLoopEx
from playground.network.testing import MockTransportToStorageStream as MockTransport
from playground.network.testing import MockTransportToProtocol

import asyncio
import random
import base64
import playground


def basicUnitTestForUtil(loggingFlag):

	# test for create_PlsHello
	nonceC = random.randint(1, 2 ^ 64)
	certs = []
	certs.append(b"certsss")
	packet1 = PlsHello.create(nonceC, certs)
	assert packet1.Nonce == nonceC
	assert packet1.Certs == certs
	if loggingFlag == True: print ("- test for PlsHello.create SUCCESS")

	# test for PlsKeyExchange
	packet1 = PlsKeyExchange.create(b"prekey", 11)
	assert packet1.Pre_Key == b"prekey"
	assert packet1.NoncePlusOne == 11
	if loggingFlag == True: print ("- test for PlsKeyExchange.create SUCCESS")

	# test for PlsHandshakeDone
	packet1 = PlsHandshakeDone.create(b"daraadefazxc")
	assert packet1.ValidationHash == b"daraadefazxc"
	if loggingFlag == True: print ("- test for PlsHandshakeDone.create SUCCESS")

	# test for PlsData
	packet1 = PlsData.create(b"daragfsdhadefazxc", b"daaraeda")
	assert packet1.Ciphertext == b"daragfsdhadefazxc"
	assert packet1.Mac == b"daaraeda"
	if loggingFlag == True: print ("- test for PlsData.create SUCCESS")

	# test for PlsClose
	packet1 = PlsClose.create("error reason is ...")
	assert packet1.Error == "error reason is ..."
	if loggingFlag == True: print ("- test for PlsClose.create SUCCESS")




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
