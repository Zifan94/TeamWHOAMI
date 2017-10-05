# import sys
# sys.path.append('~/NETWORK/netsec_fall2017/lab2')
# print(sys.path)
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER, BOOL
from ..src.lab2_packets import *
from playground.network.common import StackingProtocol, StackingTransport, StackingProtocolFactory

import playground

import random

import asyncio

class VerificationCodeServerProtocol(asyncio.Protocol):
	state = "wait_for_request_packet"
	def __init__(self, loop, logging=True):
		if logging:
			print("App_Layer Server Side: Init Compelete...")
		self.loop = loop
		self._deserializer = PacketType.Deserializer()
		self.transport = None
		self.state = "wait_for_request_packet"
		self._result = "null"
		self._verificationCode = 1
		self.logging = logging

	def connection_made(self, transport):
		if self.logging:
			print("App_Layer Server Side: Connection Made...")
		self.transport = transport

	def connection_lost(self, exc=None):
		self.transport = None
		if self.logging:
			print("App_Layer Server Side: Connection Lost...")
		self.loop.stop()

	def data_received(self, data):
		self._deserializer.update(data)
		for packet in self._deserializer.nextPackets():
			if self.transport == None:
				#self.loop.stop()
				continue
			# if self.state == "error_state":
			# 	# self.transport.close() #using pass through ptl to close
			# 	self.transport = None
			if isinstance(packet, RequestPacket):
				#print("Server: %s"%self.state)
				if self.state != "wait_for_request_packet":
					if self.logging:
						print("App_Layer Server Side: Error: State Error! Expecting wait_for_request_packet but getting %s"%self.state)
					self.state = "error_state"
					#self.loop.stop()
				else:
					outBoundPacket = VerificationCodePacket()
					outBoundPacket.ID = packet.ID
					self._verificationCode = random.randint(100000, 999999)
					outBoundPacket.originalVerificationCode = self._verificationCode
					if self.logging:
						print("App_Layer Server Side: Sending Verification Code is: %d..."%outBoundPacket.originalVerificationCode)
					packetBytes = outBoundPacket.__serialize__()
					self.state = "wait_for_verify_packet"
					self.transport.write(packetBytes)
			elif isinstance(packet, VerifyPacket):
				#print("Server: %s"%self.state)
				if self.state != "wait_for_verify_packet":
					if self.logging:
						print("App_Layer Server Side: Error: State Error! Expecting wait_for_verify_packet but getting %s"%self.state)
					self.state = "error_state"
					#self.loop.stop()
				else:
					outBoundPacket = ResultPacket()
					outBoundPacket.ID = packet.ID
					if packet.answer == self._verificationCode:
						outBoundPacket.passfail = "pass"
						self._result = "pass"
					else:
						outBoundPacket.passfail = "fail"
						self._result = "fail"
					packetBytes = outBoundPacket.__serialize__()
					self.state = "wait_for_hangup_packet"
					self.transport.write(packetBytes)
					if self.logging:
						print("App_Layer Server Side: The Verification Result is:")
						if outBoundPacket.passfail == 'pass':
							print("")
							print(" ****    *    ****  ****   ")
							print(" *  *   * *   *     *      ")
							print(" *  *  *   *  *     *      ")
							print(" ****  *****  ****  ****   ")
							print(" *     *   *     *     *   ")
							print(" *     *   *     *     *   ")
							print(" *     *   *  ****  ****   ")
							print("")
						elif outBoundPacket.passfail == 'fail':
							print("")
							print(" ****    *    ****  *      ")
							print(" *      * *    *    *      ")
							print(" *     *   *   *    *      ")
							print(" ****  *****   *    *      ")
							print(" *     *   *   *    *      ")
							print(" *     *   *   *    *      ")
							print(" *     *   *  ****  ****   ")
							print("")
						else:
							print("Undefine!")
			elif isinstance(packet, HangUpPacket):
				#print("Server: %s"%self.state)
				if self.state != "wait_for_hangup_packet":
					if __name__ =="__main__":
						print("App_Layer Server Side: Error: State Error! Expecting wait_for_hangup_packet but getting %s"%self.state)
					self.state = "error_state"
					#self.loop.stop()
				else:
					if self.logging:
						print("App_Layer Server Side: Hang up signal received, preparing to close!")
					self.state = "close_state"
			else:
				#print("Server: %s"%self.state)
				if self.logging:
					print("App_Layer Server Side: Error: Unexpected data received!")
				self.state = "error_state"
			if self.transport == None:
				#self.loop.stop()
				continue
			# if self.state == "error_state" or self.state == "close_state":
			# 	# self.transport.close() #using pass through ptl to close
			# 	self.transport = None




if __name__ =="__main__":
	
	loop = asyncio.get_event_loop()
	loop.set_debug(enabled = True)

	print("----- NEW CONNECTOR SETUP on Serve Side-----")

	coro = playground.getConnector('lab2_protocol').create_playground_server(lambda: VerificationCodeServerProtocol(loop), 101)

	server = loop.run_until_complete(coro)
	try:
		loop.run_forever()
	except KeyboardInterrupt:
		pass

	loop.close()
