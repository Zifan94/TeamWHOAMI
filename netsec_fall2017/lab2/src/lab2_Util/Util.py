from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT16, UINT8, STRING, BUFFER, BOOL
from ..lab2_packets import *


class Util():

    @staticmethod
    def create_outbound_packet(Type, seqNum=None, ackNum=None, data=None):
        outBoundPacket = PEEPPacket()
        outBoundPacket.Type = Type
        if seqNum != None:
            outBoundPacket.SequenceNumber = seqNum
        if ackNum != None:
            outBoundPacket.Acknowledgement = ackNum
        if data != None:
            outBoundPacket.Data = data
        outBoundPacket.Checksum = 0
        outBoundPacket.updateChecksum()

        return outBoundPacket
