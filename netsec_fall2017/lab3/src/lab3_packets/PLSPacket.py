from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT64, UINT32, UINT16, UINT8, STRING, BUFFER, BOOL, LIST
from playground.network.packet.fieldtypes.attributes import *


class PlsHello(PacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.hello"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Nonce", UINT64),
        ("Certs", LIST(BUFFER))
    ]

    @staticmethod
    def create(Nonce, Certs):
        newPacket = PlsHello()

        newPacket.Nonce = Nonce
        newPacket.Certs = Certs

        return newPacket


class PlsKeyExchange(PacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.keyexchange"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Pre_Key", BUFFER),
        ("NoncePlusOne", UINT64),
    ]

    @staticmethod
    def create(PreKey, NoncePlusOne):
        newPacket = PlsKeyExchange()

        newPacket.Pre_Key = PreKey
        newPacket.NoncePlusOne = NoncePlusOne

        return newPacket

class PlsHandshakeDone(PacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.handshakedone"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("ValidationHash", BUFFER)
    ]

    @staticmethod
    def create(ValidationHash):
        newPacket = PlsHandshakeDone()

        newPacket.ValidationHash = ValidationHash

        return newPacket

class PlsData(PacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.data"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Ciphertext", BUFFER),
        ("Mac", BUFFER)
    ]

    @staticmethod
    def create(Ciphertext, Mac):
        newPacket = PlsData()

        newPacket.Ciphertext = Ciphertext
        newPacket.Mac = Mac

        return newPacket

class PlsClose(PacketType):
    DEFINITION_IDENTIFIER = "netsecfall2017.pls.close"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("Error", STRING({Optional: True}))
    ]

    @staticmethod
    def create(Error):
        newPacket = PlsClose()

        newPacket.Error = Error

        return newPacket
