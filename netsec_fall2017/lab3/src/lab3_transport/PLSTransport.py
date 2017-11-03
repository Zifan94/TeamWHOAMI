from playground.network.common import StackingTransport


class PLSTransport(StackingTransport):
    def __init__(self, transport, protocol=None):
        super().__init__(transport)
        self.protocol = protocol

    def write(self, data):
        super().write(self.protocol.encrypt(data))
