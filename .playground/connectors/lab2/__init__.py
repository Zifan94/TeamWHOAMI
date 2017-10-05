import playground
from netsec_fall2017.lab2.src.lab2_protocol import *
from playground.network.common import StackingProtocolFactory

cf = StackingProtocolFactory(lambda: PassThroughProtocol1(), lambda: PEEPClientProtocol())
sf = StackingProtocolFactory(lambda: PassThroughProtocol1(), lambda: PEEPServerProtocol())

lab2_connector = playground.Connector(protocolStack=(cf, sf))
playground.setConnector('lab2_protocol', lab2_connector)
