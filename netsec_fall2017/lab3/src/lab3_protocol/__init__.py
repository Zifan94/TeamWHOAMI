from . import PLSClientProtocol
from . import PLSServerProtocol
from playground.network.common import StackingProtocolFactory
import playground

cf = StackingProtocolFactory(lambda: PLSClientProtocol())
sf = StackingProtocolFactory(lambda: PLSServerProtocol())

lab3_connector = playground.Connector(protocolStack=(cf, sf))
playground.setConnector('lab3_protocol', lab3_connector)
