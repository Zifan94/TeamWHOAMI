from .PLSClientProtocol import PLSClientProtocol
from .PLSServerProtocol import PLSServerProtocol
from .PLSProtocol import PLSProtocol
from .Engine import *
from playground.network.common import StackingProtocolFactory
import playground

cf = StackingProtocolFactory(lambda: PLSClientProtocol())
sf = StackingProtocolFactory(lambda: PLSServerProtocol())

lab333_connector = playground.Connector(protocolStack=(cf, sf))
playground.setConnector('lab333_protocol', lab333_connector)
