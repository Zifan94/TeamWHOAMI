from . import PLSClientProtocol
from . import PLSServerProtocol
from . import PLSProtocol
from . import CertFactory
from playground.network.common import StackingProtocolFactory
import playground

cf = StackingProtocolFactory(lambda: PLSClientProtocol())
sf = StackingProtocolFactory(lambda: PLSServerProtocol())

lab333_connector = playground.Connector(protocolStack=(cf, sf))
playground.setConnector('lab333_protocol', lab333_connector)
