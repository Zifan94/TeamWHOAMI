from .PassThroughProtocol import PassThroughProtocol1
from .PEEPClientProtocol import PEEPClientProtocol
from .PEEPServerProtocol import PEEPServerProtocol
from playground.network.common import StackingProtocolFactory
import playground


cf = StackingProtocolFactory(lambda: PassThroughProtocol1(), lambda: PEEPClientProtocol())
sf = StackingProtocolFactory(lambda: PassThroughProtocol1(), lambda: PEEPServerProtocol())

lab2_connector = playground.Connector(protocolStack=(cf, sf))
playground.setConnector('lab2_protocol', lab2_connector)
