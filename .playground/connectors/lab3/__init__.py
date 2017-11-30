# from PEEPClientProtocol import *
# from PEEPServerProtocol import *

# from PLSClientProtocol import *
# from PLSServerProtocol import *

from netsec_fall2017.lab3_protocol.src.lab3_protocol import *
from netsec_fall2017.lab2_protocol.src.lab2_protocol import *


from playground.network.common import StackingProtocolFactory
import playground

# you can turn off the logging of PEEP layer here for a clean logging
cf = StackingProtocolFactory(lambda: PLSClientProtocol(), lambda: PEEPClientProtocol(logging = False))
sf = StackingProtocolFactory(lambda: PLSServerProtocol(), lambda: PEEPServerProtocol(logging = False))

# cf = StackingProtocolFactory(lambda: PLSClientProtocol(), lambda: PEEPClientProtocol())
# sf = StackingProtocolFactory(lambda: PLSServerProtocol(), lambda: PEEPServerProtocol())

lab3_connector = playground.Connector(protocolStack=(cf, sf))
playground.setConnector('lab3_protocol', lab3_connector)
