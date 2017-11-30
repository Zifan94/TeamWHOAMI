from . import src
from . import lab3_test
from .CertFactory import *
import playground

from .src.lab3_protocol import *
from .lab2_protocol.src.lab2_protocol import *
from playground.network.common import StackingProtocolFactory

cf = StackingProtocolFactory(lambda: PEEPClientProtocol(logging = True), lambda: PLSClientProtocol())
sf = StackingProtocolFactory(lambda: PEEPServerProtocol(logging = True), lambda: PLSServerProtocol())

lab_connector = playground.Connector(protocolStack=(cf, sf))
playground.setConnector('lab3_protocol', lab_connector)
playground.setConnector('WHOAMI_lab3_protocol', lab_connector)
