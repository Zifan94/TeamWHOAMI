from . import src
import playground

from .src.lab2_protocol import *
from playground.network.common import StackingProtocolFactory

cf = StackingProtocolFactory(lambda: PEEPClientProtocol())
sf = StackingProtocolFactory(lambda: PEEPServerProtocol())

lab_connector = playground.Connector(protocolStack=(cf, sf))
playground.setConnector('lab2_protocol', lab_connector)