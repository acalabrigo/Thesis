# l2_pairs base
# Copyright 2011-2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# mobility extensions
# Copyright 2017 Adam Calabrigo

from pox.core import core
from pox.lib.addresses import EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.recoco import Timer
from pox.lib.revent import Event, EventHalt
import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery as discovery
from pox.lib.revent.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time
import pox

log = core.getLogger()

DEFAULT_SIPS = ["192.168.1.1", "192.168.2.1"]

class NewHostEvent(Event):
    """
    Event when new host joins network.
    """
    def __init__(self, mobile_node):
        super(NewHostEvent, self).__init__()
        self.mobile_node = mobile_node

class MobileNode(object):
    """
    Holds information on mobile node for updating controller binding table
    """
    def __init__(self, identifier, locator):
        self.id = identifier
        self.loc = locator

    def __str__(self):
        return ' '.join([str(self.id), str(self.loc)])

class MobilitySwitch (EventMixin):
    """
    Layer 2 learning switch with mobility support
    """
    _eventMixin_events = set([NewHostEvent])

    def __init__ (self, connection, ip):
        # Switch we'll be adding mobility capabilities to
        self.connection = connection
        self.ip = ip
        self.macToPort = {}

        # listen to the connection
        connection.addListeners(self)

        # set up listener for host events
        listen_args={'server_mobility':{'priority':0}}
        core.listen_to_dependencies(self, listen_args=listen_args)

        # let us know the switch-ip relation
        log.info("Added switch: dpid {0} ip {1}".format(self.connection.dpid, self.ip))

    def _handle_server_mobility_HostEvent(self, event):
        log.info("HostEvent listened to {0}".format(str(event.entry)))

        # if the host event occurred on this switch
        if event.entry.dpid == self.connection.dpid:
            # if a host has joined
            if event.join is True:
                log.info("IP contents: {0}".format(event.entry.ipaddr))
                binding = (self.ip, event.entry.ipaddr) # bind switch IP --> host IP
                self.raiseEventNoErrors(NewHostEvent, None)
        else:
            pass

    def _handle_PacketIn (self, event):
        """
        Handle packet in messages
        """

        # get the packetZ
        packet = event.parsed
        self.macToPort[packet.src] = event.port # 1
        dst_port = self.macToPort.get(packet.dst, None)
        log.info("switch dpid: {0} port: {1}".format(self.connection.dpid,event.port))
        if dst_port is None:
            # flood the packet if not in MAC table
            msg = of.ofp_packet_out(data = event.ofp)
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            event.connection.send(msg)
        else:
            # install rules for both directions
            msg = of.ofp_flow_mod()
            msg.match.dl_dst = packet.src
            msg.match.dl_src = packet.dst
            msg.actions.append(of.ofp_action_output(port = event.port))
            event.connection.send(msg)

            # forward the incoming packet
            msg = of.ofp_flow_mod()
            msg.data = event.ofp
            msg.match.dl_src = packet.src
            msg.match.dl_dst = packet.dst
            msg.actions.append(of.ofp_action_output(port = dst_port))
            event.connection.send(msg)

            log.info("Installing %s <-> %s" % (packet.src, packet.dst))

class switch_mobility (object):
    """
    Waits for OpenFlow switches to connect and enables mobility on the
    switches.
    """
    def __init__ (self, sips):
        core.openflow.addListeners(self)
        self.sips = sips
        self.sip_index = 0

    def _handle_ConnectionUp (self, event):
        try:
            log.debug("Connection %s" % (event.connection,))
            MobilitySwitch(event.connection, self.sips[self.sip_index])
            self.sip_index += 1
        except:
            raise RuntimeError("Out of switch IPs")


def launch (sips=DEFAULT_SIPS):
    try:
        assert sips is not None
    except:
        raise RuntimeError("Invalid switch IPs")

    core.registerNew(switch_mobility, sips)
