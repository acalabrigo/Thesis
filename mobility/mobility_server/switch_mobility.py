# l2_learning base
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

_flood_delay = 0
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

    def __init__ (self, connection, transparent, ip):
        # Switch we'll be adding mobility capabilities to
        self.connection = connection
        self.transparent = transparent
        self.ip = ip

        # Our table
        self.macToPort = {}

        # We want to hear PacketIn messages, so we listen
        # to the connection
        connection.addListeners(self)
        self.hold_down_expired = _flood_delay == 0

        # set up listener for host events
        listen_args={'server_mobility':{'priority':0}}
        core.listen_to_dependencies(self, listen_args=listen_args)

        log.info("Added switch: dpid {0} ip {1}".format(self.connection.dpid, self.ip))
        
    def _handle_server_mobility_HostEvent(self, event):
        log.info("HostEvent listened to {0}".format(str(event.entry)))

        # if the host event occurred on this switch
        if event.entry.dpid == self.connection.dpid:
            # if a host has joined
            if event.join is True:
                log.info("IP contents: {0}".format(event.entry.ipAddrs))
                #binding = # need to bind host IP to switch port ID HERE
                self.raiseEventNoErrors(NewHostEvent, None)
        else:
            pass

    def _handle_PacketIn (self, event):
        """
        Handle packet in messages from the switch to implement above algorithm.
        """

        packet = event.parsed

        def flood (message = None):
            """ Floods the packet """
            msg = of.ofp_packet_out()
            if time.time() - self.connection.connect_time >= _flood_delay:
            # Only flood if we've been connected for a little while...

                if self.hold_down_expired is False:
                    # Oh yes it is!
                    self.hold_down_expired = True
                    log.info("%s: Flood hold-down expired -- flooding",
                        dpid_to_str(event.dpid))

                if message is not None: log.debug(message)
                #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
                # OFPP_FLOOD is optional; on some switches you may need to change
                # this to OFPP_ALL.
                msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            else:
                pass
                #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
            msg.data = event.ofp
            msg.in_port = event.port
            self.connection.send(msg)

        def drop (duration = None):
            """
            Drops this packet and optionally installs a flow to continue
            dropping similar ones for a while
            """
            if duration is not None:
                if not isinstance(duration, tuple):
                    duration = (duration,duration)
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet)
                msg.idle_timeout = duration[0]
                msg.hard_timeout = duration[1]
                msg.buffer_id = event.ofp.buffer_id
                self.connection.send(msg)
            elif event.ofp.buffer_id is not None:
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                msg.in_port = event.port
                self.connection.send(msg)

        self.macToPort[packet.src] = event.port # 1

        if not self.transparent: # 2
            if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
                drop() # 2a
                return

        if packet.dst.is_multicast:
            flood() # 3a
        else:
            if packet.dst not in self.macToPort: # 4
                flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
            else:
                port = self.macToPort[packet.dst]
                if port == event.port: # 5
                    # 5a
                    log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
                    % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
                    drop(10)
                    return
                # 6
                log.debug("installing flow for %s.%i -> %s.%i" %
                          (packet.src, event.port, packet.dst, port))
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet, event.port)
                msg.idle_timeout = 10
                msg.hard_timeout = 30
                msg.actions.append(of.ofp_action_output(port = port))
                msg.data = event.ofp # 6a
                self.connection.send(msg)


class switch_mobility (object):
    """
    Waits for OpenFlow switches to connect and enables mobility on the
    switches.
    """
    def __init__ (self, transparent, sips):
        core.openflow.addListeners(self)
        self.transparent = transparent
        self.sips = sips
        self.sip_index = 0

    def _handle_ConnectionUp (self, event):
        try:
            log.debug("Connection %s" % (event.connection,))
            MobilitySwitch(event.connection, self.transparent,
                self.sips[self.sip_index])
            self.sip_index += 1
        except:
            raise RuntimeError("Out of switch IPs")


def launch (transparent=False, sips=DEFAULT_SIPS, hold_down=_flood_delay):
    try:
        global _flood_delay
        _flood_delay = int(str(hold_down), 10)
        assert _flood_delay >= 0
    except:
        raise RuntimeError("Expected hold-down to be a number")

    try:
        assert sips is not None
    except:
        raise RuntimeError("Invalid switch IPs")

    core.registerNew(switch_mobility, str_to_bool(transparent), sips)
