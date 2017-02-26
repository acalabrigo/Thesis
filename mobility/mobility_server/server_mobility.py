# Copyright 2011 Dorgival Guedes
# Copyright 2013 James McCauley
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
import time
import pox

log = core.getLogger()

# Times (in seconds) to use for differente timouts:
timeoutSec = dict(
  arpAware=60*2,   # Quiet ARP-responding entries are pinged after this
  arpSilent=60*20, # This is for uiet entries not known to answer ARP
  arpReply=4,      # Time to wait for an ARP reply before retrial
  timerInterval=5, # Seconds between timer routine activations
  entryMove=60     # Minimum expected time to move a physical entry
  )

# Address to send ARP pings from.
# The particular one here is just an arbitrary locally administered address.
DEFAULT_ARP_PING_SRC_MAC = '02:00:00:00:be:ef'


class HostEvent (Event):
    """
    Event when hosts join, leave, or move within the network
    """
    def __init__ (self, entry, new_dpid = None, new_port = None, join = False,
        leave = False, move = False):
        """
        @param entry
        @param new_dpid
        @param new_port
        @param join
        @param leave
        @param move
        """
        super(HostEvent,self).__init__()
        self.entry = entry
        self.join = join
        self.leave = leave
        self.move = move

        assert sum(1 for x in [join,leave,move] if x) == 1

        # You can alter these and they'll change where we think it goes...
        self._new_dpid = new_dpid
        self._new_port = new_port

        #TODO: Allow us to cancel add/removes

    @property
    def new_dpid (self):
        """
        New DPID for move events"
        """
        assert self.move
        return self._new_dpid

    @property
    def new_port (self):
        """
        New port for move events"
        """
        assert self.move
        return self._new_port

class MacEntry (object):
    """
    Not strictly an ARP entry.
    When it gets moved to Topology, may include other host info, like
    services, and it may replace dpid by a general switch object reference
    We use the port to determine which port to forward traffic out of.
    """
    def __init__ (self, dpid, port, macaddr, ipaddr):
        super(MacEntry,self).__init__()
        self.dpid = dpid
        self.port = port
        self.macaddr = macaddr
        self.ipaddr = ipaddr

    def __str__(self):
        return ' '.join([str(self.dpid), str(self.port), str(self.macaddr)])

    def __eq__ (self, other):
        if other is None:
            return False
        elif type(other) == tuple:
            return (self.dpid,self.port,self.macaddr)==other

        if self.dpid != other.dpid: return False
        if self.port != other.port: return False
        if self.macaddr != other.macaddr: return False
        if self.dpid != other.dpid: return False
        # What about ipAddrs??
        return True

    def __ne__ (self, other):
        return not self.__eq__(other)


class server_mobility (EventMixin):
    """
    Host tracking component
    """
    _eventMixin_events = set([HostEvent])   # events this class raises

    def __init__ (self):
        # The following tables should go to Topology later
        self.entryByMAC = {}

    def _all_dependencies_met (self):
        log.info("server_mobility ready")

    # The following two functions should go to Topology also
    def getMacEntry (self, macaddr):
        try:
            result = self.entryByMAC[macaddr]
        except KeyError as e:
            result = None
        return result

    def _handle_openflow_PacketIn (self, event):
        """
        Populate MAC and IP tables based on incoming packets.

        Handles only packets from ports identified as not switch-only.
        If a MAC was not seen before, insert it in the MAC table;
        otherwise, update table and enry.
        If packet has a source IP, update that info for the macEntry (may require
        removing the info from antoher entry previously with that IP address).
        It does not forward any packets, just extract info from them.
        """
        dpid = event.connection.dpid
        inport = event.port
        packet = event.parsed
        if not packet.parsed:
            log.warning("%i %i ignoring unparsed packet", dpid, inport)
            return

        if packet.type == ethernet.LLDP_TYPE: # Ignore LLDP packets
            return

        if not core.openflow_discovery.is_edge_port(dpid, inport):
            # No host should be right behind a switch-only port
            log.debug("%i %i ignoring packetIn at switch-only port", dpid, inport)
            return

        log.debug("PacketIn: %i %i ETH %s => %s",
            dpid, inport, str(packet.src), str(packet.dst))

        # Learn or update dpid/port/MAC info
        macEntry = self.getMacEntry(packet.src)
        if macEntry is None:
            # there is no known host by that MAC
            # should we raise a NewHostFound event (at the end)?
            log.info(packet.type)
            macEntry = MacEntry(dpid, inport, packet.src)
            self.entryByMAC[packet.src] = macEntry
            log.info("Learned %s", str(macEntry))
            self.raiseEventNoErrors(HostEvent, macEntry, join=True)
        elif macEntry != (dpid, inport, packet.src):
            # there is already an entry of host with that MAC, but host has moved
            # should we raise a HostMoved event (at the end)?
            log.info("Learned %s moved to %i %i", str(macEntry), dpid, inport)

            # should we create a whole new entry, or keep the previous host info?
            # for now, we keep it: IP info, answers pings, etc.
            e = HostEvent(macEntry, move=True, new_dpid = dpid, new_port = inport)
            self.raiseEventNoErrors(e)
            macEntry.dpid = e._new_dpid
            macEntry.inport = e._new_port

def launch ():
    core.registerNew(server_mobility)
