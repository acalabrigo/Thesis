# Dynamic network represented as an undirected graph of switches and hosts.
# Based on gephi_topo
#
# 2017 Adam Calabrigo

# POX
from pox.core import core
from pox.lib.recoco import Timer
from pox.lib.revent import Event, EventHalt, EventMixin
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr
from pox.lib.util import str_to_bool

# networkX
import networkx as nx

from collections import namedtuple
import time

log = core.getLogger()

# Times (in seconds) to use for differente timouts:
timeoutSec = dict(
  arpAware=30,   # Quiet ARP-responding entries are pinged after this
  arpSilent=60*20, # This is for quiet entries not known to answer ARP
  arpReply=4,      # Time to wait for an ARP reply before retrial
  timerInterval=5, # Seconds between timer routine activations
  entryMove=1     # Minimum expected time to move a physical entry
  )

# Address to send ARP pings from.
# The particular one here is just an arbitrary locally administered address.
DEFAULT_ARP_PING_SRC_MAC = '02:00:00:00:be:ef'
New = namedtuple('New', 'dpid port')

# from host_tracker.py
class Alive (object):
  """
  Holds liveliness information for MAC and IP entries.
  """

  def __init__ (self, livelinessInterval=timeoutSec['arpAware']):
    self.lastTimeSeen = time.time()
    self.interval = livelinessInterval

  def expired (self):
    return time.time() > self.lastTimeSeen + self.interval

  def refresh (self):
    self.lastTimeSeen = time.time()


class PingCtrl (Alive):
  """
  Holds information for handling ARP pings for hosts.
  """

  # Number of ARP ping attemps before deciding it failed
  pingLim=3

  def __init__ (self):
    super(PingCtrl,self).__init__(timeoutSec['arpReply'])
    self.pending = 0

  def sent (self):
    self.refresh()
    self.pending += 1

  def failed (self):
    return self.pending > PingCtrl.pingLim

  def received (self):
    # Clear any pending timeouts related to ARP pings
    self.pending = 0


# new and modified code starts here
class IPAddress (Alive):
  """
  This keeps track of IP addresses seen from each MAC entry and will
  be kept in the host object's ipaddrs dictionary. At least for now,
  there is no need to refer to the original host as the code is organized.
  """

  def __init__ (self, hasARP, ip):
    if hasARP:
      super(IPAddress,self).__init__(timeoutSec['arpAware'])
    else:
      super(IPAddress,self).__init__(timeoutSec['arpSilent'])
    self.hasARP = hasARP
    self.pings = PingCtrl()
    self.ip = ip

  def setHasARP (self):
    if not self.hasARP:
      self.hasARP = True
      self.interval = timeoutSec['arpAware']


class Host (Alive):
  """
  Not strictly an ARP entry.
  When it gets moved to Topology, may include other host info, like
  services, and it may replace dpid by a general switch object reference
  We use the port to determine which port to forward traffic out of.
  """

  def __init__ (self, dpid, port, macaddr):
    super(Host,self).__init__()
    self.dpid = dpid
    self.port = port
    self.macaddr = macaddr
    self.ipaddr = None

  def __str__ (self):
    if self.ipaddr is not None:
      return ' '.join([str(self.dpid), str(self.port), str(self.macaddr),
                       str(self.ipaddr.ip)])
    else:
      return ' '.join([str(self.dpid), str(self.port), str(self.macaddr), 'no IP'])

  def __eq__ (self, other):
    if other is None:
      return False
    elif type(other) == tuple:
      return (self.dpid,self.port,self.macaddr)==other

    if self.dpid != other.dpid: return False
    if self.port != other.port: return False
    if self.macaddr != other.macaddr: return False
    if self.dpid != other.dpid: return False
    # What about ipaddrs??
    return True

  def __ne__ (self, other):
    return not self.__eq__(other)


class StableEvent (Event):
  '''
  Event when the topology has not experienced any changes in a
  predetermined interval of time.
  '''

  def __init__ (self, stable, graph):
    super(StableEvent, self).__init__();
    self.stable = stable
    self.graph = graph


class DHCPEvent (Event):
  '''
  Event when the topology receives a DHCP packet.
  '''

  def __init__ (self, packetin, graph):
    super(DHCPEvent, self).__init__();
    self.packetin = packetin
    self.graph = graph


class FlowDeleteEvent (Event):
  '''
  Event when the topology needs to delete a flow.
  '''

  def __init__ (self,  ip, graph):
    super(FlowDeleteEvent, self).__init__();
    self.ip = ip
    self.graph = graph


class DynamicTopology (EventMixin):
  '''
  POX module that creates a dynamic adjacency list representation of the
  network topology. Uses the openflow.discovery module to track link changes
  and the host_tracker module to track host locations and MAC/IPs.
  '''

  _eventMixin_events = set([StableEvent, DHCPEvent, FlowDeleteEvent])

  # constructor
  def __init__ (self, debug = False, check_interval = 5.0, ping_src_mac = None,
                eat_packets = True):
    # the graph of the network
    self.graph = nx.Graph()
    self.hosts = []

    # send pings from dummy address to check liveliness
    if ping_src_mac is None:
      ping_src_mac = DEFAULT_ARP_PING_SRC_MAC
    self.ping_src_mac = EthAddr(ping_src_mac)

    # eat packets before other modules see them?
    self.eat_packets = eat_packets
    listen_args = {}
    if eat_packets:
      listen_args={'openflow':{'priority':1}}
    core.listen_to_dependencies(self, listen_args=listen_args)
    core.dhcp_server.addListenerByName("DHCPLease", self._dhcp_lease)

    # debug printouts
    self.debug = debug

    # cache links
    self.got_link = False
    self.waiting_links = []

    # stability information
    self.stable = False
    self.last_stable = self.stable

    # timer to check liveliness and stability
    self.last_check = time.time()
    self.check_interval = check_interval
    self._t = Timer(self.check_interval, self._run_checks, recurring=True)

  # Timer functions
  def _run_checks (self):
    '''
    At every interval, check the stability of the network (switches)
    and the status of hosts on the network.
    '''

    self._check_stability()
    self._check_host_timeouts()

  def _check_stability (self):
    '''
    Checks for network topology changes.
    '''

    # don't raise events if we haven't seen any links yet
    if self.got_link is False:
      self.stable = self.last_stable
      self.last_check = time.time()
      return

    # see if we have links waiting for switches
    while self.waiting_links != []:
      for link in self.waiting_links[:]:
        core.openflow_discovery.raiseEvent(link)

    # if the network status has changed, raise event
    if self.stable != self.last_stable:
      self.raiseEventNoErrors(StableEvent, stable = self.stable, graph = self.graph)
      self.last_stable, self.last_check = self.stable, time.time()

    # if the network has gone interval seconds without a change, we assume it is
    # now stable and raise an event
    else:
      if time.time() > self.last_check + self.check_interval:
        if self.stable is False:
          self.stable = True
          self.last_stable, self.last_check = self.stable, time.time()
          self.raiseEventNoErrors(StableEvent, stable = self.stable, graph = self.graph)

  def _check_host_timeouts (self):
    """
    Checks for timed out hosts
    """

    for host in self.hosts[:]:
      entry_pinged = False
      if host.ipaddr is not None:
        ip_addr, ip_address = host.ipaddr.ip, host.ipaddr
        if ip_address.expired():
          if ip_address.pings.failed():
            ip_addr = str(ip_addr)
            ip_address = None
            log.debug("Host %s: IP address %s expired",
                      str(host), ip_addr)
          else:
            self.sendPing(host, ip_addr)
            ip_address.pings.sent()
            entry_pinged = True
      else:
        ip_addr = None
      if host.expired() and not entry_pinged:
        log.info("Entry %s expired", str(host))

        if host.ipaddr is not None:
          log.warning("Entry %s expired but still had IP address %s",
                      str(host), str(ip_addr) )
          host.ipaddr = None
        self.update_host(host, leave=True)

  # verification that component is ready
  def _all_dependencies_met (self):
    log.info("topology_tracker ready")

  # Switch management
  def _handle_openflow_ConnectionUp (self, event):
    '''
    When switches join the network, create switch objects
    and add to the graph. Also add flow table entries so that
    this module sees ARP responses first.
    '''

    dpid = event.dpid
    if dpid not in self.graph:
      self.graph.add_node(dpid, connection=event.connection)
      self.stable, self.last_check = False, time.time()

    log.debug("Installing flow for ARP ping responses")

    m = of.ofp_flow_mod()
    m.priority += 1 # Higher than normal
    m.match.dl_type = ethernet.ARP_TYPE
    m.match.dl_dst = self.ping_src_mac

    m.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
    event.connection.send(m)

  def _handle_openflow_ConnectionDown (self, event):
    '''
    When switches leave, remove them from the graph.
    '''

    dpid = event.dpid
    if dpid in self.graph:
      self.graph.remove_node(dpid)
      self.stable, self.last_check = False, time.time()

  def _handle_openflow_discovery_LinkEvent (self, event):
    '''
    When discovery generates link events, use the link info
    to update our graph.
    '''

    self.got_link = True

    # NOTE: new code
    s1 = event.link.dpid1
    s2 = event.link.dpid2

    if s1 not in self.graph or s2 not in self.graph:
      if event not in self.waiting_links:
        self.waiting_links.append(event)
      return

    if event.added:
      self.graph.add_edge(s1, s2, link=event.link)
    elif event.removed:
      if self.graph.has_edge(s1, s2):
        self.graph.remove_edge(s1, s2)

    if event in self.waiting_links:
      self.waiting_links.remove(event)

    self.stable, self.last_check = False, time.time()

  def is_edge_port (self, dpid, inport):
    '''
    Returns true if the given port on the given switch is not connected to
    another switch.
    '''

    # Look at the link between the switch and neighbors. If the
    # the given inport is found connected to another switch, then
    # this is not an edge port. Otherwise, it is.
    for node in self.graph.neighbors(dpid):
      edge_info = self.graph[dpid][node]
      if 'link' in edge_info:
        link = edge_info['link']
        if ((link.dpid1 == dpid and link.port1 == inport) or
          (link.dpid2 == dpid and link.port2 == inport)):
          return False
    return True

  def get_link_port (self, src_dpid, dst_dpid):
    '''
    If a link exists from src_dpid to dst_dpid, return the port
    on src_dpid.
    '''

    edge = self.graph[src_dpid][dst_dpid]

    # if switch - switch link
    if 'link' in edge:
      link = edge['link']
      if src_dpid == link.dpid1:
        return link.port1
      else:
        return link.port2

    # if host - switch link
    elif 'port' in edge:
      return edge['port']
    else:
      return None

  # Host management
  def update_host (self, host, join=False, leave=False, move=False, new=None):
    '''
    When mobile_host_tracker generates HostEvents, then a host has
    joined/left/moved around the network. Use these events to
    add hosts to the graph. Expects a host object as host.
    '''

    assert sum(1 for x in [join,leave,move] if x) == 1
    m = str(host.macaddr)
    if leave:
      if str(host.macaddr) in self.graph:
        if host.ipaddr is not None:
          self.raiseEventNoErrors(FlowDeleteEvent, ip = host.ipaddr.ip, graph = self.graph)
          #self.delete_host_flows(host.ipaddr.ip, host.dpid)
        log.debug('{0} left'.format(str(host)))
        self.hosts.remove(host)
        self.graph.remove_node(m)

    elif move:
      assert new is not None
      # NOTE: this would need to be changed if multiple interfaces
      #       per host was supported
      self.raiseEventNoErrors(FlowDeleteEvent, ip = host.ipaddr.ip, graph = self.graph)
      #self.delete_host_flows(host.ipaddr.ip, host.dpid)
      #for n in self.graph.neighbors(str(host.macaddr))[:]:
        #self.graph.remove_edge(str(host.macaddr), n)

      map(lambda x: self.graph.remove_edge(m, x), self.graph.neighbors(m)[:])

      # host ports not factored in
      self.graph.add_edge(new.dpid, m, port=new.port)
      log.debug('{0} moved from {1} port {2} --> {3} port {4}'.format(
        host.macaddr, host.dpid, host.port, new.dpid, new.port))
      host.dpid = new.dpid
      host.port = new.port
      host.refresh()

    else: # join
      self.graph.add_node(m)
      self.graph.add_edge(host.dpid, m, port=host.port)
      self.graph.node[m]['info'] = host
      host.refresh()
      self.hosts.append(host)
      log.debug('{0} joined on {1} port {2}'.format(host.macaddr, host.dpid, host.port))

  def get_host_info (self, ip):
    '''
    Allows us to look up host MAC addresses by IP address, like
    what ARP does.
    '''

    hosts = [host for host in self.hosts if host.ipaddr is not None and
            host.ipaddr.ip == ip]
    return hosts[0]

  def _handle_openflow_PacketIn (self, event):
    """
    Populate MAC and IP tables based on incoming packets.
    """

    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed

    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return
    log.warn("{0}".format(packet.type))
    if packet.type == ethernet.LLDP_TYPE: # Ignore LLDP packets
      return

    # NOTE: this is critical
    if not self.is_edge_port(dpid, inport):
      # No host should be right behind a switch-only port
      log.debug("%i %i ignoring packetIn at switch-only port", dpid, inport)
      return EventHalt

    log.debug("PacketIn: %i %i ETH %s => %s",
              dpid, inport, str(packet.src), str(packet.dst))

    # Learn or update dpid/port/MAC info
    host = (str(packet.src) in self.graph)

    if host:
      host = self.graph.node[str(packet.src)]['info']
      host.refresh()

    if not host:
      host = Host(dpid,inport,packet.src)
      self.update_host(host, join = True)

    elif host != (dpid, inport, packet.src):
      self.update_host(host, move = True, new = New(dpid, inport))

    (pckt_srcip, hasARP) = self.getSrcIPandARP(packet.next)
    if pckt_srcip is not None and pckt_srcip != '0.0.0.0':
      self.updateIPInfo(pckt_srcip, host, hasARP)

    host.refresh()

    # if this is DHCP, raise event for DHCP server and halt event
    if self.is_dhcp(event):
      self.raiseEventNoErrors(DHCPEvent(event, self.graph))
      return EventHalt

    if self.eat_packets and packet.dst == self.ping_src_mac:
      return EventHalt

  def _dhcp_lease (self, event):
    '''
    Adjust Host IP information according to DHCP lease renews/expires.
    '''

    host = self.graph.node[str(event.mac)]['info']

    if event.renew:
      self.updateIPInfo(event.ip, host, True)
    else:
      host.ipaddr = None
      log.info("learned %s lost IP %s", str(event.mac), str(event.ip))

  def is_dhcp (self, event):
    '''
    Given packet in, return true if contents are DHCP, false
    if not.
    '''

    ipp = event.parsed.find('ipv4')
    if not ipp or not ipp.parsed:
      return False
    #if ipp.dstip not in (IP_ANY, IP_BROADCAST) and
       #ipp.dstip not in self.core.values():
      #return
    nwp = ipp.payload
    if not nwp or not nwp.parsed or not isinstance(nwp, pkt.udp):
      return False
    if nwp.srcport != pkt.dhcp.CLIENT_PORT:
      return False
    if nwp.dstport != pkt.dhcp.SERVER_PORT:
      return False
    p = nwp.payload
    if not p:
      log.debug("%s: no packet", str(event.connection))
      return False
    if not isinstance(p, pkt.dhcp):
      log.debug("%s: packet is not DHCP", str(event.connection))
      return False
    if not p.parsed:
      log.debug("%s: DHCP packet not parsed", str(event.connection))
      return False

    if p.op != p.BOOTREQUEST:
      return False

    t = p.options.get(p.MSG_TYPE_OPT)
    if t is None:
      return False

    return True

  # IP helpers
  def getSrcIPandARP (self, packet):
    """
    Gets source IPv4 address for packets that have one (IPv4 and ARP)

    Returns (ip_address, has_arp).  If no IP, returns (None, False).
    """

    if isinstance(packet, ipv4):
      log.debug("IP %s => %s",str(packet.srcip),str(packet.dstip))
      return (packet.srcip, False)
    elif isinstance(packet, arp):
      log.debug("ARP %s %s => %s",
                {arp.REQUEST:"request",arp.REPLY:"reply"}.get(packet.opcode,
                    'op:%i' % (packet.opcode,)),
                str(packet.protosrc), str(packet.protodst))
      if (packet.hwtype == arp.HW_TYPE_ETHERNET and
          packet.prototype == arp.PROTO_TYPE_IP and
          packet.protosrc != 0):
        return (packet.protosrc, True)

    return (None, False)

  def updateIPInfo (self, pckt_srcip, host, hasARP):
    """
    Update given Host

    If there is IP info in the incoming packet, update the host
    accordingly. In the past we assumed a 1:1 mapping between MAC and IP
    addresses, but removed that restriction later to accomodate cases
    like virtual interfaces (1:n) and distributed packet rewriting (n:1)

    I have reinstated the 1:1 mapping between MAC and IP addresses for
    the purpose of this work.
    """

    if host.ipaddr is not None and pckt_srcip == host.ipaddr.ip:
      # that entry already has that IP
      ipEntry = host.ipaddr
      ipEntry.refresh()
      log.debug("%s already has IP %s, refreshing",
                str(host.macaddr), str(pckt_srcip))
    else:
      # new mapping
      ipEntry = IPAddress(hasARP, pckt_srcip)
      host.ipaddr = ipEntry
      log.info("learned %s got IP %s", str(host.macaddr), str(pckt_srcip))
    if hasARP:
      ipEntry.pings.received()

  def sendPing (self, host, ipaddr):
    """
    Builds an ETH/IP any-to-any ARP packet (an "ARP ping")
    """

    r = arp()
    r.opcode = arp.REQUEST
    r.hwdst = host.macaddr
    r.hwsrc = self.ping_src_mac
    r.protodst = ipaddr
    # src is IP_ANY
    e = ethernet(type=ethernet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst)
    e.payload = r
    log.debug("%i %i sending ARP REQ to %s %s",
              host.dpid, host.port, str(r.hwdst), str(r.protodst))
    msg = of.ofp_packet_out(data = e.pack(),
                            action = of.ofp_action_output(port=host.port))
    if core.openflow.sendToDPID(host.dpid, msg.pack()):
      ipEntry = host.ipaddr
      ipEntry.pings.sent()
    else:
      # host is stale, remove it.
      log.debug("%i %i ERROR sending ARP REQ to %s %s",
                host.dpid, host.port, str(r.hwdst), str(r.protodst))
      del host.ipaddr
    return


# launch DynamicTopology
def launch (debug="False"):
    if not core.hasComponent("topology_tracker"):
        core.register("topology_tracker", DynamicTopology(str_to_bool(debug)))
