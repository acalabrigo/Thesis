# dhcpd_multi.py 2017 Adam Calabrigo

# A modified version of dhcpd.py capable of handling multiple subnets
# on a single network, and makes the leases actually expire.

# Built on dhcpd.py        - Copyright 2013 James McCauley
#          host_tracker.py - Copyright 2011 Dorgival Guedes

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

# POX
from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr,EthAddr,parse_cidr,cidr_to_netmask
from pox.lib.addresses import IP_BROADCAST, IP_ANY
from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.recoco import Timer

# networkX
from networkx.algorithms.clique import find_cliques
from networkx.algorithms.shortest_paths.generic import shortest_path

# general
import time
from collections import namedtuple

GATEWAY_DUMMY_MAC = '03:00:00:00:be:ef'
log = core.getLogger()

# Times (in seconds) to use for differente timouts:
timeoutSec = dict(
  timerInterval=5,     # Seconds between timer routine activations
  leaseInterval=60*60  # Time until DHCP leases expire - 1 hour
  )

# used in Subnet
Server = namedtuple('Server', 'dpid addr')


def ip_for_event (event):
  """
  Use a switch's DPID as an EthAddr.
  """

  eth = dpid_to_str(event.dpid,True).split("|")[0].replace("-",":")
  return EthAddr(eth)


# from host_tracker.py
class Alive (object):
  """
  Holds liveliness information for address pool entries
  """
  def __init__ (self, livelinessInterval=timeoutSec['leaseInterval']):
    self.lastTimeSeen = time.time()
    self.interval=livelinessInterval

  def expired (self):
    return time.time() > self.lastTimeSeen + self.interval

  def refresh (self):
    self.lastTimeSeen = time.time()


class LeaseEntry (Alive):
  """
  Holds information for leased IP addresses.
  """

  def __init__ (self, ip):
    super(LeaseEntry,self).__init__()
    self.ip = IPAddr(ip)

  def __str__(self):
    return str(self.ip)

  def __eq__ (self, other):
    if other is None:
      return False
    elif type(other) == IPAddr:
      return self.ip == other

    if self.ip != other.ip:
      return False

    return True

  def __ne__ (self, other):
    return not self.__eq__(other)


# unmodified from original dhcpd.py
class AddressPool (object):
  """
  Superclass for DHCP address pools

  Note that it's just a subset of a list (thus, you can always just use
  a list as a pool).  The one exception is an optional "subnet_mask" hint.

  It probably makes sense to change this abstraction so that we can more
  easily return addresses from multiple ranges, and because some things
  (e.g., getitem) are potentially difficult to implement and not particularly
  useful (since we only need to remove a single item at a time).
  """

  def __init__ (self):
    """
    Initialize this pool.
    """
    pass

  def __contains__ (self, item):
    """
    Is this IPAddr in the pool?
    """
    return False

  def append (self, item):
    """
    Add this IP address back into the pool
    """
    pass

  def remove (self, item):
    """
    Remove this IPAddr from the pool
    """
    pass

  def __len__ (self):
    """
    Returns number of IP addresses in the pool
    """
    return 0

  def __getitem__ (self, index):
    """
    Get an IPAddr from the pool.

    Note that this will only be called with index = 0!
    """
    pass


class SimpleAddressPool (AddressPool):
  """
  Simple AddressPool for simple subnet based pools.
  """

  def __init__ (self, network = "192.168.0.0/24", first = 1, last = None,
                count = None):
    """
    Simple subnet-based address pool

    Allocates count IP addresses out of network/network_size, starting
    with the first'th.  You may specify the end of the range with either
    last (to specify the last'th address to use) or count to specify the
    number to use.  If both are None, use up to the end of all
    legal addresses.

    Example for all of 192.168.x.x/16:
      SimpleAddressPool("192.168.0.0/16", 1, 65534)
    """

    network,network_size = parse_cidr(network)

    self.first = first
    self.network_size = network_size
    self.host_size = 32-network_size
    self.network = IPAddr(network)

    # use entire host space
    if last is None and count is None:
      self.last = (1 << self.host_size) - 2
    # set last address to use
    elif last is not None:
      self.last = last
    # just use count many
    elif count is not None:
      self.last = self.first + count - 1
    else:
      raise RuntimeError("Cannot specify both last and count")

    self.removed = set()

    # error checking here
    if self.count <= 0: raise RuntimeError("Bad first/last range")
    if first == 0: raise RuntimeError("Can't allocate 0th address")
    if self.host_size < 0 or self.host_size > 32:
      raise RuntimeError("Bad network")
    if IPAddr(self.last | self.network.toUnsigned()) not in self:
      raise RuntimeError("Bad first/last range")

  def __repr__ (self):
    return str(self)

  def __str__ (self):
    t = self.network.toUnsigned()
    t = (IPAddr(t|self.first),IPAddr(t|self.last))
    return "<Addresses from %s to %s>" % t

  @property
  def subnet_mask (self):
    return IPAddr(((1<<self.network_size)-1) << self.host_size)

  @property
  def count (self):
    return self.last - self.first + 1

  def __contains__ (self, item):
    item = IPAddr(item)
    if item in self.removed: return False
    n = item.toUnsigned()
    mask = (1<<self.host_size)-1
    nm = (n & mask) | self.network.toUnsigned()
    if nm != n: return False
    if (n & mask) == mask: return False
    if (n & mask) < self.first: return False
    if (n & mask) > self.last: return False
    return True

  def append (self, item):
    item = IPAddr(item)
    if item not in self.removed:
      if item in self:
        raise RuntimeError("%s is already in this pool" % (item,))
      else:
        raise RuntimeError("%s does not belong in this pool" % (item,))
    self.removed.remove(item)

  def remove (self, item):
    item = IPAddr(item)
    if item not in self:
      raise RuntimeError("%s not in this pool" % (item,))
    self.removed.add(item)

  def __len__ (self):
    return (self.last-self.first+1) - len(self.removed)

  def __getitem__ (self, index):
    if index < 0:
      raise RuntimeError("Negative indices not allowed")
    if index >= len(self):
      raise IndexError("Item does not exist")
    c = self.first

    # Use a heuristic to find the first element faster (we hope)
    # Note this means that removing items changes the order of
    # our "list".
    c += len(self.removed)
    while c > self.last:
      c -= self.count

    while True:
      addr = IPAddr(c | self.network.toUnsigned())
      if addr not in self.removed:
        assert addr in self
        index -= 1
        if index < 0: return addr
      c += 1
      if c > self.last: c -= self.count


# new and modified code starts here
class DHCPLease (Event):
  """
  Raised when a lease is given

  Call nak() to abort this lease
  """

  def __init__ (self, host_mac, ip, port=None,
                dpid=None, renew=False, expire=False):
    super(DHCPLease, self).__init__()
    self.mac = host_mac
    self.ip = ip
    self.port = port
    self.dpid = dpid
    self.renew = renew
    self.expire = expire
    self._nak = False

    assert sum(1 for x in [renew, expire] if x) == 1

  def nak (self):
    self._nak = True


class Subnet (object):
  '''
  Holds the information for one subnet in the network. This includes
  the network address, the IP address pool, the dpids of all switches
  in this subnet, the IP address of this subnet's DNS server (if different),
  and the dpid and IP of the subnets DHCP server. Note that this address is
  really just a dummy address.
  '''

  def __init__ (self, network, pool, switches, server, dns = None, subnet = None):

    def fix_addr (addr, backup):
      if addr is None: return None
      if addr is (): return IPAddr(backup)
      return IPAddr(addr)

    self.network = network
    self.dns_addr = fix_addr(dns, server.addr)

    # pool must be set properly
    if pool is None:
      self.pool = [IPAddr("192.168.0."+str(x)) for x in range(100,199)]
      self.subnet = IPAddr(subnet or "255.255.255.0")
    else:
      self.pool = pool
      self.subnet = cidr_to_netmask(subnet)
      if hasattr(pool, 'subnet_mask'):
        self.subnet = pool.subnet_mask
      if self.subnet is None:
        raise RuntimeError("You must specify a subnet mask or use a "
                           "pool with a subnet hint")

    self.address_pool = pool
    self.switches = switches

    assert isinstance(server, tuple)
    self.server = server # (dpid, ipaddr)

    if self.server.addr in self.pool:
      log.debug("Removing my own IP (%s) from address pool", self.server.addr)
      self.pool.remove(self.server.addr)


class DHCPDMulti (EventMixin):
  '''
  DHCP Server that handles multiple subnets in the network.
  '''

  _eventMixin_events = set([DHCPLease])

  # constructor
  def __init__ (self, network = "192.168.0.0/24", dns = None):

      # attributes of our network
      self.network, self.network_size = parse_cidr(network)
      self.dns_addr = dns
      self.subnets = {}  # IP -> subnet
      self.core = {} # dpid -> IP
      self.mobile_hosts = [] # IPs

      # attributes to track DHCP
      self.lease_time = timeoutSec['leaseInterval']
      self.offers = {} # Subnet -> {Eth -> IP we offered}
      self.leases = {} # Subnet -> {Eth -> LeaseEntry}
      self._t = None

      # if this is the first time the server has been started up
      self._first_stable = True

      core.listen_to_dependencies(self)
      core.openflow.addListeners(self)

  # server startup
  def _handle_ConnectionUp (self, event):
    '''
    When switches connect, install a flow rule to send all DHCP traffic
    to the controller automatically.
    '''

    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match()
    msg.match.dl_type = pkt.ethernet.IP_TYPE
    msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
    #msg.match.nw_dst = IP_BROADCAST
    msg.match.tp_src = pkt.dhcp.CLIENT_PORT
    msg.match.tp_dst = pkt.dhcp.SERVER_PORT
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    event.connection.send(msg)

  def _handle_core_ComponentRegistered (self, event):
    '''
    We want to listen to StableEvents, this sets that up.
    '''

    if event.name == "dynamic_topology":
      event.component.addListenerByName("StableEvent",
          self._dynamic_topology_stable)
      event.component.addListenerByName("DHCPEvent", self._dhcp_PacketIn)
      log.info('connected to dynamic_topology')

  # interacting with dynamic_topology
  def _dynamic_topology_stable (self, event):
    '''
    When the topology is stable, start the DHCP server.
    '''

    graph = event.graph
    if event.stable and self._first_stable:
      cliques = find_cliques(graph)
      core = max(cliques, key=lambda x: len(x))
      core_ips = []

      if core is None:
        log.warn('No core mesh found in this network...')
        return

      core_switches = {s:[] for s in core}
      not_core = [node for node in graph if node not in core and
                  not isinstance(node, EthAddr)]

      for switch in not_core:
        closest_core = min(core, key=lambda x: len(shortest_path(
                           graph, source=switch, target=x)))
        core_switches[closest_core].append(switch)

      for i,c in enumerate(core):
        network_addr = IPAddr(self.network).toUnsigned() | (i << (32 - self.network_size))
        server_addr = IPAddr(network_addr + 1)
        core_ips.append(server_addr)
        network_addr = IPAddr(network_addr)
        pool = SimpleAddressPool(str(network_addr) + '/' + str(self.network_size))
        subnet = Subnet(network = server_addr, pool = pool,
                        switches = core_switches[c], server = Server(c, server_addr),
                        dns = self.dns_addr, subnet = self.network_size)
        self.subnets[server_addr] = subnet
        self.leases[subnet] = {}
        self.offers[subnet] = {}
        log.info('{0} serves subnet {1} on switches {2}'.format(server_addr,
                                                                network_addr,
                                                                core_switches[c]))

      self.core = dict(zip(core, core_ips))
      self._first_stable = False
      self._t = Timer(timeoutSec['timerInterval'], self._check_leases,
                      recurring=True)

  def _dhcp_PacketIn (self, event):
    '''
    Topology has passed us a PacketIn with DHCP contents, let's handle it.
    '''

    graph = event.graph
    event = event.packetin

    # Is it to us?  (Or at least not specifically NOT to us...)
    ipp = event.parsed.find('ipv4')
    if (ipp.dstip not in (IP_ANY, IP_BROADCAST) and
       ipp.dstip not in self.core.values()):
      return

    nwp = ipp.payload
    p = nwp.payload
    t = p.options.get(p.MSG_TYPE_OPT)

    subnet = self.get_event_subnet(event)
    if subnet is None:
      return

    # ALL mobility checking done here!
    src = event.parsed.src
    host = graph.node[str(src)]
    if host is not None:
      ip_addr = host['info'].ipaddr
      if ip_addr is not None:
        ip_addr = ip_addr.ip
        home_subnet = [self.subnets[s] for s in self.subnets if ip_addr
                          in self.subnets[s].pool.removed]
        assert len(home_subnet) is 1
        home_subnet = home_subnet[0]
        if home_subnet != subnet and ip_addr not in self.mobile_hosts:
          log.info('{0} moved from {1} to {2}, is now mobile with {3}'.format(
                   src, home_subnet.server.addr, subnet.server.addr, ip_addr))
          subnet = home_subnet
          self.mobile_hosts.append(ip_addr)
        elif home_subnet == subnet and ip_addr in self.mobile_hosts:
          log.info('{0} moved from {1} to {2}, is now back on home subnet with {3}'.format(
                   src, home_subnet.server.addr, subnet.server.addr, ip_addr))
          self.mobile_hosts.remove(ip_addr)

    if t.type == p.DISCOVER_MSG:
      self.exec_discover(event, p, subnet)
    elif t.type == p.REQUEST_MSG:
      self.exec_request(event, p, subnet)
    elif t.type == p.RELEASE_MSG:
      self.exec_release(event, p, subnet)
    return EventHalt

  # verification that component is ready
  def _all_dependencies_met (self):
    log.info("dhcpd_multi ready")

  # DHCP lease service routine
  def _check_leases (self):
    """
    Checks for expired leases
    """

    for subnet in self.subnets.itervalues():
      leases = self.leases[subnet]
      for client in leases.keys():
        lease = leases[client]
        if lease.expired():
          log.debug("Entry %s: IP address %s expired",
                    str(client), str(lease.ip) )
          subnet.pool.append(lease.ip)
          ev = DHCPLease(client, lease.ip, expire=True)
          self.raiseEvent(ev)
          del leases[client]
          if ev._nak:
            self.nak(event)

  # helpers for sending DHCP packets
  def reply (self, event, subnet, msg):

    # fill out the rest of the DHCP packet
    orig = event.parsed.find('dhcp')
    broadcast = (orig.flags & orig.BROADCAST_FLAG) != 0
    msg.op = msg.BOOTREPLY
    msg.chaddr = event.parsed.src
    msg.htype = 1
    msg.hlen = 6
    msg.xid = orig.xid
    msg.add_option(pkt.DHCP.DHCPServerIdentifierOption(subnet.server.addr))

    # create ethernet header
    ethp = pkt.ethernet(src=ip_for_event(event),dst=event.parsed.src)
    ethp.type = pkt.ethernet.IP_TYPE
    ipp = pkt.ipv4(srcip = subnet.server.addr)
    ipp.dstip = event.parsed.find('ipv4').srcip
    if broadcast:
      ipp.dstip = IP_BROADCAST
      ethp.dst = pkt.ETHERNET.ETHER_BROADCAST

    # create UDP header
    ipp.protocol = ipp.UDP_PROTOCOL
    udpp = pkt.udp()
    udpp.srcport = pkt.dhcp.SERVER_PORT
    udpp.dstport = pkt.dhcp.CLIENT_PORT

    # encapsulate and reply to host
    udpp.payload = msg
    ipp.payload = udpp
    ethp.payload = ipp
    po = of.ofp_packet_out(data=ethp.pack())
    po.actions.append(of.ofp_action_output(port=event.port))
    event.connection.send(po)

  def nak (self, event, subnet, msg = None):
    if msg is None:
      msg = pkt.dhcp()
    msg.add_option(pkt.DHCP.DHCPMsgTypeOption(msg.NAK_MSG))
    msg.siaddr = subnet.server.addr
    self.reply(event, subnet, msg)

  def fill (self, wanted_opts, subnet, msg):
    """
    Fill out some options in msg
    """
    if msg.SUBNET_MASK_OPT in wanted_opts:
      msg.add_option(pkt.DHCP.DHCPSubnetMaskOption(subnet.subnet))
    if msg.ROUTERS_OPT in wanted_opts and subnet.server.addr is not None:
      msg.add_option(pkt.DHCP.DHCPRoutersOption(subnet.server.addr))
    if msg.DNS_SERVER_OPT in wanted_opts and subnet.dns_addr is not None:
      msg.add_option(pkt.DHCP.DHCPDNSServersOption(subnet.dns_addr))
    msg.add_option(pkt.DHCP.DHCPIPAddressLeaseTimeOption(self.lease_time))

  # helpers for different stages in DHCP handshake
  def exec_discover (self, event, p, subnet):
    # creates an OFFER in response to a DISCOVER
    reply = pkt.dhcp()
    reply.add_option(pkt.DHCP.DHCPMsgTypeOption(p.OFFER_MSG))
    src = event.parsed.src

    # if this host already has a lease
    if src in self.leases[subnet]:
      offer = self.leases[subnet][src].ip   # offer it the same address
      del self.leases[subnet][src]
      self.offers[subnet][src] = offer      # move from leases to offers

    # otherwise check if we already offered an address to this host
    else:
      offer = self.offers[subnet].get(src)
      if offer is None:
        if len(subnet.pool) == 0:
          log.error("Out of IP addresses")
          self.nak(event, subnet)
          return

        offer = subnet.pool[0] # offer the first available address
        if p.REQUEST_IP_OPT in p.options: # if host requested specific address
          wanted_ip = p.options[p.REQUEST_IP_OPT].addr
          if wanted_ip in subnet.pool:
            offer = wanted_ip
        subnet.pool.remove(offer)
        self.offers[subnet][src] = offer
    reply.yiaddr = offer            # your IP
    reply.siaddr = subnet.server.addr     # server's IP

    wanted_opts = set()
    if p.PARAM_REQ_OPT in p.options:
      wanted_opts.update(p.options[p.PARAM_REQ_OPT].options)
    self.fill(wanted_opts, subnet, reply)
    self.reply(event, subnet, reply)

  def exec_request (self, event, p, subnet):
    # create and send ACKNOWLEDGE in response to REQUEST

    if not p.REQUEST_IP_OPT in p.options:
      # Uhhh...
      return

    # if client asks for specific IP
    wanted_ip = p.options[p.REQUEST_IP_OPT].addr
    src = event.parsed.src
    dpid = event.connection.dpid
    port = event.port
    got_ip = None

    # renew
    if src in self.leases[subnet]:
      if wanted_ip != self.leases[subnet][src]:
        subnet.pool.append(self.leases[subnet][src].ip)
        del self.leases[subnet][src]
      else:
        got_ip = self.leases[subnet][src]
        got_ip.refresh() # this is a lease renew

    # respond to offer
    if got_ip is None:
      if src in self.offers[subnet]:    # if there was an offer to this client
        if wanted_ip != self.offers[subnet][src]:
          pool.append(self.offers[subnet][src])
          del self.offers[subnet][src]
        else:
          got_ip = LeaseEntry(self.offers[subnet][src])

    # new host request
    if got_ip is None:
      if wanted_ip in subnet.pool:
        subnet.pool.remove(wanted_ip)
        got_ip = LeaseEntry(wanted_ip)

    if got_ip is None:
      log.warn("%s asked for un-offered %s", src, wanted_ip)
      self.nak(event, subnet)
      return

    assert got_ip == wanted_ip
    self.leases[subnet][src] = got_ip
    ev = DHCPLease(src, got_ip.ip, port, dpid, renew=True)
    log.info("%s leased %s to %s" % (subnet.server.addr, got_ip, src))
    self.raiseEvent(ev)
    if ev._nak:
      self.nak(event, subnet)
      return

    # create ack reply
    reply = pkt.dhcp()
    reply.add_option(pkt.DHCP.DHCPMsgTypeOption(p.ACK_MSG))
    reply.yiaddr = wanted_ip
    reply.siaddr = subnet.server.addr

    wanted_opts = set()
    if p.PARAM_REQ_OPT in p.options:
      wanted_opts.update(p.options[p.PARAM_REQ_OPT].options)
    self.fill(wanted_opts, subnet, reply)

    self.reply(event, subnet, reply)

  def exec_release (self, event, p, subnet):
    src = event.parsed.src
    port = event.port
    dpid = event.connection.dpid

    if src != p.chaddr:
      log.warn("%s tried to release %s with bad chaddr" % (src,p.ciaddr))
      return
    if self.leases[subnet].get(p.chaddr) != p.ciaddr:
      log.warn("%s tried to release unleased %s" % (src,p.ciaddr))
      return
    ev = DHCPLease(src, p.chaddr, port, dpid, expire=True)
    log.info("%s released %s from %s" % (subnet.server.addr, p.ciaddr, src))
    self.raiseEvent(ev)
    del self.leases[subnet][p.chaddr]
    pool.append(p.ciaddr)

    log.debug("%s released %s" % (src,p.ciaddr))

  # functions for determining subnet
  def get_subnet (self, ip_addr):
    '''
    Given an IP, return the network address/subnet_mask.
    '''

    subnet = [self.subnets[s] for s in self.subnets if ip_addr in self.subnets[s].pool.removed]
    if len(subnet) != 1:
      raise RuntimeError("{0} is on {1} subnets".format(ip_addr, len(subnet)))
      return None
    subnet = subnet[0]
    network, subnet_mask = subnet.pool.network, subnet.pool.subnet_mask
    return str(network) + '/' + str(subnet_mask)

  def get_event_subnet (self, event):
    """
    Get a subnet for this event.

    Return None to not issue a subnet.  You should probably log this.
    """

    subnet = [self.subnets[s] for s in self.subnets
              if event.dpid in self.subnets[s].switches]
    assert len(subnet) == 1
    return subnet[0]

  def get_switch_subnet (self, dpid):
    '''
    Given a switch, return the network address/subnet_mask it's on.
    '''

    subnet = [self.subnets[s] for s in self.subnets if dpid in self.subnets[s].switches]
    if len(subnet) is 1:
      subnet = subnet[0]
      network, subnet_mask = subnet.pool.network, subnet.pool.subnet_mask
      return str(network) + '/' + str(subnet_mask)
    else:
      if len(subnet) > 1:
        log.warn("{0} is on multiple subnets: {1}".format(dpid, subnet))
      else:
        log.warn("{0} is not on a subnet".format(dpid))
      return None

  # functions for identifying switches
  def is_router (self, ip_addr):
    '''
    Is this IP one of our router interfaces?
    '''

    ip_addr = IPAddr(ip_addr)
    match = [ip for ip in self.subnets.itervalues() if ip_addr == ip.server.addr]
    return len(match) == 1

  def is_core (self, dpid):
    '''
    Does this DPID identify a core switch in our network?
    '''

    return (dpid in self.core)

  def is_local_path (self, path):
    '''
    Is this traffic localized to one subnet?
    '''

    core_switches = [node for node in path[1:-1] if node in self.core]
    return central_switches == []


# load DHCPDMulti
def launch (network = "192.168.0.0/24", dns = None):
  core.register('dhcpd_multi', DHCPDMulti(network, dns))
