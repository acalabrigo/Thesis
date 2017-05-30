# Dynamic network represented as an undirected graph of switches and hosts.
# Based on gephi_topo
#
# 2017 Adam Calabrigo

from pox.core import core
from pox.lib.recoco import Timer
from pox.lib.revent import Event, EventHalt
import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery as discovery
import pox.openflow.topology as of_topo
from pox.lib.revent.revent import *
from pox.lib.util import dpid_to_str, str_to_bool
from pox.lib.packet.ethernet import ethernet
import time
import pox

log = core.getLogger()

class Switch (object):
  '''
  Simple switch object for our topology.
  '''

  def __init__ (self, dpid, connection):
      self.dpid = dpid
      self.connection = connection
      self.ports = {} # port num -> entity

  def get_device_port (self, device):
    '''
    Get the port to which the target device is connected.
    '''

    port_device = self.ports.items()
    port = [p for p,d in port_device if d == device]
    if len(port) > 0:
      return port[0]
    else:
      return None

class Host (object):
  '''
  Simple host object for our topology.
  '''
  def __init__ (self, mac, entry):
    self.mac = mac
    self.entry = entry

  def get_ip(self):
    '''
    Retrieve the IP address of this host from the MAC entry.
    '''
    return self.entry.ipAddr.ip

class StableEvent (Event):
  '''
  Event when the topology has not experienced any changes in a
  predetermined interval of time.
  '''

  def __init__(self, stable):
    super(StableEvent, self).__init__();
    self.stable = stable

class DynamicTopology (EventMixin):
  '''
  POX module that creates a dynamic adjacency list representation of the
  network topology. Uses the openflow.discovery module to track link changes
  and the host_tracker module to track host locations and MAC/IPs.
  '''

  _eventMixin_events = set([StableEvent])

  def __init__ (self, debug=False, check_interval=5.0):
    core.listen_to_dependencies(self)
    self.switches = {} # dpid -> Switch
    self.hosts = {} # mac -> Host
    self.mobile_hosts = {} # mac -> IP
    self.graph = {} # ID -> set of IDs

    self.debug = debug

    self.got_link = False
    self.waiting_links = []
    self.stable = False
    self.last_stable = self.stable
    self.last_check = time.time()
    self.check_interval = check_interval
    self._t = Timer(self.check_interval, self._check_stability, recurring=True)

  def _check_stability (self):
    '''
    See if our network has undergone changes.
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
      self.raiseEventNoErrors(StableEvent, stable=self.stable)
      self.last_stable, self.last_check = self.stable, time.time()

    # if the network has gone interval seconds without a change, we assume it is
    # now stable and raise an event
    else:
      if time.time() > self.last_check + self.check_interval:
        if self.stable is False:
          self.stable = True
          self.last_stable, self.last_check = self.stable, time.time()
          self.raiseEventNoErrors(StableEvent, stable=self.stable)

    if self.debug and self.stable:
      log.debug("----- DEBUG -----")
      for s in self.switches.iteritems():
        log.debug("switch {0} : ports {1}".format(s[0], s[1].ports))
      for h in self.hosts.iteritems():
        if h[1].entry.ipAddr is not None:
          log.debug("host {0} : has ip {1}".format(h[0], h[1].entry.ipAddr.ip))
        else:
          log.debug("host {0} : no ip yet".format(h[0]))
      log.debug("graph: {0}".format(self.graph))

  def _handle_core_ComponentRegistered (self, event):
    '''
    We want to listen to HostEvents, this sets that up.
    '''

    if event.name == "mobile_host_tracker":
      event.component.addListenerByName("HostEvent",
          self.__handle_mobile_host_tracker_HostEvent)
      log.info('connected to mobile_host_tracker')

  def _delete_flows(self, ip):
    mac = self.get_host_mac_by_ip(ip)
    if mac is None:
      log.warn('trying to delete flows for IP not in use: {0}'.format(ip))
      return

    # remove this host from our flow tables
    for s in self.switches:
      msg = of.ofp_flow_mod()
      msg.match.dl_type = ethernet.IP_TYPE
      msg.match.nw_dst = ip
      msg.command = of.OFPFC_DELETE
      self.switches[s].connection.send(msg)

      msg = of.ofp_flow_mod()
      msg.match.dl_dst = mac
      msg.command = of.OFPFC_DELETE
      self.switches[s].connection.send(msg)

  def _handle_mobile_host_tracker_HostEvent (self, event):
    '''
    When host_tracker generates HostEvents, then a host has
    joined/left/moved around the network. Use these events to
    add hosts to the graph.
    '''

    # Name is intentionally mangled to keep listen_to_dependencies away
    h = str(event.entry.macaddr)
    s = dpid_to_str(event.entry.dpid)
    is_mobile = event.is_mobile

    # when hosts leave, remove them from the host dict and graph, then remove
    # them from adjacency list
    if event.leave:
      if h in self.hosts:
        if event.old_ip:
          self._delete_flows(old_ip)
        if is_mobile:
          del self.mobile_hosts[h]
        del self.hosts[h]
        del self.graph[h]
        for n in self.graph:
          if h in self.graph[n]:
            self.graph[n].remove(h)

    else:
      if event.move: # move
        if h in self.hosts:
          if h in self.mobile_hosts and is_mobile is False:
            del self.mobile_hosts[h]
          self._delete_flows(event.entry.ipAddr.ip)
          for n in self.graph:
            if n != h and h in self.graph[n]:
              switch = self.switches[n]
              del switch.ports[switch.get_device_port(h)]
              self.graph[n].remove(h)

        s = dpid_to_str(event.new_dpid)
        p = event.new_port

      else: # join
        p = event.entry.port

      self.hosts[h] = Host(event.entry.macaddr, event.entry)
      self.graph[h] = set([])

      assert s in self.graph
      self.graph[s].add(h)
      self.switches[s].ports[p] = h
      self.graph[h].add(s)
      if is_mobile:
        self.mobile_hosts[h] = event.entry.ipAddr.ip

  def _handle_openflow_ConnectionUp (self, event):
    '''
    When switches join the network, create switch objects
    and add to the graph.
    '''

    s_dpid = dpid_to_str(event.dpid)
    if s_dpid not in self.switches:
      self.switches[s_dpid] = Switch(event.dpid, event.connection)
      self.graph[s_dpid] = set([])
      self.stable, self.last_check = False, time.time()

  def _handle_openflow_ConnectionDown (self, event):
    '''
    When switches leave, remove them from the graph.
    '''

    s_dpid = dpid_to_str(event.dpid)
    if s_dpid in self.switches:
      # remove switch from graph
      del self.switches[s_dpid]
      del self.graph[s_dpid]
      for n in self.graph:
        if s_dpid in self.graph[n]:
          self.graph[n].remove(s_dpid)
          # this might not work, let's see
      self.stable, self.last_check = False, time.time()

  # this should probably be updated later to be
  # more robust
  def _handle_openflow_discovery_LinkEvent (self, event):
    '''
    When discovery generates link events, use the link info
    to update our graph.
    '''

    self.got_link = True

    # get the dpids of the switches involved
    s1_id = dpid_to_str(event.link.dpid1)
    s2_id = dpid_to_str(event.link.dpid2)

    if s1_id not in self.switches or s2_id not in self.switches:
      if event not in self.waiting_links:
        self.waiting_links.append(event)
      return

    assert s1_id in self.switches
    assert s2_id in self.switches

    # get the switches from these DPIDs
    s1 = self.switches[s1_id]
    s2 = self.switches[s2_id]
    s1_port = event.link.port1
    s2_port = event.link.port2

    # if link UP, add ports to switches and graph
    if event.added:
      s1.ports[s1_port] = s2_id
      s2.ports[s2_port] = s1_id
      self.graph[s1_id].add(s2_id)
      self.graph[s2_id].add(s1_id)

    # if link DOWN, remove ports from switches and graph
    elif event.removed:
      if s1_port in s1.ports:
        del s1.ports[s1_port]
        # if no other connection, remove from adjacency list
        if s2_id not in s1.ports.values() and s1 in self.graph:
          self.graph[s1].remove(s2_id)
      if s2_port in s2.ports:
        del s2.ports[s2_port]
        if s1_id not in s2.ports.values() and s2 in self.graph:
          self.graph[s2].remove(s1_id)

    if event in self.waiting_links:
      self.waiting_links.remove(event)

    self.stable, self.last_check = False, time.time()

  def get_host_mac_by_ip(self, ip):
    '''
    Allows us to look up host MAC addresses by IP address, like
    what ARP does.
    '''

    for host in self.hosts.itervalues():
      hip = host.get_ip()
      if hip == ip:
          return host.entry.macaddr
    return None

  def get_host_ap(self, ip):
    '''
    For the given host ip, return the switch dpid it is currently
    connected to.
    '''

    mac = str(self.get_host_mac_by_ip(ip))
    if mac is None:
      return None
    dpid = self.hosts[mac].entry.dpid
    if dpid is None:
      return None
    return dpid

def launch(debug="False"):
    if not core.hasComponent("dynamic_topology"):
        core.register("dynamic_topology", DynamicTopology(str_to_bool(debug)))
