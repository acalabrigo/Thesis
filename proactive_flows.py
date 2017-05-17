# Install proactive flow rules. Relies on dynamic_topology.
# 2017 Adam Calabrigo

from pox.core import core
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.udp import udp
from pox.lib.packet.arp import arp
from pox.lib.packet.dhcp import dhcp
from pox.lib.recoco import Timer
from pox.lib.revent import Event, EventHalt
import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery as discovery
import pox.openflow.topology as of_topo
from pox.lib.revent.revent import *
from pox.lib.util import dpid_to_str, str_to_bool
import pox

log = core.getLogger()

all_ports = of.OFPP_FLOOD

GATEWAY_DUMMY_MAC = '03:00:00:00:be:ef'

def dpid_to_mac (dpid):
    return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

class ProactiveFlows (object, idle_timeout=60*60):
  def __init__ (self):
    # need to access the graph in dynamic_topology for proactive routes
    # need access to DHCP to know IP addresses
    self._priority = 0x8000 + 1
    self.idle_timeout = idle_timeout

    core.openflow.addListeners(self)
    core.listen_to_dependencies(self, ['dynamic_topology', 'dhcpd_multi'], short_attrs=True)

  def _all_dependencies_met (self):
    log.info("proactive_flows ready")

  def is_edge_node (self, node):
    '''
    Determines whether a switch in the network is centralized or
    at an edge.
    '''

    adj_nodes = self.dynamic_topology.graph.get(node)
    if adj_nodes is not None:
      adj_switches = [n for n in adj_nodes if '-' in n]
      if len(adj_switches) > 1:
        return False
    return True

  def find_shortest_path (self, graph, start, end, path=[]):
    '''
    Finds the shortest path between two devices.
    '''

    path = path + [start]
    if start == end:
      return path
    if not start in graph:
      log.info('ended at {0}'.format(start))
      return None
    shortest = None
    for node in graph[start]:
      if node not in path:
        newpath = self.find_shortest_path(graph, node, end, path)
        if newpath:
          if not shortest or len(newpath) < len(shortest):
            shortest = newpath
    return shortest

  def _edge_reply(self, dst, node1, node2):
    '''
    Create a flow mod packet for an edge switch.
    '''

    msg = of.ofp_flow_mod()
    msg.match.dl_type = ethernet.IP_TYPE
    msg.match.nw_dst = dst
    port = self.dynamic_topology.switches[node1].get_device_port(node2)
    if port is None:
      log.warn("Could not find {0} in {1}'s port table'".format(node2, node1))
      return
    else:
      msg.actions.append(of.ofp_action_output(port = port))
    self.dynamic_topology.switches[node1].connection.send(msg)

  def _central_reply(self, dst, node1, node2, mobile=False):
    '''
    Create a flow mod packet for a central switch.
    '''
    # flow mod for outgoing packets
    msg = of.ofp_flow_mod()
    msg.match.dl_type = ethernet.IP_TYPE

    if not mobile:
      msg.match.nw_dst = self.dhcpd_multi.get_subnet(dst)
      if msg.match.nw_dst is None:
        log.warn("Could not find subnet for IP {0}'".format(dst))
        return
    else:
      msg.match.nw_dst = dst
      msg.priority = self._priority
      self._priority += 1

    port = self.dynamic_topology.switches[node1].get_device_port(node2)
    if port is None:
      log.warn("Could not find {0} in {1}'s port table'".format(node2, node1))
      return
    else:
      msg.idle_timeout = self.idle_timeout
      msg.actions.append(of.ofp_action_output(port = port))
      self.dynamic_topology.switches[node1].connection.send(msg)

  def _handle_PacketIn (self, event):
    '''
    Handler for PacketIn events. When switch doesn't have flow table entry,
    it sends packet to controller. This handler decides what flow table
    entries to install in which switches based on the received packet
    and the network topology.
    '''

    packet = event.parsed
    dpid = event.connection.dpid

    if not packet.parsed:
      return
    if packet.type == ethernet.LLDP_TYPE: # Ignore LLDP packets
      return

    # CASE: ipv4 traffic into the switch. In this case, create a flow table
    # entry in each switch along the shortest path. If a switch is an edge
    # switch, install flows based on MAC. If ta switch is centralized,
    # install flows based on IP.
    if isinstance(packet.next, ipv4):
      ip_packet = packet.next

      # ignore DHCP packets
      net_packet = ip_packet.next
      if isinstance(net_packet, udp):
        if (net_packet.srcport == dhcp.CLIENT_PORT and
            net_packet.dstport == dhcp.SERVER_PORT):
          return

      # this is the host sending a packet to its "default gateway" which doesn't
      # really exist
      true_dst = packet.dst
      if packet.dst == EthAddr(GATEWAY_DUMMY_MAC):
        true_dst = self.dynamic_topology.get_host_mac_by_ip(ip_packet.dstip)
        if true_dst is None:
          log.warning('Host with IP {0} is not on this network'.format(ip_packet.dstip))
          return

      # retrieve graph info, find shortest path between devices
      log.info("{0} Looking for path from {1} to {2}".format(dpid, packet.src, true_dst))
      graph = self.dynamic_topology.graph.copy()

      path = self.find_shortest_path(graph, str(packet.src), str(true_dst))
      log.info("path found: {0}".format(path))

      if path is None:
          log.info("No path found, waiting on mobile_host_tracker")
          return
      for i in range(1, len(path) - 1):
        device = path[i]
        log.info("adding flows to {0}".format(device))

        # if edge node, add flows for MAC
        #NOTE: checking if switch is at an edge is fine, as long as the assumption
        #      holds that only edge switches have hosts
        if self.is_edge_node(device) == True:
          self._edge_reply(ip_packet.dstip, device, path[i + 1])
          self._edge_reply(ip_packet.srcip, device, path[i - 1])

        else:   # central, so add flows for IP SUBNETS
          self._central_reply(ip_packet.dstip, device, path[i + 1],
            mobile=(ip_packet.dstip in self.dhcpd_multi.mobile_hosts.values()))
          self._central_reply(ip_packet.srcip, device, path[i - 1],
            mobile=(ip_packet.srcip in self.dhcpd_multi.mobile_hosts.values()))

    # CASE: the switch gets an ARP request from a host. In this case,
    # create an ARP reply based on the known network topology. Send this
    # back out the input port on the switch.
    elif isinstance(packet.next, arp):
      arp_packet = packet.next

      log.info("%i %i ARP %s %s => %s", dpid, event.port,
          {arp.REQUEST:"request",arp.REPLY:"reply"}.get(arp_packet.opcode,
          'op:%i' % (arp_packet.opcode,)), str(arp_packet.protosrc),
          str(arp_packet.protodst))

      if arp_packet.prototype == arp.PROTO_TYPE_IP:
        if arp_packet.hwtype == arp.HW_TYPE_ETHERNET:
          if arp_packet.protosrc != 0:
            if arp_packet.opcode == arp.REQUEST:

              # create an ARP reply header
              arp_reply = arp()
              arp_reply.hw_type = arp_packet.hwtype
              arp_reply.prototype = arp_packet.prototype
              arp_reply.hwlen = arp_packet.hwlen
              arp_reply.protolen = arp_packet.protolen
              arp_reply.opcode = arp.REPLY
              arp_reply.hwdst = arp_packet.hwsrc
              arp_reply.protodst = arp_packet.protosrc
              arp_reply.protosrc = arp_packet.protodst

              if self.dhcpd_multi.is_router(arp_packet.protodst):
                arp_reply.hwsrc = EthAddr(GATEWAY_DUMMY_MAC)
              else:
                arp_reply.hwsrc = self.dynamic_topology.get_host_mac_by_ip(
                  arp_packet.protodst)

              if arp_reply.hwsrc is None:
                #log.info("Host unknown, broadcasting ARP")
                #msg = of.ofp_packet_out(data = event.ofp)
                #msg.actions.append(of.ofp_action_output(port = all_ports))
                #event.connection.send(msg)
                log.warn('Host {0} unknown'.format(arp_packet.protodst))
                return

              # create an Ethernet header and encapsulate
              eth = ethernet(type=packet.type, src=dpid_to_mac(dpid),
                             dst=arp_packet.hwsrc)
              eth.set_payload(arp_reply)

              # send this packet back to the switch
              msg = of.ofp_packet_out()
              msg.data = eth.pack()
              msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
              msg.in_port = event.port
              event.connection.send(msg)

              log.info("%i %i answering ARP for %s" % (dpid, event.port,
                  str(arp_reply.protosrc)))
              return
    else:
      # for now, do nothing for this
      return

def launch(idle_timeout=3600):
  if not core.hasComponent("proactive_flows"):
    core.register("proactive_flows", ProactiveFlows(int(idle_timeout)))
