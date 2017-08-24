# proactive_flows.py 2017 Adam Calabrigo
# Install proactive flow rules based on dynamic_topology and dhcpd_multi.

# POX
from pox.core import core
from pox.lib.addresses import EthAddr, IPAddr, parse_cidr
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

# networkX
from networkx.algorithms.shortest_paths.generic import shortest_path

import time
from collections import namedtuple

log = core.getLogger()
all_ports = of.OFPP_FLOOD
GATEWAY_DUMMY_MAC = '03:00:00:00:be:ef'
LABEL_START = 16

LabelInfo = namedtuple('LabelInfo', 'dpid1 dpid2 dst_subnet')

def dpid_to_mac (dpid):
  '''
  Convert the dpid to a MAC address.
  '''

  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))


class ProactiveFlows (object):
  '''
  Install flow rules based on network topology. Rules are installed based on
  switch location in the network. Core switches receive broad L3 rules at the
  subnet level, while non-core switches receive IP-specific rules.
  '''

  def __init__ (self, idle_timeout=300):
    self.idle_timeout = idle_timeout
    self.label_table = {} # (dpid1, dpid2, dst_subnet) -> label number
    self.label_count = LABEL_START
    core.openflow.addListeners(self)
    core.listen_to_dependencies(self, ['dynamic_topology', 'dhcpd_multi'], short_attrs=True)

  def _all_dependencies_met (self):
    '''
    When all modules are loaded, install base flow rules based on network.
    '''

    graph = self.dynamic_topology.graph
    edge_switches = list(self.dhcpd_multi.edges)

    # install subnet-based rules between core switches
    for s1 in edge_switches:
      for s2 in [e for e in edge_switches if e != s1]:
        sp = shortest_path(graph, source = s1, target = s2)
        subnet = self.dhcpd_multi.get_switch_subnet(sp[len(sp) - 1])
        for k in range(0, len(sp) - 1):
          info = LabelInfo(sp[k], sp[k + 1], subnet)
          outlabel = self.get_label(info)
          if k > 0:
            self.install_path_rule(info, inlabel, outlabel)
          inlabel = outlabel

    log.info("proactive_flows ready")

  def get_label (self, info):
    '''
    Given information about a link and destination subnet,
    return the proper label or allocate a new label.
    '''

    if info not in self.label_table:
      self.label_table[info] = self.label_count
      self.label_count += 1
    return self.label_table[info]

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

    # CASE 1: ipv4 traffic into the switch
    if isinstance(packet.next, ipv4):
      ip_packet = packet.next

      # ignore DHCP packets
      net_packet = ip_packet.next
      if isinstance(net_packet, udp):
        if (net_packet.srcport == dhcp.CLIENT_PORT and
            net_packet.dstport == dhcp.SERVER_PORT):
          log.warn("saw DHCP packet, this shouldn't happen")
          return

      # this is the host sending a packet to its "default gateway" which doesn't
      # really exist
      true_dst = packet.dst
      dst_host = self.dynamic_topology.get_host_info(ip_packet.dstip)
      if packet.dst == EthAddr(GATEWAY_DUMMY_MAC):
        true_dst = dst_host.macaddr
        if true_dst is None:
          log.warning('Host with IP {0} is not on this network'.format(ip_packet.dstip))
          return

      dst_subnet = self.dhcpd_multi.get_switch_subnet(dst_host.dpid)
      next_hop = self.dhcpd_multi.edge_to_core[dpid]

      push_info = LabelInfo(dpid, next_hop, dst_subnet)
      pop_info = LabelInfo(self.dhcpd_multi.edge_to_core[dst_host.dpid],
                           dst_host.dpid, dst_subnet)
      self.install_push_rule(push_info, self.get_label(push_info),
                             ip_packet.dstip, true_dst)
      self.install_pop_rule(dst_host.dpid, dst_host.macaddr, self.get_label(pop_info))
      log.debug("added flows for {0} --> {1}".format(ip_packet.srcip, ip_packet.dstip))

      # resend packet
      # forward the buffer out the first hop port
      port = self.dynamic_topology.get_link_port(dpid, next_hop)
      msg = of.ofp_packet_out(data = event.ofp)
      msg.actions.append(of.ofp_action_output(port = port))
      event.connection.send(msg)

    # CASE 2: the switch gets an ARP request from a host. In this case,
    # create an ARP reply based on the known network topology. Send this
    # back out the input port on the switch.
    elif isinstance(packet.next, arp):
      arp_packet = packet.next

      log.debug("%i %i ARP %s %s => %s", dpid, event.port,
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
                host = self.dynamic_topology.get_host_info(arp_packet.protodst)
                arp_reply.hwsrc = host.macaddr

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

              log.debug("%i %i answering ARP for %s" % (dpid, event.port,
                  str(arp_reply.protosrc)))
              return

      return

  def install_push_rule (self, info, label, ip, raddr):
    '''
    Install a flow rule on an edge switch to push a label
    onto a flow.
    '''

    # message for switch
    msg = of.ofp_flow_mod()

    # match on MAC dst and IP dst
    msg.match.dl_src = None # wildcard source MAC
    msg.match.dl_dst = EthAddr(GATEWAY_DUMMY_MAC)
    msg.match.dl_type = ethernet.IP_TYPE
    msg.match.nw_src = None # wildcard source IP
    msg.match.nw_dst = ip

    # actions - rewrite MAC dst and push label
    msg.actions.append(of.ofp_action_dl_addr.set_dst(raddr))
    msg.actions.append(of.ofp_action_vlan_vid(vlan_vid=label))

    # set output port action
    port = self.dynamic_topology.get_link_port(info.dpid1, info.dpid2)
    if port is None:
      log.warn("No port connecting {0} --> {1}".format(info.dpid1, info.dpid2))
      return
    msg.actions.append(of.ofp_action_output(port = port))

    # set a timeout and send
    msg.idle_timeout = self.idle_timeout
    self.dynamic_topology.graph.node[info.dpid1]['connection'].send(msg)

  def install_pop_rule (self, dpid, mac, label):
    '''
    Install a flow rule on an edge switch to pop a label
    onto a flow.
    '''

    # message for switch
    msg = of.ofp_flow_mod()

    # match on MAC dst and IP dst
    msg.match.dl_src = None # wildcard source MAC
    msg.match.dl_dst = None
    msg.match.dl_type = ethernet.IP_TYPE
    msg.match.dl_vlan = label

    # actions - pop label
    msg.actions.append(of.ofp_action_strip_vlan())

    # set output port action
    port = self.dynamic_topology.get_link_port(dpid, str(mac))
    if port is None:
      log.warn("No port connecting {0} --> {1}".format(dpid, mac))
      return
    msg.actions.append(of.ofp_action_output(port = port))

    # set a timeout and send
    msg.idle_timeout = self.idle_timeout
    self.dynamic_topology.graph.node[dpid]['connection'].send(msg)

  def install_path_rule (self, info, inlabel, outlabel):
    '''
    Install a flow rule on a core switch to route based on label.
    '''

    # message for switch
    msg = of.ofp_flow_mod()

    # match on MAC dst and IP dst
    msg.match.dl_src = None # wildcard MACs
    msg.match.dl_dst = None
    msg.match.dl_vlan = inlabel

    # actions - rewrite MAC dst and push label
    msg.actions.append(of.ofp_action_vlan_vid(vlan_vid=outlabel))

    # set output port action
    port = self.dynamic_topology.get_link_port(info.dpid1, info.dpid2)
    if port is None:
      log.warn("No port connecting {0} --> {1}".format(info.dpid1, info.dpid2))
      return
    msg.actions.append(of.ofp_action_output(port = port))

    # set a timeout and send
    #msg.idle_timeout = None # these flows are static
    self.dynamic_topology.graph.node[info.dpid1]['connection'].send(msg)

def launch (idle_timeout=300):
  if not core.hasComponent("proactive_flows"):
    core.register("proactive_flows", ProactiveFlows(int(idle_timeout)))
