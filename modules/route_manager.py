# route_manager.py 2017 Adam Calabrigo
# Install proactive and reactive flow rules based on topology_tracker
# and dhcp_server.

# POX
from pox.core import core
from pox.lib.addresses import EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
import pox.openflow.libopenflow_01 as of

# networkX
from networkx.algorithms.shortest_paths.generic import shortest_path

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
    core.listen_to_dependencies(self, ['topology_tracker', 'dhcp_server'], short_attrs=True)

  def _all_dependencies_met (self):
    '''
    When all modules are loaded, install base flow rules based on network.
    '''

    graph = self.topology_tracker.graph
    edge_switches = list(self.dhcp_server.edges)

    # install subnet-based rules between core switches
    # TODO: optimize this, right now it doesn't matter
    for s1 in edge_switches:
      for s2 in [e for e in edge_switches if e != s1]:
        sp = shortest_path(graph, source = s1, target = s2)
        subnet = self.dhcp_server.edge_to_tuple[sp[len(sp) - 1]][0]
        inlabel = None
        for k in range(0, len(sp) - 1):
          info = LabelInfo(sp[k], sp[k + 1], subnet)
          outlabel = self.get_label(info)
          if k > 0:
            self.install_path_rule(info, inlabel, outlabel)
          inlabel = outlabel

    log.info("route_manager ready")

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

    # CASE 1: ipv4 traffic into the switch
    if isinstance(packet.next, ipv4):
      ip_packet = packet.next

      # this is the host sending a packet to its "default gateway" which doesn't
      # really exist
      dst_host = self.topology_tracker.get_host_info(ip_packet.dstip)
      true_dst = dst_host.macaddr

      dst_info = self.dhcp_server.edge_to_tuple[dst_host.dpid]
      dst_subnet = dst_info[0]
      dst_next_hop = dst_info[1]

      src_info = self.dhcp_server.edge_to_tuple[dpid]
      subnet = src_info[0]
      next_hop = src_info[1]

      if dst_subnet == subnet:
        actions = self.install_same_subnet_rule(dpid, event.connection,
                                                ip_packet.dstip, true_dst, packet.dst)
      else:
        # forward rules
        push_info = LabelInfo(dpid, next_hop, dst_subnet)
        pop_info = LabelInfo(dst_next_hop, dst_host.dpid, dst_subnet)
        actions = self.install_push_rule(push_info, self.get_label(push_info),
                                         ip_packet.dstip, true_dst, packet.dst)
        self.install_pop_rule(dst_host.dpid, dst_host.macaddr, self.get_label(pop_info))

      # forward packet
      msg = of.ofp_packet_out(data = event.ofp)
      msg.actions = actions
      event.connection.send(msg)

      log.debug("added flows for {0} --> {1}".format(ip_packet.srcip, ip_packet.dstip))

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

              if self.dhcp_server.is_router(arp_packet.protodst):
                arp_reply.hwsrc = EthAddr(GATEWAY_DUMMY_MAC)
              else:
                host = self.topology_tracker.get_host_info(arp_packet.protodst)
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

  # flow installation functions
  def install_same_subnet_rule (self, dpid, connection, ip, raddr, dstaddr):
    '''
    When the destination subnet is the same as the source subnet but
    a host is mobile, install a simpler rule without labels.
    '''

    # message for switch
    msg = of.ofp_flow_mod()

    # match on MAC dst and IP dst
    msg.match.dl_src = None # wildcard source MAC
    msg.match.dl_dst = dstaddr
    msg.match.dl_type = ethernet.IP_TYPE
    msg.match.nw_src = None # wildcard source IP
    msg.match.nw_dst = ip

    # actions - rewrite MAC dst and set port
    actions = []
    actions.append(of.ofp_action_dl_addr.set_dst(raddr))
    # set output port action
    port = self.topology_tracker.get_link_port(dpid, str(raddr))
    if port is None:
      log.warn("No port connecting {0} --> {1}".format(dpid, raddr))
      return
    actions.append(of.ofp_action_output(port = port))
    msg.actions = actions

    # set a timeout and send
    msg.idle_timeout = self.idle_timeout
    connection.send(msg)

    return actions

  def install_push_rule (self, info, label, ip, raddr, dstaddr):
    '''
    Install a flow rule on an edge switch to push a label
    onto a flow.
    '''

    # message for switch
    msg = of.ofp_flow_mod()

    # match on MAC dst and IP dst
    msg.match.dl_src = None # wildcard source MAC
    msg.match.dl_dst = dstaddr
    msg.match.dl_type = ethernet.IP_TYPE
    msg.match.nw_src = None # wildcard source IP
    msg.match.nw_dst = ip

    # actions - rewrite MAC dst and push label
    actions = []
    actions.append(of.ofp_action_dl_addr.set_dst(raddr))
    actions.append(of.ofp_action_vlan_vid(vlan_vid=label))

    # set output port action
    port = self.topology_tracker.get_link_port(info.dpid1, info.dpid2)
    if port is None:
      log.warn("No port connecting {0} --> {1}".format(info.dpid1, info.dpid2))
      return
    actions.append(of.ofp_action_output(port = port))
    msg.actions = actions

    # set a timeout and send
    msg.idle_timeout = self.idle_timeout
    self.topology_tracker.graph.node[info.dpid1]['connection'].send(msg)

    return actions

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
    port = self.topology_tracker.get_link_port(dpid, str(mac))
    if port is None:
      log.warn("No port connecting {0} --> {1}".format(dpid, mac))
      return
    msg.actions.append(of.ofp_action_output(port = port))

    # set a timeout and send
    msg.idle_timeout = self.idle_timeout
    self.topology_tracker.graph.node[dpid]['connection'].send(msg)

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
    port = self.topology_tracker.get_link_port(info.dpid1, info.dpid2)
    if port is None:
      log.warn("No port connecting {0} --> {1}".format(info.dpid1, info.dpid2))
      return
    msg.actions.append(of.ofp_action_output(port = port))

    # set a timeout and send
    #msg.idle_timeout = None # these flows are static
    self.topology_tracker.graph.node[info.dpid1]['connection'].send(msg)


def launch (idle_timeout=10):
  if not core.hasComponent("route_manager"):
    core.register("route_manager", ProactiveFlows(int(idle_timeout)))
