# Static network represented as an undirected graph of
# switches and hosts.

# 2017 Adam Calabrigo

from pox.core import core
from pox.lib.addresses import EthAddr, IPAddr
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

def int2dpid( dpid ):
        try:
            dpid = hex( dpid )[ 2: ]
            dpid = '0' * ( 16 - len( dpid ) ) + dpid
            return dpid
        except IndexError:
            raise Exception( 'Unable to derive default datapath ID - '
                             'please either specify a dpid or use a '
                             'canonical switch name such as s23.' )

def dpid2id(dpid, type='switch'):
    dpid_str = dpid_to_str(dpid)[-1:]
    if type == 'switch':
        return 's' + dpid_str
    else:
        return'h' + dpid_str

def dpid_to_mac (dpid):
    return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

all_ports = of.OFPP_FLOOD

class Device(object):
    '''
    Superclass for all devices on the network.
    '''

    def __init__(self, name):
        self.name = name

class Switch(Device):
    '''
    OFV Switches on the network. For now, end switches will install flows
    based on MAC addresses, so they have a MAC self.table.
    '''

    def __init__(self, name, connection=None):
        '''
        Switch needs to:
            1) maintain a connection object to communicate with the OFVS
            2) keep a MAC self.table for routing
        '''

        Device.__init__(self, name)
        self.deviceToPort = {}

    def add_connection(self, connection):
        self.connection = connection

class Host(Device):
    '''
    Host is any device on the network that is not a Switch. Most
    likely this is some kind of PC.
    '''

    def __init__(self, name, mac, ip):
        Device.__init__(self, name)
        self.mac = mac
        self.ip = ip

class static_network_top(object):
    '''
    This class has knowledge of the entire switch via a network graph,
    represented as an adjacency list. Right now, this network is static
    and known.
    '''

    def __init__(self):
        '''
        This class needs to:
            1) create the static graph adjacency list
            2) create Switch objects for each switch
            3) create Host objects for each host
            4) populate static device-to-port mappings
            5) setup a listener for the ConnectionUp events
        '''

        self.graph = { 's1' : ['s5', 'h1'],                 # 1
                       's2' : ['s5', 'h2'],
                       's3' : ['s5'],
                       's4' : ['s5'],
                       's5' : ['s1', 's2', 's3', 's4'],
                       'h1' : ['s1'],
                       'h2' : ['s2']}

        self.switches = { 's1' : Switch('s1'),              # 2
                          's2' : Switch('s2'),
                          's3' : Switch('s3'),
                          's4' : Switch('s4'),
                          's5' : Switch('s5') }

        self.hosts = { 'h1' : Host('h1', EthAddr('00:00:00:00:01:01'), IPAddr('10.0.0.1')),  # 3
                       'h2' : Host('h2', EthAddr('00:00:00:00:01:02'), IPAddr('10.0.0.2'))}

        self.table = {}

        # manually adding port info, this will need to be done dynamically
        # at some point
        self.switches['s1'].deviceToPort['s5'] = 1  # 4
        self.switches['s1'].deviceToPort['h1'] = 2
        self.switches['s2'].deviceToPort['s5'] = 1
        self.switches['s2'].deviceToPort['h2'] = 2
        self.switches['s3'].deviceToPort['s5'] = 1
        self.switches['s4'].deviceToPort['s5'] = 1
        self.switches['s5'].deviceToPort['s1'] = 1
        self.switches['s5'].deviceToPort['s2'] = 2
        self.switches['s5'].deviceToPort['s3'] = 3
        self.switches['s5'].deviceToPort['s4'] = 4

        core.openflow.addListeners(self)    # 5

    def is_edge_node(self, name):
        '''
        Determines whether a switch in the network is centralized or
        at an edge.
        '''

        adj_nodes = self.graph.get(name)
        if adj_nodes is not None:
            adj_switches = [n for n in adj_nodes if n[0] == 's']
            if len(adj_switches) > 1:
                return False
            else:
                return True
        else:
            return False

    def find_shortest_path(self, start, end, path=[]):
        '''
        Finds the shortest path between two devices.
        '''

        path = path + [start]
        if start == end:
            return path
        if not self.graph.has_key(start):
            return None
        shortest = None
        for node in self.graph[start]:
            if node not in path:
                newpath = self.find_shortest_path(node, end, path)
                if newpath:
                    if not shortest or len(newpath) < len(shortest):
                        shortest = newpath
        return shortest

    def get_host_by_mac(self, mac):
        '''
        Looks through the hosts, finds the host with the given MAC (if it
        exists) and returns the hosts name.
        '''

        host = [m.name for m in self.hosts.values() if m.mac == mac]
        if host != []:
            return host[0]
        else:
            return None

    def get_host_mac(self, ip):
        '''
        Essentially does what an ARP table would do. Given a host IP, finds
        that host's MAC address.
        '''

        host = [m.mac for m in self.hosts.values() if m.ip == ip]
        if host != []:
            return host[0]
        else:
            return None

    def _handle_ConnectionUp (self, event):
        '''
        Simple handler for ConnectionUp events. All it does is add the
        connection information to the Switch objects.
        '''

        log.info("Connection {0} linked to switch {1}".format(event.connection,
            dpid2id(event.connection.dpid)))
        self.switches[dpid2id(event.connection.dpid)].add_connection(event.connection)

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

        # CASE: ipv4 traffic into the switch. In this case, create a flow table
        # entry in each switch along the shortest path. If a switch is an edge
        # switch, install flows based on MAC. If ta switch is centralized,
        # install flows based on IP.
        if isinstance(packet.next, ipv4):
            ip_packet = packet.next
            log.info("%i %i IP %s => %s", dpid,event.port,
                ip_packet.srcip, ip_packet.dstip)

            # retrieve graph info, find shortest path between devices
            src_name = self.get_host_by_mac(packet.src)
            dst_name = self.get_host_by_mac(packet.dst)
            log.info("Looking for path from {0} to {1}".format(src_name, dst_name))
            path = self.find_shortest_path(src_name, dst_name)
            log.info("path found: {0}".format(path))

            for i in range(1, len(path) - 1):
                device = path[i]
                log.info("adding flows to {0}".format(device))

                # if edge node, add flows for MAC
                if self.is_edge_node(device) == True:

                    # flow mod for outgoing packets
                    msg = of.ofp_flow_mod()
                    msg.match.dl_dst = packet.dst
                    msg.match.dl_src = packet.src
                    msg.actions.append(of.ofp_action_output(port =
                        self.switches[device].deviceToPort[path[i + 1]]))
                    self.switches[device].connection.send(msg)

                    # flow mod for return packets
                    msg = of.ofp_flow_mod()
                    msg.match.dl_dst = packet.src
                    msg.match.dl_src = packet.dst
                    msg.actions.append(of.ofp_action_output(port =
                        self.switches[device].deviceToPort[path[i - 1]]))
                    self.switches[device].connection.send(msg)

                else:   # central, so add flows for IP

                    # flow mod for outgoing packets
                    msg = of.ofp_flow_mod()
                    msg.match.dl_type = ethernet.IP_TYPE
                    msg.match.nw_dst = ip_packet.dstip
                    msg.match.nw_src = ip_packet.srcip
                    msg.actions.append(of.ofp_action_output(port =
                        self.switches[device].deviceToPort[path[i + 1]]))
                    self.switches[device].connection.send(msg)

                    # flow mod for return packets
                    msg = of.ofp_flow_mod()
                    msg.match.dl_type = ethernet.IP_TYPE
                    msg.match.nw_dst = ip_packet.srcip
                    msg.match.nw_src = ip_packet.dstip
                    msg.actions.append(of.ofp_action_output(port =
                        self.switches[device].deviceToPort[path[i - 1]]))
                    self.switches[device].connection.send(msg)

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
                            arp_reply.hwsrc = self.get_host_mac(arp_packet.protodst)
                            if arp_reply.hwsrc is None:
                                log.info("problem here")
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

def launch ():
    '''
    On startup, register the network controller.
    '''

    core.registerNew(static_network_top)
