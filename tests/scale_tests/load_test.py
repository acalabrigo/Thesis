#!/usr/bin/python
# Adam Calabrigo 2017

# Tests how the mobility interval impacts the controller load. Creates a 35 switch
# Mininet topology and connects a given number of hosts. Then all those hosts are
# moved around the network for 1 minute.  The interval in which hosts are moved
# is specified. The get_flow_data_with_percent.py script is used to collect flow
# table statistics using ovs-ofctl.

# Usage: sudo python load_test.py <num_hosts> <move interval>

from mininet.topo import Topo

from mininet.log import setLogLevel, info, output, warn
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import Node

import mobility_switch
from select import poll, POLLIN
from random import randint, SystemRandom
import time
from math import log
from threading import Thread, Event
import os
import sys
import subprocess

NUM_SWITCHES = 35
NUM_CORE = 5

def int2dpid(dpid):
        try:
            dpid = hex(dpid)[2:]
            dpid = '0' * (16 - len(dpid)) + dpid
            return dpid
        except IndexError:
            raise Exception( 'Unable to derive default datapath ID - '
                             'please either specify a dpid or use a '
                             'canonical switch name such as s23.' )

def chunks(l, n):
    "Divide list l into chunks of size n - thanks Stackoverflow"
    return [ l[ i: i + n ] for i in range( 0, len( l ), n ) ]

def startpings(host, targetip):
    "Tell host to repeatedly ping targets"

    # Simple ping loop
    cmd = 'ping %s -c 1 &' % targetip
    '''cmd = ( 'while true; do '
            ' for ip in %s; do ' % targetip +
            ' echo -n %s "->" $ip ' % host.IP() +
            '  `ping -c1 -w 1 $ip | grep packets` ;'
            '  sleep 1;'
            ' done; '
            'done &' )'''

    info('*** Host %s (%s) will be pinging ip: %s\n' %
            (host.name, host.IP(), targetip))
    host.cmd(cmd)


class SupportTopo(Topo):
    def build(self, **_opts):
        # these params define our network
        num_switches = NUM_SWITCHES
        num_core = NUM_CORE

        # add switches to the network
        switches = [self.addSwitch('s{0}'.format(i), dpid=int2dpid(i))
                    for i in range(1, num_switches + 1)]

        # create the core mesh, 1 Gbps links
        mesh = {key: set([]) for key in switches}
        for i in range(0, num_core):
            for j in range(i + 1, num_core):
                if j not in mesh[switches[i]]:
                    self.addLink(switches[i], switches[j],
                                 bw=1000, delay='1ms', loss=0)
                    mesh[switches[i]].add(j)

        edge_switches = switches[2*num_core:]
        for i in range(0, num_core):
            self.addLink(switches[i], switches[i + num_core], bw=1000,
                         delay='1ms', loss=0)

        LAN_size = 5
        offset = 0
        num_LANs = len(edge_switches) // LAN_size
        for i in range(0, num_LANs):
            self.addLink(switches[num_core + i], edge_switches[offset], bw=1000,
                         delay='1ms', loss=0)
            s = edge_switches[offset]
            offset += 1
            for j in range(0, LAN_size - 1):
                self.addLink(s, edge_switches[offset], bw=1000,
                             delay='1ms', loss=0)
                offset += 1


def run(num_hosts, move_interval):
    # 2 controllers - c0 for SD-MCAN core, c1 for LANs
    c0 = RemoteController('c0', ip='127.0.0.1', port=6633)
    c1 = RemoteController('c1', ip='127.0.0.1', port=6634)

    cmap = {}
    for i in range(1, 11):
        cmap['s%s' % str(i)] = c0
    for i in range(11, 41):
        cmap['s%s' % str(i)] = c1

    class ControllerSwitch(mobility_switch.MobilitySwitch):
        ''' Allows switches to connect to a specific controller. '''
        def start( self, controllers ):
            return mobility_switch.MobilitySwitch.start(self, [cmap[self.name]])

    # build topology
    topo = SupportTopo()
    net = Mininet(topo=topo, link=TCLink, switch=ControllerSwitch, build=False)
    for c in [c0, c1]:
        net.addController(c)
    net.build()
    net.start()
    mobility_switch.printConnections(net.switches)

    # wait for topology to load
    time.sleep(20)

    # get the edge switches
    switches = [net.get('s{0}'.format(i)) for i in range(10, NUM_SWITCHES + 1)]
    subnets = chunks(switches, 5)

    hosts = []  # (host, switch) pairs
    not_pinged = []
    ping = {}

    # good random number generator
    secure_rand = SystemRandom()

    def getstats(percent):
        info('\ncalling script\n')
        p = subprocess.Popen(["sudo", "python", "get_flow_data_with_percent.py",
                              str(10), "flow_data_{0}_{1}".format(
                              num_hosts, move_interval), str(percent)],
                             stdout=subprocess.PIPE)

    # use this to move hosts
    def movehosts():
        h_list = hosts[:]
        # move these hosts
        for host in h_list:
            if host[0].name == 'h1': continue # don't move h1
            # get a new switch to connect to
            other_nets = [s for s in subnets if host[1] not in s]
            net = secure_rand.choice(other_nets)
            new = secure_rand.choice(net)

            # find an open port on the switch
            port = 0
            sports = new.ports.values()

            for i in range(0, 48):
                if i not in sports:
                    port = i
                    break

            if port != 0:
                # move the host
                info('\n* Moving', host[0], 'from', host[1], 'to', new, 'port', port, '\n')
                hintf, sintf = mobility_switch.moveHost(host[0], host[1], new, newPort=port)
                host[0].cmd('dhclient ' + host[0].defaultIntf().name)
                startpings(host[0], ping[host[0]])
                hi = hosts.index(host)
                if hi is not None:
                    hosts[hi] = (host[0], new)
                else:
                    warn('\nTHIS SHOULD NOT HAPPEN\n')
            time.sleep(move_interval)

    info('*** Adding hosts...\n')
    # add hosts
    s = 0
    ns = 5
    for h in range(1, num_hosts + 1):
        # create the host
        host = net.addHost('h{0}'.format(h))
        added = False

        while added is False:
            try:
                # get a switch to attach the host to and attach it
                switch = secure_rand.choice(subnets[s % ns])
                link = net.addLink(host, switch, bw=1, delay='1ms', loss=0)
                switch.attach(link.intf2)
                info('\n*** Added {0} to {1} port {2}\n'.format(host.name, switch.name, link.intf2.name))
                added = True
            except:
                added = False

        # get an IP for the host
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
        host.cmd('dhclient ' + host.defaultIntf().name)

        # make sure Mininet recognizes the assigned IP - this is silly and shouldn't
        # be needed, but oh well
        script = '{0}_start'.format(host.name)
        with open(script, 'w') as f:
            f.write('{0} ping -c 1 -W 1 {0}\n'.format(host.name))
        CLI(net, script=script)
        os.remove(script)

        # ping another host if there is one
        other_hosts = [h for h in not_pinged if h[0] is not host]
        if other_hosts != []:
            other_host = secure_rand.choice(other_hosts)
            ip = other_host[0].IP()
            if ip is not None:
                startpings(host, ip)
                not_pinged.remove(other_host)
                ping[host] = ip
        hosts.append((host,switch))
        not_pinged.append((host,switch))
        getstats(host.name)
        s += 1

    # move
    CLI(net)
    movehosts()

    # stop the network
    net.stop()

if __name__ == '__main__':

    if len(sys.argv) != 3:
        print('usage: load_test.py <num hosts> <move interval>')
        exit()
    setLogLevel('info')

    num_hosts = int(sys.argv[1])
    move_interval = int(sys.argv[2])
    run(num_hosts, move_interval)
