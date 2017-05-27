#!/usr/bin/python


from mininet.topo import Topo

from mininet.log import setLogLevel, info, output, warn
from mininet.cli import CLI
from mininet.node import OVSSwitch, Controller, RemoteController
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import Node

from select import poll, POLLIN
from random import randint
import time
from math import log
import thread

NUM_SWITCHES = 16
NUM_CORE = 2
NUM_HOSTS = 2
FANOUT = 2

def int2dpid(dpid):
        try:
            dpid = hex(dpid)[2:]
            dpid = '0' * (16 - len(dpid)) + dpid
            return dpid
        except IndexError:
            raise Exception( 'Unable to derive default datapath ID - '
                             'please either specify a dpid or use a '
                             'canonical switch name such as s23.' )

def startpings( host, targetips ):
    "Tell host to repeatedly ping targets"

    targetips.append( '10.0.0.200' )

    targetips = ' '.join( targetips )

    # BL: Not sure why loopback intf isn't up!
    host.cmd( 'ifconfig lo up' )

    # Simple ping loop
    cmd = ( 'while true; do '
            ' for ip in %s; do ' % targetips +
            '  echo -n %s "->" $ip ' % host.IP() +
            '   `ping -c1 -w 1 $ip | grep packets` ;'
            '  sleep 1;'
            ' done; '
            'done &' )

    print ( '*** Host %s (%s) will be pinging ips: %s' %
           ( host.name, host.IP(), targetips ) )

    host.cmd( cmd )

class MobilitySwitch(OVSSwitch):
    "Switch that can reattach and rename interfaces"

    def delIntf(self, intf):
        "Remove (and detach) an interface"
        port = self.ports[intf]
        del self.ports[intf]
        del self.intfs[port]
        del self.nameToIntf[intf.name]

    def addIntf(self, intf, rename=False, **kwargs):
        "Add (and reparent) an interface"
        OVSSwitch.addIntf(self, intf, **kwargs)
        intf.node = self
        if rename:
            self.renameIntf(intf)

    def attach(self, intf):
        "Attach an interface and set its port"
        port = self.ports[intf]
        if port:
            if self.isOldOVS():
                self.cmd('ovs-vsctl add-port', self, intf)
            else:
                self.cmd('ovs-vsctl add-port', self, intf,
                         '-- set Interface', intf,
                         'ofport_request=%s' % port)
            self.validatePort(intf)

    def validatePort(self, intf):
        "Validate intf's OF port number"
        ofport = int(self.cmd('ovs-vsctl get Interface', intf,
                              'ofport'))
        if ofport != self.ports[intf]:
            warn('WARNING: ofport for', intf, 'is actually', ofport,
                  '\n')

    def renameIntf(self, intf, newname=''):
        "Rename an interface (to its canonical name)"
        intf.ifconfig('down')
        if not newname:
            newname = '%s-eth%d' % (self.name, self.ports[intf])
        intf.cmd('ip link set', intf, 'name', newname)
        del self.nameToIntf[intf.name]
        intf.name = newname
        self.nameToIntf[intf.name] = intf
        intf.ifconfig('up')

    def moveIntf(self, intf, switch, port=None, rename=True):
        "Move one of our interfaces to another switch"
        self.detach(intf)
        self.delIntf(intf)
        switch.addIntf(intf, port=port, rename=rename)
        switch.attach(intf)


def printConnections(switches):
    "Compactly print connected nodes to each switch"
    for sw in switches:
        output('%s: ' % sw)
        for intf in sw.intfList():
            link = intf.link
            if link:
                intf1, intf2 = link.intf1, link.intf2
                remote = intf1 if intf1.node != sw else intf2
                output('%s(%s) ' % (remote.node, sw.ports[intf]))
        output('\n')


def moveHost(host, oldSwitch, newSwitch, newPort=None):
    "Move a host from old switch to new switch"
    hintf, sintf = host.connectionsTo(oldSwitch)[ 0 ]
    oldSwitch.moveIntf(sintf, newSwitch, port=newPort)
    return hintf, sintf

class WalkTopo(Topo):
    def build(self, **_opts):
        # these params define our network
        num_switches = NUM_SWITCHES
        num_core = NUM_CORE
        num_hosts = NUM_HOSTS
        fanout = FANOUT

        # number of edge switches per core switch
        edge_per_core = (num_switches - num_core) // 2

        # add switches to the network
        switches = [self.addSwitch('s{0}'.format(i), dpid=int2dpid(i))
                    for i in range(1, num_switches + 1)]

        # create the core mesh, 10 Gbps links
        mesh = {key: set([]) for key in switches}
        for i in range(0, num_core):
            for j in range(i + 1, num_core):
                if j not in mesh[switches[i]]:
                    self.addLink(switches[i], switches[j],
                                 bw=1000, delay='1ms', loss=0)
                    mesh[switches[i]].add(j)

        edge_switches = switches[num_core:]
        height = int(log(edge_per_core, fanout))
        print(height)
        # add edge switches, 1 Gbps links
        offset = 0
        for i in range(0, num_core):
            self.addLink(switches[i], edge_switches[offset],
                         bw=1000, delay='1ms', loss=0)
            nodes = [edge_switches[offset]]
            offset += 1
            added = 0
            while nodes != []:
                for j in range(0, fanout):
                    if added < edge_per_core - 1:
                        self.addLink(nodes[0], edge_switches[offset + j],
                                     bw=1000, delay='1ms', loss=0)
                        nodes.append(edge_switches[offset + j])
                        added += 1
                offset += fanout
                if added >= edge_per_core - 1:
                    break
                nodes.remove(nodes[0])

        # add hosts, don't set IPs
        #hosts = [self.addHost('h{0}'.format(i), ip=None)
        #         for i in range(1, num_hosts + 1)]

        h1 = self.addHost('h1',ip=None)  # mobile host
        h2 = self.addHost('h2', ip='10.151.120.254/24') # static host

        self.addLink(h1, switches[5], bw=1000, delay='1ms', loss=0)
        self.addLink(h2, switches[15], bw=1000, delay='1ms', loss=0)

def run():
    topo = WalkTopo()
    net = Mininet(topo=topo, link=TCLink, controller=RemoteController, switch=MobilitySwitch)
    net.start()
    info('*** Network:\n')
    printConnections(net.switches)
    # wait for topology to load
    time.sleep(15)

    h1, h2, old1 = net.get('h1', 'h2', 's5')


    '''# Create polling object
    fds = [ host.stdout.fileno() for host in hosts ]
    poller = poll()
    for fd in fds:
        poller.register( fd, POLLIN )

    # Start pings
    for subnet in subnets:
        ips = [ host.IP() for host in subnet ]
        for host in subnet:
            startpings( host, ips )

    # Monitor output
    endTime = time() + seconds
    while time() < endTime:
        readable = poller.poll(1000)
        for fd, _mask in readable:
            node = Node.outToNode[ fd ]
            print '%s:' % node.name, node.monitor().strip()

    # Stop pings
    for host in hosts:
        host.cmd( 'kill %while' )'''

    # set up hosts in starting positions
    info('*** h1 dhclient\n')
    info(h1.cmd('dhclient ' + h1.defaultIntf().name))
    info('*** h2 setting default gateway')
    info(h2.cmd('ip route add default via 10.151.120.1'))
    CLI(net, script='walk_s1')
    net.iperf([h1, h2])

    '''n = 1
    i = 0
    while i < n:
        s = 7
        new1 = net['s%d' % s]
        port1 = randint(10, 20)
        info('* Moving', h1, 'from', old1, 'to', new1, 'port', port1, '\n')
        hintf, sintf = moveHost(h1, old1, new1, newPort=port1)
        info('*', hintf, 'is now connected to', sintf, '\n')

        time.sleep(1)

        s = 8
        new2 = net['s%d' % s]
        port2 = randint(10, 20)
        info('* Moving', h2, 'from', old2, 'to', new2, 'port', port2, '\n')
        hintf, sintf = moveHost(h2, old2, new2, newPort=port2)
        info('*', hintf, 'is now connected to', sintf, '\n')

        time.sleep(1)

        info('* New network:\n')
        printConnections(net.switches)
        info('*** h1 dhclient\n')
        h1.cmd('dhclient ' + h1.defaultIntf().name)
        info('*** h2 dhclient\n')
        h1.cmd('dhclient ' + h2.defaultIntf().name)
        info( '*** Testing connectivity:\n' )
        CLI(net, script='mt3_s1')

        old1 = new1
        old2 = new2
        i += 1'''
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
