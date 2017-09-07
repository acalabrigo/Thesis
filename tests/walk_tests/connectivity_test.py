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

NUM_SWITCHES = 10
NUM_CORE = 5
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

def startiperf(host, server=False, client=False):
    "Tell host to repeatedly ping targets"

    assert sum(1 for x in [server, client] if x) == 1

    if server:
        # Simple ping loop
        cmd = ('iperf -s -u -i .5 > result &')
        print ( '*** Host %s running server' % host.name)
    else:
        cmd = ('iperf -c 192.168.0.2 -t 60 -u &' )
        print ( '*** Host %s running client' % host.name)

    host.cmd(cmd)

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
        edge_per_core = (num_switches - num_core) // num_core

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
        for i in range(0, num_core):
          self.addLink(switches[i], switches[i + num_core],
                       bw=1000, delay='1ms', loss=0)

        #j = 10
        #for i in range(5, 10):
          #self.addLink(switches[i], switches[j], bw=1000, delay='1ms', loss=0)
          #self.addLink(switches[j], switches[j + 1], bw=1000, delay='1ms', loss=0)
          #self.addLink(switches[j + 1], switches[j + 2], bw=1000, delay='1ms', loss=0)
          #j += 3

        h1 = self.addHost('h1', ip=None) # static host
        h2 = self.addHost('h2', ip=None) # mobile host

        self.addLink(h1, switches[5], bw=10, delay='1ms', loss=0)
        self.addLink(h2, switches[6], bw=10, delay='1ms', loss=0)

def run():
    topo = WalkTopo()
    net = Mininet(topo=topo, link=TCLink, controller=RemoteController, switch=MobilitySwitch)
    net.start()
    info('*** Network:\n')
    printConnections(net.switches)
    # wait for topology to load

    path = [8, 9, 10, 7, 8, 9, 10, 7, 8, 9, 10, 7, 8, 9, 10, 7, 8,
            9, 10, 7, 8]

    time.sleep(15)
    h1, h2, old = net.get('h1', 'h2', 's7')

    # set up hosts in starting positions
    info('*** h1 dhclient\n')
    info(h1.cmd('dhclient ' + h1.defaultIntf().name))
    info('*** h2 dhclient\n')
    info(h2.cmd('dhclient ' + h2.defaultIntf().name))

    info('*** Making sure Mininet gets IPs...\n')
    CLI(net, script='sdcan/tests/startup_tests/walk_s1')
    #info('*** Exit CLI to start walk\n')
    #CLI(net)

    # Create polling object
    fds = [host.stdout.fileno() for host in [h1, h2]]
    poller = poll()
    for fd in fds:
        poller.register(fd, POLLIN)

    # Start pings
    startiperf(h1, server=True)
    startiperf(h2, client=True)

    time.sleep(2.5)

    for s in path:
        new = net[ 's%d' % s ]
        port = randint( 10, 20 )
        info( '* Moving', h2, 'from', old, 'to', new, 'port', port, '\n' )
        hintf, sintf = moveHost( h2, old, new, newPort=port )
        h2.cmd('dhclient ' + h2.defaultIntf().name)
        old = new
        time.sleep(2.5)

    #CLI(net)
    # Stop iperf
    time.sleep(2)
    info("Shutting down...")
    for host in [h1, h2]:
        host.cmd('kill %while')

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
