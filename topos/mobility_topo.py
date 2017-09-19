#!/usr/bin/python
# Adam Calabrigo 2017

# Defines a Mininet topology. Import into your Mininet scripts.

from mininet.topo import Topo

# not my own function
def int2dpid(dpid):
        try:
            dpid = hex(dpid)[2:]
            dpid = '0' * (16 - len(dpid)) + dpid
            return dpid
        except IndexError:
            raise Exception( 'Unable to derive default datapath ID - '
                             'please either specify a dpid or use a '
                             'canonical switch name such as s23.' )

# Topology on which walk tests are run
class MobilityTopo(Topo):
    def build(self, **_opts):
        # these params define our network
        num_switches = 6
        num_core = 3

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

        h1 = self.addHost('h1', ip=None) # static host
        h2 = self.addHost('h2', ip=None) # mobile host

        self.addLink(h1, switches[3], bw=100, delay='1ms', loss=0)
        self.addLink(h2, switches[4], bw=100, delay='1ms', loss=0)
