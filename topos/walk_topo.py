#!/usr/bin/python
# Adam Calabrigo 2017

from mininet.topo import Topo

# not my function
# TODO: put this function in its own file because it is duplicated in these topos

def int2dpid(dpid):
        try:
            dpid = hex(dpid)[2:]
            dpid = '0' * (16 - len(dpid)) + dpid
            return dpid
        except IndexError:
            raise Exception( 'Unable to derive default datapath ID - '
                             'please either specify a dpid or use a '
                             'canonical switch name such as s23.' )

# topology on which walk tests are run
class WalkTopo(Topo):
    def build(self, **_opts):
        # these params define our network
        num_switches =10
        num_core = 5

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

        self.addLink(h1, switches[5], bw=100, delay='1ms', loss=0)
        self.addLink(h2, switches[6], bw=100, delay='1ms', loss=0)
