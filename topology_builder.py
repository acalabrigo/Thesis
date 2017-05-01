#!/usr/bin/python

# Script to create mininet topologies
# 2017 Adam Calabrigo

import sys
if len(sys.argv) <= 2:
    print("Usage: ./topology_builder.py <num switches> <num hosts> <bandwidth>")
    exit()

switches = int(sys.argv[1])
hosts = int(sys.argv[2])

outfile = 'topos/{0}_{1}.py'.format(switches, hosts)
offset = 0

hosts_per_switch = hosts // switches
extra_hosts = hosts % switches

print('hosts per edge switches: {0} with {1} extra'.format(hosts_per_switch,
                                                            extra_hosts))
with open(outfile, 'w') as f:
    # add imports
    f.write('#!/usr/bin/python\n')
    f.write('from mininet.topo import Topo\n')
    f.write('from mininet.net import Mininet\n')
    f.write('from mininet.node import Controller, RemoteController, OVSKernelSwitch, UserSwitch\n')
    f.write('from mininet.cli import CLI\n')
    f.write('from mininet.log import setLogLevel\n')
    f.write('from mininet.link import Link, TCLink\n')
    f.write('import time\n')

    # start topo class, add controller
    f.write('\n\nclass Topology(Topo):\n')
    f.write('  def build(self, **_opts):\n')
    #f.write("  c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)\n\n")

    # add switches
    for n in range(0, switches + 1):
        f.write("    s{0} = self.addSwitch('s{0}')\n".format(n))

    # add hosts
    f.write('\n')
    for n in range(0, hosts):
        f.write("    h{0} = self.addHost('h{0}')\n".format(n))

    # add links from center to switches
    f.write('\n')
    for n in range(1, switches + 1):
        f.write("    self.addLink(s0, s{0})\n".format(n))

    f.write('\n')
    for n in range(1, switches + 1):
        for m in range(0, hosts_per_switch):
            f.write("    self.addLink(s{0}, h{1})\n".format(n, m + offset))
        offset += hosts_per_switch

    for n in range(1, extra_hosts + 1):
        f.write("    self.addLink(s{0}, h{1})\n".format(n, n - 1 + offset))

    f.write("\ndef run():\n")
    f.write("  topo = Topology()\n")
    f.write("  net = Mininet(topo=topo, controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)\n")
    f.write("  net.start()\n")
    f.write("  time.sleep(30)\n")
    f.write("  net.pingAll()\n")
    f.write("  net.pingAll()\n")
    f.write("  CLI(net)\n")
    f.write("  net.stop()\n\n")

    f.write("if __name__ == '__main__':\n")
    f.write("  setLogLevel('info')\n")
    f.write("  run()\n")
