#!/usr/bin/python
# Adam Calabrigo 2017

# This test walks a mobile host around the mobility_topo.py topology for one
# minute. The user can select the mobility interval and whether they want iperf
# to collect TCP or UDP data.

# usage: sudo python walk_test.py <udp/tcp> <interval>

from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.net import Mininet

import walk_topo
import iperf
import mobility_switch

from random import randint
import time
import sys

# these parameters can be tweaked to change the test
PATH = [8, 9, 10, 7]
TEST_TIME = 60
RUNS = 1

def run():
    # get parameters
    if len(sys.argv) != 3:
        print("usage: sudo python walk_test.py <TCP/UDP> <move interval>")
        return
    proto = sys.argv[1]
    interval = float(sys.argv[2])
    num_walks = TEST_TIME // interval

    # load topology
    topo = walk_topo.WalkTopo()
    net = Mininet(topo = topo, link = TCLink, controller = RemoteController,
                  switch = mobility_switch.MobilitySwitch)
    net.start()
    info('*** Network:\n')
    mobility_switch.printConnections(net.switches)

    for h in net.hosts:
        print "disable ipv6"
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    # wait for mininet to do all its stuff
    time.sleep(20)
    h1, h2, old = net.get('h1', 'h2', 's7')

    # set up hosts in starting positions
    info('*** h1 dhclient\n')
    info(h1.cmd('dhclient ' + h1.defaultIntf().name))
    info('*** h2 dhclient\n')
    info(h2.cmd('dhclient ' + h2.defaultIntf().name))

    info('*** Making sure Mininet gets IPs...\n')
    CLI(net, script='2hostping')

    # Start pings
    if proto == "udp":
        test = iperf.start_iperf_udp
    else:
        test = iperf.start_iperf_tcp

    for n in range(0, RUNS):
        filename = proto + sys.argv[2] + '_' + str(n)
        test(h1, server=True, filename=filename)
        test(h2, client=True, filename=filename)

        time.sleep(interval)

        for i in range(0, int(num_walks - 1)):
            s = PATH[i % len(PATH)]
            new = net[ 's%d' % s ]
            port = randint( 10, 20 )
            info( '* Moving', h2, 'from', old, 'to', new, 'port', port, '\n' )
            hintf, sintf = mobility_switch.moveHost( h2, old, new, newPort=port )
            h2.cmd('dhclient ' + h2.defaultIntf().name)
            old = new
            time.sleep(interval)

        # Stop iperf
        info("Shutting down...")
        for host in [h1, h2]:
            host.cmd('pkill iperf')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
