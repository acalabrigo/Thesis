#!/usr/bin/python
# Adam Calabrigo 2017

# Script to get the average number of flow table entries
# in switches.


import sys
import subprocess

if len(sys.argv) > 1:
    num_switches = int(sys.argv[1])
    num_flows = {}
    total_flows = 0
    for i in range(0, num_switches + 1):
        p = subprocess.Popen(["sudo", "ovs-ofctl", "dump-flows", "s{0}".format(i)],
                             stdout=subprocess.PIPE)
        out = p.communicate()[0]
        flows = len([f for f in out.split('\n') if 'cookie' in f])
        print('switch {0}: {1} flows'.format(i, flows))
        num_flows[i] = flows
        total_flows += flows
    print('Avg. flows per switch: {0}'.format(total_flows / (num_switches + 1)))
else:
    print("Usage: ./get_flow_data.py <num switches>")
    exit()
