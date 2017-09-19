#!/usr/bin/python
# Adam Calabrigo 2017

# Script to get the average number of flow table entries
# in switches, with flows logged by percent mobility.

# 2017 Adam Calabrigo

import sys
import subprocess
import os

if len(sys.argv) == 4:
    num_switches = int(sys.argv[1])
    filename = sys.argv[2]
    num_flows = {}
    total_flows = 0

    print('Made it to script')
    with open(filename, 'a') as f:
        for i in range(1, num_switches + 1):
            p = subprocess.Popen(["sudo", "ovs-ofctl", "dump-flows", "s{0}".format(i)],
                                 stdout=subprocess.PIPE)
            out = p.communicate()[0]
            flows = len([x for x in out.split('\n') if 'cookie' in x])
            num_flows[i] = flows
            total_flows += flows
            f.write(str(flows) + ',')
        avg_flows = total_flows // (num_switches)
        f.write(str(total_flows) + ',' + str(avg_flows) + ',' + str(sys.argv[3]) + '\n')
else:
    print("Usage: ./get_flow_data_with_percent.py <num switches> <% move>")
    exit()
