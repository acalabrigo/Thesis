# Loads all modules and runs the controller. This is all that needs to be
# run on the POX CLI.

# Modules are as follows:
#   Not my work:
#       - topology: tracks the location of switches in the network
#       - discovery: openflow implementation that handles link up/down
#   This thesis:
#       - dynamic_topology: dynamically tracks the entire topology, including
#                           hosts and switches
#       - mobile_host_tracker: built on top of the host_tracker module, this
#                              tracks where hosts are in the network and raises
#                              HostEvents
#       - dhcpd_multi: handles all of the DHCP functionality of this system
#       - proactive_flows: installs all flow entries into the switches

# 2017 Adam Calabrigo

import pox.topology
import pox.openflow.discovery
import dynamic_topology
#import mobile_host_tracker
import dhcpd_multi
import proactive_flows

def launch (debug="False"):
  pox.topology.launch()
  pox.openflow.discovery.launch()
  dynamic_topology.launch(debug)
  dhcpd_multi.launch()
  proactive_flows.launch()
