# Loads all SD-MCAN modules and runs the controller. This is all that needs to be
# run on the POX CLI.

# Modules are as follows:
#   Not my work:
#       - topology: tracks the location of switches in the network
#       - discovery: openflow implementation that handles link up/down
#   This thesis:
#       - topology_tracker: dynamically tracks the entire topology, including
#                           hosts and switches
#       - dhcp_server: handles all of the DHCP functionality of this system
#       - route_manager: installs all flow entries into the switches
# 2017 Adam Calabrigo

import pox.topology
import pox.openflow.discovery
import topology_tracker
import dhcp_server


def launch (debug="False"):
  pox.topology.launch()
  pox.openflow.discovery.launch()
  dhcp_server.launch()
  topology_tracker.launch(debug)
