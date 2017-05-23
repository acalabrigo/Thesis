# Loads all modules and runs the controller.
#
# 2017 Adam Calabrigo

import pox.topology
import pox.openflow.discovery
import dynamic_topology
import mobile_host_tracker
import dhcpd_multi
import proactive_flows

def launch(debug="False", conf='dhcpd_conf.yaml'):
  pox.topology.launch()
  pox.openflow.discovery.launch()
  dynamic_topology.launch(debug)
  mobile_host_tracker.launch()
  dhcpd_multi.launch(conf)
  proactive_flows.launch()
