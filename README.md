# SD-MCAN: A Software-Defined Solution for IP Mobility in Campus Area Networks

This repo contains a rough prototype for the SD-MCAN architecture, implemented as an application for the POX controller. The prototype currently lacks IPv6 support, and VLAN tagging is used instead of MPLS tagging as POX only supports OpenFlow 1.0. This code has been tested and found to work with Mininet 2.2.1, Open vSwitch 2.5.2, and POX 0.5.0 (eel). For more info on SD-MCAN, consult the thesis below.

<link coming pending publication>

Requirements:

- Python 2.7
- NetworkX (get it [here](https://github.com/networkx/networkx.git))

Usage:

- ./pox.py sd-mcan

Add the contents of the modules directory into POX's ext directory and run as shown above.

