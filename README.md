# Thesis

Software-defined Networking improvements to campus networks (call it SDCAN).

# Currently have:

POX Modules:

- (1) dynamic_topology.py for tracking the complete topology
- (2) dhcpd_multi.py acts as a server for subnets and tracks mobility of hosts
- (3) proactive_flows.py installs flow rules based on (1) and (2)
- (4) sdcan.py runs all of these for you

Usage:

- ./pox.py sdcan

Tests:

- test scripts for connectivity and flow table load
- test script for simple mobility test

