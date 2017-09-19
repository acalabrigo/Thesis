#!/usr/bin/python
# Adam Calabrigo 2017

# Simple functions for starting iperf on Mininet hosts. Use these in your Mininet
# scripts.

# TODO: these could easily be merged into a single function, but oh well.

def start_iperf_udp (host, server = False, client = False, ip = "192.168.0.2", filename = "result"):
    "Run Iperf in UDP mode"

    assert sum(1 for x in [server, client] if x) == 1

    if server:
        # Simple ping loop
        cmd = ('iperf -s -u -i .5 > %s &' % filename)
        print ( '*** Host %s running server' % host.name)
    else:
        cmd = ('iperf -c %s -t 60 -u &' % ip)
        print ( '*** Host %s running client' % host.name)

    host.cmd(cmd)

def start_iperf_tcp (host, server = False, client = False, ip = "192.168.0.2", filename = "result"):
    "Run Iperf in TCP mode."

    assert sum(1 for x in [server, client] if x) == 1

    if server:
        # Simple ping loop
        cmd = ('iperf -s -i .5 > %s &' % filename)
        print ( '*** Host %s running server' % host.name)
    else:
        cmd = ('iperf -c %s -t 60 &' % ip)
        print ( '*** Host %s running client' % host.name)

    host.cmd(cmd)
