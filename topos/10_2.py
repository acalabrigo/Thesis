#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import Link, TCLink
import time


class Topology(Topo):
  def build(self, **_opts):
    s0 = self.addSwitch('s0')
    s1 = self.addSwitch('s1')
    s2 = self.addSwitch('s2')
    s3 = self.addSwitch('s3')
    s4 = self.addSwitch('s4')
    s5 = self.addSwitch('s5')
    s6 = self.addSwitch('s6')
    s7 = self.addSwitch('s7')
    s8 = self.addSwitch('s8')
    s9 = self.addSwitch('s9')
    s10 = self.addSwitch('s10')

    h0 = self.addHost('h0')
    h1 = self.addHost('h1')

    self.addLink(s0, s1)
    self.addLink(s0, s2)
    self.addLink(s0, s3)
    self.addLink(s0, s4)
    self.addLink(s0, s5)
    self.addLink(s0, s6)
    self.addLink(s0, s7)
    self.addLink(s0, s8)
    self.addLink(s0, s9)
    self.addLink(s0, s10)

    self.addLink(s1, h0)
    self.addLink(s2, h1)

def run():
  topo = Topology()
  net = Mininet(topo=topo, controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)
  net.start()
  time.sleep(10)
  net.pingAll(timeout=5)
  CLI(net)
  net.stop()

if __name__ == '__main__':
  setLogLevel('info')
  run()
