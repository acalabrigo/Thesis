# Copyright 2017 Adam Calabrigo

from pox.core import core
from pox.lib.addresses import EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.recoco import Timer
from pox.lib.revent import Event, EventHalt
import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery as discovery
from pox.lib.revent.revent import *
import time
import pox

log = core.getLogger()

class host_listener(object):
    """
    Basically, just want to test that we can listen to the events
    raised by the host_tracker.
    """
    def __init__(self):
        listen_args={'host_tracker':{'priority':0}}
        core.listen_to_dependencies(self, listen_args=listen_args)

    def _all_dependencies_met (self):
        log.info("host_listener ready")

    def _handle_host_tracker_HostEvent(self, event):
        log.info("HostEvent listened to {0}".format(str(event.entry)))

def launch():
    core.registerNew(host_listener)
