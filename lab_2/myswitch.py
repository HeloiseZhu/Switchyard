'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *

#TODO:
class Entry(object):
    def __init__(self, mac, intf):
        self.mac = mac
        self.intf = intf


def main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    # TODO:
    swtable = []

    while True:
        try:
            timestamp, input_port, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        #TODO: learning step
        f1 = False
        for e in swtable:
            if(e.mac == packet[0].src):
                f1 = True
                break
        if(f1 == False):
            swtable.append(Entry(packet[0].src, input_port))
        
        log_debug("In {} received packet {} on {}".format(
            net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug("Packet intended for me")
        else:
            # TODO: check if swtable knows the output port
            f2 = False
            for e in swtable:
                if(e.mac == packet[0].dst):
                    f2 = True
                    log_debug("Sending packet {} to {}".format(packet, e.intf))
                    net.send_packet(e.intf, packet)
                    break
            # flood the packet out all ports except input port (including broadcast)
            if(f2 == False):
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
