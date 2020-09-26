'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time

# TODO:
class Entry(object):
    def __init__(self, mac, intf, timestamp):
        self.mac = mac
        self.intf = intf
        self.timestamp = timestamp
    
def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    # TODO:
    swtable = []

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return
        
        # TODO: timeout mechanism
        for i in range(len(swtable)-1, -1, -1):
            if(time.time() - swtable[i].timestamp > 10):
                swtable.pop(i)
                
        # TODO: check if swtable contains entry for src address
        f1 = False
        for e in swtable:
            if(e.mac == packet[0].src):
                if(e.intf != input_port):
                    e.intf = input_port
                e.timestamp = time.time()
                f1 = True
                break
        if(f1 == False):
            swtable.append(Entry(packet[0].src, input_port, time.time()))
        
        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            # TODO: check if swtable knows the output port
            f2 = False
            for e in swtable:
                if(e.mac == packet[0].dst):
                    f2 = True
                    log_debug("Sending packet {} to {}".format(packet, e.intf))
                    net.send_packet(e.intf, packet)
                    break
            # flood the packet out all ports except input port
            if(f2 == False):
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
