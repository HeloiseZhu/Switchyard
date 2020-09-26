'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time

# TODO:
TABLE_SIZE = 5
class Entry(object):
    def __init__(self, mac, intf, traffic):
        self.mac = mac
        self.intf = intf
        self.traffic = traffic

def get_traffic(ele):
    return ele.traffic
    
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
                
        # TODO: check if table contains entry for src address
        f1 = False
        for e in swtable:
            if(e.mac == packet[0].src):
                if(e.intf != input_port):
                    e.intf = input_port
                f1 = True
                break
       
        if(f1 == False):
            if(len(swtable) == TABLE_SIZE):
                swtable.sort(key=get_traffic)
                swtable.pop(0)
            swtable.append(Entry(packet[0].src, input_port, 0))


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
                    e.traffic = e.traffic + 1
                    break
            # flood the packet out all ports except input port
            if(f2 == False):
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
