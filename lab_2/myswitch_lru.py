'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time

# TODO: maximum size of swtable
TABLE_SIZE = 5
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
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return
                
        # TODO: check if swtable contains entry for src address
        f1 = False
        for e in swtable:
            if(e.mac == packet[0].src):
                if(e.intf != input_port):
                    e.intf = input_port
                mru = e
                f1 = True
                break
        
        if(f1 == True):
            swtable.remove(mru)
            swtable.insert(0, mru) # swtable[0] is MRU
        else:
            if(len(swtable) == TABLE_SIZE):
                swtable.remove(swtable[-1])
            mru = Entry(packet[0].src, input_port)
            swtable.insert(0, mru)


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
                    mru = e
                    break
            if(f2 == True):
                swtable.remove(mru)
                swtable.insert(0, mru)
            else: # flood the packet out all ports except input port
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
