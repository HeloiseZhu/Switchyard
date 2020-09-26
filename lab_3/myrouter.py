#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        # TODO
        self.arptable = dict([])


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            # TODO: (Task 3)Timeout mechanism
            for key in list(self.arptable.keys()):
                if(time.time() - self.arptable[key][1] > 20):
                    self.arptable.pop(key)

            if gotpkt:
                log_info("Got a packet: {}".format(str(pkt)))
                # TODO: Handle ARP request
                arp = pkt.get_header(Arp)
                if arp is not None: # ARP packet or other packet
                    # TODO: (Task 3)Cached ARP table
                    if self.arptable.get(arp.senderprotoaddr) is None:
                        self.arptable[arp.senderprotoaddr] = [arp.senderhwaddr, time.time()]
                        log_info("The cached ARP table updated(add one entry):")
                        for key in list(self.arptable.keys()):
                            now = time.strftime("%H:%M:%S", time.localtime(self.arptable[key][1]))
                            print("IP addr: {},\tMAC addr: {},\ttime: {}".format(key, self.arptable[key][0], now))
                        print("\n")
                    else:
                        if self.arptable[arp.senderprotoaddr][0] != arp.senderhwaddr:
                            self.arptable[arp.senderprotoaddr] = [arp.senderhwaddr, time.time()]
                            log_info("The cached ARP table updated(update one entry):")
                            for key in list(self.arptable.keys()):
                                now = time.strftime("%H:%M:%S", time.localtime(self.arptable[key][1]))
                                print("IP addr: {},\tMAC addr: {},\ttime: {}".format(key, self.arptable[key][0], now))
                            print("\n")
                        else:
                            self.arptable[arp.senderprotoaddr][1] = time.time()


                    if arp.operation == ArpOperation.Request: # reply or request
                        targetip = arp.targetprotoaddr
                        for intf in self.net.interfaces():
                            if intf.ipaddr == targetip:
                                arp_reply = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, targetip, arp.senderprotoaddr)
                                log_debug("Sending packet {} to {}".format(arp_reply, intf.name))
                                self.net.send_packet(intf.name, arp_reply) 


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
