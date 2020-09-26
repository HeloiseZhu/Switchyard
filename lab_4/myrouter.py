#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *

# TODO 
# (Lab 4-Task 2) entry of forwarding table
class FTEntry(object):
    def __init__(self, prefix, mask, intf, nexthop=None):
        self.prefix = prefix    # IPv4Address
        self.mask = mask
        self.nexthop = nexthop
        self.intf = intf        # name of interface

# (Lab 4-Task 3) entry of ARP queue
class AQEntry(object):
    def __init__(self, targetip, timestamp, retrytimes, intf, arprequest, pkt):
        self.targetip = targetip        
        self.time = timestamp
        self.retry = retrytimes 
        self.intf = intf
        self.arprequest = arprequest                
        self.pkts = []
        self.pkts.append(pkt)

    def add_pkt(self, pkt):
        self.pkts.append(pkt)




class Router(object):
    def __init__(self, net):
        self.net = net
        
        # other initialization stuff here
        # (Lab 3) build ARP table
        self.arptable = dict([])

        # TODO 
        # (Lab 4-Task 2) build forwading table
        self.fwtable = []
        # source 1: net.interfaces()
        for intf in self.net.interfaces():
            prefix = IPv4Address(int(intf.ipaddr) & int(intf.netmask))
            self.fwtable.append(FTEntry(prefix, intf.netmask, intf.name))
        # source 2: forwarding_table.txt
        f = open('forwarding_table.txt', 'r')
        f.seek(0)
        while True:
            line = f.readline().strip()
            if line:
                prefix, netmask, nexthop, intf = line.split(' ')
                self.fwtable.append(FTEntry(IPv4Address(prefix), IPv4Address(netmask), intf, IPv4Address(nexthop)))
            else:
                break
        f.close()

        # (Lab 4-Task 3) build ARP queue
        self.arpqueue = []



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


            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                # TODO 
                # (Lab 4) check the destination MAC address of Ethernet header
                f1 = False
                for intf in self.net.interfaces():
                    if intf.ethaddr == pkt[Ethernet].dst:    
                        f1 = True
                        break
                if pkt[Ethernet].dst == EthAddr('ff:ff:ff:ff:ff:ff'):
                    f1 = True
                
                if f1 == True:
                    # (Lab 4-Task 2) match destination IP address
                    if pkt.has_header(IPv4):
                        # check if destination(IP address) is one of router interfaces
                        f2 = False
                        for intf in self.net.interfaces():
                            if intf.ipaddr == pkt[IPv4].dst:
                                f2 = True   # drop the packet
                                break
                        if f2 == False:
                            maxlen = 0
                            entry_used = None
                            for e in self.fwtable:
                                if (int(e.prefix) & int(pkt[IPv4].dst)) == int(e.prefix):
                                    # find longest prefix
                                    netaddr = IPv4Network("{}/{}".format(e.prefix, e.mask))
                                    if (netaddr.prefixlen > maxlen):
                                        maxlen = netaddr.prefixlen
                                        entry_used = e
                            if entry_used:
                                pkt[IPv4].ttl = pkt[IPv4].ttl - 1
                                for intf in self.net.interfaces():
                                    if intf.name == entry_used.intf:
                                        pkt[Ethernet].src = intf.ethaddr
                                        if not entry_used.nexthop:
                                            # destination is directly reachable through the interface
                                            nexthopip = pkt[IPv4].dst
                                        else: 
                                            nexthopip = entry_used.nexthop
                                        # look up ARP table
                                        if self.arptable.get(nexthopip):
                                            # construct Ethernet header and send packet
                                            pkt[Ethernet].dst = self.arptable[nexthopip]
                                            log_debug("Sending packet {} to {}".format(pkt, intf.name))
                                            self.net.send_packet(intf.name, pkt) 
                                        else:
                                            f3 = False
                                            for e in self.arpqueue:
                                                if e.targetip == nexthopip:
                                                    f3 = True
                                                    e.add_pkt(pkt)
                                                    break
                                            if f3 == False:
                                                # send ARP request and add a new entry to ARP queue
                                                arp_request = create_ip_arp_request(intf.ethaddr, intf.ipaddr, nexthopip)
                                                self.arpqueue.append(AQEntry(nexthopip, time.time(), 1, intf.name, arp_request, pkt))
                                                log_debug("Sending packet {} to {}".format(arp_request, intf.name))
                                                self.net.send_packet(intf.name, arp_request)
                                        break
                    else:
                        arp_header = pkt.get_header(Arp)
                        if arp_header:
                            # (Lab 3) update ARP table
                            if self.arptable.get(arp_header.senderprotoaddr) is None:
                                self.arptable[arp_header.senderprotoaddr] = arp_header.senderhwaddr
                                log_debug("The cached ARP table updated(add a new entry)")
                                print("ARP table:")
                                for key in list(self.arptable.keys()):
                                    print("IP addr: {},\tMAC addr: {}".format(key, self.arptable[key]))
                                print('')
                            else:
                                if self.arptable[arp_header.senderprotoaddr] != arp_header.senderhwaddr:
                                    self.arptable[arp_header.senderprotoaddr] = arp_header.senderhwaddr
                                    log_debug("The cached ARP table updated(update one entry)")
                                    print("ARP table:")
                                    for key in list(self.arptable.keys()):
                                        print("IP addr: {},\tMAC addr: {}".format(key, self.arptable[key]))
                                    print('')

                            # (Lab 3) handle ARP request
                            if arp_header.operation == ArpOperation.Request:
                                targetip = arp_header.targetprotoaddr
                                for intf in self.net.interfaces():
                                    if intf.ipaddr == targetip:
                                        arp_reply = create_ip_arp_reply(intf.ethaddr, arp_header.senderhwaddr, targetip, arp_header.senderprotoaddr)
                                        log_debug("Sending packet {} to {}".format(arp_reply, intf.name))
                                        self.net.send_packet(intf.name, arp_reply) 
                            else:
                                # TODO: (Lab 4) handle ARP reply
                                for e in self.arpqueue:
                                    if e.targetip == arp_header.senderprotoaddr:
                                        for p in e.pkts:
                                            # construct Ethernet header
                                            p[Ethernet].dst = arp_header.senderhwaddr
                                            log_debug("Sending packet {} to {}".format(p, e.intf))
                                            self.net.send_packet(e.intf, p) 
                                    self.arpqueue.remove(e)
                                    break
                
            # TODO: (Lab 4-Task 3) retransmit ARP request 
            for i in range(len(self.arpqueue)-1, -1, -1):
                if time.time() - self.arpqueue[i].time > 1:
                    if self.arpqueue[i].retry == 5:
                        self.arpqueue.pop(i)
                    else:
                        log_debug("Sending packet {} to {}".format(self.arpqueue[i].arprequest, self.arpqueue[i].intf))
                        self.net.send_packet(self.arpqueue[i].intf, self.arpqueue[i].arprequest)
                        self.arpqueue[i].retry = self.arpqueue[i].retry + 1
                        self.arpqueue[i].time = time.time()



def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()