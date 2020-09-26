#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *


# (Lab 4-Task 2) 
# entry of forwarding table
class FTEntry(object):
    def __init__(self, prefix, mask, intf, nexthop=None):
        self.prefix = prefix    # IPv4Address
        self.mask = mask
        self.nexthop = nexthop
        self.intf = intf        # name of interface


# (Lab 4-Task 3) 
# entry of ARP queue
class AQEntry(object):
    def __init__(self, targetip, timestamp, intf, arprequest, pkt=None, retrytimes=1):
        self.targetip = targetip        
        self.time = timestamp
        self.retry = retrytimes 
        self.intf = intf           # name of interface
        self.arprequest = arprequest                
        self.pkts = []
        if pkt:
            self.pkts.append(pkt)

    def add_pkt(self, pkt):
        self.pkts.append(pkt)



class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        # (Lab 3) build ARP table
        self.arptable = dict([])
        # (Lab 4-Task 2) 
        # build forwading table
        self.fwtable = []
        # source 1: interfaces
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
        # (Lab 4-Task 3) 
        # build ARP queue
        self.arpqueue = []


    # (Lab 4) look up the forwarding table
    def fwtable_lookup(self, pkt):
        maxlen = 0
        fw_entry = None
        for e in self.fwtable:
            if (int(e.mask) & int(pkt[IPv4].dst)) == int(e.prefix):
                # find longest prefix
                netaddr = IPv4Network("{}/{}".format(e.prefix, e.mask))
                if (netaddr.prefixlen > maxlen):
                    maxlen = netaddr.prefixlen
                    fw_entry = e
        return fw_entry
    

    # (Lab 4)
    ''' 
    look up the ARP table and
    forward packet or update ARP queue
    '''
    def arp_query(self, pkt, nexthop, intf):
        if self.arptable.get(nexthop):
            # construct Ethernet header and send packet
            pkt[Ethernet].dst = self.arptable[nexthop]
            log_debug("Sending packet {} to {}".format(pkt, intf.name))
            self.net.send_packet(intf.name, pkt) 
        else:
            f = False # if nexthop is in ARP queue
            for e in self.arpqueue:
                if e.targetip == nexthop:
                    f = True
                    e.add_pkt(pkt)
                    break
            if not f:
                # send ARP request and add a new entry to ARP queue
                arpreq = create_ip_arp_request(intf.ethaddr, intf.ipaddr, nexthop)
                self.arpqueue.append(AQEntry(nexthop, time.time(), intf.name, arpreq, pkt=pkt))
                log_debug("Sending packet {} to {}".format(arpreq, intf.name))
                self.net.send_packet(intf.name, arpreq)

    # TODO: (Lab 5)
    # from routertests3_template.py
    def mk_icmperr(self, ipdst, xtype, xcode, origpkt=None, ttl=64):
        ether = Ethernet()
        ether.ethertype = EtherType.IP
        ippkt = IPv4()
        ippkt.dst = IPAddr(ipdst)
        ippkt.protocol = IPProtocol.ICMP
        ippkt.ttl = ttl
        ippkt.ipid = 0
        icmppkt = ICMP()
        icmppkt.icmptype = xtype
        icmppkt.icmpcode = xcode
        if origpkt is not None:
            xpkt = deepcopy(origpkt)
            i = xpkt.get_header_index(Ethernet)
            if i >= 0:
                del xpkt[i]
            icmppkt.icmpdata.data = xpkt.to_bytes()[:28]
            icmppkt.icmpdata.origdgramlen = len(xpkt)
        return ether + ippkt + icmppkt


    # TODO: (Lab 5)
    '''
    send ICMP packets, including ICMP reply and ICMP error
    hwsrc, ipsrc(fwtable_lookup) and hwdst(arp_query) of icmppkt need setting
    op=0: send ICMP error message
    op=1: send ICMP reply message
    '''
    def send_icmppkt(self, icmppkt, op=0):
        fw_entry = self.fwtable_lookup(icmppkt)
        if fw_entry:
            for intf in self.net.interfaces():
                if intf.name == fw_entry.intf:
                    if op == 0: # send ICMP error
                        icmppkt[IPv4].src = intf.ipaddr
                    icmppkt[Ethernet].src = intf.ethaddr
                    if fw_entry.nexthop:
                        self.arp_query(icmppkt, fw_entry.nexthop, intf)
                    else: 
                        # destination is directly reachable through the interface
                        self.arp_query(icmppkt, icmppkt[IPv4].dst, intf)
                    break
        # else: drop the packet



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

                # (Lab 4) check if Ethernet frame is destined for router
                f1 = False # if Ethernet frame is destined for router
                for intf in self.net.interfaces():
                    if intf.ethaddr == pkt[Ethernet].dst:    
                        f1 = True
                        break
                if pkt[Ethernet].dst == EthAddr('ff:ff:ff:ff:ff:ff'):
                    f1 = True
                
                if f1: # Ethernet frame is destined for router
                    # (Lab 4-Task 2) match ipdst
                    if pkt.has_header(IPv4):
                        # check if IP datagram is destined for router
                        f2 = False # if IP datagram is destined for router
                        for intf in self.net.interfaces():
                            if intf.ipaddr == pkt[IPv4].dst:
                                f2 = True
                                break

                        if f2: # IP datagram is destined for router
                            if pkt.has_header(ICMP) and (pkt[ICMP].icmptype == ICMPType.EchoRequest): # TODO: (Lab 5-Task 2) 
                                # respond to ICMP echo request
                                icmpreply = Ethernet() + IPv4() + ICMP()
                                icmpreply[ICMP].icmptype = ICMPType.EchoReply
                                icmpreply[ICMP].icmpcode = ICMPCodeEchoReply.EchoReply
                                # copy icmpdata from ICMP echo request(pkt)
                                icmpreply[ICMP].icmpdata.data = pkt[ICMP].icmpdata.data
                                icmpreply[ICMP].icmpdata.identifier = pkt[ICMP].icmpdata.identifier
                                icmpreply[ICMP].icmpdata.sequence = pkt[ICMP].icmpdata.sequence
                                icmpreply[IPv4].protocol = IPProtocol.ICMP
                                icmpreply[IPv4].ttl = 64
                                icmpreply[IPv4].dst = pkt[IPv4].src
                                icmpreply[IPv4].src = pkt[IPv4].dst
                                self.send_icmppkt(icmpreply, op=1)
                            else: # TODO: (Lab 5-Task 3) 
                                # ICMP error case 4: destinaton port unreachable
                                icmperr = self.mk_icmperr(pkt[IPv4].src, 
                                                          ICMPType.DestinationUnreachable, 
                                                          ICMPCodeDestinationUnreachable.PortUnreachable, 
                                                          origpkt=pkt)
                                self.send_icmppkt(icmperr)
                        else: # IP datagram is not destined for router
                            # look up the forwarding table
                            fw_entry = self.fwtable_lookup(pkt)
                            if fw_entry:
                                pkt[IPv4].ttl -= 1
                                if pkt[IPv4].ttl == 0: # TODO: (Lab 5-Task 3) 
                                    # ICMP error case 2: time exceeded
                                    icmperr = self.mk_icmperr(pkt[IPv4].src, 
                                                              ICMPType.TimeExceeded, 
                                                              ICMPCodeTimeExceeded.TTLExpired, 
                                                              origpkt=pkt)
                                    self.send_icmppkt(icmperr)
                                else:
                                    for intf in self.net.interfaces():
                                        if intf.name == fw_entry.intf:
                                            pkt[Ethernet].src = intf.ethaddr
                                            # ARP query 
                                            if fw_entry.nexthop:
                                                self.arp_query(pkt, fw_entry.nexthop, intf)
                                            else:
                                                # destination is directly reachable through the interface
                                                self.arp_query(pkt, pkt[IPv4].dst, intf)
                                            break
                            else: # TODO: (Lab 5-Task 3) 
                                # no entry in fwtable matches pkt[IPv4].dst
                                # ICMP error case 1: destinaton network unreachable
                                icmperr = self.mk_icmperr(pkt[IPv4].src, 
                                                          ICMPType.DestinationUnreachable, 
                                                          ICMPCodeDestinationUnreachable.NetworkUnreachable, 
                                                          origpkt=pkt)
                                self.send_icmppkt(icmperr)

                    elif pkt.has_header(Arp):
                        arp_header = pkt.get_header(Arp)
                        # (Lab 3) update ARP table
                        if self.arptable.get(arp_header.senderprotoaddr):
                            if self.arptable[arp_header.senderprotoaddr] != arp_header.senderhwaddr:
                                self.arptable[arp_header.senderprotoaddr] = arp_header.senderhwaddr
                                log_info("The cached ARP table updated(update one entry)")
                                print("ARP table:")
                                for key in list(self.arptable.keys()):
                                    print("IP addr: {},\tMAC addr: {}".format(key, self.arptable[key]))
                                print('')
                        else:
                            self.arptable[arp_header.senderprotoaddr] = arp_header.senderhwaddr
                            log_info("The cached ARP table updated(add a new entry)")
                            print("ARP table:")
                            for key in list(self.arptable.keys()):
                                print("IP addr: {},\tMAC addr: {}".format(key, self.arptable[key]))
                            print('')

                        # (Lab 3) handle ARP request
                        if arp_header.operation == ArpOperation.Request:
                            for intf in self.net.interfaces():
                                if intf.ipaddr == arp_header.targetprotoaddr:
                                    arpreply = create_ip_arp_reply(intf.ethaddr, 
                                                                    arp_header.senderhwaddr, 
                                                                    arp_header.targetprotoaddr, 
                                                                    arp_header.senderprotoaddr)
                                    log_debug("Sending packet {} to {}".format(arpreply, intf.name))
                                    self.net.send_packet(intf.name, arpreply) 
                        else: # (Lab 4) handle ARP reply
                            for e in self.arpqueue:
                                if e.targetip == arp_header.senderprotoaddr:
                                    for p in e.pkts:
                                        # construct Ethernet header
                                        p[Ethernet].dst = arp_header.senderhwaddr
                                        log_debug("Sending packet {} to {}".format(p, e.intf))
                                        self.net.send_packet(e.intf, p) 
                                self.arpqueue.remove(e)
                                break
                
            # (Lab 4-Task 3) 
            # retransmit ARP request 
            for i in range(len(self.arpqueue)-1, -1, -1):
                e = self.arpqueue[i]
                if time.time() - e.time > 1:
                    if e.retry == 5: # TODO: (Lab 5-Task 3)
                        # ICMP error case 3: destinaton host unreachable
                        for p in e.pkts:
                            icmperr = self.mk_icmperr(p[IPv4].src, 
                                                      ICMPType.DestinationUnreachable, 
                                                      ICMPCodeDestinationUnreachable.HostUnreachable, 
                                                      origpkt=p)
                            self.send_icmppkt(icmperr)
                        self.arpqueue.pop(i)
                    else:
                        log_debug("Sending packet {} to {}".format(e.arprequest, e.intf))
                        self.net.send_packet(e.intf, e.arprequest)
                        e.retry += 1
                        e.time = time.time()



def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()