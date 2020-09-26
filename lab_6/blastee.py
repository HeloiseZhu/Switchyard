#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import random
import time


# TODO: (Task 3)
def generate_random_str(length):
    ret = ''
    base = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz012345678'
    for i in range(length):
        ret += base[random.randint(0,len(base)-1)]
    return ret

def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]

    # TODO: (Task 3)
    # Read blastee_params.txt
    fd = open('/home/njucs/switchyard/lab_6/blastee_params.txt', 'r')
    fd.seek(0)
    while True:
        line = fd.readline().strip()
        if line:
            option1, blasterip, option2, pktnum = line.split(' ')
            blasterip = IPv4Address(blasterip)
            pktnum = int(pktnum)
        else:
            break
    fd.close()

    while True:
        gotpkt = True
        try:
            timestamp,dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_info("I got a packet from {}".format(dev))
            # TODO: (Task 3)
            ethhdr = Ethernet()
            ethhdr.src = my_intf[0].ethaddr     # blastee
            ethhdr.dst = pkt[Ethernet].src      # eth1
            ethhdr.ethertype = EtherType.IP
            iphdr = IPv4()
            iphdr.src = my_intf[0].ipaddr       # blastee
            iphdr.dst = blasterip               # blaster
            iphdr.protocol = IPProtocol.UDP
            iphdr.ttl = 64
            udphdr = UDP()
            udphdr.src = 222
            udphdr.dst = 111
            seqnum = pkt[3].to_bytes()[:8]
            length = int().from_bytes(pkt[3].to_bytes()[8:12], byteorder='big', signed=True)
            log_info("recv sequence num: {}".format(int().from_bytes(seqnum, byteorder='big', signed=True)))
            pkthdr = RawPacketContents(raw=seqnum)
            if length >= 8:
                pktraw = pkt[3].to_bytes()[12:20]
            else:
                pktraw = pkt[3].to_bytes()[12:12+length]
                pktraw += bytes(generate_random_str(8-length), encoding='utf8')
            newpkt = ethhdr + iphdr + udphdr + pkthdr + RawPacketContents(raw=pktraw)
            net.send_packet(my_intf[0].name, newpkt)
            log_info("Sending packet {} to {}".format(newpkt, my_intf[0].name))

            
    net.shutdown()
