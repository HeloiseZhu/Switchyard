#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import random
import time

def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    # TODO: (Task 2) 
    # Read middlebox_params.txt
    fd = open('/home/njucs/switchyard/lab_6/middlebox_params.txt', 'r')
    fd.seek(0)
    while True:
        line = fd.readline().strip()
        if line:
            option, droprate = line.split(' ')
            droprate = float(droprate) 
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
            log_info("I got a packet {}".format(pkt))

        if dev == "middlebox-eth0":
            log_info("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            # TODO：(Task 2)
            p = random.uniform(0, 1)
            if p > droprate:
                pkt[Ethernet].src = '40:00:00:00:00:02' # eth1
                pkt[Ethernet].dst = '20:00:00:00:00:01' # blastee
                net.send_packet("middlebox-eth1", pkt)
                log_info("Sending packet {} to {}".format(pkt, "middlebox-eth1"))
            # else: drop the packet

        elif dev == "middlebox-eth1":
            log_info("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
            # TODO：(Task 2)
            pkt[Ethernet].src = '40:00:00:00:00:01' # eth0
            pkt[Ethernet].dst = '10:00:00:00:00:01' # blaster
            net.send_packet("middlebox-eth0", pkt)
            log_info("Sending packet {} to {}".format(pkt, "middlebox-eth0"))
            
        else:
            log_debug("Oops :))")

    net.shutdown()
