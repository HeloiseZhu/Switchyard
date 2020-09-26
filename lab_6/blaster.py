#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
import random
import time

def generate_random_str(length):
    ret = ''
    base = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz012345678'
    for i in range(length):
        ret += base[random.randint(0,len(base)-1)]
    return ret


def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    # TODO: (Task 4) 
    # Read blaster_params.txt
    fd = open('/home/njucs/switchyard/lab_6/blaster_params.txt', 'r')
    fd.seek(0)
    while True:
        line = fd.readline().strip()
        if line:
            paralist = line.split(' ')
            blasteeip = IPv4Address(paralist[1])
            pktnum = int(paralist[3])
            length = int(paralist[5])
            sw = int(paralist[7])
            to = int(paralist[9])
            recvto = float(paralist[11]) / 1000.0
        else:
            break
    fd.close()

    starttime = 0
    endtime = 0
    retxnum = 0
    tonum = 0
    retxput = 0     # bytes
    goodput = 0     # bytes
    lhs = 1
    rhs = 0
    swtimer = 0
    sendbuf = dict()
    retxque = []

    while True:
        gotpkt = True
        try:
            # TODO: Timeout value will be parameterized!
            timestamp,dev,pkt = net.recv_packet(timeout=recvto)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_info("I got a packet")
            # TODO: Handle ACK packets 
            recvseq = int().from_bytes(pkt[3].to_bytes()[:8], byteorder='big', signed=True)
            if recvseq == lhs:
                # Update LHS
                del sendbuf[recvseq]
                lhs += 1
                for i in range(recvseq+1, rhs+1):
                    if sendbuf.get(i):
                        break
                    else:
                        lhs = i + 1
                swtimer = time.time()
            elif recvseq > lhs:
                if sendbuf.get(recvseq):
                    del sendbuf[recvseq]
            log_info("recv sequence num: {}, LHS: {}, RHS: {}".format(recvseq, lhs, rhs))
            if lhs == pktnum+1:
                endtime = time.time()
                break
        else:
            log_debug("Didn't receive anything")

        # TODO: Coarse timeout
        if (time.time()-swtimer)*1000 > to and swtimer != 0:
            log_info("Timeout!")
            swtimer = time.time()
            tonum += 1
            retxque.clear()
            for i in range(lhs, rhs+1):
                if sendbuf.get(i):
                    retxque.append(i)


        # TODO: Send a packet
        retxseq = -1
        if len(retxque) != 0:
            # Retransmit a packet
            for i in range(len(retxque)):
                retxpkt = sendbuf.get(retxque[i])
                if retxpkt:
                    retxnum += 1
                    retxput += length
                    net.send_packet(my_intf[0].name, retxpkt)
                    log_info("Retransmit: {}".format(retxque[i]))
                    retxseq = i
                    break
            if retxseq >= 0:
                for i in range(retxseq, -1, -1):
                    del retxque[i]
        if retxseq == -1:
            # Send a new packet
            if rhs-lhs+1 < sw and rhs < pktnum:
                ethhdr = Ethernet()
                ethhdr.src = my_intf[0].ethaddr     # blaster
                ethhdr.dst = '40:00:00:00:00:01'    # eth0
                ethhdr.ethertype = EtherType.IP
                iphdr = IPv4()
                iphdr.src = my_intf[0].ipaddr       # blaster
                iphdr.dst = blasteeip               # blastee
                iphdr.protocol = IPProtocol.UDP
                iphdr.ttl = 64
                udphdr = UDP()
                udphdr.src = 111
                udphdr.dst = 222
                newpkt = ethhdr + iphdr + udphdr
                rhs += 1
                pktraw = rhs.to_bytes(8, byteorder='big', signed=True) + length.to_bytes(4, byteorder='big', signed=True)
                newpkt += RawPacketContents(raw=pktraw)
                pktraw = bytes(generate_random_str(length), encoding='utf8')
                newpkt += RawPacketContents(raw=pktraw)
                if rhs == 1:
                    starttime = time.time()
                    swtimer = time.time()
                sendbuf[rhs] = newpkt
                goodput += length
                net.send_packet(my_intf[0].name, newpkt)
                log_info("Sending packet {} to {}".format(newpkt, my_intf[0].name))
                log_info("send sequence num: {}, LHS: {}, RHS: {}".format(rhs, lhs, rhs))
        
        

    # TODO: Print results
    totaltime = endtime - starttime
    print("\nTotal TX time (in seconds): {}".format(totaltime))
    print("Number of reTX: {}".format(retxnum))
    print("Number of coarse TOs: {}".format(tonum))
    print("Throughput (Bps): {}".format((goodput+retxput) / totaltime))
    print("Goodput (Bps): {}".format(goodput / totaltime))

    net.shutdown()
