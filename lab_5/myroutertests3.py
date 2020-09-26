#!/usr/bin/env python

from switchyard.lib.userlib import *
from copy import deepcopy

def get_raw_pkt(pkt, xlen):
    pkt = deepcopy(pkt)
    i = pkt.get_header_index(Ethernet)
    if i >= 0:
        del pkt[i]
    b = pkt.to_bytes()[:xlen]
    return b

def mk_arpreq(hwsrc, ipsrc, ipdst):
    arp_req = Arp()
    arp_req.operation = ArpOperation.Request
    arp_req.senderprotoaddr = IPAddr(ipsrc)
    arp_req.targetprotoaddr = IPAddr(ipdst)
    arp_req.senderhwaddr = EthAddr(hwsrc)
    arp_req.targethwaddr = EthAddr("ff:ff:ff:ff:ff:ff")
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr("ff:ff:ff:ff:ff:ff")
    ether.ethertype = EtherType.ARP
    return ether + arp_req

def mk_arpresp(arpreqpkt, hwsrc, arphwsrc=None, arphwdst=None):
    if arphwsrc is None:
        arphwsrc = hwsrc
    if arphwdst is None:
        arphwdst = arpreqpkt.get_header(Arp).senderhwaddr
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = arpreqpkt.get_header(Arp).senderhwaddr
    ether.ethertype = EtherType.ARP
    arp_reply = Arp()
    arp_reply.operation = ArpOperation.Reply
    arp_reply.senderprotoaddr = IPAddr(arpreqpkt.get_header(Arp).targetprotoaddr)
    arp_reply.targetprotoaddr = IPAddr(arpreqpkt.get_header(Arp).senderprotoaddr)
    arp_reply.senderhwaddr = EthAddr(arphwsrc)
    arp_reply.targethwaddr = EthAddr(arphwdst)
    return ether + arp_reply

def mk_ping(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl=64, payload=''):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.src = IPAddr(ipsrc)
    ippkt.dst = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = ttl
    ippkt.ipid = 0
    if reply:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoReply
        icmppkt.icmpcode = ICMPCodeEchoReply.EchoReply
    else:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoRequest
        icmppkt.icmpcode = ICMPCodeEchoRequest.EchoRequest
    icmppkt.icmpdata.sequence = 42
    icmppkt.icmpdata.data = payload
    return ether + ippkt + icmppkt 

def mk_icmperr(hwsrc, hwdst, ipsrc, ipdst, xtype, xcode=0, origpkt=None, ttl=64):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.src = IPAddr(ipsrc)
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

def mk_udp(hwsrc, hwdst, ipsrc, ipdst, ttl=64, srcport=10000, dstport=10000, payload=''):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.src = IPAddr(ipsrc)
    ippkt.dst = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.UDP
    ippkt.ttl = ttl
    ippkt.ipid = 0
    udppkt = UDP()
    udppkt.src = srcport
    udppkt.dst = dstport
    return ether + ippkt + udppkt + RawPacketContents(payload)

def icmp_tests():
    s = TestScenario("IP forwarding and ARP requester tests")
    s.add_interface('router-eth0', '10:00:00:00:00:01', '192.168.1.1', '255.255.255.0')
    s.add_interface('router-eth1', '10:00:00:00:00:02', '10.10.0.1', '255.255.0.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', '172.16.42.1', '255.255.255.252')
    s.add_file('forwarding_table.txt', '''172.16.0.0 255.255.0.0 192.168.1.2 router-eth0
172.16.128.0 255.255.192.0 10.10.0.254 router-eth1
172.16.64.0 255.255.192.0 10.10.1.254 router-eth1
10.100.0.0 255.255.0.0 172.16.42.2 router-eth2
''')

    nottinyttl = '''lambda pkt: pkt.get_header(IPv4).ttl >= 8'''

    # Your tests here
    # test case 1: (ICMP error) Destination Network Unreachable
    icmpreq = mk_ping('30:00:00:00:00:01', '10:00:00:00:00:03', '172.16.42.2', '172.128.1.1', reply=False)
    s.expect(PacketInputEvent("router-eth2", icmpreq, display=ICMP), 
            '''ICMP echo request (PING) to be forwarded to 172.128.1.1 should arrive on router-eth2.  
The destination address 172.128.1.1 should not match any entry in the forwarding table.''')
    arpreq = mk_arpreq('10:00:00:00:00:03', '172.16.42.1', '172.16.42.2')
    s.expect(PacketOutputEvent("router-eth2", arpreq), 
            "Router should send an ARP request for 172.16.42.2 out router-eth2.")
    arpresp = mk_arpresp(arpreq, '10:00:00:00:00:03', arphwsrc='30:00:00:00:00:01', arphwdst='10:00:00:00:00:03')
    s.expect(PacketInputEvent("router-eth2", arpresp, display=Arp), 
            "Router should receive ARP reply for 172.16.42.2 on router-eth2")
    icmperr = mk_icmperr('10:00:00:00:00:03', '30:00:00:00:00:01', '172.16.42.1', '172.16.42.2', 
                        ICMPType.DestinationUnreachable,
                        xcode=ICMPCodeDestinationUnreachable.NetworkUnreachable, 
                        origpkt=icmpreq)
    s.expect(PacketOutputEvent("router-eth2", icmperr), 
            "Router should send an ICMP destination network unreachable error back to 172.16.42.2 out router-eth2.")

    
    # test case 2: (ICMP error) Time Exceeded
    icmpreq = mk_ping('20:00:00:00:00:01', '10:00:00:00:00:01', '192.168.1.2', '172.16.42.2', reply=False, ttl=1)
    s.expect(PacketInputEvent("router-eth0", icmpreq, display=ICMP), 
            '''ICMP echo request (PING) for 172.16.42.2 with a TTL of 1 should arrive on router-eth0.
The router should decrement the TTL to 0 then see that the packet has "expired" and generate an ICMP time exceeded error.''')
    arpreq = mk_arpreq('10:00:00:00:00:01', '192.168.1.1', '192.168.1.2')
    s.expect(PacketOutputEvent("router-eth0", arpreq), 
            "Router should send an ARP request for 192.168.1.2 out router-eth0.")
    arpresp = mk_arpresp(arpreq, '10:00:00:00:00:01', arphwsrc='20:00:00:00:00:01', arphwdst='10:00:00:00:00:01')
    s.expect(PacketInputEvent("router-eth0", arpresp, display=Arp), 
            "Router should receive ARP reply for 192.168.1.2 on router-eth0")
    icmpreq = mk_ping('20:00:00:00:00:01', '10:00:00:00:00:01', '192.168.1.2', '172.16.42.2', reply=False, ttl=0)
    icmperr = mk_icmperr('10:00:00:00:00:01', '20:00:00:00:00:01', '192.168.1.1', '192.168.1.2', 
                        ICMPType.TimeExceeded, 
                        xcode=ICMPCodeTimeExceeded.TTLExpired, 
                        origpkt=icmpreq)
    s.expect(PacketOutputEvent("router-eth0", icmperr), 
            "Router should send an ICMP time exceeded error back to 192.168.1.2 out router-eth0.")


    # test case 3: (ICMP error) Destination Host Unreachable
    icmpreq = mk_ping('30:00:00:00:00:01', '10:00:00:00:00:03', '172.16.42.2', '10.10.0.254', reply=False)
    s.expect(PacketInputEvent("router-eth2", icmpreq, display=ICMP), 
            '''ICMP echo request (PING) from 172.16.42.2 for 10.10.0.254 should arrive on router-eth2.
The host 10.10.0.254 is presumed not to exist, so any attempts to send ARP requests will eventually fail.''')
    arpreq = mk_arpreq('10:00:00:00:00:02', '10.10.0.1', '10.10.0.254')
    s.expect(PacketOutputEvent("router-eth1", arpreq), 
            "Router should send an ARP request for 10.10.0.254 out router-eth1.")
    s.expect(PacketInputTimeoutEvent(1.0), 
            "Router should try to receive a packet (ARP response), but then timeout.")
    s.expect(PacketOutputEvent("router-eth1", arpreq), 
            "Router should send an ARP request for 10.10.0.254 out router-eth1.")
    s.expect(PacketInputTimeoutEvent(1.0), 
            "Router should try to receive a packet (ARP response), but then timeout.")
    s.expect(PacketOutputEvent("router-eth1", arpreq), 
            "Router should send an ARP request for 10.10.0.254 out router-eth1.")
    s.expect(PacketInputTimeoutEvent(1.0), 
            "Router should try to receive a packet (ARP response), but then timeout.")
    s.expect(PacketOutputEvent("router-eth1", arpreq), 
            "Router should send an ARP request for 10.10.0.254 out router-eth1.")
    s.expect(PacketInputTimeoutEvent(1.0), 
            "Router should try to receive a packet (ARP response), but then timeout.")
    s.expect(PacketOutputEvent("router-eth1", arpreq), 
            "Router should send an ARP request for 10.10.0.254 out router-eth1.")
    s.expect(PacketInputTimeoutEvent(1.0), 
            '''Router should try to receive a packet (ARP response), but then timeout.
At this point, the router should give up and generate an ICMP host unreachable error.''')
    icmpreq = mk_ping('30:00:00:00:00:01', '10:00:00:00:00:03', '172.16.42.2', '10.10.0.254', reply=False, ttl=63)
    icmperr = mk_icmperr('10:00:00:00:00:03', '30:00:00:00:00:01', '172.16.42.1', '172.16.42.2', 
                        ICMPType.DestinationUnreachable,
                        xcode=ICMPCodeDestinationUnreachable.HostUnreachable, 
                        origpkt=icmpreq)
    s.expect(PacketOutputEvent("router-eth2", icmperr), 
            "Router should send an ICMP destination host unreachable error back to 172.16.42.2 out router-eth2.")
    

    # test case 4: (ICMP error) Destination Port Unreachable
    udppkt = mk_udp('20:00:00:00:00:01', '10:00:00:00:00:01', '192.168.1.2', '192.168.1.1', ttl=8)
    s.expect(PacketInputEvent("router-eth0", udppkt), 
            '''A UDP packet addressed to the router's IP address 192.168.1.1 should arrive on router-eth0.
The router cannot handle this type of packet and should generate an ICMP destination port unreachable error.''')
    icmperr = mk_icmperr('10:00:00:00:00:01', '20:00:00:00:00:01', '192.168.1.1', '192.168.1.2', 
                        ICMPType.DestinationUnreachable,
                        xcode=ICMPCodeDestinationUnreachable.PortUnreachable, 
                        origpkt=udppkt)
    s.expect(PacketOutputEvent("router-eth0", icmperr), 
            "Router should send an ICMP destination port unreachable error back to 192.168.1.2 out router-eth0.")


    # test case 5: handle multiple packets in ARP queue
    icmpreq = mk_ping('30:00:00:00:00:01', '10:00:00:00:00:03', '172.16.42.2', '10.10.1.254', reply=False, ttl=18)
    s.expect(PacketInputEvent("router-eth2", icmpreq, display=ICMP), 
            '''ICMP echo request (PING) from 172.16.42.2 for 10.10.1.254 should arrive on router-eth2.
The host 10.10.1.254 is presumed not to exist, so any attempts to send ARP requests will eventually fail.''')
    arpreq = mk_arpreq('10:00:00:00:00:02', '10.10.0.1', '10.10.1.254')
    s.expect(PacketOutputEvent("router-eth1", arpreq), 
            "Router should send an ARP request for 10.10.1.254 out router-eth1.")
    icmpreq2 = mk_ping('20:00:00:00:00:01', '10:00:00:00:00:01', '192.168.1.2', '10.10.1.254', reply=False, ttl=10)
    s.expect(PacketInputEvent("router-eth0", icmpreq2, display=ICMP), 
            "ICMP echo request (PING) from 192.168.1.2 to be forwarded to 10.10.1.254 should arrive on router-eth0.(multiple packets)")
    s.expect(PacketInputEvent("router-eth2", icmpreq, display=ICMP), 
            "ICMP echo request (PING) from 172.16.42.2 for 10.10.1.254 should arrive on router-eth2.(multiple packets)")
    s.expect(PacketInputTimeoutEvent(1.0), 
            "Router should try to receive a packet (ARP response), but then timeout.")
    s.expect(PacketOutputEvent("router-eth1", arpreq), 
            "Router should send an ARP request for 10.10.1.254 out router-eth1.")
    s.expect(PacketInputTimeoutEvent(1.0), 
            "Router should try to receive a packet (ARP response), but then timeout.")
    s.expect(PacketOutputEvent("router-eth1", arpreq), 
            "Router should send an ARP request for 10.10.1.254 out router-eth1.")
    s.expect(PacketInputTimeoutEvent(1.0), 
            "Router should try to receive a packet (ARP response), but then timeout.")
    s.expect(PacketOutputEvent("router-eth1", arpreq), 
            "Router should send an ARP request for 10.10.1.254 out router-eth1.")
    s.expect(PacketInputTimeoutEvent(1.0), 
            "Router should try to receive a packet (ARP response), but then timeout.")
    s.expect(PacketOutputEvent("router-eth1", arpreq), 
            "Router should send an ARP request for 10.10.1.254 out router-eth1.")
    s.expect(PacketInputTimeoutEvent(1.0), 
            '''Router should try to receive a packet (ARP response), but then timeout.
At this point, the router should give up and generate an ICMP host unreachable error.''')
    icmpreq = mk_ping('30:00:00:00:00:01', '10:00:00:00:00:03', '172.16.42.2', '10.10.1.254', reply=False, ttl=17)
    icmperr = mk_icmperr('10:00:00:00:00:03', '30:00:00:00:00:01', '172.16.42.1', '172.16.42.2', 
                        ICMPType.DestinationUnreachable,
                        xcode=ICMPCodeDestinationUnreachable.HostUnreachable, 
                        origpkt=icmpreq)
    s.expect(PacketOutputEvent("router-eth2", icmperr), 
            "Router should send an ICMP destination host unreachable error back to 172.16.42.2 out router-eth2.")
    icmpreq2 = mk_ping('20:00:00:00:00:01', '10:00:00:00:00:01', '192.168.1.2', '10.10.1.254', reply=False, ttl=9)
    icmperr2 = mk_icmperr('10:00:00:00:00:01', '20:00:00:00:00:01', '192.168.1.1', '192.168.1.2', 
                        ICMPType.DestinationUnreachable,
                        xcode=ICMPCodeDestinationUnreachable.HostUnreachable, 
                        origpkt=icmpreq2)
    s.expect(PacketOutputEvent("router-eth0", icmperr2), 
            "Router should send an ICMP destination host unreachable error back to 192.168.1.2 out router-eth0.")
    s.expect(PacketOutputEvent("router-eth2", icmperr), 
            "Router should send an ICMP destination host unreachable error back to 172.16.42.2 out router-eth2.")
    

    

    return s

scenario = icmp_tests()
