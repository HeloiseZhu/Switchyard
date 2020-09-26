#!/usr/bin/env python3

from switchyard.lib.userlib import *

def router_tests():
    s = TestScenario("my router tests")
    s.add_interface('eth0', '10:00:00:00:00:01', '8.4.2.1')
    s.add_interface('eth1', '10:00:00:00:00:02', '255.255.255.255')
    s.add_interface('eth2', '10:00:00:00:00:03', '192.168.2.100')

    # test case 1: ARP request for 255.255.255.255 should arrive on router-eth1
    reqpkt = create_ip_arp_request("20:00:00:00:00:02", "255.255.255.1", "255.255.255.255")
    s.expect(PacketInputEvent("eth1", reqpkt), "ARP request for 255.255.255.255 should arrive on router-eth1.")
    reppkt = create_ip_arp_reply("10:00:00:00:00:02", "20:00:00:00:00:02", "255.255.255.255", "255.255.255.1")
    s.expect(PacketOutputEvent("eth1", reppkt), "Router should send ARP reply for 255.255.255.1 on router-eth0.")

    # test case 2: ARP reply for 8.4.2.1 should arrive on router-eth0
    reppkt = create_ip_arp_reply("30:00:00:00:00:01", "10:00:00:00:00:01", "8.4.2.2", "8.4.2.1")
    s.expect(PacketInputEvent("eth0", reppkt), "ARP reply for 8.4.2.1 should arrive on router-eth0.")
    s.expect(PacketInputTimeoutEvent(1.0), "The router should not do anything in response to ARP reply but update the cached ARP table.")

    # test case 3: Update a certain entry in ARP table
    reppkt = create_ip_arp_reply("30:00:00:00:00:03", "10:00:00:00:00:01", "8.4.2.2", "8.4.2.1")
    s.expect(PacketInputEvent("eth0", reppkt), "ARP reply for 8.4.2.1 should arrive on router-eth0(The entry for IP address 8.4.2.2 should be updated).")
    s.expect(PacketInputTimeoutEvent(1.0), "The router should not do anything in response to ARP reply but update the cached ARP table.")

    # test case 4: Pause for 25 seconds 
    s.expect(PacketInputTimeoutEvent(25.0), "Pause for 25 seconds(The ARP table should be empty).")

    # test case 5: Test the timeout mechanism of the router
    reqpkt = create_ip_arp_request("40:00:00:00:00:02", "192.168.1.100", "192.168.2.100")
    s.expect(PacketInputEvent("eth2", reqpkt), "ARP request for 192.168.2.100 should arrive on router-eth2(The ARP table should contain only one entry).")
    reppkt = create_ip_arp_reply("10:00:00:00:00:03", "40:00:00:00:00:02", "192.168.2.100", "192.168.1.100")
    s.expect(PacketOutputEvent("eth2", reppkt), "Router should send ARP reply for 192.168.1.100 on router-eth2.")

    return s

scenario = router_tests()
