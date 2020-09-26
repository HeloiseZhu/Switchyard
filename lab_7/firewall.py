from switchyard.lib.userlib import *
import time
import random

'''
TODO: (Task 2)
Define the class of rules
'''
class Rule(object):
    def __init__(self):
        self.permit = False         # permit or deny
        self.protocol = None        # ip, icmp, tcp or udp
        self.srcnet = None
        self.dstnet = None
        self.srcport = None
        self.dstport = None
        self.ratelimit = None       # limit-rate given in the rule
        self.impair = False         # impair packets or not
        self.tokennum = 0           # number of tokens



'''
TODO: (Task 2)
Return the index of the first rule pkt matches.
If pkt matches no rules, return -1.
'''
def match(rules, pkt):
    idx = -1
    for i in range(len(rules)):
        rule = rules[i]
        # src ip address & dst ip address
        if rule.srcnet and int(rule.srcnet.network_address) & int(pkt[IPv4].src) != int(rule.srcnet.network_address):
            continue
        if rule.dstnet and int(rule.dstnet.network_address) & int(pkt[IPv4].dst) != int(rule.dstnet.network_address):
            continue
        # src port & dst port & headers
        if rule.protocol == 'tcp':
            if not pkt.has_header(TCP):
                continue
            if rule.srcport and rule.srcport != pkt[TCP].src:
                continue
            if rule.dstport and rule.dstport != pkt[TCP].dst:
                continue
        elif rule.protocol == 'udp':
            if not pkt.has_header(UDP):
                continue
            if rule.srcport and rule.srcport != pkt[UDP].src:
                continue
            if rule.dstport and rule.dstport != pkt[UDP].dst:
                continue
        elif rule.protocol == 'icmp':
            if not pkt.has_header(ICMP):
                continue
        idx = i
        break
    return idx



def main(net):
    # assumes that there are exactly 2 ports
    portnames = [ p.name for p in net.ports() ]
    portpair = dict(zip(portnames, portnames[::-1]))
    rules = []

    '''
    TODO: (Task 2) 
    Read firewall_rules.txt and resolve rules
    '''
    fd = open('firewall_rules.txt', 'r')
    for line in fd.readlines():                    
        line = line.strip()
        # blank line or commentary
        if not len(line) or line.startswith('#'):
            continue
        s = line.split(' ')
        r = Rule()
        if 'permit' in s:
            r.permit = True
        r.protocol = s[1]
        r.srcnet = None if s[3]=='any' else IPv4Network(s[3], strict=False)
        if r.protocol == 'ip' or r.protocol == 'icmp':
            r.dstnet = None if s[5]=='any' else IPv4Network(s[5], strict=False)
        else:
            r.dstnet = None if s[7]=='any' else IPv4Network(s[7], strict=False)
            r.srcport = None if s[5]=='any' else int(s[5])
            r.dstport = None if s[9]=='any' else int(s[9])
        if 'ratelimit' in s:
            r.ratelimit = int(s[-1])
            r.tokennum = r.ratelimit
        if 'impair' in s:
            r.impair = True
        rules.append(r)
    fd.close()


    tokentime = time.time()
    while True:
        pkt = None
        try:
            timestamp,input_port,pkt = net.recv_packet(timeout=0.25)
        except NoPackets:
            pass
        except Shutdown:
            break
        
        '''
        TODO: (Task 3)
        Update the number of tokens
        '''
        if time.time() - tokentime >= 0.5:
            tokentime = time.time()
            for i in range(len(rules)):
                rule = rules[i]
                if rule.ratelimit:
                    if rule.tokennum + rule.ratelimit/2 <= 2*rule.ratelimit:
                        rule.tokennum += rule.ratelimit/2
                    else:
                        rule.tokennum = 2*rule.ratelimit
                    log_debug("Rule {} token: {}".format(i+1, rule.tokennum))


        if pkt is not None:
            # This is logically where you'd include some  firewall
            # rule tests.  It currently just forwards the packet
            # out the other port, but depending on the firewall rules
            # the packet may be dropped or mutilated.
            log_debug("Got a packet: {}".format(str(pkt)))

            if pkt.has_header(IPv4):
                i = match(rules, pkt)
                if i != -1:
                    # Rule i+1 matches pkt
                    rule = rules[i]
                    if rule.permit:
                        # TODO: (Task 3)
                        if rule.ratelimit:
                            pktlen = len(pkt) - len(pkt.get_header(Ethernet))
                            if pktlen <= rule.tokennum:
                                rule.tokennum -= pktlen
                                net.send_packet(portpair[input_port], pkt)
                                log_debug("Sending packet {}".format(pkt))
                                log_debug("Rule {} token: {}".format(i+1,rule.tokennum))
                        # TODO: (Task 4)
                        elif rule.impair:
                            '''
                            # Randomly drop packets
                            p = random.uniform(0, 1)
                            if p > droprate:
                                net.send_packet(portpair[input_port], pkt)
                                log_info("Sending packet {}".format(pkt))
                            '''
                            hdrs = pkt[Ethernet] + pkt[IPv4] + pkt[TCP]
                            # Change payload of pkt into 'Hello, I'm Trudy.;)'
                            pkt = hdrs + bytes("Hello, I'm Trudy.;)", encoding='utf8')
                            net.send_packet(portpair[input_port], pkt)
                            log_info("Sending packet {}".format(pkt))
                        # TODO: (Task 2) Just forward pkt
                        else:
                            net.send_packet(portpair[input_port], pkt)
                            log_info("Sending packet {}".format(pkt))
                    # else: deny(drop pkt)
                else:
                    # No rule matches pkt
                    net.send_packet(portpair[input_port], pkt)
                    log_debug("Sending packet {}".format(pkt))
            else:
                # Forward IPv6, ARP and other type of packets
                net.send_packet(portpair[input_port], pkt)
                log_debug("Sending packet(not IPv4 packet) {}".format(pkt))
            
            
    net.shutdown()
