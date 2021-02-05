#!/usr/bin python

import netfilterqueue


def process_packet(packet):
    print(packet)
    packet.drop()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()


####Create net queue
    #### iptables -I FORWARD -j NFQUEUE --queue-num 0

####Reset iptables
    #### iptables --flush