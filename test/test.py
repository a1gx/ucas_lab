import pyshark

cap = pyshark.LiveCapture(interface='en0')


def print_conversation_header(pkt):
    try:
        protocol = pkt.transport_layer
        src_addr = pkt.ip.src
        src_port = pkt[pkt.transport_layer].srcport
        dst_addr = pkt.ip.dst
        dst_port = pkt[pkt.transport_layer].dstport
        print('%s  %s:%s --> %s:%s' % (protocol, src_addr, src_port, dst_addr, dst_port))
    except AttributeError as e:
        # ignore packets that aren't TCP/UDP or IPv4
        pass


cap.apply_on_packets(print_conversation_header)
