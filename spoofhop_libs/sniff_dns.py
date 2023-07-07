from scapy.all      import *
from queue          import Queue
from netfilterqueue import NetfilterQueue
import time
import multiprocessing 


def parse_dns_packet(packet):
    global domain_list

    try:
        spacket = IP(packet.get_payload())  

        if 'DNS' in spacket:   

            if len(spacket.qd.qname) > 0:
                domain = spacket.qd.qname.decode('latin-1')[0:-1]

                if domain in domain_list:
                    packet_queue.send((domain, spacket))
                    packet.drop()  
                    return

        packet.accept()

    except Exception as e:
        print(e)
        packet.accept()



def start_sniffing():
    global net_queue

    net_queue = NetfilterQueue()
    net_queue.bind(1, parse_dns_packet)

    try:
        net_queue.run()
        
    except:
        pass


def packet_sniffing_generator(_domain_list):
    global packet_queue, domain_list
    domain_list = _domain_list

    packet_queue, queue_receiver = multiprocessing.Pipe()

    process = multiprocessing.Process(target=start_sniffing)
    process.start()

    while True:
        yield queue_receiver.recv()