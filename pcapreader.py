import sys
import os
import struct


files = ['test.pcapng']

p_type = {  0x11:'udp/broadcast/multicast',
            0x06:'tcp',
            0x0806:'arp',
            0x8899:'L2broadcast',
          }


internal_ip = ['192.168.', '239.255.', '0.0.0.0']

open_files = []
t = None

class PCapFile():
    def __init__(self, filename):
        self.filename = filename
        self.format = filename.split('.')[1]
        self.data = None
        self.data_header = None
        self.valid = True
        self.p_count = 0
        self.packets = []

        self.open_pcap()

    def parse_pcap(self):
        i = 0x16c
        self.data_header = self.data[:i]
        next_len = round_up(hex_byteary_to_sum(self.data_header[-4:]), 4)

        while i < self.end_of_packets_index:
            #print("{0}.  {1}, {2}".format(self.p_count, hex(i), next_len))
            self.packets.append(Packet(self.data[i:i+next_len+32], self.p_count))
            i += next_len + 32
            next_len = round_up(hex_byteary_to_sum(self.packets[self.p_count].data[-4:]), 4)
            self.p_count += 1


    def open_pcap(self):
        if os.path.exists(self.filename):
            with open(self.filename, 'r+b') as f:
                try:
                    self.data = bytearray(f.read())
                except IOError as e:
                    print("*** I/O error({0}): {1}.\n".format(e.errno, e.strerror))
                    self.valid = False
                except:
                    print("*** Unexpected error:", sys.exc_info()[0], "\n")
                    print("*** PCapReader failed to open file \'", self.filename,"\'.\n")
                    self.valid = False
        if self.valid:
            self.end_of_packets_index = self.data.find(b'\x01\x00\x1c\x00\x43\x6f\x75\x6e')
            self.parse_pcap()

class Packet():
    def __init__(self, data, p_index):
        self.data = data
        self.length = len(data)
        self.p_index = p_index
        self.dst_mac = data[:6]
        self.src_mac = data[6:12]
        self.is_L2broad = check_for_L2b_or_arp(self.dst_mac, data[12:14])
        if self.is_L2broad:
            self.protocol = data[12:14]
            self.src_ip = b_to_ipaddr(data[28:32])
            self.dst_ip = b_to_ipaddr(data[38:42])
        else:
            self.protocol = str(data[23])
            self.src_ip = b_to_ipaddr(data[26:30])
            self.dst_ip = b_to_ipaddr(data[30:34])
        self.src_port = hex_byteary_to_sum(data[36:34:-1])
        self.dst_port = hex_byteary_to_sum(data[38:36:-1])
        self.src_isweb = check_for_internal_ip(self.src_ip)
        self.dst_isweb = check_for_internal_ip(self.dst_ip)

def b_to_ipaddr(data):
    a = []
    d = '.'
    for c in data:
        a.append(str(c))
    d = d.join(a)
    print(d)
    return d

def b_to_int(data):
    t = 0
    n = 1
    for c in data:
        t += n * c
        n *= 256
    return t

def round_up(i, base):
    i += (base - (i % base)) % base
    return i

def hex_byteary_to_sum(data):
    t = 0
    n = 1
    for c in data:
        t += n * c
        n *= 256
    return t

def check_for_internal_ip(s):
    return not any (s.startswith(x) for x in internal_ip)

def check_for_L2b_or_arp(mac, protocol):
    a = mac == b'\xff\xff\xff\xff\xff\xff' 
    b = protocol in [b'\x08\x06', b'\x88\x99']
    return(a or b)



#for f in files:
#    open_files.append(PCapFile(f))
t = PCapFile(files[0])




