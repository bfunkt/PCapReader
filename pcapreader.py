import sys
import os

files = ["test.pcapng"]

p_type = {  17:'tcp',
            6:'udp direct',
            1:'udp broadcast',
            3:'multicast',
          }

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

        while i < len(self.data):
            print("{0}.  {1}, {2}".format(self.p_count, hex(i), next_len))
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
            self.parse_pcap()

class Packet():
    def __init__(self, data, p_index):
        self.data = data
        self.length = len(data)
        self.protocol = int(data[23])
        self.p_index = p_index
        self.src_mac = data[:6]
        self.dst_mac = data[6:12]
        self.src_ip = b_to_ipaddr(data[26:30])
        self.dst_ip = b_to_ipaddr(data[30:34])
        self.src_port = hex_byteary_to_sum(data[36:34:-1])
        self.dst_port = hex_byteary_to_sum(data[38:36:-1])
        self.src_isweb = False
        self.dst_isweb = False

def b_to_ipaddr(data):
    a = []
    d = '.'
    for c in data:
        a.append(str(c))
    d = d.join(a)
    #print(d)
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





#for f in files:
#    open_files.append(PCapFile(f))
t = PCapFile(files[0])
