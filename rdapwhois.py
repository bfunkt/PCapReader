from ipwhois import IPWhois as ipw
import pprint
import socket
import sys


entries = {}
pp = pprint.PrettyPrinter(indent=4)



class MyIPW:
    def __init__(self, ip=None):
        self.ip = ip
        self.obj = None
        self.valid = True
        self.rtn = None
        try:
            self.obj = ipw(ip)
        except:
            print("*** Could not create IPWhois object. Bad IP address.\n")
            self.valid = False

    def lookup(self):
        try:
            self.rtn = self.obj.lookup_rdap(asn_methods=['http','whois','dns'], get_asn_description=True)
            return self.rtn
        except:
            print(self.ip, "lookup_rdap() failed.\n")


def run_input():
    while(True):
        print("Enter IP Address:")
        ip_input = input(">  ")
        if ip_input.lower() in ["exit", "quit", "done", "back", "end", "main"]:
            break 
        try:
            rtn = None
            socket.inet_aton(ip_input)

            if ip_input not in entries.keys():
                entry = MyIPW(ip_input)
                if entry.valid:
                    rtn = entry.lookup()
                    if entry.rtn is not None:
                        entries[ip_input] = entry
                        print("---   ", entry.rtn['asn_description'], "  |  ", entry.rtn['entities'], "\n")
                    else:
                        pass
            else:
                print("*** An entry already exists using this IP address.\n")
        except socket.error:
            print("*** socket.inet_aton error - bad IP address.\n")

run_input()



            
def show_names():
    for k, v in entries.items():
        print("---   ", k, "  |  ", v.rtn['asn_description'], "  |  ", v.rtn['entities'] )

def show_defined_kv(k, v, key):
    print("---   ", k, "  |  ")
    pp.pprint(v.rtn[key])
    print("\n")

def show_all_data(k, v):
    print("\n---   ", k, "\n")
    pp.pprint(v.rtn)
    print("\n")

def show_by_ip(ip, key):
    obj = entries[ip]
    #all keys
    if key == None:
        show_all_data(ip, obj)
    #specific key provided, found in rtn data
    elif key in obj.rtn.keys():
        show_defined_kv(ip, obj, key)
    #specific key provided, but key not found in rtn data
    else:
        print("*** Return data for entry  ", ip, "  does not contain key < ", key, " >.\n") 

def show(ip=None, key=None):
    #iterate over all entries
    if ip == None:
        for ip in entries:
            show_by_ip(ip, key)  
    #one specific entry, identified by string IP address
    elif ip in entries:
        show_by_ip(ip, key)
    #one specific entry, but IP not found
    else:
        print("*** The provided IP address does not match any current data entries.")           



