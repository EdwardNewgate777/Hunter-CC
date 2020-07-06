import sys
import socket
from scapy.sendrecv import sniff
from scapy.layers.inet import *
import pydnsbl

start = 'True'
target = sys.argv[1]
check_range = '.'.join(target.split('.')[0:3])
ip_network = ['224.0.0.251', '239.255.255.250', '224.0.0.22', '224.0.0.252', '255.255.255.255']
ip_dst = []

def check_pkt(pkt):
    if IP in pkt:
        if pkt['IP'].dst.find(check_range) == -1 and not pkt['IP'].dst in ip_network:
            ip_dst.append(pkt['IP'].dst)
            #print(pkt['IP'].dst)
            #exit()

def convertToStr(list):
    result = ','.join(list)
    return result

def check_rep(list):
    end_list = []
    ip_checker = pydnsbl.DNSBLIpChecker()

    for ip in list:
        result = ip_checker.check(ip)
        if result.blacklisted:
            end_list.append(ip)

    if len(end_list) > 0:
        print("C2 Trouver2")
        return convertToStr(end_list)
    elif len(end_list) == 0:
        print("Tout envoyer")
        return convertToStr(list)

def get_C2(all_ip):
    all_ip = list(set(all_ip))
    print(all_ip)
    if len(all_ip) == 0:
        print("Aucun C2 n'a ete trouvé")
        print(None)
    elif len(all_ip) == 1:
        print("C2 TROUVER ")
        print(convertToStr(all_ip))
    else:
        print("Plusieurs IP")
        result = check_rep(all_ip)
        print(result)


sniff(filter='src {}'.format(target), prn=check_pkt, timeout=30)
get_C2(ip_dst)



