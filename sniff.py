import ipaddress
import sys
import socket

from pydnsbl import *
from scapy.sendrecv import sniff
from scapy.layers.inet import *
from pydnsbl.providers import *

start = 'True'
target = sys.argv[1]
check_range = '.'.join(target.split('.')[0:3])
ip_network = ['224.0.0.251', '239.255.255.250', '224.0.0.22', '224.0.0.252', '255.255.255.255']
ip_dst = []

def check_pkt(pkt):
    if IP in pkt:
        if pkt['IP'].dst.find(check_range) == -1 and not pkt['IP'].dst in ip_network:
            ip_dst.append(pkt['IP'].dst)


def convertToStr(list):
    result = ', '.join(list)
    return result

def check_bl(list):
    end_list = []
    ip_checker = DNSBLIpChecker()

    for ip in list:
        result = ip_checker.check(ip)
        if result.blacklisted:
            end_list.append(ip)

    if len(end_list) > 0:
        return convertToStr(end_list)
    elif len(end_list) == 0:
        return convertToStr(list)

def check_wl(list):
    new_list = list[0:]

    with open('/home/edward/whitelist','r') as file:
        list_range = file.read().split('\n')
        del list_range[-1]

        for ip in list:
            for range in list_range:
                if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(range):
                    new_list.remove(ip)

        return new_list


def get_C2(all_ip):
    all_ip = list(set(all_ip))
    all_ip = check_wl(all_ip)
    if len(all_ip) == 0:
        print(None)
    elif len(all_ip) == 1:
        print(convertToStr(all_ip))
    else:
        result = check_bl(all_ip)
        print(result)


sniff(filter='src {}'.format(target), prn=check_pkt, timeout=30)
get_C2(ip_dst)



