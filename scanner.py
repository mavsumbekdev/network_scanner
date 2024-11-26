import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--ip", dest="ip", help="ip manzil")
    (options,args)= parser.parse_args()
    if not options.ip:
        parser.error("ip manzil kiritilmadi")
    return options
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    brodcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_brodcast = brodcast/arp_request
    answer_list = scapy.srp(arp_request_brodcast,timeout=1, verbose=False)[0]

    client_list = []
    for element in answer_list:
        client_dict = {"ip":element[1].psrc,"mac":element[1].hwsrc}
        client_list.append(client_dict)
    return client_list
    
def print_result(result_list):
    print("IP\t\t\tMac manzil\n-----------------------------------------")
    for client in result_list:
        print(client["ip"]+"\t\t"+client["mac"])

option = get_arguments()
scan_result = scan(option.ip)
print_result(scan_result)
