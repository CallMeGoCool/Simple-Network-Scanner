from scapy.all import ARP, Ether, srp

#performing ARP scan
def scan_network(target_ip):
    #mentioning whats the target IP address for ARP req
    arp = ARP(pdst=target_ip)
    #ensures ARP req reaches to all devices on network
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    #combines ARP pkt with Ethernet frame to create a complete pkt for sending
    packet = ether / arp
    #sending pkt using srp (send/req pkt) with timeout of 5s
    #verbose provides additional information beyond the essential results or errors. This is not currently req. for our pgm
    result = srp(packet, timeout=5, verbose=0)[0]
    #extracting results and storing in dictionary client
    # when a device wants to find the MAC address corresponding to an IP address, it sends an ARP request with its own IP address as the psrc
    #When a device sends an ARP request, it includes its own MAC address as the hwsrc.
    clients = [{"ip": received.psrc, "mac": received.hwsrc} for sent, received in result]

    return clients

#ensuring code runs only when the script is ru directly
if __name__ == "__main__":
    target_ip = input("Enter your IP address to scan the network [e.g format: ip_address/24]: ")

    # Perform network scan
    clients = scan_network(target_ip)

    # Print scan results
    print("IP" + " "*18 + "MAC")
    for client in clients:
        #16 specifies the min width of ip field
        #i.e. if ip field doesnot take 16 fields, it will add few blank spaces on left
        #The actual IP address remains unchanged; only the alignment is adjusted.
        print("{:16}     {}".format(client["ip"], client["mac"]))
