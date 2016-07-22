#include "getLocalAddress.h"
#include <pcap.h>
#include <stdio.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

struct myAddress getMyAddr()
{
    static int flag = 0;
    static struct myAddress myAddr;

    if(flag==0)
    {
        FILE* fp;
        char *dev;
        char cmd[256] = {0x0}, errbuf[PCAP_ERRBUF_SIZE];
        char MACbuf[20] = {0x0}, IPbuf[20] = {0x0};
        
        dev = pcap_lookupdev(errbuf);

        // get MAC info    
        sprintf(cmd,"ifconfig | grep '%s' | awk '{print $5}'", dev);
    
        fp = popen(cmd, "r");
        fgets(MACbuf, sizeof(MACbuf), fp);
        pclose(fp);

        ether_aton_r(MACbuf, &myAddr.MAC);

        // get IP info
        sprintf(cmd,"ifconfig | grep -A 1 '%s' | grep 'inet addr' | awk '{print $2}' | awk -F':' '{print $2}'", dev);
        
        fp = popen(cmd, "r");
        fgets(IPbuf, sizeof(IPbuf), fp);
        pclose(fp);

        inet_aton(IPbuf, &myAddr.IP);

        // get Subnet Mask
        sprintf(cmd,"ifconfig | grep -A 1 '%s' | grep 'Mask' | awk '{print $4}' | awk -F':' '{print $2}'", dev);
        
        fp = popen(cmd, "r");
        fgets(IPbuf, sizeof(IPbuf), fp);
        pclose(fp);

        inet_aton(IPbuf, &myAddr.subMask);

        flag = 1;
    }

    return myAddr;
}

struct in_addr getGatewayIP()
{
    static int flag = 0;
    static struct in_addr gatewayIP;

    if(flag==0)
    {
        FILE* fp;
        char *dev;
        char cmd[256] = {0x0}, errbuf[PCAP_ERRBUF_SIZE];
        char IPbuf[20] = {0x0};

        dev = pcap_lookupdev(errbuf);
        
        // get gateway IP
        sprintf(cmd,"route -n | grep '%s'  | grep 'UG' | awk '{print $2}'", dev);
        
        fp = popen(cmd, "r");
        fgets(IPbuf, sizeof(IPbuf), fp);
        pclose(fp);

        inet_aton(IPbuf, &gatewayIP);

        flag = 1;
    }

    return gatewayIP;
}