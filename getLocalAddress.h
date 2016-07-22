#include <netinet/ether.h>
#include <arpa/inet.h>

struct myAddress{
    struct in_addr IP;
    struct ether_addr MAC;
    struct in_addr subMask;
};

struct myAddress getMyAddr();
struct in_addr getGatewayIP();