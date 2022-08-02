#define ETHER_ADDR_LEN 6
#define P_IPv4 0x0800
#define P_ARP 0x0806

#define P_TCP 0x06
#define P_UDP 0x17

typedef struct ethernet {
	u_char destination[ETHER_ADDR_LEN];
	u_char source[ETHER_ADDR_LEN];
	u_int16_t type;
} Ethernet;

typedef struct ip {
	u_char version;
	u_char IHL;
	u_int16_t total_len;
	u_int32_t souce;
	u_int32_t destination;
} IP;

typedef struct tcp {
	u_int16_t sourcePort;
	u_int16_t destinationPort;
	u_char dataoffset;
} TCP;
