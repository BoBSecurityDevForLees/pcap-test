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
	u_char version_IHL;
	u_char Dscp_Ecn;
	u_int16_t total_len;
	u_int16_t identifier;
	u_int16_t flag_offset;
	u_char ttl;
	u_char protocol;
	u_int16_t checksum;
	u_int32_t source;
	u_int32_t destination;
} IP;

typedef struct tcp {
	u_int16_t sourcePort;
	u_int16_t destinationPort;
	u_char dataoffset;
} TCP;
