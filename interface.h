#define ETHER_ADDR_LEN 6
#define MAX_TCP_LEN 10

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
	u_char dscp_Ecn;
	u_int16_t total_Len;
	u_int16_t identifier;
	u_int16_t flag_Offset;
	u_char ttl;
	u_char protocol;
	u_int16_t checksum;
	struct in_addr source;
	struct in_addr destination;
} IP;

typedef struct tcp {
	u_int16_t sourcePort;
	u_int16_t destinationPort;
	u_int32_t squenceNumber;
	u_int32_t ack;
	u_char data_Reserve_Ns;
	u_char flags;
	u_int16_t window_size;
	u_int16_t checksun;
	u_int16_t URG;
} TCP;
