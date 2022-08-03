#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include "interface.h"
#include "function.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;  //error 
		Ethernet ethernet;
		IP ipv4;
		TCP tcp;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		// Ethernet struct memory copy
		if(!Ethernet_Capture(packet, &ethernet))
			// error
			return -1;

		if(ntohs(ethernet.type) == P_IPv4)
		{
			u_char* p = (u_char*)packet;
			
			// Move to Read IPv4 Data
			p+=14;
			if(!Ipv4_Capture(p, &ipv4))
				// error
				return -1;
			
			if(ipv4.protocol == P_TCP)
			{
				// Move to Read TCP Data
				p+=20;

				Tcp_Capture(p, &tcp);
				// printf("%d\n",ntohs(ipv4.total_Len));
				// printf("%d\n",(ipv4.version_IHL & 0xf) *4);
				// printf("%d\n",((tcp.data_Reserve_Ns & 0xf0)>>4)*4);
				// int tcp_Data_length = ntohs(ipv4.total_Len) 
				// - ((ipv4.version_IHL & 0xf) *4) - (((tcp.data_Reserve_Ns & 0xf0)>>4)*4);
				int tcp_Data_length = 0;
				Cal_Data_length(&ipv4, &tcp, &tcp_Data_length);
				Show_Ethernet(&ethernet);
				Show_IPv4(&ipv4);
				Show_TCP(&tcp);
				if(tcp_Data_length == 0)
					printf("There is No TCP Data\n");
				else
				{
					p+=22;
					p+=((tcp.data_Reserve_Ns & 0xf0)>>4)*4 - 22;
					u_char tcp_Data[MAX_TCP_LEN];
					if(!Data_Capture(p, tcp_Data))
						return -1;
					Show_Data(tcp_Data);
				}	
			}
			else
				printf("'%02x' This Protocol Not TCP\n",ipv4.protocol);
		}
		else
			printf("This protocol Not IPv4\n");
			
		printf("\n");
	}

	pcap_close(pcap);
}
