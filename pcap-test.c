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
			return -1;

		if(ntohs(ethernet.type) == P_IPv4)
		{
			// Show_Ethernet(&ethernet);
			u_char* p = (u_char*)packet;
			p+=14;
			if(!Ipv4_Capture(p, &ipv4))
				return -1;
			
			if(ipv4.protocol == P_TCP)
			{
				Show_IPv4(&ipv4);	
			}
			else
				printf("'%02x' This Protocol Not TCP\n",ipv4.protocol);
		}
		else
		{
			printf("This protocol is not IPv4");
			continue;
		}
	}

	pcap_close(pcap);
}
