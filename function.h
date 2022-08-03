bool Ethernet_Capture(const u_char* p, Ethernet* e)
{
    if(memcpy(e, p, 14) == NULL)
		{
			printf("Cant Memory copy Next Step");
			return false;
		}
    return true;
}

void Show_Ethernet(Ethernet* en)
{
	printf("Ethernet Source MAC ");
	for(int i = 0; i < 5; i++)
		printf("%02x:", en->source[i]);
	printf("%02x", en->source[5]);

	printf("\nEthernet Destination MAC ");
	for(int i= 0; i < 5; i++)
		printf("%02x:", en->destination[i]);
	printf("%02x\n", en->source[5]);
}

bool Ipv4_Capture(const u_char* p, IP* i)
{
   if(memcpy(i, p, 20) == NULL)
	{
		printf("Cant Memory copy");
		return false;
	}
    return true;
}

void Show_IPv4(IP* ip)
{
    printf("Source IP Address %s\n", inet_ntoa(ip->source));
    printf("Destination IP Address %s\n", inet_ntoa(ip->destination));
}

bool Tcp_Capture(const u_char* p, TCP* t)
{
	if(memcpy(t, p, 22) == NULL)
	{
		printf("Cant Memory copy");
		return false;
	}
    return true;
}

void Show_TCP(TCP* tcp)
{
	printf("Source Port %d\n",ntohs(tcp->sourcePort));
	printf("Destination Port %d\n", ntohs(tcp->destinationPort));
}

void Cal_Data_length(IP* ipv4, TCP* tcp, int* res)
{
	*res = ntohs(ipv4->total_Len) - ((ipv4->version_IHL & 0xf) *4) 
	- (((tcp->data_Reserve_Ns & 0xf0)>>4)*4);
}

bool Data_Capture(const u_char* p, u_char* d)
{
	if(memcpy(d, p, 10) == NULL)
	{
		printf("Cant Memory copy");
		return false;
	}
    return true;
}

void Show_Data(u_char* d)
{
	printf("Data: %s\n", d);
}