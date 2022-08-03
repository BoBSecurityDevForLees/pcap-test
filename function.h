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
	printf("Ethernet Source MAC");
	for(int i = 0; i < 6; i++)
		printf(" %02x:", en->source[i]);
	printf("\nEthernet Destination MAC");
	for(int i= 0; i < 6; i++)
		printf(" %02x:", en->destination[i]);
	printf("\n");
}

bool Ipv4_Capture(const u_char* p, IP* i)
{
   if(memcpy(i, p, 36) == NULL)
		{
			printf("Cant Memory copy Next Step");
			return false;
		}
    return true;
}

void Show_IPv4(IP* ip)
{
    struct in_addr Source, Destination;
    Source.s_addr = ip->source;
    Destination.s_addr = ip->destination;
    printf("Source IP Address %s\n", inet_ntoa(Source));
    printf("Destination IP Address %s\n", inet_ntoa(Destination));
}
