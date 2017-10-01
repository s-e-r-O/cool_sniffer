#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>

#include "header_reader.h"





int ether_reader(const u_char *bytes, unsignet int totalLength)
{
	struct ether_header *headerEthernet = (struct ether_header *) bytes;
  
  	printf("MAC Destination:	%s\n", ether_ntoa((struct ether_addr *) headerEthernet->ether_dhost));
  	printf("MAC Source:	%s\n", ether_ntoa((struct ether_addr *) headerEthernet->ether_shost));

  	printf("Ether Type:	0x%04x\n", ntohs(headerEthernet->ether_type));  


  	switch(ntohs(headerEthernet->ether_type))
  	{
    	case ETHERTYPE_IP:
    			printf("\nETHERTYPE:	IP\n");
				ip_reader(bytes + sizeof(*headerEthernet));
    	break;
    	case ETHERTYPE_ARP:
    			printf("\nETHERTYPE:	ARP\n");
				arp_reader(bytes + sizeof(*headerEthernet));
      	break;
    	case ETHERTYPE_IPV6:
    			printf("\nETHERTYPE:	IPv6\n");
				ipv6_reader(bytes + sizeof(*headerEthernet));
      	break;
    }
}


int ip_reader(const u_char *bytes)
{
	struct ip *headerIP = (struct ip *) bytes;
  
  	printf("Version: %u\n", headerIP->ip_v);
  	printf("Internet Header Length:	%u\n", headerIP->ip_hl);
  	printf("Type Of Service: %u\n", headerIP->ip_tos);
  	printf("Size Of Datagram Or Total Length: %u\n", headerIP->ip_len);
  	printf("Identification Tag: %u\n", headerIP->ip_id);
  	/*printf("Flag1: %x\n", headerIP->IP_RF);		// reserved bit
  	printf("Flag2: %x\n", headerIP->IP_DF);		// don't fragment
  	printf("Flag3: %x\n", headerIP->IP_MF);		// more fragments
  	printf("Flag4: %x\n", headerIP->IP_OFFMASK);	*/		
  	printf("Fragment Offset: %u\n", headerIP->ip_off);
  	printf("Time To Live TTL: %u\n", headerIP->ip_ttl);
  	printf("Protocol: %u\n", headerIP->ip_p);
  	printf("Header Checksum: %u\n", headerIP->ip_sum);
  	printf("Source Address:		%s\n", inet_ntoa(headerIP->ip_src));
  	printf("Destination Address:	%s\n", inet_ntoa(headerIP->ip_dst));

  	switch(headerIP->ip_p)
	{
		case IPPROTO_TCP:
				printf("\nPROTOCOL Inside Of The IP Is:	 TCP\n");
	    		tcp_reader(bytes + headerIP -> ip_hl * 4);
	    break;
	    case IPPROTO_UDP:
	    		printf("\nPROTOCOL Inside Of The IP Is:	 UDP\n");
	    		udp_reader(bytes + headerIP -> ip_hl * 4);
	    break;
	}

}

int arp_reader(const u_char *bytes)
{


}

int ipv6_reader(const u_char *bytes)
{
	struct ip6_hdr *headerIPv6 = (struct ip6_hdr *) bytes;

	//printf("Source: %s\n", inet_ntop(AF_INET6, *(headerIPv6->ip6_src), NULL, INET6_ADDRSTRLEN));
  	//printf("Destination: %s\n", inet_ntop(AF_INET6, *(headerIPv6->ip6_dst), NULL, INET6_ADDRSTRLEN));
}


int tcp_reader(const u_char *bytes)
{
	struct tcphdr *headerTCP = (struct tcphdr *) bytes;

	printf("Source Port: %u\n", ntohs(headerTCP->th_sport));
	printf("Destinaton Port: %u\n", ntohs(headerTCP->th_dport));
	printf("Sequence Number: %u\n", ntohl(headerTCP->th_seq));
	printf("Acknowledgment Number: %u\n", ntohl(headerTCP->th_ack));
	printf("Data Offset: %u\n", headerTCP->th_off);
	//printf("Reserved: %u\n", headerTCP->th_ack);
	printf("Flags: %u\n", headerTCP->th_flags);
	printf("Window Size: %u\n", ntohs(headerTCP->th_win));
	printf("Checksum: %u\n", ntohs(headerTCP->th_sum));
	printf("Urgent Pointer: %u\n", ntohs(headerTCP->th_urp));

	http_reader(bytes + headerTCP->th_off * 4);
}

int udp_reader(const u_char *bytes)
{
	struct udphdr *headerUDP = (struct udphdr *) bytes;

	printf("Source Port: %u\n", ntohs(headerUDP->uh_sport));
	printf("Destinaton Port: %u\n", ntohs(headerUDP->uh_dport));
	printf("UDP Length: %u\n", ntohs(headerUDP->uh_ulen));
	printf("Checksum: %u\n", ntohs(headerUDP->uh_sum));

	http_reader(bytes + headerUDP->uh_ulen);
}


int http_reader(const u_char *bytes)
{
	int i = 0;

	unsignet int aux;
	aux = totalLength - (sizeof(headerEthernet))
	for (i; i < ; ++i)
	{
		/* code */
	}
	printf("El mensaje es: %c");
}