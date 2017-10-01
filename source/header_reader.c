#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>

#include "header_reader.h"

int ether_reader(const u_char *bytes, bpf_u_int32 totalLength)
{
	struct ether_header *headerEthernet = (struct ether_header *) bytes;
  
  	printf("MAC Destination:	%s\n", ether_ntoa((struct ether_addr *) headerEthernet->ether_dhost));
  	printf("MAC Source:	%s\n", ether_ntoa((struct ether_addr *) headerEthernet->ether_shost));

  	printf("Ether Type:	0x%04x\n", ntohs(headerEthernet->ether_type));  


  	switch(ntohs(headerEthernet->ether_type))
  	{
    	case ETHERTYPE_IP:
    			printf("\nETHERTYPE:	IP\n");
				ip_reader(bytes + sizeof(*headerEthernet), totalLength);
    	break;
    	case ETHERTYPE_ARP:
    			printf("\nETHERTYPE:	ARP\n");
				arp_reader(bytes + sizeof(*headerEthernet), totalLength);
      	break;
    	case ETHERTYPE_IPV6:
    			printf("\nETHERTYPE:	IPv6\n");
				ipv6_reader(bytes + sizeof(*headerEthernet), totalLength);
      	break;
    }
}


int ip_reader(const u_char *bytes, bpf_u_int32 totalLength)
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
	    		tcp_reader(bytes + headerIP -> ip_hl * 4, totalLength);
	    break;
	    case IPPROTO_UDP:
	    		printf("\nPROTOCOL Inside Of The IP Is:	 UDP\n");
	    		udp_reader(bytes + headerIP -> ip_hl * 4, totalLength);
	    break;
	}

}

int arp_reader(const u_char *bytes, bpf_u_int32 totalLength)
{


}

int ipv6_reader(const u_char *bytes, bpf_u_int32 totalLength)
{
	struct ip6_hdr *headerIPv6 = (struct ip6_hdr *) bytes;

	//printf("Source: %s\n", inet_ntop(AF_INET6, *(headerIPv6->ip6_src), NULL, INET6_ADDRSTRLEN));
  	//printf("Destination: %s\n", inet_ntop(AF_INET6, *(headerIPv6->ip6_dst), NULL, INET6_ADDRSTRLEN));
}

int http_reader(const u_char *bytes, bpf_u_int32 totalLength)
{
	/*int i = 0;

	bpf_u_int32 aux;
	aux = totalLength - (sizeof(headerEthernet))
	for (i; i < ; ++i)
	{
		// code 
	}
	printf("El mensaje es: %c");
  */
}