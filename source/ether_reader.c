#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>

#include "header_reader.h"


int ether_reader(const u_char *bytes, bpf_u_int32 totalLength)
{
	struct ether_header *headerEthernet = (struct ether_header *) bytes;
  
    printf("MAC Destination:  %s\n", ether_ntoa((struct ether_addr *) headerEthernet->ether_dhost));
    printf("MAC Source: %s\n", ether_ntoa((struct ether_addr *) headerEthernet->ether_shost));

    printf("Ether Type: 0x%04x\n", ntohs(headerEthernet->ether_type));  


    switch(ntohs(headerEthernet->ether_type))
    {
      case ETHERTYPE_IP:
          printf("\nETHERTYPE:  IP\n");
        ip_reader(bytes + sizeof(*headerEthernet), totalLength);
      break;
      case ETHERTYPE_ARP:
          printf("\nETHERTYPE:  ARP\n");
        arp_reader(bytes + sizeof(*headerEthernet), totalLength);
        break;
      case ETHERTYPE_IPV6:
          printf("\nETHERTYPE:  IPv6\n");
        ipv6_reader(bytes + sizeof(*headerEthernet), totalLength);
        break;
    }
}
