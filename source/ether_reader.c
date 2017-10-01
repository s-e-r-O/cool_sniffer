#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>

#include "header_reader.h"


int ether_reader(const u_char *bytes, bpf_u_int32 totalLength)
{
	
  printf("\n--------------- ETHERNET ---------------\n\n");

  struct ether_header *headerEthernet = (struct ether_header *) bytes;
  
  printf("MAC Destination:  %s\n", ether_ntoa((struct ether_addr *) headerEthernet->ether_dhost));
  printf("MAC Source: %s\n", ether_ntoa((struct ether_addr *) headerEthernet->ether_shost));
  printf("Ether Type: 0x%04x\n", ntohs(headerEthernet->ether_type));  


  switch(ntohs(headerEthernet->ether_type))
  {
    case ETHERTYPE_IP:
      ip_reader(bytes + sizeof(*headerEthernet), totalLength);
      break;
    case ETHERTYPE_ARP:
      arp_reader(bytes + sizeof(*headerEthernet), totalLength);
      break;
    case ETHERTYPE_IPV6:
      ipv6_reader(bytes + sizeof(*headerEthernet), totalLength);
      break;
  }
}
