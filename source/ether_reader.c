#include <net/ethernet.h>
#include <netinet/ether.h>

#include "header_reader.h"

/* IEEE Standard for Ethernet -> http://standards.ieee.org/getieee802/download/802.3-2012_section1.pdf */

int ether_reader(const u_char *bytes, bpf_u_int32 dataLength)
{
	
  printf("\n--------------- ETHERNET ---------------\n\n");

  struct ether_header *headerEthernet = (struct ether_header *) bytes;
  
  printf("MAC Destination:  %s\n", ether_ntoa((struct ether_addr *) headerEthernet->ether_dhost));
  printf("MAC Source: %s\n", ether_ntoa((struct ether_addr *) headerEthernet->ether_shost));
  printf("Ether Type: 0x%04x\n", ntohs(headerEthernet->ether_type));  

  switch(ntohs(headerEthernet->ether_type))
  {
    case ETHERTYPE_IP:
      ip_reader(bytes + sizeof(*headerEthernet), dataLength - sizeof(*headerEthernet));
      break;
    case ETHERTYPE_ARP:
      arp_reader(bytes + sizeof(*headerEthernet), dataLength - sizeof(*headerEthernet));
      break;
    case ETHERTYPE_IPV6:
      ipv6_reader(bytes + sizeof(*headerEthernet), dataLength - sizeof(*headerEthernet));
      break;
  }
}
