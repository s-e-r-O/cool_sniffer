#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>

#include "header_reader.h"

int ip_reader(const u_char *bytes, bpf_u_int32 totalLength, unsigned int sumHeaderLength)
{

  printf("\n------------------ IP ------------------\n\n");


  struct ip *headerIP = (struct ip *) bytes;
  
  printf("Version: %u\n", headerIP->ip_v);
  printf("Internet Header Length: %u\n", headerIP->ip_hl);
  printf("Type Of Service: %u\n", headerIP->ip_tos);
  printf("Size Of Datagram Or Total Length: %u\n", headerIP->ip_len);
  printf("Identification Tag: %u\n", headerIP->ip_id);
  /*printf("Flag1: %x\n", headerIP->IP_RF);   // reserved bit
  printf("Flag2: %x\n", headerIP->IP_DF);   // don't fragment
  printf("Flag3: %x\n", headerIP->IP_MF);   // more fragments
  printf("Flag4: %x\n", headerIP->IP_OFFMASK);  */    
  printf("Fragment Offset: %u\n", headerIP->ip_off);
  printf("Time To Live TTL: %u\n", headerIP->ip_ttl);
  printf("Protocol: %u\n", headerIP->ip_p);
  printf("Header Checksum: %u\n", headerIP->ip_sum);
  printf("Source Address:   %s\n", inet_ntoa(headerIP->ip_src));
  printf("Destination Address:  %s\n", inet_ntoa(headerIP->ip_dst));

  switch(headerIP->ip_p)
  {
    case IPPROTO_ICMP:
      icmp_reader(bytes + headerIP -> ip_hl * 4, totalLength);
      break;
    case IPPROTO_TCP:
      tcp_reader(bytes + headerIP -> ip_hl * 4, totalLength, 0);
      break;
    case IPPROTO_UDP:
      udp_reader(bytes + headerIP -> ip_hl * 4, totalLength, 0);
      break;
  }
}
