#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>

#include "header_reader.h"

int ip_reader(const u_char *bytes, bpf_u_int32 dataLength)
{

  printf("\n------------------ IP ------------------\n\n");
  
  struct ip *headerIP = (struct ip *) bytes;
  
  printf("Version: %u\n", headerIP->ip_v);
  printf("Internet Header Length: %u\n", headerIP->ip_hl);
  printf("Type Of Service: %u\n", headerIP->ip_tos);
  printf("Size Of Datagram Or Total Length: %u\n", headerIP->ip_len);
  printf("Identification Tag: %u\n", headerIP->ip_id);
  printf("Flags:\n");
  if ((headerIP->ip_off & 0xD000) & IP_DF)
    printf("\tDon't Fragment\n");
  else
    printf("\tMay Fragment\n");
  if ((headerIP->ip_off & 0xD000) & IP_MF)
    printf("\tMore Fragments\n");
  else
    printf("\tLast Fragment\n");   
  printf("Fragment Offset: %u\n", headerIP->ip_off & IP_OFFMASK);
  printf("Time To Live: %u\n", headerIP->ip_ttl);
  printf("Protocol: %u\n", headerIP->ip_p);
  printf("Header Checksum: %u\n", headerIP->ip_sum);
  printf("Source Address:   %s\n", inet_ntoa(headerIP->ip_src));
  printf("Destination Address:  %s\n", inet_ntoa(headerIP->ip_dst));

  switch(headerIP->ip_p)
  {
    case IPPROTO_ICMP:
      icmp_reader(bytes + headerIP -> ip_hl * 4, dataLength - (headerIP->ip_hl*4));
      break;
    case IPPROTO_TCP:
      tcp_reader(bytes + headerIP -> ip_hl * 4, dataLength - (headerIP->ip_hl*4));
      break;
    case IPPROTO_UDP:
      udp_reader(bytes + headerIP -> ip_hl * 4, dataLength - (headerIP->ip_hl*4));
      break;
  }
}
