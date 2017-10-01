#include <stdlib.h>
#include <stdio.h>
#include <netinet/udp.h>

#include "header_reader.h"

int udp_reader(const u_char *bytes, bpf_u_int32 totalLength)
{
  struct udphdr *headerUDP = (struct udphdr *) bytes;
  
  printf("Source Port: %u\n", ntohs(headerUDP->uh_sport));
  printf("Destination Port: %u\n", ntohs(headerUDP->uh_dport));
  printf("Length: %u\n", ntohs(headerUDP->uh_ulen));
  printf("Checksum: %u\n", ntohs(headerUDP->uh_sum));

  // SEND TO AN APLICATION LAYER FUNCTION THE NEXT PARAMETERS 
  // (bytes + headerUDP -> uh_ulen, totalLength);
}