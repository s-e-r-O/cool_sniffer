#include <stdlib.h>
#include <stdio.h>
#include <netinet/udp.h>

#include "header_reader.h"

int udp_reader(const u_char *bytes)
{
  struct udphdr *headerUDP = (struct udphdr *) bytes;
  
  printf("Source Port: %u\n", headerUDP->uh_sport);
  printf("Destination Port: %u\n", headerUDP->uh_dport);
  printf("Length: %u\n", headerUDP->uh_ulen);
  printf("Checksum: %u\n", headerUDP->uh_sum);

  // SEND TO AN APLICATION LAYER FUNCTION THE NEXT PARAMETER 
  // (bytes + headerUDP -> uh_ulen);
}