#include <netinet/udp.h>

#include "header_reader.h"

/* RFC798 -> https://tools.ietf.org/html/rfc768 */

int udp_reader(const u_char *bytes, bpf_u_int32 dataLength)
{
  printf("\n----------------- UDP ------------------\n\n");

  struct udphdr *headerUDP = (struct udphdr *) bytes;
  
  char *dataTitle = "DATA";
  printf("Source Port: %u\n", ntohs(headerUDP->uh_sport));
  app_tracker(ntohs(headerUDP->uh_sport), &dataTitle);
  printf("Destination Port: %u\n", ntohs(headerUDP->uh_dport));
  app_tracker(ntohs(headerUDP->uh_dport), &dataTitle);
  printf("Length: %u\n", ntohs(headerUDP->uh_ulen));
  printf("Checksum: %u\n", ntohs(headerUDP->uh_sum));

  if (dataLength > ntohs(headerUDP->uh_ulen))
  {
  	data_reader(bytes + ntohs(headerUDP->uh_ulen), dataLength - ntohs(headerUDP->uh_ulen), dataTitle);
  }
}