#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <ctype.h>

#include "header_reader.h"

int http_reader(const u_char *bytes, bpf_u_int32 dataLength)
{
  printf("\n----------------- HTTP -----------------\n\n");

  printf("Data Length: %u\n ", dataLength);
  int i;
  //printf("El mensaje es:%u\n", dataLength);
  for (i=0; i < dataLength; i++)
  {
	printf("%02X ", bytes[i]); 
	if (!((i+1) % 13))
      printf("\n "); 
		
  }
  printf("\n"); 	
}
