#include "header_reader.h"

int data_reader(const u_char *bytes, bpf_u_int32 dataLength, const char* dataTitle)
{
  printf("\n----------------- %s -----------------\n\n", dataTitle);

  printf(" Data Length: %u\n\n ", dataLength);
  int i;
  for (i=0; i < dataLength; i++)
  {
	printf("%02X ", bytes[i]); 
	if (!((i+1) % 13))
      printf("\n "); 
		
  }
  printf("\n"); 	
}
