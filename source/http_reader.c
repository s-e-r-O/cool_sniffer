#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <ctype.h>

#include "header_reader.h"

int http_reader(const u_char *bytes, bpf_u_int32 dataLength)
{
	printf("\n----------------- HTTP -----------------\n\n");

	int i;
	printf("El mensaje es:%u\n", dataLength);

	for (i=0; i < 10; i++)
	{
		if(isprint(bytes[i]))
		{
			printf("%c", bytes[i]); 
		}
	}
}
