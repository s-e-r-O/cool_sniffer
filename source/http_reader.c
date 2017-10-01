#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <ctype.h>

#include "header_reader.h"

int http_reader(const u_char *bytes, bpf_u_int32 totalLength, unsigned int sumHeaderLength)
{
	int i = 0;

	unsigned int aux;
	aux = totalLength - sumHeaderLength;

	printf("El mensaje es:%u\n",aux);

	while (aux > 0)
	{
		if(isprint(bytes[i]))
		{
			printf("%c", bytes[i]); 
		}

		i++;
		aux--;
	}
}
