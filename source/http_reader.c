#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>

#include "header_reader.h"

int http_reader(const u_char *bytes, bpf_u_int32 totalLength, unsigned int sumHeaderLength)
{
	int i = 0;

	bpf_u_int32 aux;
	aux = totalLength - sumHeaderLength;

	/*while (aux > 0)
	{
		printf("El mensaje es: %c", bytes); 
		bytes = bytes + 1;
		i = i-1;
	}*/
}
