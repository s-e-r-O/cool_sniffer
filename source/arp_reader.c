#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <net/if_arp.h>

#include "header_reader.h"

int arp_reader(const u_char *bytes, bpf_u_int32 dataLength)
{
	printf("\n------------------ ARP ------------------\n\n");


  	struct arphdr *headerARP = (struct arphdr *) bytes;

	printf("Format Of Hardware Address: %u\n", headerARP->ar_hrd);
	printf("Format Of Protocol Address: %u\n", headerARP->ar_pro);
	printf("Length Of Hardware Address: %c\n", headerARP->ar_hln);
	printf("Length Of Protocol Address: %c\n", headerARP->ar_pln);
	printf("ARP opcode: %u\n", headerARP->ar_op);

}