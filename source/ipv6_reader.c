#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>

#include "header_reader.h"


int ipv6_reader(const u_char *bytes, bpf_u_int32 totalLength, unsigned int sumHeaderLength)
{
	struct ip6_hdr *headerIPv6 = (struct ip6_hdr *) bytes;

	//printf("Source: %s\n", inet_ntop(AF_INET6, *(headerIPv6->ip6_src), NULL, INET6_ADDRSTRLEN));
  	//printf("Destination: %s\n", inet_ntop(AF_INET6, *(headerIPv6->ip6_dst), NULL, INET6_ADDRSTRLEN));
}

