#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <ctype.h>


/* DATA LINK LAYER */
int ether_reader(const u_char *bytes, bpf_u_int32 totalLength);

/* NETWORK LAYER */
int ip_reader(const u_char *bytes, bpf_u_int32 totalLength, unsigned int sumHeaderLength);
int arp_reader(const u_char *bytes, bpf_u_int32 totalLength, unsigned int sumHeaderLength);
int ipv6_reader(const u_char *bytes, bpf_u_int32 totalLength, unsigned int sumHeaderLength);

/* PROTOCOL LAYER */
int tcp_reader(const u_char *bytes, bpf_u_int32 totalLength, unsigned int sumHeaderLength);
int udp_reader(const u_char *bytes, bpf_u_int32 totalLength, unsigned int sumHeaderLength);

/* APP LAYER */
int http_reader(const u_char *bytes, bpf_u_int32 totalLength, unsigned int sumHeaderLength);


