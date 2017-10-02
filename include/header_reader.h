#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>

/* DATA LINK LAYER */
int ether_reader(const u_char *bytes, bpf_u_int32 dataLength);

/* NETWORK LAYER */
int ip_reader(const u_char *bytes, bpf_u_int32 dataLength);
int arp_reader(const u_char *bytes, bpf_u_int32 dataLength);
int ipv6_reader(const u_char *bytes, bpf_u_int32 dataLength);

/* PROTOCOL LAYER */
int tcp_reader(const u_char *bytes, bpf_u_int32 dataLength);
int udp_reader(const u_char *bytes, bpf_u_int32 dataLength);
int icmp_reader(const u_char *bytes, bpf_u_int32 dataLength);

/* APP LAYER */
int app_tracker(u_int16_t port, char** dataTitle);
int data_reader(const u_char *bytes, bpf_u_int32 dataLength, const char* dataTitle);


