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



/* DATA LINK LAYER */
int ether_reader(const u_char *bytes);

/* NETWORK LAYER */
int ip_reader(const u_char *bytes);
int arp_reader(const u_char *bytes);
int ipv6_reader(const u_char *bytes);

/* PROTOCOL LAYER */
int tcp_reader(const u_char *bytes);
int udp_reader(const u_char *bytes);

/* APP LAYER */
int http_reader(const u_char *bytes);


