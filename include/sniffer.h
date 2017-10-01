#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void pcap_callback(u_char * user, const struct pcap_pkthdr *h, const u_char *bytes);