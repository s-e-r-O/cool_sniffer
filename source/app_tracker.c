#include "header_reader.h"

/* https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt */

/* Some of the most frequent (and not so frequent) */
enum {
  PORT_FTP = 20,
  PORT_SSH = 22,
  PORT_DNS = 53,
  PORT_BOOTPS = 67,
  PORT_BOOTPC = 68,
  PORT_HTTP = 80,
  PORT_NTP = 123,
  PORT_HTTPS = 443,
  PORT_SMB = 445,
  PORT_RDP = 3389,
  PORT_MDNS = 5353
};

int app_tracker(u_int16_t port, char** dataTitle)
{
  switch(port){
    case PORT_FTP:
      printf("\tFile Transfer Protocol (FTP).\n");
      *dataTitle = "FTP";
      break;
    case PORT_SSH:
      printf("\tSecure Shell (SSH).\n");
      *dataTitle = "SSH";
      break;
    case PORT_HTTP:
      printf("\tHypertext Transfer Protocol (HTTP).\n");
      *dataTitle = "HTTP";
      break;
    case PORT_HTTPS:
      printf("\tHypertext Transfer Protocol (HTTPS).\n");
      *dataTitle = "HTTPS";
      break;
    case PORT_SMB:
      printf("\tMicrosoft SMB file sharing (SMB).\n");
      *dataTitle = "SMB";
      break;
    case PORT_MDNS:
      printf("\tMulticast DNS (mDNS).\n");
      *dataTitle = "mDNS";
      break;
    case PORT_RDP:
      printf("\tRemote Desktop Protocol (RDP).\n");
      *dataTitle = "RDP";
      break;
    case PORT_NTP:
      printf("\tNetwork Time Protocol (NTP).\n");
      *dataTitle = "NTP";
      break;
    case PORT_DNS:
      printf("\tDomain Name System (DNS).\n");
      *dataTitle = "DNS";
      break;
    case PORT_BOOTPS:
      printf("\tBootstrap Protocol (BOOTP) server.\n");
      *dataTitle = "BOOTP";
      break;
    case PORT_BOOTPC:
      printf("\tBootstrap Protocol (BOOTP) client.\n");
      *dataTitle = "BOOTP";
      break;      
  }
}
