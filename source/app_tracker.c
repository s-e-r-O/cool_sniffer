#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <ctype.h>

#include "header_reader.h"

enum {
  PORT_FTP = 20,
  PORT_SSH = 22,
  PORT_HTTP = 80,
  PORT_HTTPS = 443,
  PORT_SMB = 445,
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
  }
}
