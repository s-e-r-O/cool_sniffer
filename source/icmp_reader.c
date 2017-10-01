#include <stdlib.h>
#include <stdio.h>
#include <netinet/ip_icmp.h>

#include "header_reader.h"

void prepare_msg_array(char* type_msg[]);

int icmp_reader(const u_char *bytes, bpf_u_int32 totalLength)
{

  printf("\n----------------- ICMP ------------------\n\n");

	struct icmphdr *headerICMP = (struct icmphdr *) bytes;
	
  u_int8_t type = ntohs(headerICMP->type);

  char *type_msg[NR_ICMP_TYPES];

  prepare_msg_array(type_msg);

  printf("Type: %u (%s)\n", type, type_msg[type]);
  printf("Code: %u\n", ntohl(headerICMP->code));
  printf("Checksum: %u\n", ntohl(headerICMP->checksum));
  switch(type){
    case ICMP_ECHOREPLY:
      printf("Identifier: %u\n", ntohl(headerICMP->un.echo.id));
      printf("Sequence Number: %u\n", ntohl(headerICMP->un.echo.sequence));
      break;
  }

  //SEND TO AN APLICATION LAYER FUNCTION THE NEXT PARAMETER (bytes + headerTCP -> th_off * 4);
}	

void prepare_msg_array(char* type_msg[])
{
  type_msg[ICMP_ECHOREPLY] = "Echo Reply";
  type_msg[ICMP_DEST_UNREACH] = "Destination Unreachable";
  type_msg[ICMP_SOURCE_QUENCH] = "Source Quench";
  type_msg[ICMP_REDIRECT] = "Redirect (change route)";
  type_msg[ICMP_ECHO] = "Echo Request";
  type_msg[ICMP_TIME_EXCEEDED] = "Time Exceeded";
  type_msg[ICMP_PARAMETERPROB] = "Parameter Problem";
  type_msg[ICMP_TIMESTAMP] = "Timestamp Request";
  type_msg[ICMP_TIMESTAMPREPLY] = "Timestamp Reply";
  type_msg[ICMP_INFO_REQUEST] = "Information Request";
  type_msg[ICMP_INFO_REPLY] = "Information Reply";
} 