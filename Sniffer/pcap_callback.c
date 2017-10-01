#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>

#include "header_reader.h"


void pcap_callback(u_char * user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    
	static int count = 1;
    printf("\nCount: %d\tCaplen: %u\tLen: %u\n", count, h->caplen, h->len);
    count++;

    
    struct ip *networkLayer;
  	int *TCPLayer;
  	int *appLayer;
  	   

    ether_reader(bytes);

   /* if(ntohs(headerEthernet->ether_type) == ETHERTYPE_IP)
    {
        printf("El protocolo Ethernet es:   IP %04x\n", ntohs(headerEthernet->ether_type));
    }
    else if(ntohs(headerEthernet->ether_type) == ETHERTYPE_ARP)
    {
        printf("El protocolo Ethernet es:   ARP\n");
    }
    else if(ntohs(headerEthernet->ether_type) == ETHERTYPE_IPV6)
    {
        printf("El protocolo Ethernet es:   IPV6\n");
    }
  

    printf("La MAC de origen es: %s\n", ether_ntoa((struct ether_addr *) headerEthernet->ether_shost));
    printf("La MAC de destino es: %s\n", ether_ntoa((struct ether_addr *) headerEthernet->ether_dhost));
    

    switch(headerEthernet->ether_type)
    {
    	case(ETHERTYPE_IP):
    		//printf("El protocolo Ethernet es:   IP %04x\n", ntohs(headerEthernet->ether_type));
    	break;

    	
    }

*/

    //printf("El tamano del header de ether es: %d\n", sizeof(struct ether_header));
    


    /*
    networkLayer = *(bytes + sizeof(struct ether_header)); //puntero en la capa de red
  	TCPLayer = *(networkLayer + sizeof(struct iphdr));   //puntero en la capa de transporte
  	appLayer = TCPLayer + sizeof(struct tcphdr);   //puntero en la capa de aplicacion
  	//appLayer = TCPLayer + sizeof(struct udphdr);   //puntero en la capa de aplicacion
  	*/



/* 	networkLayer = (bytes + sizeof(struct ether_header)); //puntero en la capa de red
  	printf("El tamano de la capa Network es: %d\n", networkLayer->ip_len);
  	printf("El tamano de la capa Network es: %d\n", networkLayer->ip_len);
  */
//  	TCPLayer = (networkLayer + sizeof(struct ip));   //puntero en la capa de transporte
  	//printf("el tamano de TCP es: %d\n", TCPLayer_);
  	//appLayer = (TCPLayer + sizeof(struct tcphdr));   //puntero en la capa de aplicacion
  	//appLayer = TCPLayer + sizeof(struct udphdr);   //puntero en la capa de aplicacion



    
}