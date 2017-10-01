#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "sniffer.h"


//void pcap_callback(u_char * user, const struct pcap_pkthdr *h, const u_char *bytes);


int main(int nargs, char* args[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device = pcap_lookupdev(errbuf); 

//printf("El tamano del header de ether es: %d\n", sizeof(struct ether_header));

    if(device == NULL)
    {
      printf("ERROR. No se pudo encontrar un dispositivo. %s\n", errbuf);
      exit(1);
    }
    
    pcap_t* p = pcap_open_live(device, BUFSIZ, 1, 5000, errbuf);   //EL BUFSIZ ES EL NUMERO MAX DE BYTES QUE QUEREMOS CAPTURAR
 
    if (p == NULL) 
    {
      perror(errbuf);
      exit(-1);
    }
      
    pcap_loop(p, -1, pcap_callback, NULL);   //devuelve 0 si ha leido el numero de paquetes especificado en el segundo parametro y un numero neg si hubo error
  
    exit(0);
}
