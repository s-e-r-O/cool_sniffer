#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>

#include "sniffer.h"

int main(int nargs, char* args[])
{
  char errbuf[PCAP_ERRBUF_SIZE];
  printf("Looking up for devices...\n");
  char *device = pcap_lookupdev(errbuf); 

  if(device == NULL)
  {
    printf("ERROR. No se pudo encontrar un dispositivo. %s\n", errbuf);
    exit(1);
  }
    
  printf("Opening %s...\n", device);
  
  pcap_t* p = pcap_open_live(device, BUFSIZ, 1, 5000, errbuf);   //EL BUFSIZ ES EL NUMERO MAX DE BYTES QUE QUEREMOS CAPTURAR
 
  if (p == NULL) 
  {
    perror(errbuf);
    exit(-1);
  }

  printf("Starting to capture...\n");
      
  pcap_loop(p, -1, pcap_callback, NULL);   //devuelve 0 si ha leido el numero de paquetes especificado en el segundo parametro y un numero neg si hubo error
  
  exit(0);
}
