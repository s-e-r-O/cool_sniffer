CC = gcc
IDIR = .
CFLAGS = -I$(IDIR) -std=gnu99
LIBS = 
OBJ = main.c pcap_callback.c header_reader.c
DEPS = sniffer.h header_reader.h

sniffer: $(OBJ) 
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) -lpcap

# clean out the dross
clean:
	rm -f sniffer  *~ *.o