CC = gcc
IDIR = ./include
CFLAGS = -I$(IDIR) -std=gnu99
LIBS = lpcap
OBJ = main.c ./src/*
DEPS = $(IDIR)/*

sniffer: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -$(LIBS)

# clean out the dross
clean:
	rm -f sniffer  *~ *.o
