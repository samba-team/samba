CFLAGS=-Wall -g
CC=gcc

%.h : %.struct
	igawk -f parser.awk < $*.struct > $*.h

OBJ = vluke.o parser.o

all: test.h vluke

test.h : test.struct

vluke: test.h $(OBJ) 
	$(CC) $(CFLAGS) -o vluke $(OBJ)

clean:
	rm -f *.o test.h

test: vluke
	./vluke test.dat > test.out
