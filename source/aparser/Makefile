CFLAGS=-Wall -g
CC=gcc

%.h : %.struct
	igawk -f parser.awk < $*.struct > $*.h

OBJ = harness.o parser.o

all: test.h harness

test.h : test.struct

harness: test.h $(OBJ) 
	$(CC) $(CFLAGS) -o harness $(OBJ)

clean:
	rm -f *.o test.h

test: harness
	./harness test.dat > test.out
