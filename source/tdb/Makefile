#
# Makefile for tdb directory
#

CFLAGS = -DSTANDALONE -DTDB_DEBUG -g -DMMAP
CC = gcc
PROGS = tdbtest tdbtool tdbtorture

default: $(PROGS)

tdbtest: tdbtest.o tdb.o
	gcc -o tdbtest tdbtest.o tdb.o -lgdbm

tdbtool: tdbtool.o tdb.o
	gcc -o tdbtool tdbtool.o tdb.o

tdbtorture: tdbtorture.o tdb.o
	gcc -o tdbtorture tdbtorture.o tdb.o

clean:
	rm -f $(PROGS) *.o *~ *% core test.db test.tdb test.gdbm
