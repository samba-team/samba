#
# Makefile for tdb directory
#

CFLAGS = -DSTANDALONE -DTDB_DEBUG -g -DMMAP
CC = insure
PROGS = tdbtest tdbtool tdbtorture

default: $(PROGS)

tdbtest: tdbtest.o tdb.o
	$(CC) $(CFLAGS) -o tdbtest tdbtest.o tdb.o -lgdbm

tdbtool: tdbtool.o tdb.o
	$(CC) $(CFLAGS) -o tdbtool tdbtool.o tdb.o

tdbtorture: tdbtorture.o tdb.o
	$(CC) $(CFLAGS) -o tdbtorture tdbtorture.o tdb.o

clean:
	rm -f $(PROGS) *.o *~ *% core test.db test.tdb test.gdbm
