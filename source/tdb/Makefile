#
# Makefile for tdb directory
#

CFLAGS = -DSTANDALONE -DTDB_DEBUG -g -DHAVE_MMAP=1
CC = gcc
PROGS = tdbtest tdbtool tdbtorture

default: $(PROGS)

tdbtest: tdbtest.o tdb.o spinlock.o
	$(CC) $(CFLAGS) -o tdbtest tdbtest.o tdb.o spinlock.o -lgdbm

tdbtool: tdbtool.o tdb.o spinlock.o
	$(CC) $(CFLAGS) -o tdbtool tdbtool.o tdb.o spinlock.o

tdbtorture: tdbtorture.o tdb.o
	$(CC) $(CFLAGS) -o tdbtorture tdbtorture.o tdb.o spinlock.o

clean:
	rm -f $(PROGS) *.o *~ *% core test.db test.tdb test.gdbm
