###########################################################################
# Makefile for ubiqx libraries under Samba.
# Copyright Chris Hertel & the Samba Team 1997
###########################################################################

.SUFFIXES:
.SUFFIXES: .c .o .h

all:	ubi_AVLtree.o ubi_BinTree.o ubi_SplayTree.o \
	ubi_dLinkList.o ubi_sLinkList.o

ubi_BinTree.o: ubi_BinTree.h
	@echo Compiling $*.c
	@$(CC) $(CFLAGS) -c $*.c

ubi_AVLtree.o: ubi_AVLtree.h ubi_BinTree.h
	@echo Compiling $*.c
	@$(CC) $(CFLAGS) -c $*.c

ubi_SplayTree.o: ubi_SplayTree.h ubi_BinTree.h
	@echo Compiling $*.c
	@$(CC) $(CFLAGS) -c $*.c

ubi_dLinkList.o: ubi_dLinkList.h
	@echo Compiling $*.c
	@$(CC) $(CFLAGS) -c $*.c

ubi_sLinkList.o: ubi_sLinkList.h
	@echo Compiling $*.c
	@$(CC) $(CFLAGS) -c $*.c

.c.o:
	@echo Compiling $*.c
	@$(CC) $(CFLAGS) -c $*.c

clean:
	rm -f core *.o *~
