#
# Makefile for samba-vfs examples
#
# $Id: Makefile,v 1.1 2000/02/03 04:40:56 tpot Exp $
#

# Variables

SAMBA_SRC = ../../source

CFLAGS = -I$(SAMBA_SRC)/include
CC = gcc

VFS_OBJS = audit.o skel.o

# Targets

default: $(VFS_OBJS)

clean:
	rm -f core $(VFS_OBJS) *~ *% *.bak
