#
# Makefile for samba-vfs examples
#
# $Id: Makefile,v 1.4 2000/11/06 20:01:03 jra Exp $
#

# Variables

CC = gcc
LIBTOOL = libtool

SAMBA_SRC = ../../source
SAMBA_INCL = ../../source/include
UBIQX_SRC = ../../source/ubiqx
SMBWR_SRC = ../../source/smbwrapper
CFLAGS = -I$(SAMBA_SRC) -I$(SAMBA_INCL) -I$(UBIQX_SRC) -I$(SMBWR_SRC) -Wall -g
VFS_OBJS = audit.so skel.so

# Default target

default: $(VFS_OBJS)

# Pattern rules

%.so: %.lo
	$(LIBTOOL) $(CC) -shared -o $@ $< $(LDFLAGS)

%.lo: %.c
	$(LIBTOOL) $(CC) $(CPPFLAGS) $(CFLAGS) -c $<

# Misc targets

clean:
	rm -rf .libs
	rm -f core *~ *% *.bak \
		$(VFS_OBJS) $(VFS_OBJS:.so=.o) $(VFS_OBJS:.so=.lo) 
