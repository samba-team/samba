#
# Makefile for samba-vfs examples
#
#

# Variables

CC = gcc
LIBTOOL = libtool

SAMBA_SRC = ../../../source
SAMBA_INCL = ${SAMBA_SRC}/include
UBIQX_SRC = ${SAMBA_SRC}/ubiqx
SMBWR_SRC = ${SAMBA_SRC}/smbwrapper
CFLAGS = -I$(SAMBA_SRC) -I$(SAMBA_INCL) -I$(UBIQX_SRC) -I$(SMBWR_SRC) -Wall -g -D_LARGEFILE63_SOURCE -D_GNU_SOURCE -fno-builtin  
 

VFS_OBJS = block.so

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
