#
# Makefile for samba-vfs examples
#
#

# Variables

CC = gcc
LIBTOOL = libtool

SAMBA_SRC = ../../source/include
CFLAGS = -I$(SAMBA_SRC)
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
