# Generated automatically from Makefile.in by configure.
CC		= gcc
CFLAGS		= -O  -I/usr/kerberos/include
CPPFLAGS	= -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE  -I/usr/kerberos/include
LDFLAGS		=  -L/usr/kerberos/lib
LDSHFLAGS	= -shared
srcdir		= /opt/src/samba-cvs/samba-3.0/samba/source
FLAGS		=  $(CFLAGS) -Iinclude -I$(srcdir)/include -I$(srcdir)/ubiqx -I$(srcdir)/smbwrapper  -I. $(CPPFLAGS) -I$(srcdir)

# Auto target
default: $(patsubst %.c,%.so,$(wildcard *.c))

# Pattern rules

%.so: %.o
	$(CC) $(LDSHFLAGS) $(LDFLAGS) -o $@ $<

%.o: %.c
	$(CC) $(FLAGS) -c $<

# Misc targets

clean:
	rm -rf .libs
	rm -f core *~ *% *.bak *.o *.so
