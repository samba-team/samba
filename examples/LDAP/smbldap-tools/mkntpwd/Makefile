# Makefile for l0phtcrack - mudge@l0pht.com 11/1/96

# C compiler
#CC=cc
CC=gcc

# Uncomment the following to add symbols to the code for debugging
#DEBUG=-g -Wall -D_DEBUG
#DEBUG=-D_DEBUG

# Optimization for the compiler
#OPTIMIZE=
OPTIMIZE=-O2

# Choose your architecture
#  note that if you are on a big-endian machine like SUN's
#  I haven't tweaked the mem-cmp's and md4 stuff to be in 
#  the correct order yet. You're on your own right now.
#
# FreeBSD
ARCH=-DMPU8086 
STATIC=
XLIBS=
#
# SUNOS
#ARCH=-DBIGENDIAN
#STATIC=
#OPTIMIZE=-O2
#XLIBS=
#
# ULTRA_SPARC w/ native compiler
#ARCH=-DBIGENDIAN
#STATIC=
#OPTIMIZE=-fast -xO4 -xdepend -xchip=ultra -xarch=v8plus
#XLIBS=
#
# SunOS/Solaris w/gcc
#ARCH=-DBIGENDIAN -DTEST
#STATIC=
#OPTIMIZE=-O2
#XLIBS=
#
# NeXTStep 3.2
#CC=cc
#ARCH=-DBIGENDIAN
#STATIC=-Bstatic
#OPTIMIZE=
#XLIBS=

CFLAGS= $(DEBUG) $(OPTIMIZE) $(ARCH) $(VISUAL) $(PERMUTE) $(STATIC) 

OBJS = getopt.o        md4.o           mkntpwd.o       smbdes.o

mkntpwd: $(OBJS)
	$(CC) $(CFLAGS) $(XLIBS) -o mkntpwd $(OBJS)

clean:
	rm -f core *.o mkntpwd

install: mkntpwd
	install -m 555 mkntpwd $(PREFIX)/sbin/mkntpwd

