# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include $(INCLUDE_krb4)

if KRB4
AFSLIBS = libkafs.a
else
AFSLIBS = 
endif
lib_LIBRARIES = $(AFSLIBS)
#EXTRA_LIBRARIES = afslib.so

libkafs_a_SOURCES = afssys.c afskrb5.c
#afslib_so_SOURCES = afslib.c


# AIX: this almost works with gcc, but somehow it fails to use the
# correct ld, use ld instead
afslib.so: afslib.o
	ld -o $@ -bM:SRE -bI:$(srcdir)/afsl.exp -bE:$(srcdir)/afslib.exp -bnoentry afslib.o

$(OBJECTS): ../../include/config.h
