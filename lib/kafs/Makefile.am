# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include $(INCLUDE_krb4) -DLIBDIR=\"$(libdir)\"

if KRB4
AFSLIBS = libkafs.a
if AIX
AFS_EXTRA_LIBS = afslib.so
else
AFS_EXTRA_LIBS = 
endif
else
AFSLIBS = 
AFS_EXTRA_LIBS =
endif
lib_LIBRARIES = $(AFSLIBS)
foodir=$(libdir)
foo_DATA = $(AFS_EXTRA_LIBS)
EXTRA_DATA = afslib.so

CLEANFILES= $(AFS_EXTRA_LIBS)

libkafs_a_SOURCES = afssys.c afskrb.c afskrb5.c common.c
#afslib_so_SOURCES = afslib.c


# AIX: this almost works with gcc, but somehow it fails to use the
# correct ld, use ld instead
afslib.so: afslib.o
	ld -o $@ -bM:SRE -bI:$(srcdir)/afsl.exp -bE:$(srcdir)/afslib.exp -bnoentry afslib.o -lc

$(OBJECTS): ../../include/config.h
