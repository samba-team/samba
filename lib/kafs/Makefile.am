# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = \
	-I$(top_builddir)/include	\
	$(INCLUDE_krb4)			\
	-DLIBDIR=\"$(libdir)\"		\
	$(AFS_EXTRA_DEFS)

if KRB4
AFSLIBS = libkafs.a
else
AFSLIBS = 
endif

if AIX
AFSL_EXP = $(srcdir)/afsl.exp

if AIX4
AFS_EXTRA_LD = -bnoentry
else
AFS_EXTRA_LD = -e _nostart
endif

if AIX_DYNAMIC_AFS
if HAVE_DLOPEN
AIX_SRC = 
else
AIX_SRC = dlfcn.c
endif
AFS_EXTRA_LIBS = afslib.so
AFS_EXTRA_DEFS =
else
AIX_SRC = afslib.c
AFS_EXTRA_LIBS = 
AFS_EXTRA_DEFS = -DSTATIC_AFS
endif

else
AFSL_EXP =
AIX_SRC =
endif # AIX


lib_LIBRARIES = $(AFSLIBS)
foodir = $(libdir)
foo_DATA = $(AFS_EXTRA_LIBS)
EXTRA_DATA = afslib.so

CLEANFILES= $(AFS_EXTRA_LIBS)

libkafs_a_SOURCES = afssys.c afskrb.c afskrb5.c common.c $(AIX_SRC)
#afslib_so_SOURCES = afslib.c


# AIX: this almost works with gcc, but somehow it fails to use the
# correct ld, use ld instead
afslib.so: afslib.o
	ld -o $@ -bM:SRE -bI:$(srcdir)/afsl.exp -bE:$(srcdir)/afslib.exp $(AFS_EXTRA_LD) afslib.o -lc

$(OBJECTS): ../../include/config.h
