# $Id$

include $(top_srcdir)/Makefile.am.common


DFSPROGS = k5dcecon
if AIX
AIX_DFSPROGS = dpagaix
dpagaix_LDFLAGS = -Wl,-edpagaix -Wl,dfspag.exp
dpagaix_LDADD =
CC = xlc_r4
endif

libexec_PROGRAMS = $(DFSPROGS) $(AIX_DFSPROGS)

LIB_dce = -ldce

k5dcecon_SOURCES  = k5dcecon.c k5dce.h

dpagaix_SOURCES = dpagaix.c

LDADD = $(LIB_roken) $(LIB_dce)
