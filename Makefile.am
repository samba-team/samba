# $Id$

include $(top_srcdir)/Makefile.am.common

if KCM
kcm_dir = kcm
endif

SUBDIRS=  include lib kuser kdc admin kadmin kpasswd 
SUBDIRS+= $(kcm_dir) appl doc tools tests packages etc

## ACLOCAL = @ACLOCAL@ -I cf
ACLOCAL_AMFLAGS = -I cf

EXTRA_DIST = \
	TODO \
	LICENSE \
	README \
	ChangeLog \
	ChangeLog.1998 \
	ChangeLog.1999 \
	ChangeLog.2000 \
	ChangeLog.2001 \
	ChangeLog.2002 \
	ChangeLog.2003 \
	ChangeLog.2004 \
	ChangeLog.2005 \
	ChangeLog.2006 \
	Makefile.am.common \
	autogen.sh \
	krb5.conf \
	cf/make-proto.pl \
	cf/check-symbols.sh \
	cf/install-catman.sh

print-distdir:
	@echo $(distdir)
