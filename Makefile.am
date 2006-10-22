# $Id$

include $(top_srcdir)/Makefile.am.common

if KCM
kcm_dir = kcm
endif

SUBDIRS=  include lib kuser kdc admin kadmin kpasswd 
SUBDIRS+= $(kcm_dir) appl doc tools tests

## ACLOCAL = @ACLOCAL@ -I cf
ACLOCAL_AMFLAGS = -I cf

EXTRA_DIST = \
	Makefile.am.common \
	krb5.conf \
	cf/make-proto.pl \
	cf/check-symbols.sh \
	cf/install-catman.sh

