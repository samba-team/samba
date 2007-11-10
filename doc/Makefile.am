# $Id$

include $(top_srcdir)/Makefile.am.common

AUTOMAKE_OPTIONS = no-texinfo.tex

MAKEINFOFLAGS = --no-split --css-include=$(srcdir)/heimdal.css

TEXI2DVI = true # ARGH, make distcheck can't be disabled to not build dvifiles

info_TEXINFOS = heimdal.texi hx509.texi


do_subst = sed -e 's,[@]srcdir[@],$(srcdir),g' \
	-e 's,[@]objdir[@],.,g' \
	-e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g'

krb5.dxy: krb5.din Makefile
	$(do_subst) < $(srcdir)/krb5.din > krb5.dxy.tmp
	chmod +x krb5.dxy.tmp
	mv krb5.dxy.tmp krb5.dxy

doxygen: krb5.dxy
	doxygen krb5.dxy

heimdal_TEXINFOS = \
	ack.texi \
	apps.texi \
	heimdal.texi \
	install.texi \
	intro.texi \
	kerberos4.texi \
	migration.texi \
	misc.texi \
	programming.texi \
	setup.texi \
	whatis.texi \
	win2k.texi

EXTRA_DIST = krb5.din doxytmpl.dxy

CLEANFILES = krb5.dxy.tmp krb5.dxy
