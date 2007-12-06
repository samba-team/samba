# $Id$

include $(top_srcdir)/Makefile.am.common

AUTOMAKE_OPTIONS = no-texinfo.tex

MAKEINFOFLAGS = --no-split --css-include=$(srcdir)/heimdal.css

TEXI2DVI = true # ARGH, make distcheck can't be disabled to not build dvifiles

info_TEXINFOS = heimdal.texi hx509.texi

dxy_subst = sed -e 's,[@]srcdir[@],$(srcdir),g' \
	-e 's,[@]objdir[@],.,g' \
	-e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g'

krb5.dxy: krb5.din Makefile
	$(dxy_subst) < $(srcdir)/krb5.din > krb5.dxy.tmp
	chmod +x krb5.dxy.tmp
	mv krb5.dxy.tmp krb5.dxy

ntlm.dxy: ntlm.din Makefile
	$(dxy_subst) < $(srcdir)/ntlm.din > ntlm.dxy.tmp
	chmod +x ntlm.dxy.tmp
	mv ntlm.dxy.tmp ntlm.dxy

texi_subst = sed -e 's,[@]dbdir[@],$(localstatedir),g' \
	-e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g'

vars.texi: vars.tin Makefile
	$(texi_subst) < $(srcdir)/vars.tin > vars.texi.tmp
	chmod +x vars.texi.tmp
	mv vars.texi.tmp vars.texi

doxygen: krb5.dxy ntlm.dxy
	doxygen krb5.dxy
	doxygen ntlm.dxy

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
	vars.texi \
	whatis.texi \
	win2k.texi

EXTRA_DIST = \
	krb5.din \
	ntlm.din \
	doxytmpl.dxy \
	vars.tin

CLEANFILES = \
	krb5.dxy* \
	ntlm.dxy* \
	vars.texi*

