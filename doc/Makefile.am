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

hx509.dxy: hx509.din Makefile
	$(dxy_subst) < $(srcdir)/hx509.din > hx509.dxy.tmp
	chmod +x hx509.dxy.tmp
	mv hx509.dxy.tmp hx509.dxy

hcrypto.dxy: hcrypto.din Makefile
	$(dxy_subst) < $(srcdir)/hcrypto.din > hcrypto.dxy.tmp
	chmod +x hcrypto.dxy.tmp
	mv hcrypto.dxy.tmp hcrypto.dxy

wind.dxy: wind.din Makefile
	$(dxy_subst) < $(srcdir)/wind.din > wind.dxy.tmp
	chmod +x wind.dxy.tmp
	mv wind.dxy.tmp wind.dxy

gssapi.dxy: gssapi.din Makefile
	$(dxy_subst) < $(srcdir)/gssapi.din > gssapi.dxy.tmp
	chmod +x gssapi.dxy.tmp
	mv gssapi.dxy.tmp gssapi.dxy



texi_subst = sed -e 's,[@]dbdir[@],$(localstatedir),g' \
	-e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g'

vars.texi: vars.tin Makefile
	$(texi_subst) < $(srcdir)/vars.tin > vars.texi.tmp
	chmod +x vars.texi.tmp
	mv vars.texi.tmp vars.texi

PROJECTS = hcrypto hx509 krb5 ntlm wind gssapi

$(PROJECTS): doxygen

doxygen: krb5.dxy ntlm.dxy hx509.dxy hcrypto.dxy wind.dxy gssapi.din
	@for a in $(PROJECTS) ; do \
		echo $$a ; \
		rm -rf $(srcdir)/$$a ; \
		mkdir $(srcdir)/$$a ; \
		doxygen $$a.dxy; \
		(cd $(srcdir) && find $$a/man -type f > $$a/manpages ) ; \
	done

install-data-hook: install-doxygen-manpage
uninstall-hook: uninstall-doxygen-manpage
dist-hook: doxygen

install-doxygen-manpage:
	for a in $(PROJECTS) ; do \
		f="$(srcdir)/$$a/manpages" ; \
		test -f $$f || continue ; \
		echo "install $$a manual pages" ; \
		while read x ; do \
			section=`echo "$$x" | sed 's/.*\.\([0-9]\)/\1/'` ; \
			$(mkinstalldirs) "$(DESTDIR)$(mandir)/man$$section" ; \
			$(INSTALL_DATA) $(srcdir)/$$x "$(DESTDIR)$(mandir)/man$$section" ; \
		done < $$f ; \
	done ; exit 0

uninstall-doxygen-manpage:
	@for a in $(PROJECTS) ; do \
		f="$(srcdir)/$$a/manpages" ; \
		test -f $$f || continue ; \
		echo "removing $$a manual pages" ; \
		while read x ; do \
			section=`echo "$$x" | sed 's/.*\.\([0-9]\)/\1/'` ; \
			base=`basename $$x` ; \
			rm "$(DESTDIR)$(mandir)/man$$section/$$base" ; \
		done < $$f ; \
	done


heimdal_TEXINFOS = \
	ack.texi \
	apps.texi \
	copyright.texi \
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
	$(PROJECTS) \
	krb5.din \
	ntlm.din \
	hx509.din \
	hcrypto.din \
	heimdal.css \
	init-creds \
	latin1.tex \
	layman.asc \
	doxytmpl.dxy \
	wind.din \
	vars.tin

CLEANFILES = \
	krb5.dxy* \
	gssapi.dxy* \
	ntlm.dxy* \
	hx509.dxy* \
	hcrypto.dxy* \
	wind.dxy* \
	vars.texi*
