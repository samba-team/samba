# $Id$

include $(top_srcdir)/Makefile.am.common

CLEANFILES = krb5-config krb5-config.new

bin_SCRIPTS = krb5-config

man_MANS = krb5-config.1

if PKINIT
LIB_pkinit = -lhx509
endif


krb5-config: krb5-config.in
	sed	-e "s!@PACKAGE\@!$(PACKAGE)!g" \
		-e "s!@VERSION\@!$(VERSION)!g" \
		-e "s!@prefix\@!$(prefix)!g" \
		-e "s!@exec_prefix\@!$(exec_prefix)!g" \
		-e "s!@libdir\@!$(libdir)!g" \
		-e "s!@includedir\@!$(includedir)!g" \
		-e "s!@LIB_crypt\@!$(LIB_crypt)!g" \
		-e "s!@LIB_dbopen\@!$(LIB_dbopen)!g" \
		-e "s!@INCLUDE_des\@!$(INCLUDE_des)!g" \
		-e "s!@LIB_des_appl\@!$(LIB_des_appl)!g" \
		-e "s!@LIB_dlopen\@!$(LIB_dlopen)!g" \
		-e "s!@LIB_door_create\@!$(LIB_door_create)!g" \
		-e "s!@LIB_pkinit\@!$(LIB_pkinit)!g" \
		-e "s!@LIBS\@!$(LIBS)!g" \
		$(srcdir)/krb5-config.in > $@.new
	mv $@.new $@
	chmod +x $@

EXTRA_DIST = heimdal-build.sh krb5-config.in $(man_MANS)
