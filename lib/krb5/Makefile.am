# $Id$

AUTOMAKE_OPTIONS = no-dependencies

INCLUDES = -I$(top_builddir)/include 

lib_LIBRARIES = krb5

krb5_SOURCES = cache.c config_file.y constants.c context.c data.c \
	get_addrs.c get_cred.c get_in_tkt.c get_in_tkt_pw.c get_port.c \
	krbhst.c misc.c principal.c principal_p.c send_to_kdc.c str2key.c

config_file.c: config_file.y
	$(YACC) -p __k5cf_ $<
	mv -f y.tab.c config_file.c
