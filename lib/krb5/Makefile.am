# $Id$

AUTOMAKE_OPTIONS = no-dependencies

SUBDIRS = error

INCLUDES = -I$(top_builddir)/include 

lib_LIBRARIES = krb5

krb5_SOURCES = cache.c config_file.y constants.c context.c data.c \
	get_addrs.c get_cred.c get_in_tkt.c get_in_tkt_pw.c get_port.c \
	krbhst.c misc.c principal.c principal_p.c send_to_kdc.c str2key.c \
	crc.c build_ap_req.c build_auth.c mk_req.c get_host_realm.c \
	auth_context.c rd_rep.c keytab.c

config_file.c: config_file.y
	$(YACC) -p __k5cf_ $<
	mv -f y.tab.c config_file.c
