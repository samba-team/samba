# $Id$

AUTOMAKE_OPTIONS = no-dependencies

SUBDIRS = error

INCLUDES = -I$(top_builddir)/include

lib_LIBRARIES = libkrb5.a

libkrb5_a_SOURCES = address.c asn1_glue.c auth_context.c \
	build_ap_req.c build_auth.c cache.c checksum.c config_file.y \
	constants.c context.c crc.c data.c decrypt.c encrypt.c get_addrs.c \
	get_cred.c get_host_realm.c get_in_tkt.c get_in_tkt_pw.c get_port.c \
	keytab.c krbhst.c misc.c mk_priv.c mk_rep.c mk_req.c mk_req_ext.c \
	mk_safe.c principal.c principal_p.c rd_priv.c rd_rep.c rd_req.c \
	rd_safe.c send_to_kdc.c sendauth.c store.c store_emem.c store_fd.c \
	store_mem.c str2key.c net_write.c net_read.c recvauth.c verify_user.c \
	error/error.c error/krb5_err.c error/asn1_err.c error/hdb_err.c

config_file.c: config_file.y
	$(YACC) -p __k5cf_ $<
	mv -f y.tab.c config_file.c
