# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

lib_LIBRARIES = libkrb5.a

libkrb5_a_SOURCES = address.c asn1_glue.c auth_context.c build_ap_req.c	\
	build_auth.c cache.c checksum.c config_file.c constants.c	\
	context.c crc.c data.c encrypt.c fcache.c			\
	generate_seq_number.c generate_subkey.c get_addrs.c get_cred.c	\
	get_default_realm.c get_host_realm.c get_in_tkt.c		\
	get_in_tkt_pw.c get_port.c keyblock.c keytab.c krbhst.c kuserok.c \
	misc.c mk_error.c mk_priv.c mk_rep.c mk_req.c mk_req_ext.c	\
	mk_safe.c net_read.c net_write.c principal.c rd_priv.c rd_rep.c \
	rd_req.c rd_safe.c recvauth.c send_to_kdc.c sendauth.c		\
	set_default_realm.c store.c store_emem.c store_fd.c		\
	store_mem.c str2key.c verify_user.c

libkrb5_a_LIBADD = ../error/error.o ../error/krb5_err.o \
	../error/asn1_err.o ../error/hdb_err.o
