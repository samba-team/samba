# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

CFLAGS=$(WFLAGS) @CFLAGS@

lib_LIBRARIES = libkrb5.a

libkrb5_a_SOURCES = \
	addr_families.c \
	address.c \
	asn1_glue.c \
	auth_context.c \
	build_ap_req.c \
	build_auth.c \
	cache.c \
	changepw.c \
	checksum.c \
	config_file.c \
	convert_creds.c \
	constants.c \
	context.c \
	crc.c \
	creds.c \
	data.c \
	encrypt.c \
	fcache.c \
	free.c \
	free_host_realm.c \
	generate_seq_number.c \
	generate_subkey.c \
	get_addrs.c \
	get_cred.c \
	get_default_principal.c \
	get_default_realm.c \
	get_for_creds.c \
	get_host_realm.c \
	get_in_tkt.c \
	get_in_tkt_pw.c \
	get_in_tkt_with_keytab.c \
	get_in_tkt_with_skey.c \
	get_port.c \
	init_creds.c \
	init_creds_pw.c \
	keyblock.c \
	keytab.c \
	krbhst.c \
	kuserok.c \
	log.c \
	mcache.c \
	misc.c \
	mk_error.c \
	mk_priv.c \
	mk_rep.c \
	mk_req.c \
	mk_req_ext.c \
	mk_safe.c \
	net_read.c \
	net_write.c \
	padata.c \
	principal.c \
	prog_setup.c \
	prompter_posix.c \
	rd_cred.c \
	rd_error.c \
	rd_priv.c \
	rd_rep.c \
	rd_req.c \
	rd_safe.c \
	read_message.c \
	recvauth.c \
	send_to_kdc.c \
	sendauth.c \
	set_default_realm.c \
	sock_principal.c \
	store.c \
	store_emem.c \
	store_fd.c \
	store_mem.c \
	str2key.c \
	ticket.c \
	time.c \
	transited.c \
	verify_init.c \
	verify_user.c \
	version.c \
	warn.c \
	write_message.c

$(libkrb5_a_OBJECTS): $(srcdir)/krb5-protos.h

$(srcdir)/krb5-protos.h:
	cd $(srcdir); perl ../../aux/make-proto.pl $(libkrb5_a_SOURCES) > krb5-protos.h || rm -f krb5-protos.h

INCLUDES = $(INCLUDE_krb4)

libkrb5_a_LIBADD = ../error/error.o ../error/krb5_err.o \
	../error/asn1_err.o ../error/heim_err.o

man_MANS = krb5.conf.5 krb5_warn.3 krb5_openlog.3 \
	krb5_425_conv_principal.3 krb5_build_principal.3 krb5_free_principal.3 \
	krb5_parse_name.3 krb5_sname_to_principal.3 krb5_unparse_name.3
