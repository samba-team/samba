# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

CFLAGS=$(WFLAGS) @CFLAGS@

COMPILE_ET = ../com_err/compile_et

lib_LTLIBRARIES = libkrb5.la

SUFFIXES = .et .h

ERR_FILES = krb5_err.c heim_err.c

libkrb5_la_SOURCES = \
	addr_families.c \
	address.c \
	aname_to_localname.c \
	asn1_glue.c \
	auth_context.c \
	build_ap_req.c \
	build_auth.c \
	cache.c \
	changepw.c \
	codec.c \
	config_file.c \
	convert_creds.c \
	constants.c \
	context.c \
	crc.c \
	creds.c \
	crypto.c \
	data.c \
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
	n-fold.c \
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
	ticket.c \
	time.c \
	transited.c \
	verify_init.c \
	verify_user.c \
	version.c \
	warn.c \
	write_message.c \
	$(ERR_FILES)


$(libkrb5_la_OBJECTS): $(srcdir)/krb5-protos.h

$(srcdir)/krb5-protos.h:
	cd $(srcdir); perl ../../cf/make-proto.pl $(libkrb5_la_SOURCES) > krb5-protos.h || rm -f krb5-protos.h

INCLUDES = $(INCLUDE_krb4)

libkrb5_la_LIBADD = ../com_err/error.lo ../com_err/com_err.lo

man_MANS = krb5.conf.5 krb5_warn.3 krb5_openlog.3 \
	krb5_425_conv_principal.3 krb5_build_principal.3 krb5_free_principal.3 \
	krb5_parse_name.3 krb5_sname_to_principal.3 krb5_unparse_name.3



incdir = $(includedir)
inc_DATA = krb5_err.h heim_err.h
idir = $(top_builddir)/include

CLEANFILES = krb5_err.c krb5_err.h heim_err.c heim_err.h

all-local: $(inc_DATA)
	@for i in $(inc_DATA); do \
		if cmp -s  $$i $(idir)/$$i 2> /dev/null ; then :; else\
			echo " $(INSTALL_DATA) $$i $(idir)/$$i"; \
			$(INSTALL_DATA) $$i $(idir)/$$i; \
		fi ; \
	done

.et.c:
	$(COMPILE_ET) $<

.et.h:
	$(COMPILE_ET) $<

krb5_err.h: krb5_err.et

krb5_err.c: krb5_err.et

heim_err.h: heim_err.et

heim_err.c: heim_err.et

$(libkrb5_la_OBJECTS): krb5_err.h heim_err.h
