# $Id$

include $(top_srcdir)/Makefile.am.common

lib_LTLIBRARIES = libkadm5srv.la libkadm5clnt.la
sbin_PROGRAMS = dump_log replay_log

libexec_PROGRAMS = ipropd-master ipropd-slave

kadm5includedir = $(includedir)/kadm5
buildkadm5include = $(buildinclude)/kadm5

kadm5include_HEADERS = kadm5_err.h admin.h private.h

install-build-headers::
	@foo='$(kadm5include_HEADERS)'; \
	for f in $$foo; do \
		if test -f "$(srcdir)/$$f"; then file="$(srcdir)/$$f"; \
		else file="$$f"; fi; \
		if cmp -s  $$file $(buildkadm5include)/$$f 2> /dev/null ; then \
		: ; else \
			echo "$(INSTALL_DATA) $$file $(buildkadm5include)/$$f";\
			$(INSTALL_DATA) $$file $(buildkadm5include)/$$f; \
		fi ; \
	done

COMMON_SOURCES =	\
	acl.c		\
	admin.h		\
	chpass_c.c	\
	chpass_s.c	\
	common_glue.c	\
	context_s.c	\
	create_c.c	\
	create_s.c	\
	delete_c.c	\
	delete_s.c	\
	destroy_c.c	\
	destroy_s.c	\
	ent_setup.c	\
	error.c		\
	flush.c		\
	free.c		\
	get_c.c		\
	get_princs_c.c	\
	get_princs_s.c	\
	get_s.c		\
	init_c.c	\
	init_s.c	\
	kadm5_err.c	\
	kadm5_locl.h	\
	log.c		\
	marshall.c	\
	modify_c.c	\
	modify_s.c	\
	private.h	\
	privs_c.c	\
	privs_s.c	\
	randkey_c.c	\
	randkey_s.c	\
	rename_c.c	\
	rename_s.c	\
	send_recv.c	\
	server.c	\
	set_keys.c	\
	set_modifier.c
	
libkadm5srv_la_SOURCES = $(COMMON_SOURCES) server_glue.c
libkadm5clnt_la_SOURCES = $(COMMON_SOURCES) client_glue.c

dump_log_SOURCES = dump_log.c kadm5_locl.h

replay_log_SOURCES = replay_log.c kadm5_locl.h

ipropd_master_SOURCES = ipropd_master.c iprop.h kadm5_locl.h

ipropd_slave_SOURCES = ipropd_slave.c iprop.h kadm5_locl.h

LDADD = \
	libkadm5srv.la \
	$(top_builddir)/lib/hdb/libhdb.la \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/roken/libroken.la \
	$(DBLIB)

CLEANFILES = kadm5_err.c kadm5_err.h

$(libkadm5srv_la_OBJECTS): kadm5_err.h

client_glue.lo server_glue.lo: $(srcdir)/common_glue.c
