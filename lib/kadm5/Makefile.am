# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = $(WFLAGS)
##INCLUDES = -I$(top_builddir)/include

COMPILE_ET = ../com_err/compile_et

lib_LTLIBRARIES = libkadm5srv.la libkadm5clnt.la
sbin_PROGRAMS = dump_log replay_log

libexec_PROGRAMS = ipropd-master ipropd-slave

incdir = $(includedir)/kadm5
idir = $(top_builddir)/include/kadm5
inc_DATA = kadm5_err.h

COMMON_SOURCES =				\
	acl.c					\
	chpass_c.c				\
	chpass_s.c				\
	common_glue.c				\
	context_s.c				\
	create_c.c				\
	create_s.c				\
	delete_c.c				\
	delete_s.c				\
	destroy_c.c				\
	destroy_s.c				\
	ent_setup.c				\
	error.c					\
	flush.c					\
	free.c					\
	get_c.c					\
	get_princs_c.c				\
	get_princs_s.c				\
	get_s.c					\
	init_c.c				\
	init_s.c				\
	kadm5_err.c				\
	log.c					\
	marshall.c				\
	modify_c.c				\
	modify_s.c				\
	privs_c.c				\
	privs_s.c				\
	randkey_c.c				\
	randkey_s.c				\
	rename_c.c				\
	rename_s.c				\
	send_recv.c				\
	server.c				\
	set_keys.c				\
	set_modifier.c
	
libkadm5srv_la_SOURCES = $(COMMON_SOURCES) server_glue.c
libkadm5clnt_la_SOURCES = $(COMMON_SOURCES) client_glue.c

dump_log_SOURCES = dump_log.c

replay_log_SOURCES = replay_log.c

ipropd_master_SOURCES = ipropd_master.c

ipropd_slave_SOURCES = ipropd_slave.c

LDADD = \
	libkadm5srv.la \
	$(top_builddir)/lib/hdb/libhdb.la \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/roken/libroken.la \
	$(DBLIB)

CLEANFILES = kadm5_err.c kadm5_err.h

SUFFIXES = .et .h

all-local: $(inc_DATA)
	@for i in $(inc_DATA); do \
		if cmp -s  $$i $(idir)/$$i 2> /dev/null ; then :; else\
			echo " $(INSTALL_DATA) $$i $(idir)/$$i"; \
			$(INSTALL_DATA) $$i $(idir)/$$i; \
		fi ; \
	done

.et.h:
	$(COMPILE_ET) $<

.et.c:
	$(COMPILE_ET) $<

$(libkadm5srv_la_OBJECTS): kadm5_err.h

client_glue.lo server_glue.lo: $(srcdir)/common_glue.c

kadm5_err.h: kadm5_err.et

kadm5_err.c: kadm5_err.et
