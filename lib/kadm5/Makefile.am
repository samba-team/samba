# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

##INCLUDES = -I$(top_builddir)/include

lib_LIBRARIES = libkadm5srv.a libkadm5clnt.a

incdir = $(includedir)/kadm5
idir = $(top_builddir)/include/kadm5
inc_DATA = kadm5_err.h

COMMON_SOURCES = \
	acl.c chpass_c.c chpass_s.c context_s.c create_c.c	\
	create_s.c delete_c.c delete_s.c destroy_c.c		\
	destroy_s.c ent_setup.c error.c flush.c free.c		\
	get_c.c get_s.c init_c.c init_s.c kadm5_err.c		\
	marshall.c modify_c.c modify_s.c privs_c.c privs_s.c	\
	randkey_c.c randkey_s.c rename_c.c rename_s.c 		\
	send_recv.c server.c set_keys.c set_modifier.c

libkadm5srv_a_SOURCES = $(COMMON_SOURCES) server_glue.c
libkadm5clnt_a_SOURCES = $(COMMON_SOURCES) client_glue.c

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
	$(SHELL) ../error/compile_et $<

.et.c:
	$(SHELL) ../error/compile_et $<

$(libkadm5srv_a_OBJECTS): kadm5_err.h
