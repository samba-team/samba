# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

##INCLUDES = -I$(top_builddir)/include

lib_LIBRARIES = libkadm5.a libkadm5srv.a

libkadm5_a_SOURCES = \
	chpass_s.c context_s.c create_s.c delete_s.c destroy_s.c	\
	ent_setup.c flush.c free.c get_s.c init_s.c kadm5_err.c	\
	modify_s.c randkey_s.c rename_s.c set_modifier.c set_keys.c

libkadm5srv_a_SOURCES = $(libkadm5_a_SOURCES) server_glue.c

CLEANFILES = kadm5_err.c kadm5_err.h

SUFFIXES = .et .h

.et.h:
	$(SHELL) ../error/compile_et $<

.et.c:
	$(SHELL) ../error/compile_et $<

$(libkadm5_a_OBJECTS): kadm5_err.h
