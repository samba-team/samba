# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include -I$(srcdir)/../krb5

lib_LIBRARIES = libgssapi.a

libgssapi_a_SOURCES = \
	8003.c accept_sec_context.c add_oid_set_member.c \
	create_emtpy_oid_set.c decapsulate.c \
	delete_sec_context.c display_name.c \
	duplicate_name.c encapsulate.c external.c \
	get_mic.c import_name.c indicate_mechs.c \
	init.c init_sec_context.c inquire_context.c \
	release_buffer.c release_name.c release_oid_set.c \
	test_oid_set_member.c unwrap.c verify_mic.c \
	wrap.c
