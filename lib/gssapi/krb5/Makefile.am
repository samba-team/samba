# $Id$

include $(top_srcdir)/Makefile.am.common

INCLUDES += -I$(srcdir)/../krb5 \
	-I${srcdir}/../asn1/include \
	$(INCLUDE_des) \
	$(INCLUDE_krb4)

spnego_files =					\
	asn1_ContextFlags.x			\
	asn1_MechType.x				\
	asn1_MechTypeList.x			\
	asn1_NegTokenInit.x			\
	asn1_NegTokenTarg.x

BUILT_SOURCES = $(spnego_files:.x=.c)

lib_LTLIBRARIES = libgssapi.la
libgssapi_la_LDFLAGS = -version-info 4:0:0
libgssapi_la_LIBADD  = ../krb5/libkrb5.la $(LIB_des) ../asn1/libasn1.la ../roken/libroken.la

man_MANS = gssapi.3 gss_acquire_cred.3

include_HEADERS = gssapi.h

libgssapi_la_SOURCES =		\
	$(BUILT_SOURCES)	\
	8003.c			\
	accept_sec_context.c	\
	acquire_cred.c		\
	add_cred.c		\
	add_oid_set_member.c	\
	arcfour.c		\
	canonicalize_name.c	\
	cfx.c			\
	compare_name.c		\
	compat.c		\
	context_time.c		\
	copy_ccache.c		\
	create_emtpy_oid_set.c	\
	decapsulate.c		\
	delete_sec_context.c	\
	display_name.c		\
	display_status.c	\
	duplicate_name.c	\
	encapsulate.c		\
	export_sec_context.c	\
	export_name.c		\
	external.c		\
	get_mic.c		\
	gssapi.h		\
	gssapi_locl.h		\
	import_name.c		\
	import_sec_context.c	\
	indicate_mechs.c	\
	init.c			\
	init_sec_context.c	\
	inquire_context.c	\
	inquire_cred.c		\
	inquire_cred_by_mech.c	\
	inquire_mechs_for_name.c \
	inquire_names_for_mech.c \
	release_buffer.c	\
	release_cred.c		\
	release_name.c		\
	release_oid_set.c	\
	sequence.c		\
	process_context_token.c \
	test_oid_set_member.c	\
	unwrap.c		\
	v1.c			\
	verify_mic.c		\
        wrap.c                  \
        address_to_krb5addr.c

CLEANFILES = $(BUILT_SOURCES) $(spnego_files) spnego_asn1.h asn1_files

$(spnego_files) spnego_asn1.h: asn1_files

asn1_files: ../asn1/asn1_compile$(EXEEXT) $(srcdir)/spnego.asn1
	../asn1/asn1_compile$(EXEEXT) $(srcdir)/spnego.asn1 spnego_asn1

$(libgssapi_la_OBJECTS): spnego_asn1.h

check_PROGRAMS = test_acquire_cred test_sequence
LDADD = libgssapi.la
