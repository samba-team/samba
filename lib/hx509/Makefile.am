# $Id$

include $(top_srcdir)/Makefile.am.common

lib_LTLIBRARIES = libhx509.la
libhx509_la_LDFLAGS = -version-info 1:0:0

BUILT_SOURCES = hx509_err.c hx509_err.h

libhx509_la_LIBADD = ../asn1/libasn1.la

libhx509_la_CPPFLAGS = -I$(srcdir)/ref $(INCLUDE_des)

libhx509_la_SOURCES = \
	cert.c \
	cms.c \
	collector.c \
	crypto.c \
	file.c \
	hx509.h \
	hx509_err.c \
	hx509_err.h \
	keyset.c \
	ks_dir.c \
	ks_file.c \
	ks_mem.c \
	ks_null.c \
	ks_p11.c \
	ks_p12.c \
	lock.c \
	name.c \
	print.c

$(libhx509_la_OBJECTS): $(srcdir)/hx509-protos.h $(srcdir)/hx509-private.h

$(srcdir)/hx509-protos.h:
	cd $(srcdir) && perl ../../cf/make-proto.pl -E HX509_LIB_FUNCTION -q -P comment -o hx509-protos.h $(libhx509_la_SOURCES) || rm -f hx509-protos.h

$(srcdir)/hx509-private.h:
	cd $(srcdir) && perl ../../cf/make-proto.pl -q -P comment -p hx509-private.h $(libhx509_la_SOURCES) || rm -f hx509-private.h

include_HEADERS = hx509.h hx509-protos.h hx509_err.h

SLC = $(top_builddir)/lib/sl/slc

bin_PROGRAMS = hxtool

hxtool-commands.c hxtool-commands.h: hxtool-commands.in $(SLC)
	$(SLC) $(srcdir)/hxtool-commands.in

hxtool_SOURCES = \
	hxtool.c \
	hxtool-commands.c

$(hxtool_SOURCES): hxtool-commands.h

hxtool_CPPFLAGS = $(INCLUDE_des)
hxtool_LDADD = libhx509.la $(LIB_roken) ../sl/libsl.la $(LIB_des)
hxtool_LDFLAGS = -pthread

EXTRA_DIST = hx509_err.et

CLEANFILES = hx509_err.c hx509_err.h $(TESTS) \
	hxtool-commands.c hxtool-commands.h *.tmp \
	sd.data sd.data.out


#
# regression tests
#

TESTS = test_chain test_cms test_nist test_nist_pkcs12 test_query

do_subst = sed -e 's,[@]srcdir[@],$(srcdir),g'

test_chain: test_chain.in Makefile
	$(do_subst) < $(srcdir)/test_chain.in > test_chain.tmp
	chmod +x test_chain.tmp
	mv test_chain.tmp test_chain

test_cms: test_cms.in Makefile
	$(do_subst) < $(srcdir)/test_cms.in > test_cms.tmp
	chmod +x test_cms.tmp
	mv test_cms.tmp test_cms

test_nist: test_nist.in Makefile
	$(do_subst) < $(srcdir)/test_nist.in > test_nist.tmp
	chmod +x test_nist.tmp
	mv test_nist.tmp test_nist

test_nist_pkcs12: test_nist_pkcs12.in Makefile
	$(do_subst) < $(srcdir)/test_nist_pkcs12.in > test_nist_pkcs12.tmp
	chmod +x test_nist_pkcs12.tmp
	mv test_nist_pkcs12.tmp test_nist_pkcs12

test_query: test_query.in Makefile
	$(do_subst) < $(srcdir)/test_query.in > test_query.tmp
	chmod +x test_query.tmp
	mv test_query.tmp test_query
