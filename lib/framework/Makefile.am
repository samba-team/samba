# $Id$

include $(top_srcdir)/Makefile.am.common

basedir = /Libraries/Frameworks/Heimdal.framework

resourcedir = $(basedir)/Resources

resource_LTLIBRARIES = Heimdal.la

Heimdal_la_SOURCES = Heimdal.c

if PKINIT
LIB_pkinit = ../hx509/libnhx509.la
endif

Heimdal_la_LIBADD = \
	../gssapi/libngssapi.la \
	../ntlm/libnheimntlm.la  \
	../krb5/libnkrb5.la \
	$(LIB_pkinit) \
	../wind/libnwind.la  \
	$(LIB_hcrypto) \
	../asn1/libnasn1.la  \
	$(LIB_sqlite3) \
	../com_err/libncom_err.la \
	../roken/libnroken.la


Heimdal_la_LDFLAGS = -module

$(Heimdal_la_OBJECTS): symbollist.map
Heimdal_la_LDFLAGS += -Wl,-dead_strip -Wl,-exported_symbols_list,symbollist.map

#	../hx509/version-script.map

SYMBOLFILES = \
	../krb5/version-script.map \
	../gssapi/version-script.map

symbollist.map: $(SYMBOLFILES)
	perl -e 'while(<>) { print "_$$1\n" if m/\t\t([^*#]+);/ } ' $^ > symbollist.map.new
	mv symbollist.map.new symbollist.map

CLEANFILES = symbollist.map symbollist.map.new
