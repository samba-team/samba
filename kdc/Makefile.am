# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = $(WFLAGS) -I$(top_builddir)/include $(INCLUDE_krb4)

bin_PROGRAMS = string2key

sbin_PROGRAMS = kstash

libexec_PROGRAMS = hprop hpropd kdc

man_MANS = kdc.8 kstash.8 hprop.8 hpropd.8

hprop_SOURCES = hprop.c hprop-common.c
hpropd_SOURCES = hpropd.c hprop-common.c

kdc_SOURCES = 524.c connect.c config.c kerberos4.c kerberos5.c log.c main.c misc.c kaserver.c

if KRB4
hprop_LDADD = ../lib/hdb/libhdb.a \
	../lib/krb5/libkrb5.a \
	../lib/des/libdes.a \
	../lib/asn1/libasn1.a \
	$(LIB_krb4) -lkdb $(LIB_krb4) \
	../lib/roken/libroken.a \
	$(DBLIB) 
else
hprop_LDADD = $(LDADD)
endif

LDADD = ../lib/hdb/libhdb.a \
	../lib/krb5/libkrb5.a \
	../lib/des/libdes.a \
	../lib/asn1/libasn1.a \
	$(LIB_krb4) \
	../lib/roken/libroken.a \
	$(DBLIB)

