# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include $(INCLUDE_krb4)

bin_PROGRAMS = string2key

sbin_PROGRAMS = kstash

libexec_PROGRAMS = hprop hpropd kdc

man_MANS = kdc.8 kstash.8 hprop.8 hpropd.8

hprop_SOURCES = hprop.c hprop-common.c
hpropd_SOURCES = hpropd.c hprop-common.c

kdc_SOURCES = 524.c connect.c config.c kerberos4.c kerberos5.c log.c main.c misc.c kaserver.c

if KRB4
hprop_LDADD = -L$(top_builddir)/lib/hdb -lhdb -L$(top_builddir)/lib/krb5 -lkrb5 -L$(top_builddir)/lib/des -ldes $(LIB_krb4) -lkdb $(LIB_krb4) -L$(top_builddir)/lib/asn1 -lasn1 -L$(top_builddir)/lib/roken -lroken
else
hprop_LDADD = $(LDADD)
endif

LDADD = ../lib/hdb/libhdb.a ../lib/krb5/libkrb5.a ../lib/asn1/libasn1.a ../lib/des/libdes.a $(LIB_krb4) ../lib/roken/libroken.a 

