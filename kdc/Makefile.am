# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include 

bin_PROGRAMS = string2key

sbin_PROGRAMS = kstash

libexec_PROGRAMS = kdc

kdc_SOURCES = connect.c config.c kerberos4.c kerberos5.c log.c main.c misc.c

LDADD = -L$(top_builddir)/lib/hdb -lhdb -L$(top_builddir)/lib/krb5 -lkrb5 -L$(top_builddir)/lib/des -ldes -L$(top_builddir)/lib/asn1 -lasn1 -L$(top_builddir)/lib/roken -lroken
