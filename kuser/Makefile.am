# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include 

man_MANS = kinit.1 klist.1 kdestroy.1

bin_PROGRAMS = kinit klist kdestroy

noinst_PROGRAMS = kfoo krenew kverify

LDADD = ../lib/krb5/libkrb5.a ../lib/asn1/libasn1.a \
	../lib/des/libdes.a ../lib/roken/libroken.a 
