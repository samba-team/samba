# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include -I$(srcdir)/.. $(INCLUDE_krb4)

noinst_LIBRARIES = libtelnet.a

libtelnet_a_SOURCES = auth.c encrypt.c genget.c enc_des.c misc.c kerberos.c \
		      kerberos5.c read_password.c
