# $Id$

AUTOHEADER_FLAGS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include -I$(srcdir)/..

bin_PROGRAMS = telnet

telnet_SOURCES  = authenc.c commands.c main.c network.c ring.c \
		  sys_bsd.c telnet.c terminal.c \
		  utilities.c

LDADD = -L../libtelnet -ltelnet -L$(top_builddir)/lib/krb5 -lkrb5 -L$(top_builddir)/lib/des -ldes $(LIB_krb4) -L$(top_builddir)/lib/asn1 -lasn1 @LIB_tgetent@ -L$(top_builddir)/lib/roken -lroken
