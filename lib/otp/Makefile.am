# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

noinst_PROGRAMS = otptest

otptest_LDADD = libotp.la \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/roken/libroken.la

lib_LTLIBRARIES = libotp.la

libotp_la_SOURCES = \
	otp.c \
	otp_challenge.c \
	otp_db.c \
	otp_md.c \
	otp_parse.c \
	otp_print.c \
	otp_verify.c
