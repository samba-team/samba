# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

noinst_PROGRAMS = otptest

otptest_LDADD = libotp.a -L$(top_builddir)/lib/des -ldes -L$(top_builddir)/lib/roken -lroken

lib_LIBRARIES = libotp.a

libotp_a_SOURCES = \
	otp.c \
	otp_challenge.c \
	otp_db.c \
	otp_md.c \
	otp_parse.c \
	otp_print.c \
	otp_verify.c
