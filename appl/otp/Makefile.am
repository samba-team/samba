# $Id$

include $(top_srcdir)/Makefile.am.common

AM_CPPFLAGS += $(INCLUDE_hcrypto)

bin_PROGRAMS = otp otpprint
bin_SUIDS = otp
otp_SOURCES = otp.c otp_locl.h
otpprint_SOURCES = otpprint.c otp_locl.h

man_MANS = otp.1  otpprint.1

LDADD = \
	$(top_builddir)/lib/otp/libotp.la	\
	$(LIB_roken)

EXTRA_DIST = $(man_MANS)
