# $Id$

include $(top_srcdir)/cf/Makefile.am.common

bin_PROGRAMS = otp otpprint
bin_SUIDS = otp
otp_SOURCES = otp.c otp_locl.h
otpprint_SOURCES = otpprint.c otp_locl.h

LDADD = \
	$(top_builddir)/lib/otp/libotp.la \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/roken/libroken.la \
	$(DBLIB)
