# $Id$

AUTOMAKE_OPTIONS = foreign no-dependencies 

CFLAGS = @CFLAGS@ $(WFLAGS)

bin_PROGRAMS = otp otpprint
otp_SOURCES = otp.c otp_locl.h
otpprint_SOURCES = otpprint.c otp_locl.h

LDADD = \
	$(top_builddir)/lib/otp/libotp.la \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/roken/libroken.la \
	$(DBLIB)

## XXX how should this be done?
install-exec-hook:
	@if chown 0:0 $(bindir)/otp && chmod u+s $(bindir)/otp; then :;else \
	chmod 0 /usr/heimdal/bin/otp; fi
