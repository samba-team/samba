# $Id$

include $(top_srcdir)/cf/Makefile.am.common

if KRB4
dir_45 = 45
endif

SUBDIRS = roken editline com_err sl asn1 des krb5 \
	kafs hdb kadm5 gssapi $(dir_45) @OTP_dir@

DIST_SUBDIRS = roken editline com_err sl asn1 des krb5 \
	kafs hdb kadm5 gssapi 45 otp
