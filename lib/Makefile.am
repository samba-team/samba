# $Id$

include $(top_srcdir)/Makefile.am.common

if KRB4
dir_45 = 45
endif
if OTP
dir_otp = otp
endif

SUBDIRS = roken vers editline com_err sl asn1 des krb5 \
	kafs hdb kadm5 gssapi auth $(dir_45) $(dir_otp) $(LIB_dce)
