# $Id$

include $(top_srcdir)/Makefile.am.common

if KRB4
dir_45 = 45
endif
if OTP
dir_otp = otp
endif
if DCE
dir_dce = kdfs
endif

SUBDIRS = @DIR_roken@ vers editline @DIR_com_err@ sl asn1 @DIR_des@ hx509 \
	krb5 kafs gssapi hdb kadm5 auth $(dir_45) $(dir_otp) $(dir_dce)
