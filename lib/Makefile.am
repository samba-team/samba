# $Id$

include $(top_srcdir)/Makefile.am.common

if EDITLINE
dir_editline = editline
endif
if KRB4
dir_45 = 45
endif
if OTP
dir_otp = otp
endif
if DCE
dir_dce = kdfs
endif
if COM_ERR
dir_com_err = com_err
endif
if !HAVE_OPENSSL
dir_hcrypto = hcrypto
endif
if !SQLITE3
dir_sqlite = sqlite
endif

SUBDIRS = \
	roken \
	vers \
	$(dir_editline) \
	$(dir_com_err) \
	sl \
	wind \
	asn1 \
	$(dir_sqlite) \
	$(dir_hcrypto) \
	hx509 \
	krb5 \
	ntlm \
	kafs \
	gssapi \
	hdb \
	kadm5 \
	$(dir_45) \
	$(dir_otp) \
	$(dir_dce) \
	auth
