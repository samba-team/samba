# $Id$

include $(top_srcdir)/Makefile.am.common

if OTP
dir_otp = otp
endif
if DCE
dir_dce = dceutils
endif
if !NO_AFS
dir_afsutil = afsutil
endif
SUBDIRS = 					\
	  $(dir_afsutil)			\
	  dbutils				\
	  $(dir_otp)				\
	  gssmask				\
	  test					\
	  kf					\
	  $(dir_dce)

EXTRA_DIST = NTMakefile
