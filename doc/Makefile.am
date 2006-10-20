# $Id$

include $(top_srcdir)/Makefile.am.common

AUTOMAKE_OPTIONS = no-texinfo.tex

MAKEINFOFLAGS = --no-split --css-include=$(srcdir)/heimdal.css

TEXI2DVI = true # ARGH, make distcheck can't be disabled to not build dvifiles

info_TEXINFOS = heimdal.texi
heimdal_TEXINFOS = \
	ack.texi \
	apps.texi \
	heimdal.texi \
	install.texi \
	install.texi \
	intro.texi \
	kerberos4.texi \
	migration.texi \
	misc.texi \
	programming.texi \
	setup.texi \
	setup.texi \
	whatis.texi \
	win2k.texi
