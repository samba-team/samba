# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

XINCS = @X_CFLAGS@
XLIBS = @X_XLIBS@ @LIB_XauReadAuth@ @X_PRE_LIBS@ @X_EXTRA_LIBS@

INCLUDES = -I$(top_builddir)/include $(INCLUDE_krb4) $(XINCS)

bin_PROGRAMS = kx rxterm rxtelnet tenletxr

libexec_PROGRAMS = kxd

encdata.c:
	$(LN_S) $(srcdir)/../kauth/encdata.c .

common_SOURCES = \
	common.c \
	encdata.c \
	@XauWriteAuth_c@

kx_SOURCES = kx.c \
	$(common_SOURCES)

kxd_SOURCES = kxd.c \
	$(common_SOURCES)

rxterm: rxterm.in
	sed -e "s!%bindir%!$(bindir)!" $(srcdir)/rxterm.in > $@
	chmod +x $@

rxtelnet: rxtelnet.in
	sed -e "s!%bindir%!$(bindir)!" $(srcdir)/rxtelnet.in > $@
	chmod +x $@

tenletxr: tenletxr.in
	sed -e "s!%bindir%!$(bindir)!" $(srcdir)/tenletxr.in > $@
	chmod +x $@

LDADD = -L$(top_builddir)/lib/krb5 -lkrb5 $(LIB_otp) -L$(top_builddir)/lib/des -ldes $(LIB_krb4) -L$(top_builddir)/lib/asn1 -lasn1 -L$(top_builddir)/lib/roken -lroken $(XLIBS)
