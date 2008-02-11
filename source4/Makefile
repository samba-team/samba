#!gmake

include mkconfig.mk

VPATH = $(builddir):$(srcdir):heimdal_build:heimdal/lib/asn1:heimdal/lib/krb5:heimdal/lib/gssapi:heimdal/lib/hdb:heimdal/lib/roken:heimdal/lib/des

BASEDIR = $(prefix)
TORTUREDIR = $(libdir)/torture
SWATDIR = $(datadir)/swat
JSDIR = $(datadir)/js
SETUPDIR = $(datadir)/setup
NCALRPCDIR = $(localstatedir)/ncalrpc

BNLD = $(LD)
BNLD_FLAGS = $(LDFLAGS)

HOSTCC_FLAGS = -D_SAMBA_HOSTCC_ $(CFLAGS)
HOSTLD_FLAGS = $(LDFLAGS)

default: all

include data.mk

DEFAULT_HEADERS = $(srcdir)/lib/util/dlinklist.h \
		  $(srcdir)/version.h

binaries:: $(BINARIES)
libraries:: $(STATIC_LIBS) $(SHARED_LIBS)
modules:: $(SHARED_MODULES)
headers:: $(PUBLIC_HEADERS) $(DEFAULT_HEADERS)
manpages:: $(MANPAGES)
all:: showflags $(ALL_PREDEP) bin/asn1_compile bin/compile_et binaries modules pythonmods
everything:: all libraries headers

LD_LIBPATH_OVERRIDE = $(LIB_PATH_VAR)=$(builddir)/bin/shared

# 'make testsuite' creates all binaries which are
# needed by samba3's 'make test' and the build-farm
# scripts use that it as fallback in case
# 'make everything' fails
testsuite:: bin/smbclient bin/cifsdd bin/smbtorture bin/nmblookup

showlayout:: 
	@echo 'Samba will be installed into:'
	@echo '  basedir:     $(BASEDIR)'
	@echo '  bindir:      $(bindir)'
	@echo '  sbindir:     $(sbindir)'
	@echo '  libdir:      $(libdir)'
	@echo '  modulesdir:  $(modulesdir)'
	@echo '  includedir:  $(includedir)'
	@echo '  vardir:      $(localstatedir)'
	@echo '  privatedir:  $(privatedir)'
	@echo '  piddir:      $(piddir)'
	@echo '  lockdir:     $(lockdir)'
	@echo '  logfilebase: $(logfilebase)'
	@echo '  setupdir:    $(SETUPDIR)'
	@echo '  jsdir:       $(JSDIR)'
	@echo '  swatdir:     $(SWATDIR)'
	@echo '  mandir:      $(mandir)'
	@echo '  torturedir:  $(TORTUREDIR)'
	@echo '  datadir:     $(datadir)'
	@echo '  winbindd_socket_dir:  $(winbindd_socket_dir)'

showflags::
	@echo '  srcdir     = $(srcdir)'
	@echo '  builddir   = $(builddir)'

# The permissions to give the executables
INSTALLPERMS = 0755

install:: showlayout everything installbin installdat installswat installmisc installlib \
	installheader installpc installplugins

# DESTDIR is used here to prevent packagers wasting their time
# duplicating the Makefile. Remove it and you will have the privilege
# of packaging each samba release for multiple versions of multiple
# distributions and operating systems, or at least supplying patches
# to all the packaging files required for this, prior to committing
# the removal of DESTDIR. Do not remove it even though you think it
# is not used.

installdirs::
	@$(SHELL) $(srcdir)/script/installdirs.sh \
		$(DESTDIR)$(BASEDIR) \
		$(DESTDIR)$(bindir) \
		$(DESTDIR)$(sbindir) \
		$(DESTDIR)$(TORTUREDIR) \
		$(DESTDIR)$(libdir) \
		$(DESTDIR)$(modulesdir) \
		$(DESTDIR)$(mandir) \
		$(DESTDIR)$(localstatedir) \
		$(DESTDIR)$(privatedir) \
		$(DESTDIR)$(datadir) \
		$(DESTDIR)$(piddir) \
		$(DESTDIR)$(lockdir) \
		$(DESTDIR)$(logfilebase) \
		$(DESTDIR)$(privatedir)/tls \
		$(DESTDIR)$(includedir) \
		$(DESTDIR)$(PKGCONFIGDIR) \
		$(DESTDIR)$(sysconfdir) \

installbin:: $(SBIN_PROGS) $(BIN_PROGS) $(TORTURE_PROGS) installdirs
	@$(SHELL) $(srcdir)/script/installbin.sh \
		$(INSTALLPERMS) \
		$(DESTDIR)$(BASEDIR) \
		$(DESTDIR)$(sbindir) \
		$(DESTDIR)$(libdir) \
		$(DESTDIR)$(localstatedir) \
		$(SBIN_PROGS)
	@$(SHELL) $(srcdir)/script/installbin.sh \
		$(INSTALLPERMS) \
		$(DESTDIR)$(BASEDIR) \
		$(DESTDIR)$(bindir) \
		$(DESTDIR)$(libdir) \
		$(DESTDIR)$(localstatedir) \
		$(BIN_PROGS)
	@$(SHELL) $(srcdir)/script/installtorture.sh \
		$(INSTALLPERMS) \
		$(DESTDIR)$(TORTUREDIR) \
		$(TORTURE_PROGS)

installlib:: $(INSTALLABLE_SHARED_LIBS) $(STATIC_LIBS) installdirs
	@$(SHELL) $(srcdir)/script/installlib.sh $(DESTDIR)$(libdir) "$(SHLIBEXT)" $(INSTALLABLE_SHARED_LIBS) 
	#@$(SHELL) $(srcdir)/script/installlib.sh $(DESTDIR)$(libdir) "$(STLIBEXT)" $(STATIC_LIBS)

installheader:: headers installdirs
	@srcdir=$(srcdir) builddir=$(builddir) $(PERL) $(srcdir)/script/installheader.pl $(DESTDIR)$(includedir) $(PUBLIC_HEADERS) $(DEFAULT_HEADERS)

installdat:: installdirs
	@$(SHELL) $(srcdir)/script/installdat.sh $(DESTDIR)$(datadir) $(srcdir)

installswat:: installdirs
	@$(SHELL) $(srcdir)/script/installswat.sh $(DESTDIR)$(SWATDIR) $(srcdir)

installman:: manpages installdirs
	@$(SHELL) $(srcdir)/script/installman.sh $(DESTDIR)$(mandir) $(MANPAGES)

installmisc:: installdirs
	@$(SHELL) $(srcdir)/script/installmisc.sh $(srcdir) $(DESTDIR)$(JSDIR) $(DESTDIR)$(SETUPDIR) $(DESTDIR)$(bindir)

installpc:: installdirs
	@$(SHELL) $(srcdir)/script/installpc.sh $(builddir) $(DESTDIR)$(PKGCONFIGDIR) $(PC_FILES)

uninstall:: uninstallbin uninstallman uninstallmisc uninstalllib uninstallheader \
	uninstallplugins

uninstallmisc::
	#FIXME

uninstallbin::
	@$(SHELL) $(srcdir)/script/uninstallbin.sh $(INSTALLPERMS) $(DESTDIR)$(BASEDIR) $(DESTDIR)$(sbindir) $(DESTDIR)$(libdir) $(DESTDIR)$(localstatedir) $(DESTDIR)$(SBIN_PROGS)
	@$(SHELL) $(srcdir)/script/uninstallbin.sh $(INSTALLPERMS) $(DESTDIR)$(BASEDIR) $(DESTDIR)$(bindir) $(DESTDIR)$(libdir) $(DESTDIR)$(localstatedir) $(DESTDIR)$(BIN_PROGS)
	@$(SHELL) $(srcdir)/script/uninstalltorture.sh $(DESTDIR)$(TORTUREDIR) $(TORTURE_PROGS)

uninstalllib::
	@$(SHELL) $(srcdir)/script/uninstalllib.sh $(DESTDIR)$(libdir) $(SHARED_LIBS)
	#@$(SHELL) $(srcdir)/script/uninstalllib.sh $(DESTDIR)$(libdir) $(STATIC_LIBS) 

uninstallheader::
	@$(SHELL) $(srcdir)/script/uninstallheader.sh $(DESTDIR)$(includedir) $(PUBLIC_HEADERS)

uninstallman::
	@$(SHELL) $(srcdir)/script/uninstallman.sh $(DESTDIR)$(mandir) $(MANPAGES)

data.mk: config.status $(MK_FILES)
	./config.status

pidl/Makefile: pidl/Makefile.PL
	cd pidl && $(PERL) Makefile.PL 

testcov-html:: pidl-testcov

pidl-testcov: pidl/Makefile
	cd pidl && cover -test

installpidl:: pidl/Makefile
	$(MAKE) -C pidl install

uninstallpidl:: pidl/Makefile
	$(MAKE) -C pidl uninstall

$(IDL_HEADER_FILES) \
	$(IDL_NDR_PARSE_H_FILES) $(IDL_NDR_PARSE_C_FILES) \
	$(IDL_NDR_CLIENT_C_FILES) $(IDL_NDR_CLIENT_H_FILES) \
	$(IDL_NDR_SERVER_C_FILES) $(IDL_SWIG_FILES) \
	$(IDL_NDR_EJS_C_FILES) $(IDL_NDR_EJS_H_FILES) \
	$(IDL_NDR_PY_C_FILES) $(IDL_NDR_PY_H_FILES): idl

idl_full:: pidl/lib/Parse/Pidl/IDL.pm pidl/lib/Parse/Pidl/Expr.pm 
	@CPP="$(CPP)" PERL="$(PERL)" srcdir=$(srcdir) $(srcdir)/script/build_idl.sh FULL

idl:: pidl/lib/Parse/Pidl/IDL.pm pidl/lib/Parse/Pidl/Expr.pm 
	@CPP="$(CPP)" PERL="$(PERL)" srcdir=$(srcdir) $(srcdir)/script/build_idl.sh PARTIAL 

pidl/lib/Parse/Pidl/IDL.pm: pidl/idl.yp
	-$(YAPP) -m 'Parse::Pidl::IDL' -o pidl/lib/Parse/Pidl/IDL.pm pidl/idl.yp ||\
		touch pidl/lib/Parse/Pidl/IDL.pm 

pidl/lib/Parse/Pidl/Expr.pm: pidl/idl.yp
	-$(YAPP) -m 'Parse::Pidl::Expr' -o pidl/lib/Parse/Pidl/Expr.pm pidl/expr.yp ||\
		touch pidl/lib/Parse/Pidl/Expr.pm 

include selftest/config.mk
include rules.mk

showflags::
	@echo '  pwd        = '`/bin/pwd`
