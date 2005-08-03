# master list of build config files for Samba4
include heimdal_build/config.mk
include config.mk
include dsdb/config.mk
include gtk/config.mk
include smbd/config.mk
include smbd/process_model.mk
include libnet/config.mk
include auth/config.mk
include nsswitch/config.mk
include lib/basic.mk
include lib/socket/config.mk
include lib/ldb/config.mk
include lib/talloc/config.mk
include lib/tdb/config.mk
include lib/tls/config.mk
include lib/registry/config.mk
include lib/messaging/config.mk
include lib/events/config.mk
include lib/popt/config.mk
include lib/cmdline/config.mk
include lib/socket_wrapper/config.mk
include lib/appweb/config.mk
include param/config.mk
include smb_server/config.mk
include rpc_server/config.mk
include ldap_server/config.mk
include web_server/config.mk
include winbind/config.mk
include nbt_server/config.mk
include cldap_server/config.mk
include auth/gensec/config.mk
include auth/kerberos/config.mk
include auth/ntlmssp/config.mk
include libcli/auth/config.mk
include libcli/ldap/config.mk
include libcli/config.mk
include utils/net/config.mk
include utils/config.mk
include ntvfs/posix/config.mk
include ntvfs/config.mk
include ntvfs/unixuid/config.mk
include ntptr/config.mk
include torture/config.mk
include librpc/config.mk
include client/config.mk
include libcli/config.mk
include libcli/security/config.mk
include lib/com/config.mk
include scripting/config.mk
include kdc/config.mk
include lib/replace/config.mk
include scripting/ejs/config.mk

all: basics binaries
binaries: $(BIN_PROGS) $(SBIN_PROGS)
manpages: $(MANPAGES)
everything: all

showlayout: 
	@echo "Samba will be installed into:"
	@echo "  basedir: $(BASEDIR)"
	@echo "  bindir:  $(BINDIR)"
	@echo "  sbindir: $(SBINDIR)"
	@echo "  libdir:  $(LIBDIR)"
	@echo "  vardir:  $(VARDIR)"
	@echo "  privatedir:  $(PRIVATEDIR)"
	@echo "  piddir:   $(PIDDIR)"
	@echo "  lockdir:  $(LOCKDIR)"
	@echo "  swatdir:  $(SWATDIR)"
	@echo "  mandir:   $(MANDIR)"

showflags:
	@echo "Samba will be compiled with flags:"
	@echo "  CFLAGS = $(CFLAGS)"
	@echo "  LD_FLAGS = $(LD_FLAGS)"
	@echo "  STLD_FLAGS = $(STLD_FLAGS)"
	@echo "  SHLD_FLAGS = $(SHLD_FLAGS)"

install: showlayout installbin installdat installswat

# DESTDIR is used here to prevent packagers wasting their time
# duplicating the Makefile. Remove it and you will have the privilege
# of packaging each samba release for multiple versions of multiple
# distributions and operating systems, or at least supplying patches
# to all the packaging files required for this, prior to committing
# the removal of DESTDIR. Do not remove it even though you think it
# is not used.

installdirs:
	@$(SHELL) $(srcdir)/script/installdirs.sh $(DESTDIR)$(BASEDIR) $(DESTDIR)$(BINDIR) $(DESTDIR)$(SBINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(VARDIR) $(DESTDIR)$(PRIVATEDIR) $(DESTDIR)$(PIDDIR) $(DESTDIR)$(LOCKDIR) $(DESTDIR)$(PRIVATEDIR)/tls

installbin: binaries installdirs
	@$(SHELL) $(srcdir)/script/installbin.sh $(INSTALLPERMS) $(DESTDIR)$(BASEDIR) $(DESTDIR)$(SBINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(VARDIR) $(SBIN_PROGS)
	@$(SHELL) $(srcdir)/script/installbin.sh $(INSTALLPERMS) $(DESTDIR)$(BASEDIR) $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(VARDIR) $(BIN_PROGS)

installdat: installdirs
	@$(SHELL) $(srcdir)/script/installdat.sh $(DESTDIR)$(LIBDIR) $(srcdir)

installswat: installdirs
	@$(SHELL) $(srcdir)/script/installswat.sh $(DESTDIR)$(SWATDIR) $(srcdir) $(DESTDIR)$(LIBDIR)

installman: installdirs
	@$(SHELL) $(srcdir)/script/installman.sh $(DESTDIR)$(MANDIR) $(MANPAGES)

uninstall: uninstallbin uninstallman

uninstallbin:
	@$(SHELL) $(srcdir)/script/uninstallbin.sh $(INSTALLPERMS) $(DESTDIR)$(BASEDIR) $(DESTDIR)$(SBINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(VARDIR) $(DESTDIR)$(SBIN_PROGS)
	@$(SHELL) $(srcdir)/script/uninstallbin.sh $(INSTALLPERMS) $(DESTDIR)$(BASEDIR) $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(VARDIR) $(DESTDIR)$(BIN_PROGS)

uninstallman:
	@$(SHELL) $(srcdir)/script/uninstallman.sh $(DESTDIR)$(MANDIR) $(MANPAGES)


etags:
	etags `find $(srcdir) -name "*.[ch]"`

ctags:
	ctags `find $(srcdir) -name "*.[ch]"`

idl_full: build/pidl/Parse/Pidl/IDL.pm
	@CPP="$(CPP)" PERL="$(PERL)" script/build_idl.sh FULL @PIDL_ARGS@

idl: build/pidl/Parse/Pidl/IDL.pm
	@CPP="$(CPP)" PERL="$(PERL)" script/build_idl.sh PARTIAL @PIDL_ARGS@

build/pidl/Parse/Pidl/IDL.pm: build/pidl/idl.yp
	-yapp -s -m 'Parse::Pidl::IDL' -o build/pidl/Parse/Pidl/IDL.pm build/pidl/idl.yp 

smb_interfaces: build/pidl/smb_interfaces.pm
	$(PERL) -Ibuild/pidl script/build_smb_interfaces.pl \
		include/smb_interfaces.h

build/pidl/smb_interfaces.pm: build/pidl/smb_interfaces.yp
	-yapp -s -m 'smb_interfaces' -o build/pidl/smb_interfaces.pm build/pidl/smb_interfaces.yp 

pch: proto include/includes.h.gch

pch_clean:
	-rm -f include/includes.h.gch

basics: idl proto_exists heimdal/lib/hdb/hdb_asn1.h heimdal/lib/gssapi/spnego_asn1.h heimdal/lib/asn1/krb5_asn1.h heimdal/lib/roken/vis.h heimdal/lib/roken/err.h

test: $(DEFAULT_TEST_TARGET)

test-swrap: all
	./script/tests/selftest.sh ${selftest_prefix}/st all SOCKET_WRAPPER

test-noswrap: all
	./script/tests/selftest.sh ${selftest_prefix}/st all

quicktest: all
	./script/tests/selftest.sh ${selftest_prefix}/st quick SOCKET_WRAPPER

valgrindtest: all
	SMBD_VALGRIND="xterm -n smbd -e valgrind -q --db-attach=yes --num-callers=30" \
	./script/tests/selftest.sh ${selftest_prefix}/st quick SOCKET_WRAPPER

.y.c:
	$(YACC) -d -o $@ $<	

.l.c:
	$(LEX) -o $@ $<
