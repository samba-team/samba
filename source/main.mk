all: binary_asn1_compile binary_compile_et binaries

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
include param/config.mk
include smb_server/config.mk
include rpc_server/config.mk
include ldap_server/config.mk
include web_server/config.mk
include winbind/config.mk
include nbt_server/config.mk
include wrepl_server/config.mk
include cldap_server/config.mk
include utils/net/config.mk
include utils/config.mk
include ntvfs/config.mk
include ntptr/config.mk
include torture/config.mk
include librpc/config.mk
include client/config.mk
include libcli/config.mk
include scripting/config.mk
include kdc/config.mk

binaries: $(BIN_PROGS) $(SBIN_PROGS)
libraries: $(STATIC_LIBS) $(SHARED_LIBS)
headers: $(PUBLIC_HEADERS)
manpages: $(MANPAGES)
everything: all

showlayout: 
	@echo "Samba will be installed into:"
	@echo "  basedir: $(BASEDIR)"
	@echo "  bindir:  $(BINDIR)"
	@echo "  sbindir: $(SBINDIR)"
	@echo "  libdir:  $(LIBDIR)"
	@echo "  includedir:  $(INCLUDEDIR)"
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
	@echo "  LIBS = $(LIBS)"

install: showlayout installbin installdat installswat installmisc installlib \
	installheader

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

installlib: libraries installdirs
	@$(SHELL) $(srcdir)/script/installlib.sh $(DESTDIR)$(LIBDIR) $(SHARED_LIBS) 
	@$(SHELL) $(srcdir)/script/installlib.sh $(DESTDIR)$(LIBDIR) $(STATIC_LIBS)

installheader: headers installdirs
	@$(SHELL) $(srcdir)/script/installheader.sh $(DESTDIR)$(INCLUDEDIR) $(PUBLIC_HEADERS)

installdat: installdirs
	@$(SHELL) $(srcdir)/script/installdat.sh $(DESTDIR)$(LIBDIR) $(srcdir)

installswat: installdirs
	@$(SHELL) $(srcdir)/script/installswat.sh $(DESTDIR)$(SWATDIR) $(srcdir) $(DESTDIR)$(LIBDIR)

installman: installdirs
	@$(SHELL) $(srcdir)/script/installman.sh $(DESTDIR)$(MANDIR) $(MANPAGES)

installmisc: installdirs
	@$(SHELL) $(srcdir)/script/installmisc.sh $(srcdir) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(BINDIR)

uninstall: uninstallbin uninstallman uninstallmisc uninstalllib uninstallheader

uninstallmisc:
	#FIXME

uninstallbin:
	@$(SHELL) $(srcdir)/script/uninstallbin.sh $(INSTALLPERMS) $(DESTDIR)$(BASEDIR) $(DESTDIR)$(SBINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(VARDIR) $(DESTDIR)$(SBIN_PROGS)
	@$(SHELL) $(srcdir)/script/uninstallbin.sh $(INSTALLPERMS) $(DESTDIR)$(BASEDIR) $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(VARDIR) $(DESTDIR)$(BIN_PROGS)

uninstalllib:
	@$(SHELL) $(srcdir)/script/uninstalllib.sh $(DESTDIR)$(LIBDIR) $(SHARED_LIBS)
	@$(SHELL) $(srcdir)/script/uninstalllib.sh $(DESTDIR)$(LIBDIR) $(STATIC_LIBS) 

uninstallheader:
	@$(SHELL) $(srcdir)/script/uninstallheader.sh $(DESTDIR)$(INCLUDEDIR) $(PUBLIC_HEADERS)

uninstallman:
	@$(SHELL) $(srcdir)/script/uninstallman.sh $(DESTDIR)$(MANDIR) $(MANPAGES)

etags:
	etags `find $(srcdir) -name "*.[ch]"`

ctags:
	ctags `find $(srcdir) -name "*.[ch]"`

idl_full: pidl/lib/Parse/Pidl/IDL.pm
	@CPP="$(CPP)" PERL="$(PERL)" script/build_idl.sh FULL $(PIDL_ARGS)

idl: pidl/lib/Parse/Pidl/IDL.pm
	@CPP="$(CPP)" PERL="$(PERL)" script/build_idl.sh PARTIAL $(PIDL_ARGS)

pidl/lib/Parse/Pidl/IDL.pm: pidl/idl.yp
	-$(YAPP) -s -m 'Parse::Pidl::IDL' -o pidl/lib/Parse/Pidl/IDL.pm pidl/idl.yp 

smb_interfaces: pidl/smb_interfaces.pm
	$(PERL) -Ipidl script/build_smb_interfaces.pl \
		include/smb_interfaces.h

pidl/smb_interfaces.pm: pidl/smb_interfaces.yp
	-$(YAPP) -s -m 'smb_interfaces' -o pidl/smb_interfaces.pm pidl/smb_interfaces.yp 

include/config.h:
	@echo "include/config.h not present"
	@echo "You need to rerun ./autogen.sh and ./configure"
	@/bin/false

include/proto.h: $(PROTO_PROTO_OBJS:.o=.c)
	@-rm -f include/includes.h.gch
	@$(SHELL) script/mkproto.sh "$(PERL)" \
	  -h _PROTO_H_ include/proto.h \
	  $(PROTO_PROTO_OBJS)
	@touch include/proto.h

proto: include/proto.h
pch: include/config.h \
	include/proto.h \
	idl \
	include/includes.h.gch

basics: include/config.h \
	include/proto.h \
	idl \
	heimdal_basics

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
	@echo "Building $< with $(YACC)"
	@-$(srcdir)/script/yacc_compile.sh "$(YACC)" "$<" "$@"

.l.c:
	@echo "Building $< with $(LEX)"
	@-$(srcdir)/script/lex_compile.sh "$(LEX)" "$<" "$@"
