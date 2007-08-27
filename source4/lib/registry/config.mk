[SUBSYSTEM::TDR_REGF]
PUBLIC_DEPENDENCIES = TDR 
OBJ_FILES = tdr_regf.o

# Special support for external builddirs
lib/registry/regf.c: lib/registry/tdr_regf.c
$(srcdir)/lib/registry/regf.c: lib/registry/tdr_regf.c
lib/registry/tdr_regf.h: lib/registry/tdr_regf.c
lib/registry/tdr_regf.c: $(srcdir)/lib/registry/regf.idl
	@CPP="$(CPP)" srcdir="$(srcdir)" $(PERL) $(srcdir)/pidl/pidl $(PIDL_ARGS) \
		--header --outputdir=lib/registry \
		--tdr-parser -- $(srcdir)/lib/registry/regf.idl

clean::
	@-rm -f lib/registry/regf.h lib/registry/tdr_regf*

################################################
# Start SUBSYSTEM registry
[LIBRARY::registry]
VERSION = 0.0.1
SO_VERSION = 0
DESCRIPTION = Windows-style registry library
OBJ_FILES = \
		interface.o \
		util.o \
		samba.o \
		patchfile_dotreg.o \
		patchfile_preg.o \
		patchfile.o \
		regf.o \
		hive.o \
		local.o \
		ldb.o \
		dir.o \
		rpc.o
PUBLIC_DEPENDENCIES = \
		LIBSAMBA-UTIL CHARSET TDR_REGF LIBLDB \
		RPC_NDR_WINREG
PUBLIC_HEADERS = registry.h hive.h patchfile.h
# End MODULE registry_ldb
################################################

[SUBSYSTEM::registry_common]
PUBLIC_DEPENDENCIES = registry
OBJ_FILES = tools/common.o
PRIVATE_PROTO_HEADER = tools/common.h

################################################
# Start BINARY regdiff
[BINARY::regdiff]
INSTALLDIR = BINDIR
OBJ_FILES = tools/regdiff.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG registry LIBPOPT POPT_SAMBA POPT_CREDENTIALS
MANPAGE = man/regdiff.1
# End BINARY regdiff
################################################

################################################
# Start BINARY regpatch
[BINARY::regpatch]
INSTALLDIR = BINDIR
OBJ_FILES = tools/regpatch.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG registry LIBPOPT POPT_SAMBA POPT_CREDENTIALS \
		registry_common
MANPAGE = man/regpatch.1
# End BINARY regpatch
################################################

################################################
# Start BINARY regshell
[BINARY::regshell]
INSTALLDIR = BINDIR
OBJ_FILES = tools/regshell.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG LIBPOPT registry POPT_SAMBA POPT_CREDENTIALS \
		SMBREADLINE registry_common
MANPAGE = man/regshell.1
# End BINARY regshell
################################################

################################################
# Start BINARY regtree
[BINARY::regtree]
INSTALLDIR = BINDIR
OBJ_FILES = tools/regtree.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG LIBPOPT registry POPT_SAMBA POPT_CREDENTIALS \
		registry_common
MANPAGE = man/regtree.1
# End BINARY regtree
################################################
