[SUBSYSTEM::TDR_REGF]
PUBLIC_DEPENDENCIES = TDR 

TDR_REGF_OBJ_FILES = lib/registry/tdr_regf.o

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
PC_FILE = registry.pc
SO_VERSION = 0
PUBLIC_DEPENDENCIES = \
		LIBSAMBA-UTIL CHARSET TDR_REGF LIBLDB \
		RPC_NDR_WINREG LDB_WRAP
# End MODULE registry_ldb
################################################

registry_OBJ_FILES = $(addprefix lib/registry/, interface.o util.o samba.o \
					patchfile_dotreg.o patchfile_preg.o patchfile.o regf.o \
					hive.o local.o ldb.o dir.o rpc.o)

PUBLIC_HEADERS += $(addprefix lib/registry/, registry.h hive.h patchfile.h)

[SUBSYSTEM::registry_common]
PUBLIC_DEPENDENCIES = registry
PRIVATE_PROTO_HEADER = tools/common.h

registry_common_OBJ_FILES = lib/registry/tools/common.o

################################################
# Start BINARY regdiff
[BINARY::regdiff]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG registry LIBPOPT POPT_SAMBA POPT_CREDENTIALS
# End BINARY regdiff
################################################

regdiff_OBJ_FILES = lib/registry/tools/regdiff.o

MANPAGES += lib/registry/man/regdiff.1

################################################
# Start BINARY regpatch
[BINARY::regpatch]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG registry LIBPOPT POPT_SAMBA POPT_CREDENTIALS \
		registry_common
# End BINARY regpatch
################################################

regpatch_OBJ_FILES = lib/registry/tools/regpatch.o

MANPAGES += lib/registry/man/regpatch.1

################################################
# Start BINARY regshell
[BINARY::regshell]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG LIBPOPT registry POPT_SAMBA POPT_CREDENTIALS \
		SMBREADLINE registry_common
# End BINARY regshell
################################################

regshell_OBJ_FILES = lib/registry/tools/regshell.o

MANPAGES += lib/registry/man/regshell.1

################################################
# Start BINARY regtree
[BINARY::regtree]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG LIBPOPT registry POPT_SAMBA POPT_CREDENTIALS \
		registry_common
# End BINARY regtree
################################################

regtree_OBJ_FILES = lib/registry/tools/regtree.o

MANPAGES += lib/registry/man/regtree.1

[SUBSYSTEM::torture_registry]
PRIVATE_DEPENDENCIES = registry
PRIVATE_PROTO_HEADER = tests/proto.h

torture_registry_OBJ_FILES = $(addprefix lib/registry/tests/, generic.o hive.o diff.o registry.o)

[PYTHON::swig_registry]
PUBLIC_DEPENDENCIES = registry
SWIG_FILE = registry.i

