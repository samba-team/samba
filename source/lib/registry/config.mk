# Registry backends

################################################
# Start MODULE registry_nt4
[MODULE::registry_nt4]
INIT_FUNCTION = registry_nt4_init
SUBSYSTEM = registry
OBJ_FILES = \
		reg_backend_nt4.o
PUBLIC_DEPENDENCIES = TDR_REGF
# End MODULE registry_nt4
################################################

[SUBSYSTEM::TDR_REGF]
PUBLIC_DEPENDENCIES = TDR 
OBJ_FILES = tdr_regf.o

# Special support for external builddirs
lib/registry/reg_backend_nt4.c: lib/registry/tdr_regf.c
$(srcdir)/lib/registry/reg_backend_nt4.c: lib/registry/tdr_regf.c
lib/registry/tdr_regf.h: lib/registry/tdr_regf.c
lib/registry/tdr_regf.c: $(srcdir)/lib/registry/regf.idl
	@CPP="$(CPP)" $(PERL) $(srcdir)/pidl/pidl $(PIDL_ARGS) \
		--header --outputdir=lib/registry \
		--tdr-parser -- $(srcdir)/lib/registry/regf.idl

clean::
	@-rm -f lib/registry/regf.h lib/registry/tdr_regf*

################################################
# Start MODULE registry_w95
[MODULE::registry_w95]
INIT_FUNCTION = registry_w95_init
SUBSYSTEM = registry
OBJ_FILES = \
		reg_backend_w95.o
# End MODULE registry_w95
################################################

################################################
# Start MODULE registry_dir
[MODULE::registry_dir]
INIT_FUNCTION = registry_dir_init
SUBSYSTEM = registry
OBJ_FILES = \
		reg_backend_dir.o
PUBLIC_DEPENDENCIES = LIBTALLOC
# End MODULE registry_dir
################################################

################################################
# Start MODULE registry_rpc
[MODULE::registry_rpc]
INIT_FUNCTION = registry_rpc_init
OUTPUT_TYPE = INTEGRATED
SUBSYSTEM = registry
OBJ_FILES = \
		reg_backend_rpc.o
PUBLIC_DEPENDENCIES = RPC_NDR_WINREG
# End MODULE registry_rpc
################################################

################################################
# Start MODULE registry_ldb
[MODULE::registry_ldb]
INIT_FUNCTION = registry_ldb_init
SUBSYSTEM = registry
OBJ_FILES = \
		reg_backend_ldb.o
PUBLIC_DEPENDENCIES = \
		ldb
# End MODULE registry_ldb
################################################

################################################
# Start SUBSYSTEM registry
[LIBRARY::registry]
VERSION = 0.0.1
SO_VERSION = 0
DESCRIPTION = Windows-style registry library
OBJ_FILES = \
		common/reg_interface.o \
		common/reg_util.o \
		reg_samba.o \
		patchfile.o
PUBLIC_DEPENDENCIES = \
		LIBSAMBA-UTIL CHARSET
PUBLIC_HEADERS = registry.h
# End MODULE registry_ldb
################################################

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
		LIBSAMBA-CONFIG registry LIBPOPT POPT_SAMBA POPT_CREDENTIALS
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
		SMBREADLINE
MANPAGE = man/regshell.1
# End BINARY regshell
################################################

################################################
# Start BINARY regtree
[BINARY::regtree]
INSTALLDIR = BINDIR
OBJ_FILES = tools/regtree.o
PRIVATE_DEPENDENCIES = \
		LIBSAMBA-CONFIG LIBPOPT registry POPT_SAMBA POPT_CREDENTIALS
MANPAGE = man/regtree.1
# End BINARY regtree
################################################
