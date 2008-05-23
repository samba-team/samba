################################################
# Start SUBSYSTEM LIBLDB_CMDLINE
[SUBSYSTEM::LIBLDB_CMDLINE]
CFLAGS = -Ilib/ldb -Ilib/ldb/include
PUBLIC_DEPENDENCIES = LIBLDB LIBPOPT
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL POPT_SAMBA POPT_CREDENTIALS gensec
# End SUBSYSTEM LIBLDB_CMDLINE
################################################

LIBLDB_CMDLINE_OBJ_FILES = lib/ldb/tools/cmdline.o

################################################
# Start BINARY ldbadd
[BINARY::ldbadd]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE LIBCLI_RESOLVE
# End BINARY ldbadd
################################################


ldbadd_OBJ_FILES = lib/ldb/tools/ldbadd.o

MANPAGES += $(ldbdir)/man/ldbadd.1

################################################
# Start BINARY ldbdel
[BINARY::ldbdel]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
# End BINARY ldbdel
################################################

ldbdel_OBJ_FILES = lib/ldb/tools/ldbdel.o

MANPAGES += $(ldbdir)/man/ldbdel.1

################################################
# Start BINARY ldbmodify
[BINARY::ldbmodify]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
# End BINARY ldbmodify
################################################

ldbmodify_OBJ_FILES = lib/ldb/tools/ldbmodify.o
MANPAGES += $(ldbdir)/man/ldbmodify.1

################################################
# Start BINARY ldbsearch
[BINARY::ldbsearch]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE 
# End BINARY ldbsearch
################################################

ldbsearch_OBJ_FILES = lib/ldb/tools/ldbsearch.o

MANPAGES += $(ldbdir)/man/ldbsearch.1

################################################
# Start BINARY ldbedit
[BINARY::ldbedit]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
# End BINARY ldbedit
################################################

ldbedit_OBJ_FILES = lib/ldb/tools/ldbedit.o

MANPAGES += $(ldbdir)/man/ldbedit.1

################################################
# Start BINARY ldbrename
[BINARY::ldbrename]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
# End BINARY ldbrename
################################################

ldbrename_OBJ_FILES = lib/ldb/tools/ldbrename.o

MANPAGES += $(ldbdir)/man/ldbrename.1


