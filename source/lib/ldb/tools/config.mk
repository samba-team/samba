################################################
# Start SUBSYSTEM LIBLDB_CMDLINE
[SUBSYSTEM::LIBLDB_CMDLINE]
CFLAGS = -Ilib/ldb -Ilib/ldb/include
OBJ_FILES= \
		cmdline.o
PUBLIC_DEPENDENCIES = LIBLDB LIBPOPT
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL POPT_SAMBA POPT_CREDENTIALS gensec
# End SUBSYSTEM LIBLDB_CMDLINE
################################################

################################################
# Start BINARY ldbadd
[BINARY::ldbadd]
INSTALLDIR = BINDIR
OBJ_FILES = \
		ldbadd.o
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE LIBCLI_RESOLVE
# End BINARY ldbadd
################################################

MANPAGES += $(ldbdir)/../man/ldbadd.1

################################################
# Start BINARY ldbdel
[BINARY::ldbdel]
INSTALLDIR = BINDIR
OBJ_FILES= \
		ldbdel.o
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
# End BINARY ldbdel
################################################

MANPAGES += $(ldbdir)/../man/ldbdel.1

################################################
# Start BINARY ldbmodify
[BINARY::ldbmodify]
INSTALLDIR = BINDIR
OBJ_FILES= \
		ldbmodify.o
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
# End BINARY ldbmodify
################################################

MANPAGES += $(ldbdir)/../man/ldbmodify.1

################################################
# Start BINARY ldbsearch
[BINARY::ldbsearch]
INSTALLDIR = BINDIR
OBJ_FILES= \
		ldbsearch.o
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE 
# End BINARY ldbsearch
################################################

MANPAGES += $(ldbdir)/../man/ldbsearch.1

################################################
# Start BINARY ldbedit
[BINARY::ldbedit]
INSTALLDIR = BINDIR
OBJ_FILES= \
		ldbedit.o
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
# End BINARY ldbedit
################################################

MANPAGES += $(ldbdir)/../man/ldbedit.1

################################################
# Start BINARY ldbrename
[BINARY::ldbrename]
INSTALLDIR = BINDIR
OBJ_FILES= \
		ldbrename.o
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
# End BINARY ldbrename
################################################

MANPAGES += $(ldbdir)/../man/ldbrename.1


