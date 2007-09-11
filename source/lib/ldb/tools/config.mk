################################################
# Start SUBSYSTEM LIBLDB_CMDLINE
[SUBSYSTEM::LIBLDB_CMDLINE]
CFLAGS = -Ilib/ldb
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
MANPAGE = ../man/ldbadd.1
# End BINARY ldbadd
################################################

################################################
# Start BINARY ldbdel
[BINARY::ldbdel]
INSTALLDIR = BINDIR
OBJ_FILES= \
		ldbdel.o
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
MANPAGE = ../man/ldbdel.1
# End BINARY ldbdel
################################################

################################################
# Start BINARY ldbmodify
[BINARY::ldbmodify]
INSTALLDIR = BINDIR
OBJ_FILES= \
		ldbmodify.o
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
MANPAGE = ../man/ldbmodify.1
# End BINARY ldbmodify
################################################

################################################
# Start BINARY ldbsearch
[BINARY::ldbsearch]
INSTALLDIR = BINDIR
OBJ_FILES= \
		ldbsearch.o
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE 
MANPAGE = ../man/ldbsearch.1
# End BINARY ldbsearch
################################################

################################################
# Start BINARY ldbedit
[BINARY::ldbedit]
INSTALLDIR = BINDIR
OBJ_FILES= \
		ldbedit.o
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
MANPAGE = ../man/ldbedit.1
# End BINARY ldbedit
################################################

################################################
# Start BINARY ldbrename
[BINARY::ldbrename]
INSTALLDIR = BINDIR
OBJ_FILES= \
		ldbrename.o
PRIVATE_DEPENDENCIES = \
		LIBLDB_CMDLINE
MANPAGE = ../man/ldbrename.1
# End BINARY ldbrename
################################################


