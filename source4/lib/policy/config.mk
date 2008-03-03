[SUBSYSTEM::LIBPOLICY]
CFLAGS = -Iheimdal/lib/roken
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL LIBSAMBA-CONFIG LIBTALLOC CHARSET 

LIBPOLICY_OBJ_FILES = lib/policy/lex.o lib/policy/parse_adm.o 

lib/policy/lex.l: lib/policy/parse_adm.h

lib/policy/parse_adm.h: lib/policy/parse_adm.c

[BINARY::dumpadm]
PRIVATE_DEPENDENCIES = LIBPOLICY LIBPOPT LIBSAMBA-CONFIG LIBTALLOC LIBSAMBA-UTIL CHARSET

dumpadmin_OBJ_FILES = lib/policy/dumpadm.o
