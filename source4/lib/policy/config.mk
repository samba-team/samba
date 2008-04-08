[SUBSYSTEM::LIBPOLICY]
CFLAGS = -Iheimdal/lib/roken
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL LIBSAMBA-HOSTCONFIG LIBTALLOC CHARSET 

LIBPOLICY_OBJ_FILES = lib/policy/lex.o lib/policy/parse_adm.o 

lib/policy/lex.l: lib/policy/parse_adm.h

lib/policy/parse_adm.h: lib/policy/parse_adm.c

[BINARY::dumpadm]
PRIVATE_DEPENDENCIES = LIBPOLICY LIBPOPT LIBSAMBA-HOSTCONFIG LIBTALLOC LIBSAMBA-UTIL CHARSET

dumpadm_OBJ_FILES = lib/policy/dumpadm.o
