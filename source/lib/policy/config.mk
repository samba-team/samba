[LIBRARY::LIBPOLICY]
CFLAGS = -Iheimdal/lib/roken
OBJ_FILES = lex.o parse_adm.o 
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL LIBSAMBA-CONFIG LIBTALLOC CHARSET 

lib/policy/lex.l: lib/policy/parse_adm.h

lib/policy/parse_adm.h: lib/policy/parse_adm.c

[BINARY::dumpadm]
OBJ_FILES = dumpadm.o
PRIVATE_DEPENDENCIES = LIBPOLICY LIBPOPT LIBSAMBA-CONFIG LIBTALLOC LIBSAMBA-UTIL CHARSET
