/*
   Copyright (C) Andrew Tridgell <genstruct@tridgell.net> 2002
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#error SAMBA4 clean up
#error this file should be (re)moved 
#error and all unused stuff should go

#ifndef _GENPARSER_H
#define _GENPARSER_H

/* these macros are needed for genstruct auto-parsers */
#ifndef GENSTRUCT
#define GENSTRUCT
#define _LEN(x)
#define _NULLTERM
#endif

/*
  automatic marshalling/unmarshalling system for C structures
*/

/* flag to mark a fixed size array as actually being null terminated */
#define FLAG_NULLTERM 1
#define FLAG_ALWAYS 2

struct enum_struct {
	const char *name;
	unsigned value;
};

/* intermediate dumps are stored in one of these */
struct parse_string {
	unsigned allocated;
	unsigned length;
	char *s;
};

typedef int (*gen_dump_fn)(TALLOC_CTX *, struct parse_string *, const char *ptr, unsigned indent);
typedef int (*gen_parse_fn)(TALLOC_CTX *, char *ptr, const char *str);

/* genstruct.pl generates arrays of these */
struct parse_struct {
	const char *name;
	unsigned ptr_count;
	unsigned size;
	unsigned offset;
	unsigned array_len;
	const char *dynamic_len;
	unsigned flags;
	gen_dump_fn dump_fn;
	gen_parse_fn parse_fn;
};

#define DUMP_PARSE_DECL(type) \
  int gen_dump_ ## type(TALLOC_CTX *, struct parse_string *, const char *, unsigned); \
  int gen_parse_ ## type(TALLOC_CTX *, char *, const char *);

DUMP_PARSE_DECL(char)
DUMP_PARSE_DECL(int)
DUMP_PARSE_DECL(unsigned)
DUMP_PARSE_DECL(double)
DUMP_PARSE_DECL(float)

#define gen_dump_unsigned_char gen_dump_char
#define gen_parse_unsigned_char gen_parse_char

#endif /* _GENPARSER_H */
