/*
   Copyright (C) Andrew Tridgell <genstruct@tridgell.net> 2002
   Copyright (C) Simo Sorce <idra@samba.org> 2002
   
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

#include "includes.h"
#include "genparser_samba.h"

/* PARSE functions */

int gen_parse_uint8(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	*(uint8 *)ptr = atoi(str);
	return 0;
}

int gen_parse_uint16(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	*(uint16 *)ptr = atoi(str);
	return 0;
}

int gen_parse_uint32(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	*(uint32 *)ptr = strtoul(str, NULL, 10);
	return 0;
}

int gen_parse_NTTIME(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	if(sscanf(str, "%u,%u", &(((NTTIME *)(ptr))->high), &(((NTTIME *)(ptr))->low)) != 2) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

int gen_parse_DOM_SID(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	if(!string_to_sid((DOM_SID *)ptr, str)) return -1;
	return 0;
}

int gen_parse_SEC_ACCESS(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	((SEC_ACCESS *)ptr)->mask = strtoul(str, NULL, 10);
	return 0;
}

int gen_parse_GUID(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	int info[UUID_FLAT_SIZE];
	int i;
	char *sc;
       	char *p;
	char *m;

	m = strdup(str);
	if (!m) return -1;
	sc = m;
	
	memset(info, 0, sizeof(info));
	for (i = 0; i < UUID_FLAT_SIZE; i++) {
		p = strchr(sc, ',');
		if (p != NULL) p = '\0';
		info[i] = atoi(sc);
		if (p != NULL) sc = p + 1;
	}
	free(m);
		
	for (i = 0; i < UUID_FLAT_SIZE; i++) {
		((UUID_FLAT *)ptr)->info[i] = info[i];
	}
		
	return 0;
}

int gen_parse_SEC_ACE(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	return gen_parse_struct(mem_ctx, pinfo_security_ace_info, ptr, str);
}

int gen_parse_SEC_ACL(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	return gen_parse_struct(mem_ctx, pinfo_security_acl_info, ptr, str);
}

int gen_parse_SEC_DESC(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	return gen_parse_struct(mem_ctx, pinfo_security_descriptor_info, ptr, str);
}

int gen_parse_LUID_ATTR(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	return gen_parse_struct(mem_ctx, pinfo_luid_attr_info, ptr, str);
}

int gen_parse_LUID(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	if(sscanf(str, "%u,%u", &(((LUID *)(ptr))->high), &(((LUID *)(ptr))->low)) != 2) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

int gen_parse_DATA_BLOB(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	return gen_parse_struct(mem_ctx, pinfo_data_blob_info, ptr, str);
}

int gen_parse_TALLOC_CTX(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	(TALLOC_CTX *)ptr = NULL;
	return 0;
}

/* DUMP functions */

int gen_dump_uint8(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return addshort(mem_ctx, p, "%u", *(uint8 *)(ptr));
}

int gen_dump_uint16(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return addshort(mem_ctx, p, "%u", *(uint16 *)(ptr));
}

int gen_dump_uint32(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return addshort(mem_ctx, p, "%u", *(uint32 *)(ptr));
}

int gen_dump_NTTIME(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	uint32 low, high;

	high = ((NTTIME *)(ptr))->high;
	low = ((NTTIME *)(ptr))->low;
	return addshort(mem_ctx, p, "%u,%u", high, low);
}

int gen_dump_DOM_SID(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	fstring sidstr;

	sid_to_string(sidstr, (DOM_SID *)ptr);
	return addstr(mem_ctx, p, sidstr);
}

int gen_dump_SEC_ACCESS(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return addshort(mem_ctx, p, "%u", ((SEC_ACCESS *)ptr)->mask);
}

int gen_dump_GUID(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	int i, r;

	for (i = 0; i < (UUID_FLAT_SIZE - 1); i++) {
		if (!(r = addshort(mem_ctx, p, "%d,", ((UUID_FLAT *)ptr)->info[i]))) return r;
	}
	return addshort(mem_ctx, p, "%d", ((UUID_FLAT *)ptr)->info[i]);
}

int gen_dump_SEC_ACE(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return gen_dump_struct(mem_ctx, pinfo_security_ace_info, p, ptr, indent);
}

int gen_dump_SEC_ACL(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return gen_dump_struct(mem_ctx, pinfo_security_acl_info, p, ptr, indent);
}

int gen_dump_SEC_DESC(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return gen_dump_struct(mem_ctx, pinfo_security_descriptor_info, p, ptr, indent);
}

int gen_dump_LUID_ATTR(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return gen_dump_struct(mem_ctx, pinfo_luid_attr_info, p, ptr, indent);
}

int gen_dump_LUID(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	uint32 low, high;

	high = ((LUID *)(ptr))->high;
	low = ((LUID *)(ptr))->low;
	return addshort(mem_ctx, p, "%u,%u", high, low);
}

int gen_dump_DATA_BLOB(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return gen_dump_struct(mem_ctx, pinfo_data_blob_info, p, ptr, indent);
}

int gen_dump_TALLOC_CTX(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return addshort(mem_ctx, p, "TALLOC_CTX");
}
