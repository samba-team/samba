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

int gen_parse_uint8(char *ptr, const char *str)
{
	*(uint8 *)ptr = atoi(str);
	return 0;
}

int gen_parse_uint16(char *ptr, const char *str)
{
	*(uint16 *)ptr = atoi(str);
	return 0;
}

int gen_parse_uint32(char *ptr, const char *str)
{
	*(uint32 *)ptr = strtoul(str, NULL, 10);
	return 0;
}

int gen_parse_NTTIME(char *ptr, const char *str)
{
	if(sscanf(str, "%u,%u", &(((NTTIME *)(ptr))->high), &(((NTTIME *)(ptr))->low)) != 2) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

int gen_parse_DOM_SID(char *ptr, const char *str)
{
	if(!string_to_sid((DOM_SID *)ptr, str)) return -1;
	return 0;
}

int gen_parse_SEC_ACCESS(char *ptr, const char *str)
{
	((SEC_ACCESS *)ptr)->mask = strtoul(str, NULL, 10);
	return 0;
}

int gen_parse_GUID(char *ptr, const char *str)
{
	int info[GUID_SIZE];
	int i;
	char *sc;
       	char *p;
	char *m;

	m = strdup(str);
	if (!m) return -1;
	sc = m;
	
	memset(info, 0, sizeof(info));
	for (i = 0; i < GUID_SIZE; i++) {
		p = strchr(sc, ',');
		if (p != NULL) p = '\0';
		info[i] = atoi(sc);
		if (p != NULL) sc = p + 1;
	}
	free(m);
		
	for (i = 0; i < GUID_SIZE; i++) {
		((GUID *)ptr)->info[i] = info[i];
	}
		
	return 0;
}

int gen_parse_SEC_ACE(char *ptr, const char *str)
{
	return gen_parse_struct(pinfo_security_ace_info, ptr, str);
}

int gen_parse_SEC_ACL(char *ptr, const char *str)
{
	return gen_parse_struct(pinfo_security_acl_info, ptr, str);
}

int gen_parse_SEC_DESC(char *ptr, const char *str)
{
	return gen_parse_struct(pinfo_security_descriptor_info, ptr, str);
}

int gen_parse_LUID_ATTR(char *ptr, const char *str)
{
	return gen_parse_struct(pinfo_luid_attr_info, ptr, str);
}

int gen_parse_LUID(char *ptr, const char *str)
{
	if(sscanf(str, "%u,%u", &(((LUID *)(ptr))->high), &(((LUID *)(ptr))->low)) != 2) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}



/* DUMP functions */

int gen_dump_uint8(struct parse_string *p, const char *ptr, unsigned indent)
{
	return addshort(p, "%u", *(uint8 *)(ptr));
}

int gen_dump_uint16(struct parse_string *p, const char *ptr, unsigned indent)
{
	return addshort(p, "%u", *(uint16 *)(ptr));
}

int gen_dump_uint32(struct parse_string *p, const char *ptr, unsigned indent)
{
	return addshort(p, "%u", *(uint32 *)(ptr));
}

int gen_dump_NTTIME(struct parse_string *p, const char *ptr, unsigned indent)
{
	uint32 low, high;

	high = ((NTTIME *)(ptr))->high;
	low = ((NTTIME *)(ptr))->low;
	return addshort(p, "%u,%u", high, low);
}

int gen_dump_DOM_SID(struct parse_string *p, const char *ptr, unsigned indent)
{
	fstring sidstr;

	sid_to_string(sidstr, (DOM_SID *)ptr);
	return addstr(p, sidstr);
}

int gen_dump_SEC_ACCESS(struct parse_string *p, const char *ptr, unsigned indent)
{
	return addshort(p, "%u", ((SEC_ACCESS *)ptr)->mask);
}

int gen_dump_GUID(struct parse_string *p, const char *ptr, unsigned indent)
{
	int i, r;

	for (i = 0; i < (GUID_SIZE - 1); i++) {
		if (!(r = addshort(p, "%d,", ((GUID *)ptr)->info[i]))) return r;
	}
	return addshort(p, "%d", ((GUID *)ptr)->info[i]);
}

int gen_dump_SEC_ACE(struct parse_string *p, const char *ptr, unsigned indent)
{
	return gen_dump_struct(pinfo_security_ace_info, p, ptr, indent);
}

int gen_dump_SEC_ACL(struct parse_string *p, const char *ptr, unsigned indent)
{
	return gen_dump_struct(pinfo_security_acl_info, p, ptr, indent);
}

int gen_dump_SEC_DESC(struct parse_string *p, const char *ptr, unsigned indent)
{
	return gen_dump_struct(pinfo_security_descriptor_info, p, ptr, indent);
}

int gen_dump_LUID_ATTR(struct parse_string *p, const char *ptr, unsigned indent)
{
	return gen_dump_struct(pinfo_luid_attr_info, p, ptr, indent);
}

int gen_dump_LUID(struct parse_string *p, const char *ptr, unsigned indent)
{
	uint32 low, high;

	high = ((LUID *)(ptr))->high;
	low = ((LUID *)(ptr))->low;
	return addshort(p, "%u,%u", high, low);
}

