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

/*
  automatic marshalling/unmarshalling system for C structures
*/

#include "includes.h"

/* see if a range of memory is all zero. Used to prevent dumping of zero elements */
static int all_zero(const char *ptr, unsigned size)
{
	int i;
	if (!ptr) return 1;
	for (i=0;i<size;i++) {
		if (ptr[i]) return 0;
	}
	return 1;
}

/* encode a buffer of bytes into a escaped string */
static char *encode_bytes(TALLOC_CTX *mem_ctx, const char *ptr, unsigned len)
{
	const char *hexdig = "0123456789abcdef";
	char *ret, *p;
	unsigned i;
	ret = talloc(mem_ctx, len*3 + 1); /* worst case size */
	if (!ret) return NULL;
	for (p=ret,i=0;i<len;i++) {
		if (isalnum(ptr[i]) || isspace(ptr[i]) ||
		    (ispunct(ptr[i]) && !strchr("\\{}", ptr[i]))) {
			*p++ = ptr[i];
		} else {
			unsigned char c = *(unsigned char *)(ptr+i);
			if (c == 0 && all_zero(ptr+i, len-i)) break;
			p[0] = '\\';
			p[1] = hexdig[c>>4];
			p[2] = hexdig[c&0xF];
			p += 3;
		}
	}

	*p = 0;

	return ret;
}

/* decode an escaped string from encode_bytes() into a buffer */
static char *decode_bytes(TALLOC_CTX *mem_ctx, const char *s, unsigned *len) 
{
	char *ret, *p;
	unsigned i;
	int slen = strlen(s) + 1;

	ret = talloc(mem_ctx, slen); /* worst case length */
	if (!ret)
		return NULL;
	memset(ret, 0, slen);

	if (*s == '{') s++;

	for (p=ret,i=0;s[i];i++) {
		if (s[i] == '}') {
			break;
		} else if (s[i] == '\\') {
			unsigned v;
			if (sscanf(&s[i+1], "%02x", &v) != 1 || v > 255) {
				return NULL;
			}
			*(unsigned char *)p = v;
			p++;
			i += 2;
		} else {
			*p++ = s[i];
		}
	}
	*p = 0;

	(*len) = (unsigned)(p - ret);
	
	return ret;
}

/* the add*() functions deal with adding things to a struct
   parse_string */

/* allocate more space if needed */
static int addgen_alloc(TALLOC_CTX *mem_ctx, struct parse_string *p, int n)
{
	if (p->length + n <= p->allocated) return 0;
	p->allocated = p->length + n + 200;
	p->s = talloc_realloc(mem_ctx, p->s, p->allocated);
	if (!p->s) {
		errno = ENOMEM;
		return -1;
	}
	return 0;
}

/* add a character to the buffer */
static int addchar(TALLOC_CTX *mem_ctx, struct parse_string *p, char c)
{
	if (addgen_alloc(mem_ctx, p, 2) != 0) {
		return -1;
	}
	p->s[p->length++] = c;
	p->s[p->length] = 0;
	return 0;
}

/* add a string to the buffer */
int addstr(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *s)
{
	int len = strlen(s);
	if (addgen_alloc(mem_ctx, p, len+1) != 0) {
		return -1;
	}
	memcpy(p->s + p->length, s, len+1);
	p->length += len;
	return 0;
}

/* add a string to the buffer with a tab prefix */
static int addtabbed(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *s, unsigned indent)
{
	int len = strlen(s);
	if (addgen_alloc(mem_ctx, p, indent+len+1) != 0) {
		return -1;
	}
	while (indent--) {
		p->s[p->length++] = '\t';
	}
	memcpy(p->s + p->length, s, len+1);
	p->length += len;
	return 0;
}

/* note! this can only be used for results up to 60 chars wide! */
int addshort(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *fmt, ...)
{
	char buf[60];
	int n;
	va_list ap;
	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (addgen_alloc(mem_ctx, p, n + 1) != 0) {
		return -1;
	}
	if (n != 0) {
		memcpy(p->s + p->length, buf, n);
	}
	p->length += n;
	p->s[p->length] = 0;
	return 0;
}

/* 
   this is here to make it easier for people to write dump functions 
   for their own types
 */
int gen_addgen(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *fmt, ...)
{
	char *buf = NULL;
	int n;
	va_list ap;
	va_start(ap, fmt);
	n = vasprintf(&buf, fmt, ap);
	va_end(ap);
	if (addgen_alloc(mem_ctx, p, n + 1) != 0) {
		if (buf) free(buf);
		return -1;
	}
	if (n != 0) {
		memcpy(p->s + p->length, buf, n);
	}
	p->length += n;
	p->s[p->length] = 0;
	if (buf) free(buf);
	return 0;
}

/* dump a enumerated type */
int gen_dump_enum(TALLOC_CTX *mem_ctx,
		  const struct enum_struct *einfo,
		  struct parse_string *p, 
		  const char *ptr,
		  unsigned indent)
{
	unsigned v = *(unsigned *)ptr;
	int i;
	for (i=0;einfo[i].name;i++) {
		if (v == einfo[i].value) {
			addstr(mem_ctx, p, einfo[i].name);
			return 0;
		}
	}
	/* hmm, maybe we should just fail? */
	return gen_dump_unsigned(mem_ctx, p, ptr, indent);
}

/* dump a single non-array element, hanlding struct and enum */
static int gen_dump_one(TALLOC_CTX *mem_ctx,
			struct parse_string *p, 
			const struct parse_struct *pinfo,
			const char *ptr,
			unsigned indent)
{
	if (pinfo->dump_fn == gen_dump_char && pinfo->ptr_count == 1) {
		char *s = encode_bytes(mem_ctx, ptr, strlen(ptr));
		if (addchar(mem_ctx, p,'{') ||
		    addstr(mem_ctx, p, s) ||
		    addstr(mem_ctx, p, "}")) {
			return -1;
		}
		return 0;
	}

	return pinfo->dump_fn(mem_ctx, p, ptr, indent);
}

/* handle dumping of an array of arbitrary type */
static int gen_dump_array(TALLOC_CTX *mem_ctx,
			  struct parse_string *p,
			  const struct parse_struct *pinfo, 
			  const char *ptr,
			  int array_len,
			  int indent)
{
	int i, count=0;

	/* special handling of fixed length strings */
	if (array_len != 0 && 
	    pinfo->ptr_count == 0 &&
	    pinfo->dump_fn == gen_dump_char) {
		char *s = encode_bytes(mem_ctx, ptr, array_len);
		if (!s) return -1;
		if (addtabbed(mem_ctx, p, pinfo->name, indent) ||
		    addstr(mem_ctx, p, " = {") ||
		    addstr(mem_ctx, p, s) ||
		    addstr(mem_ctx, p, "}\n")) {
			return -1;
		}
		return 0;
	}

	for (i=0;i<array_len;i++) {
		const char *p2 = ptr;
		unsigned size = pinfo->size;

		/* generic pointer dereference */
		if (pinfo->ptr_count) {
			p2 = *(const char **)ptr;
			size = sizeof(void *);
		}
		
		if ((count || pinfo->ptr_count) && 
		    !(pinfo->flags & FLAG_ALWAYS) &&
		    all_zero(ptr, size)) {
			ptr += size;
			continue;
		}
		if (count == 0) {
			if (addtabbed(mem_ctx, p, pinfo->name, indent) ||
			    addshort(mem_ctx, p, " = %u:", i)) {
				return -1;
			}
		} else {
			if (addshort(mem_ctx, p, ", %u:", i) != 0) {
				return -1;
			}
		}
		if (gen_dump_one(mem_ctx, p, pinfo, p2, indent) != 0) {
			return -1;
		}
		ptr += size;
		count++;
	}
	if (count) {
		return addstr(mem_ctx, p, "\n");
	}
	return 0;
}

/* find a variable by name in a loaded structure and return its value
   as an integer. Used to support dynamic arrays */
static int find_var(const struct parse_struct *pinfo,
		    const char *data,
		    const char *var)
{
	int i;
	const char *ptr;

	/* this allows for constant lengths */
	if (isdigit(*var)) {
		return atoi(var);
	}

	for (i=0;pinfo[i].name;i++) {
		if (strcmp(pinfo[i].name, var) == 0) break;
	}
	if (!pinfo[i].name) return -1;

	ptr = data + pinfo[i].offset;

	switch (pinfo[i].size) {
	case sizeof(int):
		return *(int *)ptr;
	case sizeof(char):
		return *(char *)ptr;
	}

	return -1;
}


int gen_dump_struct(TALLOC_CTX *mem_ctx,
		    const struct parse_struct *pinfo,
		    struct parse_string *p, 
		    const char *ptr, 
		    unsigned indent)
{
	char *s = gen_dump(mem_ctx, pinfo, ptr, indent+1);
	if (!s) return -1;
	if (addstr(mem_ctx, p, "{\n") || 
	    addstr(mem_ctx, p, s) || 
	    addtabbed(mem_ctx, p, "}", indent)) {
		return -1;
	}
	return 0;
}

static int gen_dump_string(TALLOC_CTX *mem_ctx,
			   struct parse_string *p,
			   const struct parse_struct *pinfo, 
			   const char *data, 
			   unsigned indent)
{
	const char *ptr = *(char **)data;
	char *s = encode_bytes(mem_ctx, ptr, strlen(ptr));
	if (addtabbed(mem_ctx, p, pinfo->name, indent) ||
	    addstr(mem_ctx, p, " = ") ||
	    addchar(mem_ctx, p, '{') ||
	    addstr(mem_ctx, p, s) ||
	    addstr(mem_ctx, p, "}\n")) {
		return -1;
	}
	return 0;
}

/* 
   find the length of a nullterm array
*/
static int len_nullterm(const char *ptr, int size, int array_len)
{
	int len;

	if (size == 1) {
		len = strnlen(ptr, array_len);
	} else {
		for (len=0; len < array_len; len++) {
			if (all_zero(ptr+len*size, size)) break;
		}
	}

	if (len == 0) len = 1;

	return len;
}


/* the generic dump routine. Scans the parse information for this structure
   and processes it recursively */
char *gen_dump(TALLOC_CTX *mem_ctx,
	       const struct parse_struct *pinfo, 
	       const char *data, 
	       unsigned indent)
{
	struct parse_string p;
	int i;
	
	p.length = 0;
	p.allocated = 0;
	p.s = NULL;

	if (addstr(mem_ctx, &p, "") != 0) {
		return NULL;
	}
	
	for (i=0;pinfo[i].name;i++) {
		const char *ptr = data + pinfo[i].offset;
		unsigned size = pinfo[i].size;

		if (pinfo[i].ptr_count) {
			size = sizeof(void *);
		}

		/* special handling for array types */
		if (pinfo[i].array_len) {
			unsigned len = pinfo[i].array_len;
			if (pinfo[i].flags & FLAG_NULLTERM) {
				len = len_nullterm(ptr, size, len);
			}
			if (gen_dump_array(mem_ctx, &p, &pinfo[i], ptr, 
					   len, indent)) {
				goto failed;
			}
			continue;
		}

		/* and dynamically sized arrays */
		if (pinfo[i].dynamic_len) {
			int len = find_var(pinfo, data, pinfo[i].dynamic_len);
			struct parse_struct p2 = pinfo[i];
			if (len < 0) {
				goto failed;
			}
			if (len > 0) {
				if (pinfo[i].flags & FLAG_NULLTERM) {
					len = len_nullterm(*(char **)ptr, 
							   pinfo[i].size, len);
				}
				p2.ptr_count--;
				p2.dynamic_len = NULL;
				if (gen_dump_array(mem_ctx, &p, &p2,
						   *(char **)ptr, 
						   len, indent) != 0) {
					goto failed;
				}
			}
			continue;
		}

		/* don't dump zero elements */
		if (!(pinfo[i].flags & FLAG_ALWAYS) && all_zero(ptr, size)) continue;

		/* assume char* is a null terminated string */
		if (pinfo[i].size == 1 && pinfo[i].ptr_count == 1 &&
		    pinfo[i].dump_fn == gen_dump_char) {
			if (gen_dump_string(mem_ctx, &p, &pinfo[i], ptr, indent) != 0) {
				goto failed;
			}
			continue;
		}

		/* generic pointer dereference */
		if (pinfo[i].ptr_count) {
			ptr = *(const char **)ptr;
		}

		if (addtabbed(mem_ctx, &p, pinfo[i].name, indent) ||
		    addstr(mem_ctx, &p, " = ") ||
		    gen_dump_one(mem_ctx, &p, &pinfo[i], ptr, indent) ||
		    addstr(mem_ctx, &p, "\n")) {
			goto failed;
		}
	}
	return p.s;

failed:
	return NULL;
}

/* search for a character in a string, skipping over sections within
   matching braces */
static char *match_braces(char *s, char c)
{
	int depth = 0;
	while (*s) {
		switch (*s) {
		case '}':
			depth--;
			break;
		case '{':
			depth++;
			break;
		}
		if (depth == 0 && *s == c) {
			return s;
		}
		s++;
	}
	return s;
}

/* parse routine for enumerated types */
int gen_parse_enum(TALLOC_CTX *mem_ctx,
		   const struct enum_struct *einfo, 
		   char *ptr, 
		   const char *str)
{
	unsigned v;
	int i;

	if (isdigit(*str)) {
		if (sscanf(str, "%u", &v) != 1) {
			errno = EINVAL;
			return -1;
		}
		*(unsigned *)ptr = v;
		return 0;
	}

	for (i=0;einfo[i].name;i++) {
		if (strcmp(einfo[i].name, str) == 0) {
			*(unsigned *)ptr = einfo[i].value;
			return 0;
		}
	}

	/* unknown enum value?? */
	return -1;
}


/* parse all base types */
static int gen_parse_base(TALLOC_CTX *mem_ctx,
			  const struct parse_struct *pinfo, 
			  char *ptr, 
			  const char *str)
{
	if (pinfo->parse_fn == gen_parse_char && pinfo->ptr_count==1) {
		unsigned len;
		char *s = decode_bytes(mem_ctx, str, &len);
		if (!s) return -1;
		*(char **)ptr = s;
		return 0;
	}

	if (pinfo->ptr_count) {
		unsigned size = pinfo->ptr_count>1?sizeof(void *):pinfo->size;
		struct parse_struct p2 = *pinfo;
		*(void **)ptr = talloc(mem_ctx, size);
		if (! *(void **)ptr) {
			return -1;
		}
		memset(*(void **)ptr, 0, size);
		ptr = *(char **)ptr;
		p2.ptr_count--;
		return gen_parse_base(mem_ctx, &p2, ptr, str);
	}

	return pinfo->parse_fn(mem_ctx, ptr, str);
}

/* parse a generic array */
static int gen_parse_array(TALLOC_CTX *mem_ctx,
			   const struct parse_struct *pinfo, 
			   char *ptr, 
			   const char *str,
			   int array_len)
{
	char *p, *p2;
	unsigned size = pinfo->size;

	/* special handling of fixed length strings */
	if (array_len != 0 && 
	    pinfo->ptr_count == 0 &&
	    pinfo->dump_fn == gen_dump_char) {
		unsigned len = 0;
		char *s = decode_bytes(mem_ctx, str, &len);
		if (!s || (len > array_len)) return -1;
		memset(ptr, 0, array_len);
		memcpy(ptr, s, len);
		return 0;
	}

	if (pinfo->ptr_count) {
		size = sizeof(void *);
	}

	while (*str) {
		unsigned idx;
		int done;

		idx = atoi(str);
		p = strchr(str,':');
		if (!p) break;
		p++;
		p2 = match_braces(p, ',');
		done = (*p2 != ',');
		*p2 = 0;

		if (*p == '{') {
			p++;
			p[strlen(p)-1] = 0;
		}

		if (gen_parse_base(mem_ctx, pinfo, ptr + idx*size, p) != 0) {
			return -1;
		}

		if (done) break;
		str = p2+1;
	}

	return 0;
}

/* parse one element, hanlding dynamic and static arrays */
static int gen_parse_one(TALLOC_CTX *mem_ctx,
			 const struct parse_struct *pinfo, 
			 const char *name, 
			 char *data, 
			 const char *str)
{
	int i;
	for (i=0;pinfo[i].name;i++) {
		if (strcmp(pinfo[i].name, name) == 0) {
			break;
		}
	}
	if (pinfo[i].name == NULL) {
		return 0;
	}

	if (pinfo[i].array_len) {
		return gen_parse_array(mem_ctx, &pinfo[i],
				       data+pinfo[i].offset, 
				       str, pinfo[i].array_len);
	}

	if (pinfo[i].dynamic_len) {
		int len = find_var(pinfo, data, pinfo[i].dynamic_len);
		if (len < 0) {
			errno = EINVAL;
			return -1;
		}
		if (len > 0) {
			struct parse_struct p2 = pinfo[i];
			char *ptr;
			unsigned size = pinfo[i].ptr_count>1?sizeof(void*):pinfo[i].size;
			ptr = talloc(mem_ctx, len*size);
			if (!ptr) {
				errno = ENOMEM;
				return -1;
			}
			memset(ptr, 0, len*size);
			*((char **)(data + pinfo[i].offset)) = ptr;
			p2.ptr_count--;
			p2.dynamic_len = NULL;
			return gen_parse_array(mem_ctx, &p2, ptr, str, len);
		}
		return 0;
	}

	return gen_parse_base(mem_ctx, &pinfo[i], data + pinfo[i].offset, str);
}

int gen_parse_struct(TALLOC_CTX * mem_ctx, const struct parse_struct *pinfo, char *ptr, const char *str)
{
	return gen_parse(mem_ctx, pinfo, ptr, str);
}

/* the main parse routine */
int gen_parse(TALLOC_CTX *mem_ctx, const struct parse_struct *pinfo, char *data, const char *s)
{
	char *str, *s0;
	
	s0 = talloc_strdup(mem_ctx, s);
	str = s0;

	while (*str) {
		char *p;
		char *name;
		char *value;

		/* skip leading whitespace */
		while (isspace(*str)) str++;

		p = strchr(str, '=');
		if (!p) break;
		value = p+1;
		while (p > str && isspace(*(p-1))) {
			p--;
		}

		*p = 0;
		name = str;

		while (isspace(*value)) value++;

		if (*value == '{') {
			str = match_braces(value, '}');
			value++;
		} else {
			str = match_braces(value, '\n');
		}

		*str++ = 0;
		
		if (gen_parse_one(mem_ctx, pinfo, name, data, value) != 0) {
			return -1;
		}
	}

	return 0;
}



/* for convenience supply some standard dumpers and parsers here */

int gen_parse_char(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	*(unsigned char *)ptr = atoi(str);
	return 0;
}

int gen_parse_int(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	*(int *)ptr = atoi(str);
	return 0;
}

int gen_parse_unsigned(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	*(unsigned *)ptr = strtoul(str, NULL, 10);
	return 0;
}

int gen_parse_time_t(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	*(time_t *)ptr = strtoul(str, NULL, 10);
	return 0;
}

int gen_parse_double(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	*(double *)ptr = atof(str);
	return 0;
}

int gen_parse_float(TALLOC_CTX *mem_ctx, char *ptr, const char *str)
{
	*(float *)ptr = atof(str);
	return 0;
}

int gen_dump_char(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return addshort(mem_ctx, p, "%u", *(unsigned char *)(ptr));
}

int gen_dump_int(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return addshort(mem_ctx, p, "%d", *(int *)(ptr));
}

int gen_dump_unsigned(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return addshort(mem_ctx, p, "%u", *(unsigned *)(ptr));
}

int gen_dump_time_t(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return addshort(mem_ctx, p, "%u", *(time_t *)(ptr));
}

int gen_dump_double(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return addshort(mem_ctx, p, "%lg", *(double *)(ptr));
}

int gen_dump_float(TALLOC_CTX *mem_ctx, struct parse_string *p, const char *ptr, unsigned indent)
{
	return addshort(mem_ctx, p, "%g", *(float *)(ptr));
}
