/* 
   ldb database library

   Copyright (C) Simo Sorce 2005

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldb dn explode and utility functions
 *
 *  Description: - explode a dn into it's own basic elements
 *                 and put them in a structure
 *               - manipulate ldb_dn structures
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"


#define LDB_DN_NULL_FAILED(x) if (!(x)) goto failed

static char *ldb_dn_escape_value(void *mem_ctx, struct ldb_val value)
{
	const char *p, *s, *src;
	char *d, *dst;
	int len;

	if (!value.length)
		return NULL;

	p = s = src = (const char *)value.data;
	len = value.length;

	/* allocate destination string, it will be at most 3 times the source */
	dst = d = talloc_array(mem_ctx, char, len * 3 + 1);
	LDB_DN_NULL_FAILED(dst);

	while (p - src < len) {

		p += strcspn(p, ",=\n+<>#;\\\"");

		if (p - src == len) /* found no escapable chars */
			break;

		memcpy(d, s, p - s); /* copy the part of the string before the stop */
		d += (p - s); /* move to current position */

		if (*p) { /* it is a normal escapable character */
			*d++ = '\\';
			*d++ = *p++;
		} else { /* we have a zero byte in the string */
			strncpy(d, "\00", 3); /* escape the zero */
			d = d + 3;
			p++; /* skip the zero */
		}
		s = p; /* move forward */
	}

	/* copy the last part (with zero) and return */
	memcpy(d, s, &src[len] - s + 1);

	return dst;

failed:
	talloc_free(dst);
	return NULL;
}

static struct ldb_val ldb_dn_unescape_value(void *mem_ctx, const char *src)
{
	struct ldb_val value;
	unsigned x;
	char *p, *dst = NULL, *end;

	value.length = 0;

	LDB_DN_NULL_FAILED(src);

	dst = p = talloc_memdup(mem_ctx, src, strlen(src) + 1);
	LDB_DN_NULL_FAILED(dst);

	end = &dst[strlen(dst)];

	while (*p) {
		p += strcspn(p, ",=\n+<>#;\\\"");

		if (*p == '\\') {
			if (strchr(",=\n+<>#;\\\"", p[1])) {
				memmove(p, p + 1, end - (p + 1) + 1);
				end--;
				p++;
				continue;
			}

			if (sscanf(p + 1, "%02x", &x) == 1) {
				*p = (unsigned char)x;
				memmove(p + 1, p + 3, end - (p + 3) + 1);
				end -= 2;
				p++;
				continue;
			}
		}

		/* a string with not escaped specials is invalid (tested) */
		if (*p != '\0') {
			goto failed;
		}
	}

	value.length = end - dst;
	value.data = dst;
	return value;

failed:
	talloc_free(dst);
	return value;
}

/* check if the string contains quotes
 * skips leading and trailing spaces
 * - returns 0 if no quotes found
 * - returns 1 if quotes are found and put their position
 *   in *quote_start and *quote_end parameters
 * - return -1 if there are open quotes
 */

static int get_quotes_position(const char *source, int *quote_start, int *quote_end)
{
	const char *p;

	p = source;

	/* check if there are quotes surrounding the value */
	p += strspn(p, " \n"); /* skip white spaces */

	if (*p == '\"') {
		*quote_start = p - source;

		p++;
		while (*p != '\"') {
			p = strchr(p, '\"');
			LDB_DN_NULL_FAILED(p);

			if (*(p - 1) == '\\')
				p++;
		}

		*quote_end = p - source;
		return 1;
	}

	return 0;

failed:
	return -1;
}

static char *seek_to_separator(char *string, const char *separators)
{
	char *p;
	int ret, qs, qe;

	p = strchr(string, '=');
	LDB_DN_NULL_FAILED(p);

	p++;

	/* check if there are quotes surrounding the value */

	ret = get_quotes_position(p, &qs, &qe);
	if (ret == -1)
		return NULL;

	if (ret == 1) { /* quotes found */

		p += qe; /* positioning after quotes */
		p += strspn(p, " \n"); /* skip white spaces after the quote */

		if (strcspn(p, separators) != 0) /* if there are characters between quotes */
			return NULL;	    /* and separators, the dn is invalid */

		return p; /* return on the separator */
	}

	/* no quotes found seek to separators */
	ret = strcspn(p, separators);
	if (ret == 0) /* no separators ?! bail out */
		return NULL;

	return p + ret;

failed:
	return NULL;
}

static char *ldb_dn_trim_string(char *string, const char *edge)
{
	char *s, *p;

	/* seek out edge from start of string */
	s = string + strspn(string, edge);

	/* backwards skip from end of string */
	p = &s[strlen(s) - 1];
	while (p > s && strchr(edge, *p)) {
		*p = '\0';
		p--;
	}

	return s;
}

/* we choosed to not support multpile valued components */
static struct ldb_dn_component ldb_dn_explode_component(void *mem_ctx, char *raw_component)
{
	struct ldb_dn_component dc;
	char *p;
	int ret, qs, qe;

	/* find attribute type/value separator */
	p = strchr(raw_component, '=');
	LDB_DN_NULL_FAILED(p);

	*p++ = '\0'; /* terminate name and point to value */

	/* copy and trim name in the component */
	dc.name = talloc_strdup(mem_ctx, ldb_dn_trim_string(raw_component, " \n"));
	if (!dc.name)
		return dc;

	ret = get_quotes_position(p, &qs, &qe);

	switch (ret) {
	case 0: /* no quotes trim the string */
		p = ldb_dn_trim_string(p, " \n");
		dc.value = ldb_dn_unescape_value(mem_ctx, p);
		break;

	case 1: /* quotes found get the unquoted string */
		p[qe] = '\0';
		p = p + qs + 1;
		dc.value.length = strlen(p);
		dc.value.data = talloc_memdup(mem_ctx, p, dc.value.length + 1);
		break;

	default: /* mismatched quotes ot other error, bail out */
		goto failed;
	}

	if (dc.value.length == 0) {
		goto failed;
	}

	return dc;

failed:
	talloc_free(dc.name);
	dc.name = NULL;
	return dc;
}

struct ldb_dn *ldb_dn_explode(void *mem_ctx, const char *dn)
{
	struct ldb_dn *edn; /* the exploded dn */
	char *pdn, *p;

	pdn = NULL;

	/* Allocate a structure to hold the exploded DN */
	edn = talloc(mem_ctx, struct ldb_dn);
	LDB_DN_NULL_FAILED(edn);

	/* Initially there are no components */
	edn->comp_num = 0;
	edn->components = NULL;

	pdn = p = talloc_strdup(edn, dn);
	LDB_DN_NULL_FAILED(pdn);

	/* get the components */
	do {
		char *t;

		/* terminate the current component and return pointer to the next one */
		t = seek_to_separator(p, ",;");
		LDB_DN_NULL_FAILED(t);

		if (*t) { /* here there is a separator */
			*t = '\0'; /*terminate */
			t++; /* a separtor means another component follows */
		}

		/* allocate space to hold the dn component */
		edn->components = talloc_realloc(edn, edn->components,
						 struct ldb_dn_component,
						 edn->comp_num + 1);
		if (edn->components == NULL)
			goto failed;

		/* store the exploded component in the main structure */
		edn->components[edn->comp_num] = ldb_dn_explode_component(edn, p);
		LDB_DN_NULL_FAILED(edn->components[edn->comp_num].name);

		edn->comp_num++;

		/* jump to the next component if any */
		p = t;

	} while(*p);

	talloc_free(pdn);
	return edn;

failed:
	talloc_free(pdn);
	talloc_free(edn);
	return NULL;
}

char *ldb_dn_linearize(void *mem_ctx, const struct ldb_dn *edn)
{
	char *dn, *value;
	const char *format = "%s=%s";
	int i;

	dn = talloc_strdup(mem_ctx, "");
	LDB_DN_NULL_FAILED(dn);

	for (i = 0; i < edn->comp_num; i++) {

		if (i != 0) {
			format = ",%s=%s";
		}

		value = ldb_dn_escape_value(dn, edn->components[i].value);
		LDB_DN_NULL_FAILED(value);

		dn = talloc_asprintf_append(dn, format, edn->components[i].name, value);
		LDB_DN_NULL_FAILED(dn);

		talloc_free(value);
	}

	return dn;

failed:
	talloc_free(dn);
	return NULL;
}

/* compare DNs using casefolding compare functions */
int ldb_dn_compare(struct ldb_context *ldb, const struct ldb_dn *edn0, const struct ldb_dn *edn1)
{
	int i, ret;

	/* if the number of components doesn't match they differ */
	if (edn0->comp_num != edn1->comp_num)
		return (edn1->comp_num - edn0->comp_num);

	for (i = 0; i < edn0->comp_num; i++) {
		const struct ldb_attrib_handler *h;

		/* compare names (attribute names are guaranteed to be ASCII only) */
		ret = ldb_caseless_cmp(edn0->components[i].name,
				       edn1->components[i].name);
		if (ret) {
			return ret;
		}

		/* names match, compare values */
		h = ldb_attrib_handler(ldb, edn0->components[i].name);
		ret = h->comparison_fn(ldb, ldb, &(edn0->components[i].value),
						  &(edn1->components[i].value));
		if (ret) {
			return ret;
		}
	}

	return 0;
}

/*
  casefold a dn. We need to casefold the attribute names, and canonicalize 
  attribute values of case insensitive attributes.
*/
struct ldb_dn *ldb_dn_casefold(struct ldb_context *ldb, const struct ldb_dn *edn)
{
	struct ldb_dn *cedn;
	int i;

	cedn = talloc(ldb, struct ldb_dn);
	LDB_DN_NULL_FAILED(cedn);

	cedn->comp_num = edn->comp_num;
	cedn->components = talloc_array(cedn, struct ldb_dn_component, edn->comp_num);
	LDB_DN_NULL_FAILED(cedn->components);

	for (i = 0; i < edn->comp_num; i++) {
		struct ldb_dn_component dc;
		const struct ldb_attrib_handler *h;

		dc.name = ldb_casefold(cedn, edn->components[i].name);
		LDB_DN_NULL_FAILED(dc.name);

		h = ldb_attrib_handler(ldb, dc.name);
		if (h->canonicalise_fn(ldb, cedn, &(edn->components[i].value), &(dc.value)) != 0) {
			goto failed;
		}

		cedn->components[i] = dc;
	}

	return cedn;

failed:
	talloc_free(cedn);
	return NULL;
}

