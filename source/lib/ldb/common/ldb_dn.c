/* 
   ldb database library

   Copyright (C) Simo Sorce 2004

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
#include "ldb/include/ldb_dn.h"


#define LDB_DN_NULL_RETURN(x) do { if (!x) return NULL; } while(0) 

static char *escape_string(void *mem_ctx, const char *src)
{
	const char *p, *s;
	char *d, *dst;

	LDB_DN_NULL_RETURN(src);

	/* allocate destination string, it will be at most 3 times the source */
	dst = d = talloc_array(mem_ctx, char, strlen(src) * 3 + 1);
	LDB_DN_NULL_RETURN(dst);

	p = s = src;

	while (p) {
		p += strcspn(p, ",=\n+<>#;\\\"");
		if (*p == '\0') /* no special s found, all ok */
			break;

		if (*p) { /* copy part of the string and escape */
			memcpy(d, s, p - s);
			d += (p - s);
			*d++ = '\\';
			*d++ = *p++;
			s = p;
		}
	}

	/* copy the last part (with zero) and return */
	memcpy(d, s, &src[strlen(src)] - s + 1);

	return dst;
}

static char *unescape_string(void *mem_ctx, const char *src)
{
	unsigned x;
	char *p, *dst, *end;

	LDB_DN_NULL_RETURN(src);

	dst = p = talloc_strdup(mem_ctx, src);
	LDB_DN_NULL_RETURN(dst);

	end = &dst[strlen(dst)];

	while (*p) {
		p += strcspn(p, ",=\n+<>#;\\\"");
		if (*p == '\0')	/* no escapes or specials found, all ok */
			return dst;

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

		/* a string with not escaped specials is invalid */	

		return NULL;
	}

	return dst;
}

static char *seek_to_separator(char *string, const char *separator)
{
	char *p;

	p = strchr(string, '=');

	LDB_DN_NULL_RETURN(p);

	p++;

	/* check if there are quotes surrounding the value */
	p += strspn(p, " \n"); /* skip white spaces after '=' */

	if (*p == '\"') {
		p++;
		while (*p != '\"') {
			p = strchr(p, '\"');
			LDB_DN_NULL_RETURN(p);

			if (*(p - 1) == '\\')
				p++;
		}
	}

	p += strcspn(p, separator);

	return p;
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

static struct ldb_dn_attribute *ldb_dn_explode_attribute(void *mem_ctx, char *raw_attribute)
{
	struct ldb_dn_attribute *at;
	char *p;

	at = talloc(mem_ctx, struct ldb_dn_attribute);
	LDB_DN_NULL_RETURN(at);

	p = strchr(raw_attribute, '=');

	LDB_DN_NULL_RETURN(p);

	*p = '\0';

	at->name = talloc_strdup(at, ldb_dn_trim_string(raw_attribute, " \n"));
	LDB_DN_NULL_RETURN(at->name);

	p++;

	p = ldb_dn_trim_string(p, " \n");

	if (*p == '\"') { /* quotes at start means there must be quotes at the end */
		if (p[strlen(p) - 1] != '\"') /* malformed value */
			return NULL;
	
		p++;
		p[strlen(p) - 1] = '\0';
		at->value = talloc_strdup(at, p);

		return at;
	}
	/* no quotes means we must unescape the string */
	at->value = unescape_string(at, p);
	LDB_DN_NULL_RETURN(at->value);

	return at;
}

static struct ldb_dn_component *explode_component(void *mem_ctx, char *raw_component)
{
	struct ldb_dn_component *dc;
	char *p;

	dc = talloc(mem_ctx, struct ldb_dn_component);
	LDB_DN_NULL_RETURN(dc);

	dc->attr_num = 0;
	dc->attributes = NULL;

	p = raw_component;

	/* get the components */
	do {
		char *t;

		/* terminate the current attribute and return pointer to the next one */
		t = seek_to_separator(p, "+");
		LDB_DN_NULL_RETURN(t);

		if (*t) { /* here there is a separator */
			*t = '\0'; /*terminate */
			t++; /* a separtor means there's another attribute that follows */
		}

		/* allocate attributes pointer */
		dc->attributes = talloc_realloc(dc, dc->attributes,
						struct ldb_dn_attribute *,
						dc->attr_num + 1);
		LDB_DN_NULL_RETURN(dc->attributes);

		/* store the exploded attirbute in the main structure */
		dc->attributes[dc->attr_num] = ldb_dn_explode_attribute(dc->attributes, p);
		LDB_DN_NULL_RETURN(dc->attributes[dc->attr_num]);

		dc->attr_num++;

		/* jump to the next attribute if any */
		p = t;

	} while(*p);

	return dc;
}

/* FIXME: currently consider a dn composed of only case insensitive attributes
	  this is not correct and need to be fixed soon */
static void ldb_dn_sort_attributes(struct ldb_dn *edn)
{
	struct ldb_dn_attribute *at0, *at1;
	int i, j, k, l;

	for (i = 0; i < edn->comp_num; i++) {
		if (edn->components[i]->attr_num > 1) {

			/* it is very unlikely that there is a multivalued RDN. In that
			   unlikely case it is very unlikely you will find more than 2
			   values. So the use of bubble sort here seem to be acceptable */
			for (j = 0; (j + 1) < edn->components[i]->attr_num; j++) {
				for (k = j; k >= 0; k--) {
					at0 = edn->components[i]->attributes[k];
					at1 = edn->components[i]->attributes[k + 1];
					l = ldb_caseless_cmp(at0->name, at1->name);
					if (l > 0) {
						/* already sorted, so no bubbles to move exit inner loop */
						break;
					}
					if (l == 0) {
						if (ldb_caseless_cmp(at0->value, at1->value) >= 0) {
							/* already sorted, so no bubbles to move exit inner loop */
							break;
						}
					}
					
					edn->components[i]->attributes[k] = at1;
					edn->components[i]->attributes[k + 1] = at0;
				}
			}
		}
	}
}

struct ldb_dn *ldb_dn_explode(void *mem_ctx, const char *dn)
{
	struct ldb_dn *edn; /* the exploded dn */
	char *pdn, *p;

	/* Allocate a structure to hold the exploded DN */
	edn = talloc(mem_ctx, struct ldb_dn);
	LDB_DN_NULL_RETURN(edn);

	/* Initially there are no components */
	edn->comp_num = 0;
	edn->components = NULL;

	pdn = p = talloc_strdup(edn, dn);
	if (!pdn)
		goto error;

	/* get the components */
	do {
		char *t;

		/* terminate the current component and return pointer to the next one */
		t = seek_to_separator(p, ",;");
		if (t == NULL)
			goto error;

		if (*t) { /* here there is a separator */
			*t = '\0'; /*terminate */
			t++; /* a separtor means there's another component that follows */
		}

		/* allocate space to hold the dn component */
		edn->components = talloc_realloc(edn, edn->components,
						 struct ldb_dn_component *,
						 edn->comp_num + 1);
		if (edn->components == NULL)
			goto error;

		/* store the exploded component in the main structure */
		edn->components[edn->comp_num] = explode_component(edn->components, p);
		if (edn->components[edn->comp_num] == NULL)
			goto error;

		edn->comp_num++;

		/* jump to the next component if any */
		p = t;

	} while(*p);

	/* sort attributes if there's any multivalued component */
	ldb_dn_sort_attributes(edn);

	talloc_free(pdn);
	return edn;

error:
	talloc_free(edn);
	return NULL;
}

char *ldb_dn_linearize(void *mem_ctx, struct ldb_dn *edn)
{
	char *dn, *format, *ename, *evalue;
	int i, j;

	dn = talloc_strdup(mem_ctx, "");
	LDB_DN_NULL_RETURN(dn);

	for (i = 0; i < edn->comp_num; i++) {
		if (i != 0) {
			dn = talloc_append_string(mem_ctx, dn, ",");
		}
		for (j = 0; j < edn->components[i]->attr_num; j++) {
			if (i != 0 && j == 0)
				format = ",%s=%s";
			else if (i == 0 && j == 0)
				format = "%s=%s";
			else
				format = "+%s=%s";

			ename = escape_string(mem_ctx, edn->components[i]->attributes[j]->name);
			LDB_DN_NULL_RETURN(ename);

			evalue = escape_string(mem_ctx, edn->components[i]->attributes[j]->value);
			LDB_DN_NULL_RETURN(evalue);

			dn = talloc_asprintf_append(dn, format, ename, evalue);
			LDB_DN_NULL_RETURN(dn);

			talloc_free(ename);
			talloc_free(evalue);
		}
	}

	return dn;
}

/* FIXME: currently consider a dn composed of only case insensitive attributes
	  this is not correct and need to be fixed soon */
int ldb_dn_compare(struct ldb_dn *edn0, struct ldb_dn *edn1)
{
	struct ldb_dn_attribute *at0, *at1;
	int i, j, k;

	/* if the number of components doesn't match they differ */
	if (edn0->comp_num != edn1->comp_num)
		return (edn1->comp_num - edn0->comp_num);

	for (i = 0; i < edn0->comp_num; i++) {

		/* if the number of attributes per component doesn't match they differ */
		if (edn0->components[i]->attr_num != edn1->components[i]->attr_num)
			return (edn1->components[i]->attr_num - edn0->components[i]->attr_num);

		for (j = 0; j < edn0->components[i]->attr_num; j++) {
			at0 = edn0->components[i]->attributes[j];
			at1 = edn1->components[i]->attributes[j];

			/* compare names */
			k = ldb_caseless_cmp(at0->name, at1->name);
			if (k)
				return k;

			/* names match, compare values */
			k = ldb_caseless_cmp(at0->value, at1->value);
			if (k)
				return k;
		}
	}
}

/*
  casefold a dn. We need to uppercase the attribute names, and the 
  attribute values of case insensitive attributes. We also need to remove
  extraneous spaces between elements
*/
struct ldb_dn *ldb_dn_casefold(void *mem_ctx, struct ldb_dn *edn, void *user_data,
				int (* case_fold_attr_fn)(void * user_data, char * attr))
{
	struct ldb_dn *cedn;
	int i, j;

	cedn = talloc(mem_ctx, struct ldb_dn);
	LDB_DN_NULL_RETURN(cedn);

	cedn->comp_num = edn->comp_num;
	cedn->components = talloc_array(cedn, struct ldb_dn_component *, edn->comp_num);
	LDB_DN_NULL_RETURN(cedn->components);

	for (i = 0; i < edn->comp_num; i++) {
		struct ldb_dn_component *dc;

		dc = talloc(cedn->components, struct ldb_dn_component);
		LDB_DN_NULL_RETURN(dc);

		dc->attr_num = edn->components[i]->attr_num;
		dc->attributes = edn->components[i]->attributes;
		LDB_DN_NULL_RETURN(dc->attributes);

		for (j = 0; j < edn->components[i]->attr_num; j++) {
			struct ldb_dn_attribute *at;

			at = talloc(dc->attributes, struct ldb_dn_attribute);
			LDB_DN_NULL_RETURN(at);

			at->name = ldb_casefold(at, edn->components[i]->attributes[j]->name);
			LDB_DN_NULL_RETURN(at->name);

			if (case_fold_attr_fn(user_data, at->name)) {
				at->value = ldb_casefold(at, edn->components[i]->attributes[j]->value);
			} else {
				at->value = talloc_strdup(at, edn->components[i]->attributes[j]->value);
			}
			LDB_DN_NULL_RETURN(at->value);

			dc->attributes[j] = at;
		}

		cedn->components[i] = dc;
	}

	return cedn;
}

