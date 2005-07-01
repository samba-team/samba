/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2005

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
  attribute handlers for well known attribute types, selected by syntax OID
  see rfc2252
*/

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include <ctype.h>

/*
  default handler that just copies a ldb_val.
*/
int ldb_handler_copy(struct ldb_context *ldb, 
		     const struct ldb_val *in, struct ldb_val *out)
{
	*out = ldb_val_dup(ldb, in);
	if (out->data == NULL) {
		ldb_oom(ldb);
		return -1;
	}
	return 0;
}

/*
  a case folding copy handler, removing leading and trailing spaces and
  multiple internal spaces
*/
static int ldb_handler_fold(struct ldb_context *ldb, 
			    const struct ldb_val *in, struct ldb_val *out)
{
	uint8_t *s1, *s2;
	out->data = talloc_size(ldb, strlen(in->data)+1);
	if (out->data == NULL) {
		ldb_oom(ldb);
		return -1;
	}
	s1 = in->data;
	s2 = out->data;
	while (*s1 == ' ') s1++;
	while (*s1) {
		*s2 = toupper(*s1);
		if (s1[0] == ' ') {
			while (s1[0] == s1[1]) s1++;
		}
		s2++; s1++;
	}
	*s2 = 0;
	out->length = strlen(out->data);
	return 0;
}


/*
  a case folding copy handler, removing leading and trailing spaces and
  multiple internal spaces, and checking for wildcard characters
*/
static int ldb_handler_fold_wildcard(struct ldb_context *ldb, 
				     const struct ldb_val *in, struct ldb_val *out)
{
	if (strchr(in->data, '*')) {
		return -1;
	}
	return ldb_handler_fold(ldb, in, out);
}

/*
  canonicalise a ldap Integer
  rfc2252 specifies it should be in decimal form
*/
static int ldb_canonicalise_Integer(struct ldb_context *ldb, 
				    const struct ldb_val *in, struct ldb_val *out)
{
	char *end;
	long long i = strtoll(in->data, &end, 0);
	if (*end != 0) {
		return -1;
	}
	out->data = talloc_asprintf(ldb, "%lld", i);
	if (out->data == NULL) {
		return -1;
	}
	out->length = strlen(out->data);
	return 0;
}

/*
  compare two Integers
*/
static int ldb_comparison_Integer(struct ldb_context *ldb, 
				  const struct ldb_val *v1, const struct ldb_val *v2)
{
	return strtoll(v1->data, NULL, 0) - strtoll(v2->data, NULL, 0);
}

/*
  compare two binary blobs
*/
int ldb_comparison_binary(struct ldb_context *ldb, 
			  const struct ldb_val *v1, const struct ldb_val *v2)
{
	if (v1->length != v2->length) {
		return v1->length - v2->length;
	}
	return memcmp(v1->data, v2->data, v1->length);
}

/*
  compare two case insensitive strings, ignoring multiple whitespace
  and leading and trailing whitespace
  see rfc2252 section 8.1
*/
static int ldb_comparison_fold(struct ldb_context *ldb, 
			       const struct ldb_val *v1, const struct ldb_val *v2)
{
	const char *s1=v1->data, *s2=v2->data;
	while (*s1 == ' ') s1++;
	while (*s2 == ' ') s2++;
	/* TODO: make utf8 safe, possibly with helper function from application */
	while (*s1 && *s2) {
		if (toupper(*s1) != toupper(*s2)) break;
		if (*s1 == ' ') {
			while (s1[0] == s1[1]) s1++;
			while (s2[0] == s2[1]) s2++;
		}
		s1++; s2++;
	}
	while (*s1 == ' ') s1++;
	while (*s2 == ' ') s2++;
	return (int)(*s1) - (int)(*s2);
}

/*
  compare two case insensitive strings, ignoring multiple whitespace
  and leading and trailing whitespace
  see rfc2252 section 8.1
  handles wildcards
*/
static int ldb_comparison_fold_wildcard(struct ldb_context *ldb, 
					const struct ldb_val *v1, 
					const struct ldb_val *v2)
{
	const char *s1=v1->data, *s2=v2->data;
	while (*s1 == ' ') s1++;
	while (*s2 == ' ') s2++;
	/* TODO: make utf8 safe, possibly with helper function from application */
	while (*s1 && *s2) {
		if (s1[0] == '*' && s1[1] == 0) {
			return 0;
		}
		if (toupper(*s1) != toupper(*s2)) break;
		if (*s1 == ' ') {
			while (s1[0] == s1[1]) s1++;
			while (s2[0] == s2[1]) s2++;
		}
		s1++; s2++;
	}
	while (*s1 == ' ') s1++;
	while (*s2 == ' ') s2++;
	return (int)(*s1) - (int)(*s2);
}


/*
  canonicalise a attribute in DN format
*/
static int ldb_canonicalise_dn(struct ldb_context *ldb, 
			       const struct ldb_val *in, struct ldb_val *out)
{
	struct ldb_dn *dn2=NULL, *dn1 = ldb_dn_explode(ldb, in->data);
	out->data = NULL;
	if (dn1 == NULL) {
		goto failed;
	}
	dn2 = ldb_dn_casefold(ldb, dn1);
	if (dn2 == NULL) goto failed;

	out->data = ldb_dn_linearize(ldb, dn2);
	if (out->data == NULL) goto failed;

	talloc_free(dn1);
	talloc_free(dn2);
	return 0;

failed:
	talloc_free(dn1);
	talloc_free(dn2);
	return -1;
}

/*
  compare two dns
*/
static int ldb_comparison_dn(struct ldb_context *ldb, 
			     const struct ldb_val *v1, const struct ldb_val *v2)
{
	struct ldb_val cv1, cv2;
	int ret;
	if (ldb_canonicalise_dn(ldb, v1, &cv1) != 0 ||
	    ldb_canonicalise_dn(ldb, v2, &cv2) != 0) {
		goto failed;
	}
	ret = strcmp(cv1.data, cv2.data);
	talloc_free(cv1.data);
	talloc_free(cv2.data);
	return ret;
failed:
	talloc_free(cv1.data);
	talloc_free(cv2.data);
	return -1;
}

/*
  compare two objectclasses, looking at subclasses
*/
static int ldb_comparison_objectclass(struct ldb_context *ldb, 
				      const struct ldb_val *v1, const struct ldb_val *v2)
{
	int ret, i;
	const char **subclasses;
	ret = ldb_comparison_fold(ldb, v1, v2);
	if (ret == 0) {
		return 0;
	}
	fprintf(stderr, "looing for %s %s\n", v1->data, v2->data);
	subclasses = ldb_subclass_list(ldb, v1->data);
	if (subclasses == NULL) {
		return ret;
	}
	for (i=0;subclasses[i];i++) {
		struct ldb_val vs;
		vs.data = discard_const(subclasses[i]);
		vs.length = strlen(subclasses[i]);
		if (ldb_comparison_objectclass(ldb, &vs, v2) == 0) {
			return 0;
		}
	}
	return ret;
}

/*
  table of standard attribute handlers
*/
static const struct ldb_attrib_handler ldb_standard_attribs[] = {
	{ 
		.attr            = LDB_SYNTAX_INTEGER,
		.flags           = 0,
		.ldif_read_fn    = ldb_handler_copy,
		.ldif_write_fn   = ldb_handler_copy,
		.canonicalise_fn = ldb_canonicalise_Integer,
		.comparison_fn   = ldb_comparison_Integer
	},
	{ 
		.attr            = LDB_SYNTAX_OCTET_STRING,
		.flags           = 0,
		.ldif_read_fn    = ldb_handler_copy,
		.ldif_write_fn   = ldb_handler_copy,
		.canonicalise_fn = ldb_handler_copy,
		.comparison_fn   = ldb_comparison_binary
	},
	{ 
		.attr            = LDB_SYNTAX_DIRECTORY_STRING,
		.flags           = 0,
		.ldif_read_fn    = ldb_handler_copy,
		.ldif_write_fn   = ldb_handler_copy,
		.canonicalise_fn = ldb_handler_fold,
		.comparison_fn   = ldb_comparison_fold
	},
	{ 
		.attr            = LDB_SYNTAX_WILDCARD,
		.flags           = LDB_ATTR_FLAG_WILDCARD,
		.ldif_read_fn    = ldb_handler_copy,
		.ldif_write_fn   = ldb_handler_copy,
		.canonicalise_fn = ldb_handler_fold_wildcard,
		.comparison_fn   = ldb_comparison_fold_wildcard
	},
	{ 
		.attr            = LDB_SYNTAX_DN,
		.flags           = 0,
		.ldif_read_fn    = ldb_handler_copy,
		.ldif_write_fn   = ldb_handler_copy,
		.canonicalise_fn = ldb_canonicalise_dn,
		.comparison_fn   = ldb_comparison_dn
	},
	{ 
		.attr            = LDB_SYNTAX_OBJECTCLASS,
		.flags           = 0,
		.ldif_read_fn    = ldb_handler_copy,
		.ldif_write_fn   = ldb_handler_copy,
		.canonicalise_fn = ldb_handler_fold,
		.comparison_fn   = ldb_comparison_objectclass
	}
};


/*
  return the attribute handlers for a given syntax name
*/
const struct ldb_attrib_handler *ldb_attrib_handler_syntax(struct ldb_context *ldb,
							   const char *syntax)
{
	int i;
	unsigned num_handlers = sizeof(ldb_standard_attribs)/sizeof(ldb_standard_attribs[0]);
	/* TODO: should be replaced with a binary search */
	for (i=0;i<num_handlers;i++) {
		if (strcmp(ldb_standard_attribs[i].attr, syntax) == 0) {
			return &ldb_standard_attribs[i];
		}
	}
	return NULL;
}

