/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004

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
 *  Component: ldb utf8 handling
 *
 *  Description: case folding and case comparison for UTF8 strings
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include <ctype.h>

/*
  TODO:
  a simple case folding function - will be replaced by a UTF8 aware function later
*/
char *ldb_casefold(void *mem_ctx, const char *s)
{
	int i;
	char *ret = talloc_strdup(mem_ctx, s);
	if (!s) {
		errno = ENOMEM;
		return NULL;
	}
	for (i=0;ret[i];i++) {
		ret[i] = toupper(ret[i]);
	}
	return ret;
}

/*
  a caseless compare, optimised for 7 bit
  TODO: doesn't yet handle UTF8
*/
static int ldb_caseless_cmp(const char *s1, const char *s2)
{
	int i;
	for (i=0;s1[i] != 0;i++) {
		int c1 = toupper(s1[i]), c2 = toupper(s2[i]);
		if (c1 != c2) {
			return c1 - c2;
		}
	}
	return s2[i];
}

/*
  compare two basedn fields
  return 0 for match
*/
int ldb_dn_cmp(const char *dn1, const char *dn2)
{
	return ldb_caseless_cmp(dn1, dn2);
}

/*
  compare two attributes
  return 0 for match
*/
int ldb_attr_cmp(const char *dn1, const char *dn2)
{
	return ldb_caseless_cmp(dn1, dn2);
}


/*
  casefold a dn. We need to uppercase the attribute names, and the 
  attribute values of case insensitive attributes. We also need to remove
  extraneous spaces between elements
*/
char *ldb_dn_fold(void * mem_ctx,
                  const char * dn,
                  void * user_data,
                  int (* case_fold_attr_fn)(void * user_data, char * attr))
{
	const char *dn_orig = dn;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	char *ret;
	size_t len;

	ret = talloc_strdup(tmp_ctx, "");
	if (ret == NULL) goto failed;

	while ((len = strcspn(dn, ",")) > 0) {
		char *p = strchr(dn, '=');
		char *attr, *value;
		int case_fold_required;

		if (p == NULL || (p-dn) > len) goto failed;

		attr = talloc_strndup(tmp_ctx, dn, p-dn);
		if (attr == NULL) goto failed;

		/* trim spaces from the attribute name */
		while (' ' == *attr) attr++;
		while (' ' == attr[strlen(attr)-1]) {
			attr[strlen(attr)-1] = 0;
		}
		if (*attr == 0) goto failed;

		value = talloc_strndup(tmp_ctx, p+1, len-(p+1-dn));
		if (value == NULL) goto failed;

		/* trim spaces from the value */
		while (' ' == *value) value++;
		while (' ' == value[strlen(value)-1]) {
			value[strlen(value)-1] = 0;
		}
		if (*value == 0) goto failed;

		case_fold_required = case_fold_attr_fn(user_data, attr);

		attr = ldb_casefold(tmp_ctx, attr);
		if (attr == NULL) goto failed;
		talloc_steal(tmp_ctx, attr);

		if (case_fold_required) {
			value = ldb_casefold(tmp_ctx, value);
			if (value == NULL) goto failed;
			talloc_steal(tmp_ctx, value);
		}		

		if (dn[len] == ',') {
			ret = talloc_asprintf_append(ret, "%s=%s,", attr, value);
		} else {
			ret = talloc_asprintf_append(ret, "%s=%s", attr, value);
		}
		if (ret == NULL) goto failed;

		dn += len;
		if (*dn == ',') dn++;
	}

	talloc_steal(mem_ctx, ret);
	talloc_free(tmp_ctx);
	return ret;

failed:
	talloc_free(tmp_ctx);
	return ldb_casefold(mem_ctx, dn_orig);
}

