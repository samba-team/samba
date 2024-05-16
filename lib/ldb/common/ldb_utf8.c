/*
   ldb database library

   Copyright (C) Andrew Tridgell  2004

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
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

#include "ldb_private.h"
#include "system/locale.h"

/*
 * Set functions for comparing and case-folding case-insensitive ldb val
 * strings.
 */
void ldb_set_utf8_functions(struct ldb_context *ldb,
			    void *context,
			    char *(*casefold)(void *, void *, const char *, size_t),
			    int (*casecmp)(void *ctx,
					   const struct ldb_val *v1,
					   const struct ldb_val *v2))
{
	if (context) {
		ldb->utf8_fns.context = context;
	}
	if (casefold) {
		ldb->utf8_fns.casefold = casefold;
	}
	if (casecmp) {
		ldb->utf8_fns.casecmp = casecmp;
	}
}

/*
  this allow the user to pass in a caseless comparison
  function to handle utf8 caseless comparisons
 */
void ldb_set_utf8_fns(struct ldb_context *ldb,
		      void *context,
		      char *(*casefold)(void *, void *, const char *, size_t))
{
	ldb_set_utf8_functions(ldb, context, casefold, NULL);
}


/*
  a simple case folding function
  NOTE: does not handle UTF8
*/
char *ldb_casefold_default(void *context, TALLOC_CTX *mem_ctx, const char *s, size_t n)
{
	size_t i;
	char *ret = talloc_strndup(mem_ctx, s, n);
	if (!s) {
		errno = ENOMEM;
		return NULL;
	}
	for (i=0;ret[i];i++) {
		ret[i] = ldb_ascii_toupper(ret[i]);
	}
	return ret;
}


/*
 * The default comparison fold function only knows ASCII. Multiple
 * spaces (0x20) are collapsed into one, and [a-z] map to [A-Z]. All
 * other bytes are compared without casefolding.
 *
 * Note that as well as not handling UTF-8, this function does not exactly
 * implement RFC 4518 (2.6.1. Insignificant Space Handling and Appendix B).
 */

int ldb_comparison_fold_ascii(void *ignored,
			      const struct ldb_val *v1,
			      const struct ldb_val *v2)
{
	const uint8_t *s1 = v1->data;
	const uint8_t *s2 = v2->data;
	size_t n1 = v1->length, n2 = v2->length;

	while (n1 && *s1 == ' ') { s1++; n1--; };
	while (n2 && *s2 == ' ') { s2++; n2--; };

	while (n1 && n2 && *s1 && *s2) {
		if (ldb_ascii_toupper(*s1) != ldb_ascii_toupper(*s2)) {
			break;
		}
		if (*s1 == ' ') {
			while (n1 > 1 && s1[0] == s1[1]) { s1++; n1--; }
			while (n2 > 1 && s2[0] == s2[1]) { s2++; n2--; }
		}
		s1++; s2++;
		n1--; n2--;
	}

	/* check for trailing spaces only if the other pointers has
	 * reached the end of the strings otherwise we can
	 * mistakenly match.  ex. "domain users" <->
	 * "domainUpdates"
	 */
	if (n1 && *s1 == ' ' && (!n2 || !*s2)) {
		while (n1 && *s1 == ' ') { s1++; n1--; }
	}
	if (n2 && *s2 == ' ' && (!n1 || !*s1)) {
		while (n2 && *s2 == ' ') { s2++; n2--; }
	}
	if (n1 == 0 && n2 != 0) {
		return *s2 ? -1 : 0;
	}
	if (n2 == 0 && n1 != 0) {
		return *s1 ? 1 : 0;
	}
	if (n1 == 0 && n2 == 0) {
		return 0;
	}
	return NUMERIC_CMP(*s1, *s2);
}

void ldb_set_utf8_default(struct ldb_context *ldb)
{
	ldb_set_utf8_functions(ldb, NULL,
			  ldb_casefold_default,
			  ldb_comparison_fold_ascii);
}

char *ldb_casefold(struct ldb_context *ldb, TALLOC_CTX *mem_ctx, const char *s, size_t n)
{
	return ldb->utf8_fns.casefold(ldb->utf8_fns.context, mem_ctx, s, n);
}

/*
  check the attribute name is valid according to rfc2251
  returns 1 if the name is ok
 */

int ldb_valid_attr_name(const char *s)
{
	size_t i;

	if (!s || !s[0])
		return 0;

	/* handle special ldb_tdb wildcard */
	if (strcmp(s, "*") == 0) return 1;

	for (i = 0; s[i]; i++) {
		if (! isascii(s[i])) {
			return 0;
		}
		if (i == 0) { /* first char must be an alpha (or our special '@' identifier) */
			if (! (isalpha(s[i]) || (s[i] == '@'))) {
				return 0;
			}
		} else {
			if (! (isalnum(s[i]) || (s[i] == '-'))) {
				return 0;
			}
		}
	}
	return 1;
}

char *ldb_attr_casefold(TALLOC_CTX *mem_ctx, const char *s)
{
	size_t i;
	char *ret = talloc_strdup(mem_ctx, s);
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}
	for (i = 0; ret[i]; i++) {
		ret[i] = ldb_ascii_toupper(ret[i]);
	}
	return ret;
}

/*
  we accept either 'dn' or 'distinguishedName' for a distinguishedName
*/
int ldb_attr_dn(const char *attr)
{
	if (ldb_attr_cmp(attr, "dn") == 0 ||
	    ldb_attr_cmp(attr, "distinguishedName") == 0) {
		return 0;
	}
	return -1;
}

_PRIVATE_ char ldb_ascii_toupper(char c) {
	/*
	 * We are aiming for a 1970s C-locale toupper(), when all letters
	 * were 7-bit and behaved with true American spirit.
	 *
	 * For example, we don't want the "i" in "<guid=" to be upper-cased to
	 * "İ" as would happen in some locales, or we won't be able to parse
	 * that properly. This is unfortunate for cases where we are dealing
	 * with real text; a search for the name "Ali" would need to be
	 * written "Alİ" to match.
	 */
	return ('a' <= c && c <= 'z') ? c ^ 0x20 : c;
}
