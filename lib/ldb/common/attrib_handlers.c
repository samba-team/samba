/*
   ldb database library

   Copyright (C) Andrew Tridgell  2005
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006-2009

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
  attribute handlers for well known attribute types, selected by syntax OID
  see rfc2252
*/

#include "ldb_private.h"
#include "system/locale.h"
#include "ldb_handlers.h"

/*
  default handler that just copies a ldb_val.
*/
int ldb_handler_copy(struct ldb_context *ldb, void *mem_ctx,
		     const struct ldb_val *in, struct ldb_val *out)
{
	*out = ldb_val_dup(mem_ctx, in);
	if (in->length > 0 && out->data == NULL) {
		ldb_oom(ldb);
		return -1;
	}
	return 0;
}

/*
  a case folding copy handler, removing leading and trailing spaces and
  multiple internal spaces

  We exploit the fact that utf8 never uses the space octet except for
  the space itself
*/
int ldb_handler_fold(struct ldb_context *ldb, void *mem_ctx,
			    const struct ldb_val *in, struct ldb_val *out)
{
	char *s, *t, *start;
	bool in_space;

	if (!in || !out || !(in->data)) {
		return -1;
	}

	out->data = (uint8_t *)ldb_casefold(ldb, mem_ctx, (const char *)(in->data), in->length);
	if (out->data == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "ldb_handler_fold: unable to casefold string [%.*s]", (int)in->length, (const char *)in->data);
		return -1;
	}

	start = (char *)(out->data);
	in_space = true;
	t = start;
	for (s = start; *s != '\0'; s++) {
		if (*s == ' ') {
			if (in_space) {
				/*
				 * We already have one (or this is the start)
				 * and we don't want to add more
				 */
				continue;
			}
			in_space = true;
		} else {
			in_space = false;
		}
		*t = *s;
		t++;
	}

	if (in_space && t != start) {
		/* the loop will have left a single trailing space */
		t--;
	}
	*t = '\0';

	out->length = t - start;
	return 0;
}

/* length limited conversion of a ldb_val to an int64_t */
static int val_to_int64(const struct ldb_val *in, int64_t *v)
{
	char *end;
	char buf[64];

	/* make sure we don't read past the end of the data */
	if (in->length > sizeof(buf)-1) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}
	strncpy(buf, (char *)in->data, in->length);
	buf[in->length] = 0;

	*v = (int64_t) strtoll(buf, &end, 0);
	if (*end != 0) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}
	return LDB_SUCCESS;
}


/*
  canonicalise a ldap Integer
  rfc2252 specifies it should be in decimal form
*/
static int ldb_canonicalise_Integer(struct ldb_context *ldb, void *mem_ctx,
				    const struct ldb_val *in, struct ldb_val *out)
{
	int64_t i;
	int ret;

	ret = val_to_int64(in, &i);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	out->data = (uint8_t *) talloc_asprintf(mem_ctx, "%lld", (long long)i);
	if (out->data == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	out->length = strlen((char *)out->data);
	return 0;
}

/*
 * Lexicographically ordered format for a ldap Integer
 *
 * [ INT64_MIN ... -3, -2, -1 | 0 | +1, +2, +3 ... INT64_MAX ]
 *             n                o              p
 *
 * For human readability sake, we continue to format the key as a string
 * (like the canonicalize) rather than store as a fixed binary representation.
 *
 * In order to sort the integers in the correct string order, there are three
 * techniques we use:
 *
 * 1. Zero padding
 * 2. Negative integer inversion
 * 3. 1-byte prefixes: 'n' < 'o' < 'p'
 *
 * 1. To have a fixed-width representation so that 10 sorts after 2 rather than
 * after 1, we zero pad, like this 4-byte width example:
 *
 *     0001, 0002, 0010
 *
 * INT64_MAX = 2^63 - 1 = 9223372036854775807 (19 characters long)
 *
 * Meaning we need to pad to 19 characters.
 *
 * 2. This works for positive integers, but negative integers will still be
 * sorted backwards, for example:
 *
 *     -9223372036854775808 ..., -0000000000000000002, -0000000000000000001
 *          INT64_MIN                    -2                    -1
 *
 *   gets sorted based on string as:
 *
 *     -0000000000000000001, -0000000000000000002, ... -9223372036854775808
 *
 * In order to fix this, we invert the negative integer range, so that they
 * get sorted the same way as positive numbers. INT64_MIN becomes the lowest
 * possible non-negative number (zero), and -1 becomes the highest (INT64_MAX).
 *
 * The actual conversion applied to negative number 'x' is:
 *   INT64_MAX - abs(x) + 1
 * (The +1 is needed because abs(INT64_MIN) is one greater than INT64_MAX)
 *
 * 3. Finally, we now have two different numbers that map to the same key, e.g.
 * INT64_MIN maps to -0000000000000000000 and zero maps to 0000000000000000000.
 * In order to avoid confusion, we give every number a prefix representing its
 * sign: 'n' for negative numbers, 'o' for zero, and 'p' for positive. (Note
 * that '+' and '-' weren't used because they sort the wrong way).
 *
 * The result is a range of key values that look like this:
 *
 *     n0000000000000000000, ... n9223372036854775807,
 *          INT64_MIN                    -1
 *
 *     o0000000000000000000,
 *            ZERO
 *
 *     p0000000000000000001, ... p9223372036854775807
 *            +1                       INT64_MAX
 */
static int ldb_index_format_Integer(struct ldb_context *ldb,
				    void *mem_ctx,
				    const struct ldb_val *in,
				    struct ldb_val *out)
{
	int64_t i;
	int ret;
	char prefix;
	size_t len;

	ret = val_to_int64(in, &i);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (i < 0) {
		/*
		 * i is negative, so this is subtraction rather than
		 * wrap-around.
		 */
		prefix = 'n';
		i = INT64_MAX + i + 1;
	} else if (i > 0) {
		prefix = 'p';
	} else {
		prefix = 'o';
	}

	out->data = (uint8_t *) talloc_asprintf(mem_ctx, "%c%019lld", prefix, (long long)i);
	if (out->data == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	len = talloc_array_length(out->data) - 1;
	if (len != 20) {
		ldb_debug(ldb, LDB_DEBUG_ERROR,
			  __location__ ": expected index format str %s to"
			  " have length 20 but got %zu",
			  (char*)out->data, len);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	out->length = 20;
	return 0;
}

/*
  compare two Integers
*/
static int ldb_comparison_Integer(struct ldb_context *ldb, void *mem_ctx,
				  const struct ldb_val *v1, const struct ldb_val *v2)
{
	int64_t i1=0, i2=0;
	val_to_int64(v1, &i1);
	val_to_int64(v2, &i2);
	if (i1 == i2) return 0;
	return i1 > i2? 1 : -1;
}

/*
  canonicalise a ldap Boolean
  rfc2252 specifies it should be either "TRUE" or "FALSE"
*/
static int ldb_canonicalise_Boolean(struct ldb_context *ldb, void *mem_ctx,
			     const struct ldb_val *in, struct ldb_val *out)
{
	if (in->length >= 4 && strncasecmp((char *)in->data, "TRUE", in->length) == 0) {
		out->data = (uint8_t *)talloc_strdup(mem_ctx, "TRUE");
		out->length = 4;
	} else if (in->length >= 5 && strncasecmp((char *)in->data, "FALSE", in->length) == 0) {
		out->data = (uint8_t *)talloc_strdup(mem_ctx, "FALSE");
		out->length = 5;
	} else {
		return -1;
	}
	return 0;
}

/*
 * compare two Booleans.
 *
 * According to RFC4517 4.2.2, "the booleanMatch rule is an equality matching
 * rule", meaning it isn't used for ordering.
 *
 * However, it seems conceivable that Samba could be coerced into sorting on a
 * field with Boolean syntax, so we might as well have consistent behaviour in
 * that case.
 *
 * The most probable values are {"FALSE", 5} and {"TRUE", 4}. To save time we
 * compare first by length, which makes FALSE > TRUE. This is somewhat
 * contrary to convention, but is how Samba has worked forever.
 *
 * If somehow we are comparing incompletely normalised values where the length
 * is the same (for example {"false", 5} and {"TRUE\0", 5}), the length is the
 * same, and we fall back to a strncasecmp. In this case, since "FALSE" is
 * alphabetically lower, we swap the order, so that "TRUE\0" again comes
 * before "FALSE".
 *
 * ldb_canonicalise_Boolean (just above) gives us a clue as to what we might
 * expect to cope with by way of invalid values.
 */
static int ldb_comparison_Boolean(struct ldb_context *ldb, void *mem_ctx,
			   const struct ldb_val *v1, const struct ldb_val *v2)
{
	if (v1->length != v2->length) {
		return NUMERIC_CMP(v2->length, v1->length);
	}
	/* reversed, see long comment above */
	return strncasecmp((char *)v2->data, (char *)v1->data, v1->length);
}


/*
  compare two binary blobs
*/
int ldb_comparison_binary(struct ldb_context *ldb, void *mem_ctx,
			  const struct ldb_val *v1, const struct ldb_val *v2)
{
	if (v1->length != v2->length) {
		return NUMERIC_CMP(v1->length, v2->length);
	}
	return memcmp(v1->data, v2->data, v1->length);
}

/*
 * ldb_comparison_fold is a schema syntax comparison_fn for utf-8 strings that
 * collapse multiple spaces into one (e.g. "Directory String" syntax).
 *
 * The default comparison function only performs ASCII case-folding, and only
 * collapses multiple spaces, not tabs and other whitespace (contrary to
 * RFC4518). To change the comparison function (as Samba does), use
 * ldb_set_utf8_functions().
 */
int ldb_comparison_fold(struct ldb_context *ldb, void *mem_ctx,
			const struct ldb_val *v1, const struct ldb_val *v2)
{
	return ldb->utf8_fns.casecmp(ldb->utf8_fns.context, v1, v2);
}


/*
  canonicalise a attribute in DN format
*/
static int ldb_canonicalise_dn(struct ldb_context *ldb, void *mem_ctx,
			       const struct ldb_val *in, struct ldb_val *out)
{
	struct ldb_dn *dn;
	int ret = -1;

	out->length = 0;
	out->data = NULL;

	dn = ldb_dn_from_ldb_val(mem_ctx, ldb, in);
	if ( ! ldb_dn_validate(dn)) {
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	out->data = (uint8_t *)ldb_dn_alloc_casefold(mem_ctx, dn);
	if (out->data == NULL) {
		goto done;
	}
	out->length = strlen((char *)out->data);

	ret = 0;

done:
	talloc_free(dn);

	return ret;
}

/*
  compare two dns
*/
static int ldb_comparison_dn(struct ldb_context *ldb, void *mem_ctx,
			     const struct ldb_val *v1, const struct ldb_val *v2)
{
	struct ldb_dn *dn1 = NULL, *dn2 = NULL;
	int ret;

	dn1 = ldb_dn_from_ldb_val(mem_ctx, ldb, v1);
	if ( ! ldb_dn_validate(dn1)) return -1;

	dn2 = ldb_dn_from_ldb_val(mem_ctx, ldb, v2);
	if ( ! ldb_dn_validate(dn2)) {
		talloc_free(dn1);
		return -1;
	}

	ret = ldb_dn_compare(dn1, dn2);

	talloc_free(dn1);
	talloc_free(dn2);
	return ret;
}

/*
  compare two utc time values. 1 second resolution
*/
static int ldb_comparison_utctime(struct ldb_context *ldb, void *mem_ctx,
				  const struct ldb_val *v1, const struct ldb_val *v2)
{
	time_t t1=0, t2=0;
	ldb_val_to_time(v1, &t1);
	ldb_val_to_time(v2, &t2);
	if (t1 == t2) return 0;
	return t1 > t2? 1 : -1;
}

/*
  canonicalise a utc time
*/
static int ldb_canonicalise_utctime(struct ldb_context *ldb, void *mem_ctx,
				    const struct ldb_val *in, struct ldb_val *out)
{
	time_t t;
	int ret;
	ret = ldb_val_to_time(in, &t);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	out->data = (uint8_t *)ldb_timestring_utc(mem_ctx, t);
	if (out->data == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	out->length = strlen((char *)out->data);
	return 0;
}

/*
  canonicalise a generalized time
*/
static int ldb_canonicalise_generalizedtime(struct ldb_context *ldb, void *mem_ctx,
				        const struct ldb_val *in, struct ldb_val *out)
{
	time_t t;
	int ret;
	ret = ldb_val_to_time(in, &t);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	out->data = (uint8_t *)ldb_timestring(mem_ctx, t);
	if (out->data == NULL) {
		ldb_oom(ldb);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	out->length = strlen((char *)out->data);
	return 0;
}

/*
  table of standard attribute handlers
*/
static const struct ldb_schema_syntax ldb_standard_syntaxes[] = {
	{
		.name            = LDB_SYNTAX_INTEGER,
		.ldif_read_fn    = ldb_handler_copy,
		.ldif_write_fn   = ldb_handler_copy,
		.canonicalise_fn = ldb_canonicalise_Integer,
		.comparison_fn   = ldb_comparison_Integer
	},
	{
		.name            = LDB_SYNTAX_ORDERED_INTEGER,
		.ldif_read_fn    = ldb_handler_copy,
		.ldif_write_fn   = ldb_handler_copy,
		.canonicalise_fn = ldb_canonicalise_Integer,
		.index_format_fn = ldb_index_format_Integer,
		.comparison_fn   = ldb_comparison_Integer
	},
	{
		.name            = LDB_SYNTAX_OCTET_STRING,
		.ldif_read_fn    = ldb_handler_copy,
		.ldif_write_fn   = ldb_handler_copy,
		.canonicalise_fn = ldb_handler_copy,
		.comparison_fn   = ldb_comparison_binary
	},
	{
		.name            = LDB_SYNTAX_DIRECTORY_STRING,
		.ldif_read_fn    = ldb_handler_copy,
		.ldif_write_fn   = ldb_handler_copy,
		.canonicalise_fn = ldb_handler_fold,
		.comparison_fn   = ldb_comparison_fold
	},
	{
		.name            = LDB_SYNTAX_DN,
		.ldif_read_fn    = ldb_handler_copy,
		.ldif_write_fn   = ldb_handler_copy,
		.canonicalise_fn = ldb_canonicalise_dn,
		.comparison_fn   = ldb_comparison_dn
	},
	{
		.name            = LDB_SYNTAX_OBJECTCLASS,
		.ldif_read_fn    = ldb_handler_copy,
		.ldif_write_fn   = ldb_handler_copy,
		.canonicalise_fn = ldb_handler_fold,
		.comparison_fn   = ldb_comparison_fold
	},
	{
		.name            = LDB_SYNTAX_UTC_TIME,
		.ldif_read_fn    = ldb_handler_copy,
		.ldif_write_fn   = ldb_handler_copy,
		.canonicalise_fn = ldb_canonicalise_utctime,
		.comparison_fn   = ldb_comparison_utctime
	},
	{
		.name            = LDB_SYNTAX_GENERALIZED_TIME,
		.ldif_read_fn    = ldb_handler_copy,
		.ldif_write_fn   = ldb_handler_copy,
		.canonicalise_fn = ldb_canonicalise_generalizedtime,
		.comparison_fn   = ldb_comparison_utctime
	},
	{
		.name            = LDB_SYNTAX_BOOLEAN,
		.ldif_read_fn    = ldb_handler_copy,
		.ldif_write_fn   = ldb_handler_copy,
		.canonicalise_fn = ldb_canonicalise_Boolean,
		.comparison_fn   = ldb_comparison_Boolean
	},
};


/*
  return the attribute handlers for a given syntax name
*/
const struct ldb_schema_syntax *ldb_standard_syntax_by_name(struct ldb_context *ldb,
							    const char *syntax)
{
	unsigned int i;
	unsigned num_handlers = sizeof(ldb_standard_syntaxes)/sizeof(ldb_standard_syntaxes[0]);
	/* TODO: should be replaced with a binary search */
	for (i=0;i<num_handlers;i++) {
		if (strcmp(ldb_standard_syntaxes[i].name, syntax) == 0) {
			return &ldb_standard_syntaxes[i];
		}
	}
	return NULL;
}

int ldb_any_comparison(struct ldb_context *ldb, void *mem_ctx,
		       ldb_attr_handler_t canonicalise_fn,
		       const struct ldb_val *v1,
		       const struct ldb_val *v2)
{
	int ret, ret1, ret2;
	struct ldb_val v1_canon, v2_canon;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	/* I could try and bail if tmp_ctx was NULL, but what return
	 * value would I use?
	 *
	 * It seems easier to continue on the NULL context
	 */
	ret1 = canonicalise_fn(ldb, tmp_ctx, v1, &v1_canon);
	ret2 = canonicalise_fn(ldb, tmp_ctx, v2, &v2_canon);

	if (ret1 == LDB_SUCCESS && ret2 == LDB_SUCCESS) {
		ret = ldb_comparison_binary(ldb, mem_ctx, &v1_canon, &v2_canon);
	} else {
		ret = ldb_comparison_binary(ldb, mem_ctx, v1, v2);
	}
	talloc_free(tmp_ctx);
	return ret;
}
