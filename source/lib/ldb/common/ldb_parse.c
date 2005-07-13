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
 *  Component: ldb expression parsing
 *
 *  Description: parse LDAP-like search expressions
 *
 *  Author: Andrew Tridgell
 */

/*
  TODO:
      - add RFC2254 binary string handling
      - possibly add ~=, <= and >= handling
      - expand the test suite
      - add better parse error handling

*/

#include "includes.h"
#include "ldb/include/ldb.h"
#include <ctype.h>


/*
a filter is defined by:
               <filter> ::= '(' <filtercomp> ')'
               <filtercomp> ::= <and> | <or> | <not> | <simple>
               <and> ::= '&' <filterlist>
               <or> ::= '|' <filterlist>
               <not> ::= '!' <filter>
               <filterlist> ::= <filter> | <filter> <filterlist>
               <simple> ::= <attributetype> <filtertype> <attributevalue>
               <filtertype> ::= '=' | '~=' | '<=' | '>='
*/

#define LDB_ALL_SEP "()&|=!"

/*
  return next token element. Caller frees
*/
static char *ldb_parse_lex(void *ctx, const char **s, const char *sep)
{
	const char *p = *s;
	char *ret;

	while (isspace((unsigned char)*p)) {
		p++;
	}
	*s = p;

	if (*p == 0) {
		return NULL;
	}

	if (strchr(sep, *p)) {
		(*s) = p+1;
		ret = talloc_strndup(ctx, p, 1);
		if (!ret) {
			errno = ENOMEM;
		}
		return ret;
	}

	while (*p && (isalnum((unsigned char)*p) || !strchr(sep, *p))) {
		p++;
	}

	if (p == *s) {
		return NULL;
	}

	ret = talloc_strndup(ctx, *s, p - *s);
	if (!ret) {
		errno = ENOMEM;
	}

	*s = p;

	return ret;
}

/*
  find a matching close brace in a string
*/
static const char *match_brace(const char *s)
{
	unsigned int count = 0;
	while (*s && (count != 0 || *s != ')')) {
		if (*s == '(') {
			count++;
		}
		if (*s == ')') {
			count--;
		}
		s++;
	}
	if (! *s) {
		return NULL;
	}
	return s;
}

/*
   decode a RFC2254 binary string representation of a buffer.
   Used in LDAP filters.
*/
struct ldb_val ldb_binary_decode(void *mem_ctx, const char *str)
{
	int i, j;
	struct ldb_val ret;
	int slen = str?strlen(str):0;

	ret.data = talloc_size(mem_ctx, slen+1);
	ret.length = 0;
	if (ret.data == NULL) return ret;

	for (i=j=0;i<slen;i++) {
		if (str[i] == '\\') {
			unsigned c;
			if (sscanf(&str[i+1], "%02X", &c) != 1) {
				talloc_free(ret.data);
				memset(&ret, 0, sizeof(ret));
				return ret;
			}
			((uint8_t *)ret.data)[j++] = c;
			i += 2;
		} else {
			((uint8_t *)ret.data)[j++] = str[i];
		}
	}
	ret.length = j;
	((uint8_t *)ret.data)[j] = 0;

	return ret;
}


/*
   encode a blob as a RFC2254 binary string, escaping any
   non-printable or '\' characters
*/
char *ldb_binary_encode(void *mem_ctx, struct ldb_val val)
{
	int i;
	char *ret;
	int len = val.length;
	unsigned char *buf = val.data;

	for (i=0;i<val.length;i++) {
		if (!isprint(buf[i]) || strchr(" *()\\&|!\"", buf[i])) {
			len += 2;
		}
	}
	ret = talloc_array(mem_ctx, char, len+1);
	if (ret == NULL) return NULL;

	len = 0;
	for (i=0;i<val.length;i++) {
		if (!isprint(buf[i]) || strchr(" *()\\&|!\"", buf[i])) {
			snprintf(ret+len, 4, "\\%02X", buf[i]);
			len += 3;
		} else {
			ret[len++] = buf[i];
		}
	}

	ret[len] = 0;

	return ret;	
}

/* find the first matching wildcard */
static char *ldb_parse_find_wildcard(char *value)
{
	while (*value) {
		value = strpbrk(value, "\\*");
		if (value == NULL) return NULL;

		if (value[0] == '\\') {
			if (value[1] == '\0') return NULL;
			value += 2;
			continue;
		}

		if (value[0] == '*') return value;
	}

	return NULL;
}

/* return a NULL terminated list of binary strings representing the value
   chunks separated by wildcards that makes the value portion of the filter
*/
static struct ldb_val **ldb_wildcard_decode(void *mem_ctx, const char *string)
{
	struct ldb_val **ret = NULL;
	int val = 0;
	char *wc, *str;

	wc = talloc_strdup(mem_ctx, string);
	if (wc == NULL) return NULL;

	while (wc && *wc) {
		str = wc;
		wc = ldb_parse_find_wildcard(str);
		if (wc && *wc) {
			if (wc == str) {
				wc++;
				continue;
			}
			*wc = 0;
			wc++;
		}

		ret = talloc_realloc(mem_ctx, ret, struct ldb_val *, val + 2);
		if (ret == NULL) return NULL;

		ret[val] = talloc(mem_ctx, struct ldb_val);
		if (ret[val] == NULL) return NULL;

		*(ret[val]) = ldb_binary_decode(mem_ctx, str);
		if ((ret[val])->data == NULL) return NULL;

		val++;
	}

	ret[val] = NULL;

	return ret;
}

static struct ldb_parse_tree *ldb_parse_filter(void *mem_ctx, const char **s);


/*
  parse an extended match

  possible forms:
        (attr:oid:=value)
        (attr:dn:oid:=value)
        (attr:dn:=value)
        (:dn:oid:=value)

  the ':dn' part sets the dnAttributes boolean if present
  the oid sets the rule_id string
  
*/
static struct ldb_parse_tree *ldb_parse_extended(struct ldb_parse_tree *ret, 
						 char *attr, char *value)
{
	char *p1, *p2, *p3;

	ret->operation = LDB_OP_EXTENDED;
	ret->u.extended.value = ldb_binary_decode(ret, value);
	if (ret->u.extended.value.data == NULL) goto failed;

	p1 = strchr(attr, ':');
	if (p1 == NULL) goto failed;
	p2 = strchr(p1+1, ':');
	if (p2 == NULL) goto failed;
	p3 = strchr(p2+1, ':');

	*p1 = 0;
	*p2 = 0;
	if (p3) *p3 = 0;

	ret->u.extended.attr = talloc_strdup(ret, attr);
	if (ret->u.extended.attr == NULL) goto failed;
	if (strcmp(p1+1, "dn") == 0) {
		ret->u.extended.dnAttributes = 1;
		if (p3) {
			ret->u.extended.rule_id = talloc_strdup(ret, p2+1);
			if (ret->u.extended.rule_id == NULL) goto failed;
		} else {
			ret->u.extended.rule_id = NULL;
		}
	} else {
		ret->u.extended.dnAttributes = 0;
		ret->u.extended.rule_id = talloc_strdup(ret, p1+1);
		if (ret->u.extended.rule_id == NULL) goto failed;
	}

	return ret;

failed:
	talloc_free(ret);
	return NULL;
}


/*
  <simple> ::= <attributetype> <filtertype> <attributevalue>
*/
static struct ldb_parse_tree *ldb_parse_simple(void *mem_ctx, const char *s)
{
	char *eq, *val, *l;
	struct ldb_parse_tree *ret;

	ret = talloc(mem_ctx, struct ldb_parse_tree);
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	l = ldb_parse_lex(ret, &s, LDB_ALL_SEP);
	if (!l) {
		talloc_free(ret);
		return NULL;
	}

	if (strchr("()&|=", *l)) {
		talloc_free(ret);
		return NULL;
	}

	eq = ldb_parse_lex(ret, &s, LDB_ALL_SEP);
	if (!eq || strcmp(eq, "=") != 0) {
		talloc_free(ret);
		return NULL;
	}
	talloc_free(eq);

	val = ldb_parse_lex(ret, &s, ")");
	if (val && strchr("()&|", *val)) {
		talloc_free(ret);
		return NULL;
	}

	if (l[strlen(l)-1] == ':') {
		/* its an extended match */
		return ldb_parse_extended(ret, l, val);
	}

	if (val && strcmp(val, "*") == 0) {
		ret->operation = LDB_OP_PRESENT;
		ret->u.present.attr = l;

		return ret;
	}

	if (val && ldb_parse_find_wildcard(val) != NULL) {
		ret->operation = LDB_OP_SUBSTRING;
		ret->u.substring.attr = l;
		ret->u.substring.start_with_wildcard = 0;
		ret->u.substring.end_with_wildcard = 0;
		ret->u.substring.chunks = ldb_wildcard_decode(ret, val);
		if (ret->u.substring.chunks == NULL){
			talloc_free(ret);
			return NULL;
		}
		if (val[0] == '*') ret->u.substring.start_with_wildcard = 1;
		if (val[strlen(val) - 1] == '*') ret->u.substring.end_with_wildcard = 1;

		return ret;
	}

	ret->operation = LDB_OP_SIMPLE;
	ret->u.simple.attr = l;
	ret->u.simple.value = ldb_binary_decode(ret, val);
	if (ret->u.simple.value.data == NULL) {
		talloc_free(ret);
		return NULL;
	}

	return ret;
}


/*
  parse a filterlist
  <and> ::= '&' <filterlist>
  <or> ::= '|' <filterlist>
  <filterlist> ::= <filter> | <filter> <filterlist>
*/
static struct ldb_parse_tree *ldb_parse_filterlist(void *mem_ctx,
						   enum ldb_parse_op op, const char *s)
{
	struct ldb_parse_tree *ret, *next;

	ret = talloc(mem_ctx, struct ldb_parse_tree);
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	ret->operation = op;
	ret->u.list.num_elements = 1;
	ret->u.list.elements = talloc(ret, struct ldb_parse_tree *);
	if (!ret->u.list.elements) {
		errno = ENOMEM;
		talloc_free(ret);
		return NULL;
	}

	ret->u.list.elements[0] = ldb_parse_filter(ret->u.list.elements, &s);
	if (!ret->u.list.elements[0]) {
		talloc_free(ret);
		return NULL;
	}

	while (isspace((unsigned char)*s)) s++;

	while (*s && (next = ldb_parse_filter(ret->u.list.elements, &s))) {
		struct ldb_parse_tree **e;
		e = talloc_realloc(ret, ret->u.list.elements, 
				     struct ldb_parse_tree *, 
				     ret->u.list.num_elements+1);
		if (!e) {
			errno = ENOMEM;
			talloc_free(ret);
			return NULL;
		}
		ret->u.list.elements = e;
		ret->u.list.elements[ret->u.list.num_elements] = next;
		ret->u.list.num_elements++;
		while (isspace((unsigned char)*s)) s++;
	}

	return ret;
}


/*
  <not> ::= '!' <filter>
*/
static struct ldb_parse_tree *ldb_parse_not(void *mem_ctx, const char *s)
{
	struct ldb_parse_tree *ret;

	ret = talloc(mem_ctx, struct ldb_parse_tree);
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	ret->operation = LDB_OP_NOT;
	ret->u.isnot.child = ldb_parse_filter(ret, &s);
	if (!ret->u.isnot.child) {
		talloc_free(ret);
		return NULL;
	}

	return ret;
}

/*
  parse a filtercomp
  <filtercomp> ::= <and> | <or> | <not> | <simple>
*/
static struct ldb_parse_tree *ldb_parse_filtercomp(void *mem_ctx, const char *s)
{
	while (isspace((unsigned char)*s)) s++;

	switch (*s) {
	case '&':
		return ldb_parse_filterlist(mem_ctx, LDB_OP_AND, s+1);

	case '|':
		return ldb_parse_filterlist(mem_ctx, LDB_OP_OR, s+1);

	case '!':
		return ldb_parse_not(mem_ctx, s+1);

	case '(':
	case ')':
		return NULL;
	}

	return ldb_parse_simple(mem_ctx, s);
}


/*
  <filter> ::= '(' <filtercomp> ')'
*/
static struct ldb_parse_tree *ldb_parse_filter(void *mem_ctx, const char **s)
{
	char *l, *s2;
	const char *p, *p2;
	struct ldb_parse_tree *ret;

	l = ldb_parse_lex(mem_ctx, s, LDB_ALL_SEP);
	if (!l) {
		return NULL;
	}

	if (strcmp(l, "(") != 0) {
		talloc_free(l);
		return NULL;
	}
	talloc_free(l);

	p = match_brace(*s);
	if (!p) {
		return NULL;
	}
	p2 = p + 1;

	s2 = talloc_strndup(mem_ctx, *s, p - *s);
	if (!s2) {
		errno = ENOMEM;
		return NULL;
	}

	ret = ldb_parse_filtercomp(mem_ctx, s2);
	talloc_free(s2);

	*s = p2;

	return ret;
}


/*
  main parser entry point. Takes a search string and returns a parse tree

  expression ::= <simple> | <filter>
*/
struct ldb_parse_tree *ldb_parse_tree(void *mem_ctx, const char *s)
{
	while (isspace((unsigned char)*s)) s++;

	if (*s == '(') {
		return ldb_parse_filter(mem_ctx, &s);
	}

	return ldb_parse_simple(mem_ctx, s);
}


/*
  construct a ldap parse filter given a parse tree
*/
char *ldb_filter_from_tree(void *mem_ctx, struct ldb_parse_tree *tree)
{
	char *s, *s2, *ret;
	int i;

	switch (tree->operation) {
	case LDB_OP_SIMPLE:
		s = ldb_binary_encode(mem_ctx, tree->u.simple.value);
		if (s == NULL) return NULL;
		ret = talloc_asprintf(mem_ctx, "(%s=%s)", 
				      tree->u.simple.attr, s);
		talloc_free(s);
		return ret;
	case LDB_OP_EXTENDED:
		s = ldb_binary_encode(mem_ctx, tree->u.extended.value);
		if (s == NULL) return NULL;
		ret = talloc_asprintf(mem_ctx, "(%s%s%s%s:=%s)", 
				      tree->u.extended.attr?tree->u.extended.attr:"", 
				      tree->u.extended.dnAttributes?":dn":"",
				      tree->u.extended.rule_id?":":"", 
				      tree->u.extended.rule_id?tree->u.extended.rule_id:"", 
				      s);
		talloc_free(s);
		return ret;
	case LDB_OP_SUBSTRING:
		ret = talloc_strdup(mem_ctx, (tree->u.substring.start_with_wildcard)?"*":"");
		if (ret == NULL) return NULL;
		for (i = 0; tree->u.substring.chunks[i]; i++) {
			s2 = ldb_binary_encode(mem_ctx, *(tree->u.substring.chunks[i]));
			if (s2 == NULL) {
				talloc_free(ret);
				return NULL;
			}
			s = talloc_asprintf_append(ret, "%s*", s2);
			if (s == NULL) {
				talloc_free(ret);
				return NULL;
			}
			ret = s;
		}
		if ( ! tree->u.substring.end_with_wildcard ) {
			ret[strlen(ret) - 1] = '\0'; /* remove last wildcard */
		}
		return ret;
	case LDB_OP_PRESENT:
		ret = talloc_strdup(mem_ctx, "*");
		if (ret == NULL) return NULL;
		return ret;
	case LDB_OP_AND:
	case LDB_OP_OR:
		ret = talloc_asprintf(mem_ctx, "(%c", (char)tree->operation);
		if (ret == NULL) return NULL;
		for (i=0;i<tree->u.list.num_elements;i++) {
			s = ldb_filter_from_tree(mem_ctx, tree->u.list.elements[i]);
			if (s == NULL) {
				talloc_free(ret);
				return NULL;
			}
			s2 = talloc_asprintf_append(ret, "%s", s);
			talloc_free(s);
			if (s2 == NULL) {
				talloc_free(ret);
				return NULL;
			}
			ret = s2;
		}
		s = talloc_asprintf_append(ret, ")");
		if (s == NULL) {
			talloc_free(ret);
			return NULL;
		}
		return s;
	case LDB_OP_NOT:
		s = ldb_filter_from_tree(mem_ctx, tree->u.isnot.child);
		if (s == NULL) return NULL;

		ret = talloc_asprintf(mem_ctx, "(!%s)", s);
		talloc_free(s);
		return ret;
	}
	
	return NULL;
}
