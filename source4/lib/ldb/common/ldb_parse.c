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
#include "ldb/include/ldb_private.h"
#include "ldb/include/ldb_parse.h"
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
static char *ldb_parse_lex(TALLOC_CTX *ctx, const char **s, const char *sep)
{
	const char *p = *s;
	char *ret;

	while (isspace(*p)) {
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

	while (*p && (isalnum(*p) || !strchr(sep, *p))) {
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


static struct ldb_parse_tree *ldb_parse_filter(TALLOC_CTX *ctx, const char **s);

/*
  <simple> ::= <attributetype> <filtertype> <attributevalue>
*/
static struct ldb_parse_tree *ldb_parse_simple(TALLOC_CTX *ctx, const char *s)
{
	char *eq, *val, *l;
	struct ldb_parse_tree *ret;

	ret = talloc_p(ctx, struct ldb_parse_tree);
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
	
	ret->operation = LDB_OP_SIMPLE;
	ret->u.simple.attr = l;
	ret->u.simple.value.data = val;
	ret->u.simple.value.length = val?strlen(val):0;

	return ret;
}


/*
  parse a filterlist
  <and> ::= '&' <filterlist>
  <or> ::= '|' <filterlist>
  <filterlist> ::= <filter> | <filter> <filterlist>
*/
static struct ldb_parse_tree *ldb_parse_filterlist(TALLOC_CTX *ctx,
						   enum ldb_parse_op op, const char *s)
{
	struct ldb_parse_tree *ret, *next;

	ret = talloc_p(ctx, struct ldb_parse_tree);
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	ret->operation = op;
	ret->u.list.num_elements = 1;
	ret->u.list.elements = talloc_p(ret, struct ldb_parse_tree *);
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

	while (isspace(*s)) s++;

	while (*s && (next = ldb_parse_filter(ret->u.list.elements, &s))) {
		struct ldb_parse_tree **e;
		e = talloc_realloc_p(ret, ret->u.list.elements, 
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
		while (isspace(*s)) s++;
	}

	return ret;
}


/*
  <not> ::= '!' <filter>
*/
static struct ldb_parse_tree *ldb_parse_not(TALLOC_CTX *ctx, const char *s)
{
	struct ldb_parse_tree *ret;

	ret = talloc_p(ctx, struct ldb_parse_tree);
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	ret->operation = LDB_OP_NOT;
	ret->u.not.child = ldb_parse_filter(ret, &s);
	if (!ret->u.not.child) {
		talloc_free(ret);
		return NULL;
	}

	return ret;
}

/*
  parse a filtercomp
  <filtercomp> ::= <and> | <or> | <not> | <simple>
*/
static struct ldb_parse_tree *ldb_parse_filtercomp(TALLOC_CTX *ctx, const char *s)
{
	while (isspace(*s)) s++;

	switch (*s) {
	case '&':
		return ldb_parse_filterlist(ctx, LDB_OP_AND, s+1);

	case '|':
		return ldb_parse_filterlist(ctx, LDB_OP_OR, s+1);

	case '!':
		return ldb_parse_not(ctx, s+1);

	case '(':
	case ')':
		return NULL;
	}

	return ldb_parse_simple(ctx, s);
}


/*
  <filter> ::= '(' <filtercomp> ')'
*/
static struct ldb_parse_tree *ldb_parse_filter(TALLOC_CTX *ctx, const char **s)
{
	char *l, *s2;
	const char *p, *p2;
	struct ldb_parse_tree *ret;

	l = ldb_parse_lex(ctx, s, LDB_ALL_SEP);
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

	s2 = talloc_strndup(ctx, *s, p - *s);
	if (!s2) {
		errno = ENOMEM;
		return NULL;
	}

	ret = ldb_parse_filtercomp(ctx, s2);
	talloc_free(s2);

	*s = p2;

	return ret;
}


/*
  main parser entry point. Takes a search string and returns a parse tree

  expression ::= <simple> | <filter>
*/
struct ldb_parse_tree *ldb_parse_tree(struct ldb_context *ldb, const char *s)
{
	while (isspace(*s)) s++;

	if (*s == '(') {
		return ldb_parse_filter(ldb, &s);
	}

	return ldb_parse_simple(ldb, s);
}

/*
  free a parse tree returned from ldb_parse_tree()
*/
void ldb_parse_tree_free(struct ldb_context *ldb, struct ldb_parse_tree *tree)
{
	talloc_free(tree);
}

