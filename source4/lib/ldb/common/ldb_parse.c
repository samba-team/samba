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

/*
  return next token element. Caller frees
*/
static char *ldb_parse_lex(struct ldb_context *ldb, const char **s)
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

	if (strchr("()&|=!", *p)) {
		(*s) = p+1;
		ret = ldb_strndup(ldb, p, 1);
		if (!ret) {
			errno = ENOMEM;
		}
		return ret;
	}

	while (*p && (isalnum(*p) || !strchr("()&|=!", *p))) {
		p++;
	}

	if (p == *s) {
		return NULL;
	}

	ret = ldb_strndup(ldb, *s, p - *s);
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


static struct ldb_parse_tree *ldb_parse_filter(struct ldb_context *ldb, const char **s);

/*
  <simple> ::= <attributetype> <filtertype> <attributevalue>
*/
static struct ldb_parse_tree *ldb_parse_simple(struct ldb_context *ldb, const char *s)
{
	char *eq, *val, *l;
	struct ldb_parse_tree *ret;

	l = ldb_parse_lex(ldb, &s);
	if (!l) {
		return NULL;
	}

	if (strchr("()&|=", *l)) {
		ldb_free(ldb, l);
		return NULL;
	}

	eq = ldb_parse_lex(ldb, &s);
	if (!eq || strcmp(eq, "=") != 0) {
		ldb_free(ldb, l);
		if (eq) ldb_free(ldb, eq);
		return NULL;
	}
	ldb_free(ldb, eq);

	val = ldb_parse_lex(ldb, &s);
	if (val && strchr("()&|=", *val)) {
		ldb_free(ldb, l);
		if (val) ldb_free(ldb, val);
		return NULL;
	}
	
	ret = ldb_malloc_p(ldb, struct ldb_parse_tree);
	if (!ret) {
		errno = ENOMEM;
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
static struct ldb_parse_tree *ldb_parse_filterlist(struct ldb_context *ldb,
						   enum ldb_parse_op op, const char *s)
{
	struct ldb_parse_tree *ret, *next;

	ret = ldb_malloc_p(ldb, struct ldb_parse_tree);
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	ret->operation = op;
	ret->u.list.num_elements = 1;
	ret->u.list.elements = ldb_malloc_p(ldb, struct ldb_parse_tree *);
	if (!ret->u.list.elements) {
		errno = ENOMEM;
		ldb_free(ldb, ret);
		return NULL;
	}

	ret->u.list.elements[0] = ldb_parse_filter(ldb, &s);
	if (!ret->u.list.elements[0]) {
		ldb_free(ldb, ret->u.list.elements);
		ldb_free(ldb, ret);
		return NULL;
	}

	while (isspace(*s)) s++;

	while (*s && (next = ldb_parse_filter(ldb, &s))) {
		struct ldb_parse_tree **e;
		e = ldb_realloc_p(ldb, ret->u.list.elements, 
				  struct ldb_parse_tree *, 
				  ret->u.list.num_elements+1);
		if (!e) {
			errno = ENOMEM;
			ldb_parse_tree_free(ldb, next);
			ldb_parse_tree_free(ldb, ret);
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
static struct ldb_parse_tree *ldb_parse_not(struct ldb_context *ldb, const char *s)
{
	struct ldb_parse_tree *ret;

	ret = ldb_malloc_p(ldb, struct ldb_parse_tree);
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	ret->operation = LDB_OP_NOT;
	ret->u.not.child = ldb_parse_filter(ldb, &s);
	if (!ret->u.not.child) {
		ldb_free(ldb, ret);
		return NULL;
	}

	return ret;
}

/*
  parse a filtercomp
  <filtercomp> ::= <and> | <or> | <not> | <simple>
*/
static struct ldb_parse_tree *ldb_parse_filtercomp(struct ldb_context *ldb, 
						   const char *s)
{
	while (isspace(*s)) s++;

	switch (*s) {
	case '&':
		return ldb_parse_filterlist(ldb, LDB_OP_AND, s+1);

	case '|':
		return ldb_parse_filterlist(ldb, LDB_OP_OR, s+1);

	case '!':
		return ldb_parse_not(ldb, s+1);

	case '(':
	case ')':
		return NULL;
	}

	return ldb_parse_simple(ldb, s);
}


/*
  <filter> ::= '(' <filtercomp> ')'
*/
static struct ldb_parse_tree *ldb_parse_filter(struct ldb_context *ldb, const char **s)
{
	char *l, *s2;
	const char *p, *p2;
	struct ldb_parse_tree *ret;

	l = ldb_parse_lex(ldb, s);
	if (!l) {
		return NULL;
	}

	if (strcmp(l, "(") != 0) {
		ldb_free(ldb, l);
		return NULL;
	}
	ldb_free(ldb, l);

	p = match_brace(*s);
	if (!p) {
		return NULL;
	}
	p2 = p + 1;

	s2 = ldb_strndup(ldb, *s, p - *s);
	if (!s2) {
		errno = ENOMEM;
		return NULL;
	}

	ret = ldb_parse_filtercomp(ldb, s2);
	ldb_free(ldb, s2);

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
	int i;

	switch (tree->operation) {
	case LDB_OP_SIMPLE:
		ldb_free(ldb, tree->u.simple.attr);
		if (tree->u.simple.value.data) ldb_free(ldb, tree->u.simple.value.data);
		break;

	case LDB_OP_AND:
	case LDB_OP_OR:
		for (i=0;i<tree->u.list.num_elements;i++) {
			ldb_parse_tree_free(ldb, tree->u.list.elements[i]);
		}
		if (tree->u.list.elements) ldb_free(ldb, tree->u.list.elements);
		break;

	case LDB_OP_NOT:
		ldb_parse_tree_free(ldb, tree->u.not.child);
		break;
	}

	ldb_free(ldb, tree);
}

