 /* 
   Unix SMB/CIFS implementation.

   parse a LDAP-like expression

   Copyright (C) Andrew Tridgell 2004
   
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
static char *ldb_parse_lex(const char **s)
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
		ret = strndup(p, 1);
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

	ret = strndup(*s, p - *s);
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


static struct ldb_parse_tree *ldb_parse_filter(const char **s);

/*
  <simple> ::= <attributetype> <filtertype> <attributevalue>
*/
static struct ldb_parse_tree *ldb_parse_simple(const char *s)
{
	char *eq, *val, *l;
	struct ldb_parse_tree *ret;

	l = ldb_parse_lex(&s);
	if (!l) {
		fprintf(stderr, "Unexpected end of expression\n");
		return NULL;
	}

	if (strchr("()&|=", *l)) {
		fprintf(stderr, "Unexpected token '%s'\n", l);
		free(l);
		return NULL;
	}

	eq = ldb_parse_lex(&s);
	if (!eq || strcmp(eq, "=") != 0) {
		fprintf(stderr, "Expected '='\n");
		free(l);
		if (eq) free(eq);
		return NULL;
	}
	free(eq);

	val = ldb_parse_lex(&s);
	if (val && strchr("()&|=", *val)) {
		fprintf(stderr, "Unexpected token '%s'\n", val);
		free(l);
		if (val) free(val);
		return NULL;
	}
	
	ret = malloc_p(struct ldb_parse_tree);
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
static struct ldb_parse_tree *ldb_parse_filterlist(enum ldb_parse_op op, const char *s)
{
	struct ldb_parse_tree *ret, *next;

	ret = malloc_p(struct ldb_parse_tree);
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	ret->operation = op;
	ret->u.list.num_elements = 1;
	ret->u.list.elements = malloc_p(struct ldb_parse_tree *);
	if (!ret->u.list.elements) {
		errno = ENOMEM;
		free(ret);
		return NULL;
	}

	ret->u.list.elements[0] = ldb_parse_filter(&s);
	if (!ret->u.list.elements[0]) {
		free(ret->u.list.elements);
		free(ret);
		return NULL;
	}

	while (isspace(*s)) s++;

	while (*s && (next = ldb_parse_filter(&s))) {
		struct ldb_parse_tree **e;
		e = realloc_p(ret->u.list.elements, 
			      struct ldb_parse_tree *, 
			      ret->u.list.num_elements+1);
		if (!e) {
			errno = ENOMEM;
			ldb_parse_tree_free(next);
			ldb_parse_tree_free(ret);
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
static struct ldb_parse_tree *ldb_parse_not(const char *s)
{
	struct ldb_parse_tree *ret;

	ret = malloc_p(struct ldb_parse_tree);
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}

	ret->operation = LDB_OP_NOT;
	ret->u.not.child = ldb_parse_filter(&s);
	if (!ret->u.not.child) {
		free(ret);
		return NULL;
	}

	return ret;
}

/*
  parse a filtercomp
  <filtercomp> ::= <and> | <or> | <not> | <simple>
*/
static struct ldb_parse_tree *ldb_parse_filtercomp(const char *s)
{
	while (isspace(*s)) s++;

	switch (*s) {
	case '&':
		return ldb_parse_filterlist(LDB_OP_AND, s+1);

	case '|':
		return ldb_parse_filterlist(LDB_OP_OR, s+1);

	case '!':
		return ldb_parse_not(s+1);

	case '(':
	case ')':
		fprintf(stderr, "Unexpected token '%c'\n", *s);
		return NULL;
	}

	return ldb_parse_simple(s);
}


/*
  <filter> ::= '(' <filtercomp> ')'
*/
static struct ldb_parse_tree *ldb_parse_filter(const char **s)
{
	char *l, *s2;
	const char *p, *p2;
	struct ldb_parse_tree *ret;

	l = ldb_parse_lex(s);
	if (!l) {
		fprintf(stderr, "Unexpected end of expression\n");
		return NULL;
	}

	if (strcmp(l, "(") != 0) {
		free(l);
		fprintf(stderr, "Expected '('\n");
		return NULL;
	}
	free(l);

	p = match_brace(*s);
	if (!p) {
		fprintf(stderr, "Parse error - mismatched braces\n");
		return NULL;
	}
	p2 = p + 1;

	s2 = strndup(*s, p - *s);
	if (!s2) {
		errno = ENOMEM;
		return NULL;
	}

	ret = ldb_parse_filtercomp(s2);
	free(s2);

	*s = p2;

	return ret;
}


/*
  main parser entry point. Takes a search string and returns a parse tree

  expression ::= <simple> | <filter>
*/
struct ldb_parse_tree *ldb_parse_tree(const char *s)
{
	while (isspace(*s)) s++;

	if (*s == '(') {
		return ldb_parse_filter(&s);
	}

	return ldb_parse_simple(s);
}

/*
  free a parse tree returned from ldb_parse_tree()
*/
void ldb_parse_tree_free(struct ldb_parse_tree *tree)
{
	int i;

	switch (tree->operation) {
	case LDB_OP_SIMPLE:
		free(tree->u.simple.attr);
		if (tree->u.simple.value.data) free(tree->u.simple.value.data);
		break;

	case LDB_OP_AND:
	case LDB_OP_OR:
		for (i=0;i<tree->u.list.num_elements;i++) {
			ldb_parse_tree_free(tree->u.list.elements[i]);
		}
		if (tree->u.list.elements) free(tree->u.list.elements);
		break;

	case LDB_OP_NOT:
		ldb_parse_tree_free(tree->u.not.child);
		break;
	}

	free(tree);
}

#if TEST_PROGRAM
/*
  return a string representation of a parse tree
  used for debugging
*/
static char *tree_string(struct ldb_parse_tree *tree)
{
	char *s = NULL;
	char *s1, *s2;
	int i;

	switch (tree->operation) {
	case LDB_OP_SIMPLE:
		asprintf(&s, "( %s = \"%s\" )", tree->u.simple.attr, 
			 (char *)tree->u.simple.value.data);
		break;

	case LDB_OP_AND:
	case LDB_OP_OR:
		asprintf(&s, "( %c", tree->operation==LDB_OP_AND?'&':'|');
		if (!s) return NULL;

		for (i=0;i<tree->u.list.num_elements;i++) {
			s1 = tree_string(tree->u.list.elements[i]);
			if (!s1) {
				free(s);
				return NULL;
			}
			asprintf(&s2, "%s %s", s, s1);
			free(s);
			free(s1);
			s = s2;
		}
		if (!s) {
			return NULL;
		}
		asprintf(&s2, "%s )", s);
		free(s);
		s = s2;
		break;

	case LDB_OP_NOT:
		s1 = tree_string(tree->u.not.child);
		asprintf(&s, "( ! %s )", s1);
		free(s1);
		break;
	}
	return s;
}


/*
  print a tree
 */
static void print_tree(struct ldb_parse_tree *tree)
{
	char *s = tree_string(tree);
	printf("%s\n", s);
	free(s);
}


 int main(void)
{
	char line[1000];
	int ret = 0;

	while (fgets(line, sizeof(line)-1, stdin)) {
		struct ldb_parse_tree *tree;

		if (line[strlen(line)-1] == '\n') {
			line[strlen(line)-1] = 0;
		}
		tree = ldb_parse_tree(line);
		if (!tree) {
			fprintf(stderr, "Failed to parse\n");
			ret = 1;
			continue;
		}
		print_tree(tree);
		ldb_parse_tree_free(tree);
	}
	
	return ret;
}
#endif /* TEST_PROGRAM */

