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
  register handlers for specific attributes and objectclass relationships

  this allows a backend to store its schema information in any format
  it likes (or to not have any schema information at all) while keeping the 
  message matching logic generic
*/

#include "includes.h"
#include "ldb/include/includes.h"

/*
  add a attribute to the ldb_schema

  if flags contains LDB_ATTR_FLAG_ALLOCATED
  the attribute name string will be copied using
  talloc_strdup(), otherwise it needs to be a static const
  string at least with a lifetime longer than the ldb struct!
  
  the ldb_schema_syntax structure should be a pointer
  to a static const struct or at least it needs to be
  a struct with a longer lifetime than the ldb context!

*/
int ldb_schema_attribute_add_with_syntax(struct ldb_context *ldb, 
					 const char *attribute,
					 unsigned flags,
					 const struct ldb_schema_syntax *syntax)
{
	int i, n;
	struct ldb_schema_attribute *a;

	n = ldb->schema.num_attributes + 1;

	a = talloc_realloc(ldb, ldb->schema.attributes,
			   struct ldb_schema_attribute, n);
	if (a == NULL) {
		ldb_oom(ldb);
		return -1;
	}
	ldb->schema.attributes = a;

	for (i = 0; i < ldb->schema.num_attributes; i++) {
		if (ldb_attr_cmp(attribute, a[i].name) < 0) {
			memmove(a+i+1, a+i, sizeof(*a) * (ldb->schema.num_attributes-i));
			break;
		}
	}

	a[i].name	= attribute;
	a[i].flags	= flags;
	a[i].syntax	= syntax;

	if (a[i].flags & LDB_ATTR_FLAG_ALLOCATED) {
		a[i].name = talloc_strdup(a, a[i].name);
		if (a[i].name == NULL) {
			ldb_oom(ldb);
			return -1;
		}
	}

	ldb->schema.num_attributes++;
	return 0;
}

/*
  return the attribute handlers for a given attribute
*/
const struct ldb_schema_attribute *ldb_schema_attribute_by_name(struct ldb_context *ldb,
								const char *name)
{
	int i, e, b = 0, r;
	const struct ldb_schema_attribute *def = NULL;

	/* as handlers are sorted, '*' must be the first if present */
	if (strcmp(ldb->schema.attributes[0].name, "*") == 0) {
		def = &ldb->schema.attributes[0];
		b = 1;
	}

	/* do a binary search on the array */
	e = ldb->schema.num_attributes - 1;

	while (b <= e) {

		i = (b + e) / 2;

		r = ldb_attr_cmp(name, ldb->schema.attributes[i].name);
		if (r == 0) {
			return &ldb->schema.attributes[i];
		}
		if (r < 0) {
			e = i - 1;
		} else {
			b = i + 1;
		}

	}

	return def;
}


/*
  add to the list of ldif handlers for this ldb context
*/
void ldb_schema_attribute_remove(struct ldb_context *ldb, const char *name)
{
	const struct ldb_schema_attribute *a;
	int i;

	a = ldb_schema_attribute_by_name(ldb, name);
	if (a == NULL) {
		return;
	}

	if (a->flags & LDB_ATTR_FLAG_ALLOCATED) {
		talloc_free(discard_const_p(char, a->name));
	}

	i = a - ldb->schema.attributes;
	if (i < ldb->schema.num_attributes - 1) {
		memmove(&ldb->schema.attributes[i], 
			a+1, sizeof(*a) * (ldb->schema.num_attributes-(i+1)));
	}

	ldb->schema.num_attributes--;
}

/*
  setup a attribute handler using a standard syntax
*/
int ldb_schema_attribute_add(struct ldb_context *ldb,
			     const char *attribute,
			     unsigned flags,
			     const char *syntax)
{
	const struct ldb_schema_syntax *s = ldb_standard_syntax_by_name(ldb, syntax);
	return ldb_schema_attribute_add_with_syntax(ldb, attribute, flags, s);
}

/*
  setup the attribute handles for well known attributes
*/
int ldb_setup_wellknown_attributes(struct ldb_context *ldb)
{
	const struct {
		const char *attr;
		const char *syntax;
	} wellknown[] = {
		{ "*", LDB_SYNTAX_OCTET_STRING },
		{ "dn", LDB_SYNTAX_DN },
		{ "distinguishedName", LDB_SYNTAX_DN },
		{ "cn", LDB_SYNTAX_DIRECTORY_STRING },
		{ "dc", LDB_SYNTAX_DIRECTORY_STRING },
		{ "ou", LDB_SYNTAX_DIRECTORY_STRING },
		{ "objectClass", LDB_SYNTAX_OBJECTCLASS }
	};
	int i;
	int ret;

	for (i=0;i<ARRAY_SIZE(wellknown);i++) {
		ret = ldb_schema_attribute_add(ldb, wellknown[i].attr, 0,
					       wellknown[i].syntax);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return LDB_SUCCESS;
}

/*
  return the list of subclasses for a class
*/
const char **ldb_subclass_list(struct ldb_context *ldb, const char *classname)
{
	int i;
	for (i=0;i<ldb->schema.num_classes;i++) {
		if (ldb_attr_cmp(classname, ldb->schema.classes[i].name) == 0) {
			return (const char **)ldb->schema.classes[i].subclasses;
		}
	}
	return NULL;
}


/*
  add a new subclass
*/
static int ldb_subclass_new(struct ldb_context *ldb, const char *classname, const char *subclass)
{
	struct ldb_subclass *s, *c;
	s = talloc_realloc(ldb, ldb->schema.classes, struct ldb_subclass, ldb->schema.num_classes+1);
	if (s == NULL) goto failed;

	ldb->schema.classes = s;
	c = &s[ldb->schema.num_classes];
	c->name = talloc_strdup(s, classname);
	if (c->name == NULL) goto failed;

	c->subclasses = talloc_array(s, char *, 2);
	if (c->subclasses == NULL) goto failed;

	c->subclasses[0] = talloc_strdup(c->subclasses, subclass);
	if (c->subclasses[0] == NULL) goto failed;
	c->subclasses[1] = NULL;

	ldb->schema.num_classes++;

	return 0;
failed:
	ldb_oom(ldb);
	return -1;
}

/*
  add a subclass
*/
int ldb_subclass_add(struct ldb_context *ldb, const char *classname, const char *subclass)
{
	int i, n;
	struct ldb_subclass *c;
	char **s;

	for (i=0;i<ldb->schema.num_classes;i++) {
		if (ldb_attr_cmp(classname, ldb->schema.classes[i].name) == 0) {
			break;
		}
	}
	if (i == ldb->schema.num_classes) {
		return ldb_subclass_new(ldb, classname, subclass);
	}
	c = &ldb->schema.classes[i];
	
	for (n=0;c->subclasses[n];n++) /* noop */;

	s = talloc_realloc(ldb->schema.classes, c->subclasses, char *, n+2);
	if (s == NULL) {
		ldb_oom(ldb);
		return -1;
	}

	c->subclasses = s;
	s[n] = talloc_strdup(s, subclass);
	if (s[n] == NULL) {
		ldb_oom(ldb);
		return -1;
	}
	s[n+1] = NULL;

	return 0;
}

/*
  remove a set of subclasses for a class
*/
void ldb_subclass_remove(struct ldb_context *ldb, const char *classname)
{
	int i;
	struct ldb_subclass *c;

	for (i=0;i<ldb->schema.num_classes;i++) {
		if (ldb_attr_cmp(classname, ldb->schema.classes[i].name) == 0) {
			break;
		}
	}
	if (i == ldb->schema.num_classes) {
		return;
	}

	c = &ldb->schema.classes[i];
	talloc_free(c->name);
	talloc_free(c->subclasses);
	if (ldb->schema.num_classes-(i+1) > 0) {
		memmove(c, c+1, sizeof(*c) * (ldb->schema.num_classes-(i+1)));
	}
	ldb->schema.num_classes--;
	if (ldb->schema.num_classes == 0) {
		talloc_free(ldb->schema.classes);
		ldb->schema.classes = NULL;
	}
}
