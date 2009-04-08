/* 
   Unix SMB/CIFS mplementation.

   implement possibleInferiors calculation
   
   Copyright (C) Andrew Tridgell 2009
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2009

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
   
*/
/*
  This module is a C implementation of the logic in the
  dsdb/samdb/ldb_modules/tests/possibleInferiors.py code

  To understand the C code, please see the python code first
 */

#include "includes.h"
#include "dsdb/samdb/samdb.h"



/*
  create the SUPCLASSES() list
 */
static char * const *schema_supclasses(struct dsdb_schema *schema, 
				       TALLOC_CTX *mem_ctx, struct dsdb_class *schema_class)
{
	char * const *list;

	if (schema_class->supclasses) {
		return schema_class->supclasses;
	}

	list = str_list_make(mem_ctx, NULL, NULL);
	if (list == NULL) {
		DEBUG(0,(__location__ " out of memory\n"));
		return NULL;
	}

	/* Cope with 'top SUP top', ie top is subClassOf top */ 
	if (strcmp(schema_class->lDAPDisplayName, schema_class->subClassOf) == 0) {
		schema_class->supclasses = list;
		return list;
	}

	if (schema_class->subClassOf) {
		char **list2;
		list = str_list_add(list, schema_class->subClassOf);

		list2 = schema_supclasses(schema, mem_ctx, dsdb_class_by_lDAPDisplayName(schema, schema_class->subClassOf));
		list = str_list_append(list, list2);
	}

	schema_class->supclasses = list;
	
	return list;
}

/*
  this one is used internally
  matches SUBCLASSES() python function
 */
static char **schema_subclasses(struct dsdb_schema *schema, TALLOC_CTX *mem_ctx,
				const char * const *oclist)
{
	char **list = str_list_make(mem_ctx, NULL, NULL);
	int i;

	for (i=0; oclist && oclist[i]; i++) {
		struct dsdb_class *schema_class = dsdb_class_by_lDAPDisplayName(schema, oclist[i]);
		list = str_list_append(list, schema_class->subclasses);
	}
	return list;
}


/* 
   equivalent of the POSSSUPERIORS() python function
 */
static char **schema_posssuperiors(struct dsdb_schema *schema, TALLOC_CTX *mem_ctx,
				   struct dsdb_class *schema_class)
{
	char **list = str_list_make(mem_ctx, NULL, NULL);

	if (schema_class->posssuperiors) {
		return schema_class->posssuperiors;
	} else {
		char * const *list2 = str_list_make(mem_ctx, NULL, NULL);
		list2 = str_list_append(list2, schema_class->systemPossSuperiors);
		list2 = str_list_append(list2, schema_class->possSuperiors);
		list2 = str_list_append(list2, schema_supclasses(schema, list2, schema_class));
		list2 = str_list_append(list2, schema_subclasses(schema, list2, list2));

		schema_class->posssuperiors = list2;
		return schema_class->posssuperiors;
	}

	return list;
}

static char **schema_subclasses_recurse(struct dsdb_schema *schema, struct dsdb_class *schema_class)
{
	char * const *list = str_list_copy(schema_class, schema_class->subclasses_direct);
	int i;
	for (i=0;list && list[i]; i++) {
		struct dsdb_class *schema_class2 = dsdb_class_by_lDAPDisplayName(schema, list[i]);
		if (schema_class != schema_class2) {
			list = str_list_append(list, schema_subclasses_recurse(schema, schema_class2));
		}
	}
	return list;
}

static void schema_create_subclasses(struct dsdb_schema *schema)
{
	struct dsdb_class *schema_class;

	for (schema_class=schema->classes; schema_class; schema_class=schema_class->next) {
		struct dsdb_class *schema_class2 = dsdb_class_by_lDAPDisplayName(schema, schema_class->subClassOf);
		schema_class->subclasses_direct = str_list_make(schema_class, NULL, NULL);
		if (schema_class != schema_class2) {
			if (schema_class2->subclasses_direct == NULL) {
				schema_class2->subclasses_direct = str_list_make(schema_class2, NULL, NULL);
			}
			schema_class2->subclasses_direct = str_list_add(schema_class2->subclasses_direct, 
									schema_class->subClassOf);
		}
	}

	for (schema_class=schema->classes; schema_class; schema_class=schema_class->next) {
		schema_class->subclasses = schema_subclasses_recurse(schema, schema_class);
	}	
}

static void schema_fill_possible_inferiors(struct dsdb_schema *schema, struct dsdb_class *schema_class)
{
	struct dsdb_class *c2;

	for (c2=schema->classes; c2; c2=c2->next) {
		char **superiors = schema_posssuperiors(schema, c2, c2);
		if (c2->systemOnly == false 
		    && c2->objectClassCategory != 2 
		    && c2->objectClassCategory != 3
		    && str_list_check(superiors, schema_class->lDAPDisplayName)) {
			if (c2->possible_inferiors == NULL) {
				c2->possible_inferiors = str_list_make(c2, NULL, NULL);
			}
			c2->possible_inferiors = str_list_add_unique(c2->possible_inferiors,
								     schema_class->lDAPDisplayName);
		}
		talloc_free(superiors);
	}
}

void schema_fill_constructed(struct dsdb_schema *schema) 
{
	struct dsdb_class *schema_class;

	schema_create_subclasses(schema);

	for (schema_class=schema->classes; schema_class; schema_class=schema_class->next) {
		schema_fill_possible_inferiors(schema, schema_class);
	}
}
