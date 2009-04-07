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
static char **schema_supclasses(struct dsdb_schema *schema, 
				TALLOC_CTX *mem_ctx, const char *oc)
{
	char **list;
	const struct dsdb_class *class;

	list = str_list_make(mem_ctx, NULL, NULL);
	if (list == NULL) {
		DEBUG(0,(__location__ " out of memory\n"));
		return NULL;
	}

	if (strcmp(oc, "top") == 0) {
		return list;
	}

	class = dsdb_class_by_lDAPDisplayName(schema, oc);
	if (class == NULL) {
		DEBUG(0,(__location__ " objectClass '%s' does not exist\n", oc));
		return NULL;
	}
	
	if (class->supclasses) {
		return class->supclasses;
	}

	if (class->subClassOf) {
		char **list2;
		list = str_list_add(list, class->subClassOf);
		list2 = schema_supclasses(schema, mem_ctx, class->subClassOf);
		list = str_list_append(list, list2);
	}

	class->supclasses = list;
	
	return list;
}

/*
  this one is used internally
  matches SUBCLASSES() python function
 */
static char **schema_subclasses(struct dsdb_schema *schema, TALLOC_CTX *mem_ctx,
				const char **oclist)
{
	const char *oc;
	char **list = str_list_make(mem_ctx, NULL, NULL);
	int i;

	for (i=0; oclist && oclist[i]; i++) {
		struct dsdb_class *class = dsdb_class_by_lDAPDisplayName(schema, oclist[i]);
		list = str_list_append(list, class->subclasses);
	}
	return list;
}


/* 
   equivalent of the POSSSUPERIORS() python function
 */
static char **schema_posssuperiors(struct dsdb_schema *schema, TALLOC_CTX *mem_ctx,
				   const char **oclist)
{
	const char *oc;
	char **list = str_list_make(mem_ctx, NULL, NULL);
	int i;

	for (i=0; oclist && oclist[i]; i++) {
		struct dsdb_class *class = dsdb_class_by_lDAPDisplayName(schema, oclist[i]);
		if (class->posssuperiors) {
			list = str_list_append(list, class->posssuperiors);
		} else {
			char **list2 = str_list_make(mem_ctx, NULL, NULL);
			list2 = str_list_append(list2, class->systemPossSuperiors);
			list2 = str_list_append(list2, class->possSuperiors);
			list2 = str_list_append(list2, schema_supclasses(schema, list2, oclist[i]));
			list2 = str_list_append(list2, schema_subclasses(schema, list2, list2));
			class->posssuperiors = list2;
			list = str_list_append(list, list2);
		}
	}

	return list;
}

static char **schema_subclasses_recurse(struct dsdb_schema *schema, struct dsdb_class *class)
{
	char **list = str_list_copy(class, class->subclasses_direct);
	int i;
	for (i=0;list && list[i]; i++) {
		struct dsdb_class *class2 = dsdb_class_by_lDAPDisplayName(schema, list[i]);
		list = str_list_append(list, schema_subclasses_recurse(schema, class2));
	}
	return list;
}

static void schema_create_subclasses(struct dsdb_schema *schema)
{
	struct dsdb_class *class;

	for (class=schema->classes; class; class=class->next) {
		struct dsdb_class *class2 = dsdb_class_by_lDAPDisplayName(schema, class->subClassOf);
		class->subclasses_direct = str_list_make(class, NULL, NULL);
		if (class != class2) {
			if (class2->subclasses_direct == NULL) {
				class2->subclasses_direct = str_list_make(class2, NULL, NULL);
			}
			class2->subclasses_direct = str_list_add(class2->subclasses_direct, 
								 class->subClassOf);
		}
	}

	for (class=schema->classes; class; class=class->next) {
		class->subclasses = schema_subclasses_recurse(schema, class);
	}	
}

void schema_fill_possible_inferiors(struct dsdb_schema *schema, struct dsdb_class *class)
{
	struct dsdb_class *c2;
	
}

def possible_inferiors_constructed(db, classinfo, c):
    list = []
    for oc in classinfo:
        superiors = POSSSUPERIORS(classinfo, [oc])
        if (is_in_list(superiors, c) and
            classinfo[oc]["systemOnly"] == False and
            classinfo[oc]["objectClassCategory"] != 2 and
            classinfo[oc]["objectClassCategory"] != 3):
            list.append(oc)
    list = uniq_list(list)
    list.sort()
    return list
