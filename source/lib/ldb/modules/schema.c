/* 
   ldb database library

   Copyright (C) Simo Sorce  2004

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
 *  Component: ldb schema module
 *
 *  Description: add schema check functionality
 *
 *  Author: Simo Sorce
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"

struct attribute_syntax {
	const char *name;
	const char *syntax_id;
};

static struct attribute_syntax attrsyn[] = {
		{ "Object(DS-DN)", "2.5.5.1"},
		{ "String(Object-Identifier)", "2.5.5.2"},
		{ "", "2.5.5.3"},
		{ "String(Teletex)", "2.5.5.4"},
		{ "String(IA5)", "2.5.5.5"}, /* Also String(Printable) */
		{ "String(Numeric)", "2.5.5.6"},
		{ "Object(DN-Binary)", "2.5.5.7"}, /* Also Object(OR-Name) */
		{ "Boolean", "2.5.5.8"},
		{ "Integer", "2.5.5.9"}, /* Also Enumeration (3 types ?) ... */
		{ "String(Octet)", "2.5.5.10"}, /* Also Object(Replica-Link) */
		{ "String(UTC-Time)", "2.5.5.11"}, /* Also String(Generalized-Time) */
		{ "String(Unicode)", "2.5.5.12"},
		{ "Object(Presentation-Address)", "2.5.5.13"},
		{ "Object(DN-String)", "2.5.5.14"}, /* Also Object(Access-Point) */
		{ "String(NT-Sec-Desc))", "2.5.5.15"},
		{ "LargeInteger", "2.5.5.16"}, /* Also Interval ... */
		{ "String(Sid)", "2.5.5.17"}
	};

#define SCHEMA_TALLOC_CHECK(root, mem, ret) do { if (!mem) { talloc_free(root); return ret;} } while(0);

#define SA_FLAG_RESET   	0
#define SA_FLAG_AUXCLASS 	1
#define SA_FLAG_CHECKED  	2

struct private_data {
	struct ldb_context *schema_db;
	const char *error_string;
};

/* close */
static int schema_close(struct ldb_module *module)
{
	return ldb_next_close(module);
}

/* search */
static int schema_search(struct ldb_module *module, const char *base,
		       enum ldb_scope scope, const char *expression,
		       const char * const *attrs, struct ldb_message ***res)
{
	return ldb_next_search(module, base, scope, expression, attrs, res); 
}

/* search_free */
static int schema_search_free(struct ldb_module *module, struct ldb_message **res)
{
	return ldb_next_search_free(module, res);
}

struct attribute_list {
	int flags;
	char *name;
};

struct schema_structures {
	struct attribute_list *check_list;
	struct attribute_list *objectclass_list;
	struct attribute_list *must;
	struct attribute_list *may;
	int check_list_num;
	int objectclass_list_num;
	int must_num;
	int may_num;
};

static int get_object_objectclasses(struct ldb_context *ldb, const char *dn, struct schema_structures *schema_struct)
{
	char *filter = talloc_asprintf(schema_struct, "dn=%s", dn);
	const char *attrs[] = {"objectClass", NULL};
	struct ldb_message **srch;
	int i, j, ret;

	schema_struct->objectclass_list = NULL;
	schema_struct->objectclass_list_num = 0;
	ret = ldb_search(ldb, NULL, LDB_SCOPE_SUBTREE, filter, attrs, &srch);
	if (ret == 1) {
		for (i = 0; i < (*srch)->num_elements; i++) {
			schema_struct->objectclass_list_num = (*srch)->elements[i].num_values;
			schema_struct->objectclass_list = talloc_array(schema_struct,
									 struct attribute_list,
									 schema_struct->objectclass_list_num);
			if (schema_struct->objectclass_list == 0) {
				ldb_search_free(ldb, srch);
				return -1;
			}
			for (j = 0; j < schema_struct->objectclass_list_num; j++) {
				schema_struct->objectclass_list[j].name = talloc_strndup(schema_struct->objectclass_list,
											 (*srch)->elements[i].values[j].data,
											 (*srch)->elements[i].values[j].length);
				if (schema_struct->objectclass_list[j].name == 0) {
					ldb_search_free(ldb, srch);
					return -1;
				}
				schema_struct->objectclass_list[j].flags = SA_FLAG_RESET;
			}
		}
		ldb_search_free(ldb, srch);
	} else {
		ldb_search_free(ldb, srch);
		return -1;
	}

	return 0;
}

static int get_check_list(struct ldb_module *module, struct schema_structures *schema_struct, const struct ldb_message *msg)
{
	int i, j, k;

	schema_struct->objectclass_list = NULL;
	schema_struct->objectclass_list_num = 0;
	schema_struct->check_list_num = msg->num_elements;
	schema_struct->check_list = talloc_array(schema_struct,
						   struct attribute_list,
						   schema_struct->check_list_num);
	if (schema_struct->check_list == 0) {
		return -1;
	}
	for (i = 0, j = 0; i < msg->num_elements; i++) {
		if (strcasecmp(msg->elements[i].name, "objectclass") == 0) {
			schema_struct->objectclass_list_num = msg->elements[i].num_values;
			schema_struct->objectclass_list = talloc_array(schema_struct,
									 struct attribute_list,
									 schema_struct->objectclass_list_num);
			if (schema_struct->objectclass_list == 0) {
				return -1;
			}
			for (k = 0; k < schema_struct->objectclass_list_num; k++) {
				schema_struct->objectclass_list[k].name = talloc_strndup(schema_struct->objectclass_list,
											 msg->elements[i].values[k].data,
											 msg->elements[i].values[k].length);
				if (schema_struct->objectclass_list[k].name == 0) {
					return -1;
				}
				schema_struct->objectclass_list[k].flags = SA_FLAG_RESET;
			}
		}

		schema_struct->check_list[j].flags = SA_FLAG_RESET;
		schema_struct->check_list[j].name = talloc_strdup(schema_struct->check_list,
								  msg->elements[i].name);
		if (schema_struct->check_list[j].name == 0) {
			return -1;
		}
		j++;
	}

	return 0;
}

static int add_attribute_uniq(struct attribute_list **list, int *list_num, int flags, struct ldb_message_element *el, void *mem_ctx)
{
	int i, j, vals;

	vals = el->num_values;
	*list = talloc_realloc(mem_ctx, *list, struct attribute_list, *list_num + vals);
	if (list == 0) {
		return -1;
	}
	for (i = 0, j = 0; i < vals; i++) {
		int c, found, len;

		found = 0;
		for (c = 0; c < *list_num; c++) {
			len = strlen((*list)[c].name);
			if (len == el->values[i].length) {
				if (strncasecmp((*list)[c].name, el->values[i].data, len) == 0) {
					found = 1;
					break;
				}
			}
		}
		if (!found) {
			(*list)[j + *list_num].name = talloc_strndup(*list, el->values[i].data, el->values[i].length);
			if ((*list)[j + *list_num].name == 0) {
				return -1;
			}
			(*list)[j + *list_num].flags = flags;
			j++;
		}
	}
	*list_num += j;

	return 0;
}

static int get_attr_list_recursive(struct ldb_module *module, struct ldb_context *ldb, struct schema_structures *schema_struct)
{
	struct private_data *data = (struct private_data *)module->private_data;
	struct ldb_message **srch;
	int i, j;
	int ret;

	schema_struct->must = NULL;
	schema_struct->may = NULL;
	schema_struct->must_num = 0;
	schema_struct->may_num = 0;
	for (i = 0; i < schema_struct->objectclass_list_num; i++) {
		char *filter;

		filter = talloc_asprintf(schema_struct, "lDAPDisplayName=%s", schema_struct->objectclass_list[i].name);
		SCHEMA_TALLOC_CHECK(schema_struct, filter, -1);
		ret = ldb_search(ldb, NULL, LDB_SCOPE_SUBTREE, filter, NULL, &srch);
		if (ret == 0) {
			int ok;

			ok = 0;
			/* suppose auxiliary classeschema_struct are not required */
			if (schema_struct->objectclass_list[i].flags & SA_FLAG_AUXCLASS) {
				int d;
				ok = 1;
				schema_struct->objectclass_list_num -= 1;
				for (d = i; d < schema_struct->objectclass_list_num; d++) {
					schema_struct->objectclass_list[d] = schema_struct->objectclass_list[d + 1];
				}
				i -= 1;
			}
			if (!ok) {
				/* Schema Violation: Object Class Description Not Found */
				data->error_string = "ObjectClass not found";
				return -1;
			}
			continue;
		} else {
			if (ret < 0) {
				/* Schema DB Error: Error occurred retrieving Object Class Description */
				data->error_string = "Internal error. Error retrieving schema objectclass";
				return -1;
			}
			if (ret > 1) {
				/* Schema DB Error: Too Many Records */
				data->error_string = "Internal error. Too many records searching for schema objectclass";
				return -1;
			}
		}

		/* Add inherited classes eliminating duplicates */
		/* fill in kust and may attribute lists */
		for (j = 0; j < (*srch)->num_elements; j++) {
			int is_aux, is_class;

			is_aux = 0;
			is_class = 0;
			if (strcasecmp((*srch)->elements[j].name, "systemAuxiliaryclass") == 0) {
				is_aux = SA_FLAG_AUXCLASS;
				is_class = 1;
			}
			if (strcasecmp((*srch)->elements[j].name, "subClassOf") == 0) {
				is_class = 1;
			}

			if (is_class) {
				if (add_attribute_uniq(&schema_struct->objectclass_list,
							&schema_struct->objectclass_list_num,
							is_aux,
							&(*srch)->elements[j],
							schema_struct) != 0) {
					return -1;
				}
			} else {

				if (strcasecmp((*srch)->elements[j].name, "mustContain") == 0 ||
					strcasecmp((*srch)->elements[j].name, "SystemMustContain") == 0) {
					if (add_attribute_uniq(&schema_struct->must,
								&schema_struct->must_num,
								SA_FLAG_RESET,
								&(*srch)->elements[j],
								schema_struct) != 0) {
						return -1;
					}
				}

				if (strcasecmp((*srch)->elements[j].name, "mayContain") == 0 ||
				    strcasecmp((*srch)->elements[j].name, "SystemMayContain") == 0) {

					if (add_attribute_uniq(&schema_struct->may,
								&schema_struct->may_num,
								SA_FLAG_RESET,
								&(*srch)->elements[j],
								schema_struct) != 0) {
						return -1;
					}
				}
			}
		}

		ldb_search_free(ldb, srch);
	}

	return 0;
}

/* add_record */
static int schema_add_record(struct ldb_module *module, const struct ldb_message *msg)
{
	struct private_data *data = (struct private_data *)module->private_data;
	struct schema_structures *entry_structs;
	int i, j;
	int ret;

	/* First implementation:
		Build up a list of must and mays from each objectclass
		Check all the musts are there and all the other attributes are mays
		Throw an error in case a check fail
		Free all structures and commit the change
	*/

	entry_structs = talloc(module, struct schema_structures);
	if (!entry_structs) {
		return -1;
	}

	ret = get_check_list(module, entry_structs, msg);
	if (ret != 0) {
		talloc_free(entry_structs);
		return ret;
	}

	/* find all other objectclasses recursively */
	ret = get_attr_list_recursive(module, data->schema_db, entry_structs);
	if (ret != 0) {
		talloc_free(entry_structs);
		return ret;
	}

	/* now check all musts are present */
	for (i = 0; i < entry_structs->must_num; i++) {
		int found;

		found = 0;
		for (j = 0; j < entry_structs->check_list_num; j++) {
			if (strcasecmp(entry_structs->must[i].name, entry_structs->check_list[j].name) == 0) {
				entry_structs->check_list[j].flags = SA_FLAG_CHECKED;
				found = 1;
				break;
			}
		}

		if ( ! found ) {
			/* TODO: set the error string */
			data->error_string = "Objectclass violation, a required attribute is mischema_structing";
			talloc_free(entry_structs);
			return -1;
		}
	}

	/* now check all others atribs are found in mays */
	for (i = 0; i < entry_structs->check_list_num; i++) {

		if (entry_structs->check_list[i].flags != SA_FLAG_CHECKED) {
			int found;

			found = 0;
			for (j = 0; j < entry_structs->may_num; j++) {
				if (strcasecmp(entry_structs->may[j].name, entry_structs->check_list[i].name) == 0) {
					entry_structs->check_list[i].flags = SA_FLAG_CHECKED;
					found = 1;
					break;
				}
			}

			if ( ! found ) {
				data->error_string = "Objectclass violation, an invalid attribute name was found";
				talloc_free(entry_structs);
				return -1;
			}
		}
	}

	talloc_free(entry_structs);

	return ldb_next_add_record(module, msg);
}

/* modify_record */
static int schema_modify_record(struct ldb_module *module, const struct ldb_message *msg)
{
	struct private_data *data = (struct private_data *)module->private_data;
	struct schema_structures *entry_structs, *modify_structs;
	int i, j;
	int ret;

	/* First implementation:
		Retrieve the ldap entry and get the objectclasses,
		add msg contained objectclasses if any.
		Build up a list of must and mays from each objectclass
		Check all musts for the defined objectclass and it's specific
		inheritance are there.
		Check all other the attributes are mays or musts.
		Throw an error in case a check fail.
		Free all structures and commit the change.
	*/

	/* allocate object structs */
	entry_structs = talloc(module, struct schema_structures);
	if (!entry_structs) {
		return -1;
	}

	/* allocate modification entry structs */
	modify_structs = talloc(entry_structs, struct schema_structures);
	if (!modify_structs) {
		talloc_free(entry_structs);
		return -1;
	}

	/* get list of values to modify */
	ret = get_check_list(module, modify_structs, msg);
	if (ret != 0) {
		talloc_free(entry_structs);
		return ret;
	}

	/* find all modify objectclasses recursively if any objectclass is being added */
	ret = get_attr_list_recursive(module, data->schema_db, modify_structs);
	if (ret != 0) {
		talloc_free(entry_structs);
		return ret;
	}

	/* now search for the original object objectclasses */
	ret = get_object_objectclasses(module->ldb, msg->dn, entry_structs);
	if (ret != 0) {
		talloc_free(entry_structs);
		return ret;
	}

	/* find all other objectclasses recursively */
	ret = get_attr_list_recursive(module, data->schema_db, entry_structs);
	if (ret != 0) {
		talloc_free(entry_structs);
		return ret;
	}

	/* now check all entries are present either as musts or mays of curent objectclasses */
	/* do not return errors there may be attirbutes defined in new objectclasses */
	/* just mark them as being proved valid attribs */
	for (i = 0; i < modify_structs->check_list_num; i++) {
		int found;

		found = 0;
		for (j = 0; j < entry_structs->may_num; j++) {
			if (strcasecmp(entry_structs->may[j].name, modify_structs->check_list[i].name) == 0) {
				modify_structs->check_list[i].flags = SA_FLAG_CHECKED;
				found = 1;
				break;
			}
		}
		if ( ! found) {
			for (j = 0; j < entry_structs->must_num; j++) {
				if (strcasecmp(entry_structs->must[j].name, modify_structs->check_list[i].name) == 0) {
					modify_structs->check_list[i].flags = SA_FLAG_CHECKED;
					break;
				}
			}
		}
	}

	/* now check all new objectclasses musts are present */
	for (i = 0; i < modify_structs->must_num; i++) {
		int found;

		found = 0;
		for (j = 0; j < modify_structs->check_list_num; j++) {
			if (strcasecmp(modify_structs->must[i].name, modify_structs->check_list[j].name) == 0) {
				modify_structs->check_list[j].flags = SA_FLAG_CHECKED;
				found = 1;
				break;
			}
		}

		if ( ! found ) {
			/* TODO: set the error string */
			data->error_string = "Objectclass violation, a required attribute is missing";
			talloc_free(entry_structs);
			return -1;
		}
	}

	/* now check all others atribs are found in mays */
	for (i = 0; i < modify_structs->check_list_num; i++) {

		if (modify_structs->check_list[i].flags != SA_FLAG_CHECKED) {
			int found;

			found = 0;
			for (j = 0; j < modify_structs->may_num; j++) {
				if (strcasecmp(modify_structs->may[j].name, modify_structs->check_list[i].name) == 0) {
					modify_structs->check_list[i].flags = SA_FLAG_CHECKED;
					found = 1;
					break;
				}
			}

			if ( ! found ) {
				data->error_string = "Objectclass violation, an invalid attribute name was found";
				talloc_free(entry_structs);
				return -1;
			}
		}
	}

	talloc_free(entry_structs);

	return ldb_next_modify_record(module, msg);
}

/* delete_record */
static int schema_delete_record(struct ldb_module *module, const char *dn)
{
/*	struct private_data *data = (struct private_data *)module->private_data; */
	return ldb_next_delete_record(module, dn);
}

/* rename_record */
static int schema_rename_record(struct ldb_module *module, const char *olddn, const char *newdn)
{
	return ldb_next_rename_record(module, olddn, newdn);
}

static int schema_named_lock(struct ldb_module *module, const char *name) {
	return ldb_next_named_lock(module, name);
}

static int schema_named_unlock(struct ldb_module *module, const char *name) {
	return ldb_next_named_unlock(module, name);
}

/* return extended error information */
static const char *schema_errstring(struct ldb_module *module)
{
	struct private_data *data = (struct private_data *)module->private_data;

	if (data->error_string) {
		const char *error;

		error = data->error_string;
		data->error_string = NULL;
		return error;
	}

	return ldb_next_errstring(module);
}

static const struct ldb_module_ops schema_ops = {
	"schema",
	schema_close, 
	schema_search,
	schema_search_free,
	schema_add_record,
	schema_modify_record,
	schema_delete_record,
	schema_rename_record,
	schema_named_lock,
	schema_named_unlock,
	schema_errstring,
};

#define SCHEMA_PREFIX		"schema:"
#define SCHEMA_PREFIX_LEN	7

#ifdef HAVE_DLOPEN_DISABLED
struct ldb_module *init_module(struct ldb_context *ldb, const char *options[])
#else
struct ldb_module *schema_module_init(struct ldb_context *ldb, const char *options[])
#endif
{
	struct ldb_module *ctx;
	struct private_data *data;
	char *db_url = NULL;
	int i;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx) {
		return NULL;
	}

	if (options) {
		for (i = 0; options[i] != NULL; i++) {
			if (strncmp(options[i], SCHEMA_PREFIX, SCHEMA_PREFIX_LEN) == 0) {
				db_url = talloc_strdup(ctx, &options[i][SCHEMA_PREFIX_LEN]);
				SCHEMA_TALLOC_CHECK(ctx, db_url, NULL);
			}
		}
	}

	if (!db_url) { /* search if it is defined in the calling ldb */
		int ret;
		const char * attrs[] = { "@SCHEMADB", NULL };
		struct ldb_message **msgs;

		ret = ldb_search(ldb, "", LDB_SCOPE_BASE, "dn=@MODULES", (const char * const *)attrs, &msgs);
		if (ret == 0) {
			ldb_debug(ldb, LDB_DEBUG_TRACE, "Schema DB not found\n");
			ldb_search_free(ldb, msgs);
			return NULL;
		} else {
			if (ret < 0) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "ldb error (%s) occurred searching for schema db, bailing out!\n", ldb_errstring(ldb));
				ldb_search_free(ldb, msgs);
				return NULL;
			}
			if (ret > 1) {
				ldb_debug(ldb, LDB_DEBUG_FATAL, "Too many records found, bailing out\n");
				ldb_search_free(ldb, msgs);
				return NULL;
			}

			db_url = talloc_strndup(ctx, msgs[0]->elements[0].values[0].data, msgs[0]->elements[0].values[0].length);
			SCHEMA_TALLOC_CHECK(ctx, db_url, NULL);
		}

		ldb_search_free(ldb, msgs);
	}

	data = talloc(ctx, struct private_data);
	SCHEMA_TALLOC_CHECK(ctx, data, NULL);

	data->schema_db = ldb_connect(db_url, 0, NULL); 
	SCHEMA_TALLOC_CHECK(ctx, data->schema_db, NULL);

	data->error_string = NULL;
	ctx->private_data = data;
	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &schema_ops;

	return ctx;
}
