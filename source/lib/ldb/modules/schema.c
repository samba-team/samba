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

#define SCHEMA_FLAG_RESET	0
#define SCHEMA_FLAG_MOD_MASK	0x03
#define SCHEMA_FLAG_MOD_ADD	0x01
#define SCHEMA_FLAG_MOD_REPLACE	0x02
#define SCHEMA_FLAG_MOD_DELETE	0x03
#define SCHEMA_FLAG_AUXCLASS 	0x10
#define SCHEMA_FLAG_CHECKED  	0x20


struct private_data {
	const char *error_string;
};

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

/* This function embedds the knowledge of aliased names.
   Currently it handles only dn vs distinguishedNAme as a special case as AD
   only have this special alias case, in future we should read the schema
   to find out which names have an alias and check for them */
static int schema_attr_cmp(const char *attr1, const char *attr2)
{
	int ret;

	ret = ldb_attr_cmp(attr1, attr2);
	if (ret != 0) {
		if ((ldb_attr_cmp("dn", attr1) == 0) &&
		    (ldb_attr_cmp("distinguishedName", attr2) == 0)) {
			return 0;
		}
		if ((ldb_attr_cmp("dn", attr2) == 0) &&
		    (ldb_attr_cmp("distinguishedName", attr1) == 0)) {
			return 0;
		}
	}
	return ret;
}

struct attribute_list *schema_find_attribute(struct attribute_list *list, int attr_num, const char *attr_name)
{
	unsigned int i;
	for (i = 0; i < attr_num; i++) {
		if (ldb_attr_cmp(list[i].name, attr_name) == 0) {
			return &list[i];
		}
	}
	return NULL;
}

/* get objectclasses of dn */
static int get_object_objectclasses(struct ldb_context *ldb, const char *dn, struct schema_structures *schema_struct)
{
	char *filter = talloc_asprintf(schema_struct, "dn=%s", dn);
	const char *attrs[] = {"objectClass", NULL};
	struct ldb_message **srch;
	int i, j, ret;

	schema_struct->objectclass_list = NULL;
	schema_struct->objectclass_list_num = 0;
	ret = ldb_search(ldb, NULL, LDB_SCOPE_SUBTREE, filter, attrs, &srch);
	if (ret != 1) {
		ldb_search_free(ldb, srch);
		return -1;
	}

	for (i = 0; i < (*srch)->num_elements; i++) {
		schema_struct->objectclass_list_num = (*srch)->elements[i].num_values;
		schema_struct->objectclass_list = talloc_array(schema_struct,
								 struct attribute_list,
								 schema_struct->objectclass_list_num);
		if (schema_struct->objectclass_list == NULL) {
			ldb_search_free(ldb, srch);
			return -1;
		}
		for (j = 0; j < schema_struct->objectclass_list_num; j++) {
			schema_struct->objectclass_list[j].name = talloc_strndup(schema_struct->objectclass_list,
									 (*srch)->elements[i].values[j].data,
										 (*srch)->elements[i].values[j].length);
			if (schema_struct->objectclass_list[j].name == NULL) {
				ldb_search_free(ldb, srch);
				return -1;
			}
			schema_struct->objectclass_list[j].flags = SCHEMA_FLAG_RESET;
		}
	}
	ldb_search_free(ldb, srch);

	return 0;
}

/* get all the attributes and objectclasses found in msg and put them in schema_structure
   attributes go in the check_list structure for later checking
   objectclasses go in the objectclass_list structure */
static int get_check_list(struct ldb_module *module, struct schema_structures *schema_struct, const struct ldb_message *msg)
{
	int i, j, k;

	schema_struct->objectclass_list = NULL;
	schema_struct->objectclass_list_num = 0;
	schema_struct->check_list_num = msg->num_elements;
	schema_struct->check_list = talloc_array(schema_struct,
						   struct attribute_list,
						   schema_struct->check_list_num);
	if (schema_struct->check_list == NULL) {
		return -1;
	}
	for (i = 0, j = 0; i < msg->num_elements; i++) {
		if (schema_attr_cmp(msg->elements[i].name, "objectclass") == 0) {
			schema_struct->objectclass_list_num = msg->elements[i].num_values;
			schema_struct->objectclass_list = talloc_array(schema_struct,
									 struct attribute_list,
									 schema_struct->objectclass_list_num);
			if (schema_struct->objectclass_list == NULL) {
				return -1;
			}
			for (k = 0; k < schema_struct->objectclass_list_num; k++) {
				schema_struct->objectclass_list[k].name = talloc_strndup(schema_struct->objectclass_list,
											 msg->elements[i].values[k].data,
											 msg->elements[i].values[k].length);
				if (schema_struct->objectclass_list[k].name == NULL) {
					return -1;
				}
				schema_struct->objectclass_list[k].flags = msg->elements[i].flags;
			}
		}

		schema_struct->check_list[j].flags = msg->elements[i].flags;
		schema_struct->check_list[j].name = talloc_strdup(schema_struct->check_list,
								  msg->elements[i].name);
		if (schema_struct->check_list[j].name == NULL) {
			return -1;
		}
		j++;
	}

	return 0;
}

/* add all attributes in el avoiding duplicates in attribute_list */
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


/* we need to get all attributes referenced by the entry objectclasses,
   recursively get parent objectlasses attributes */
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

		if ((schema_struct->objectclass_list[i].flags & SCHEMA_FLAG_MOD_MASK) == SCHEMA_FLAG_MOD_DELETE) {
			continue;
		}
		filter = talloc_asprintf(schema_struct, "lDAPDisplayName=%s", schema_struct->objectclass_list[i].name);
		if (filter == NULL) {
			return -1;
		}

		ret = ldb_search(ldb, NULL, LDB_SCOPE_SUBTREE, filter, NULL, &srch);

		if (ret <= 0) {
			/* Schema DB Error: Error occurred retrieving Object Class Description */
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Error retrieving Objectclass %s.\n", schema_struct->objectclass_list[i].name);
			data->error_string = "Internal error. Error retrieving schema objectclass";
			return -1;
		}
		if (ret > 1) {
			/* Schema DB Error: Too Many Records */
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Too many records found retrieving Objectclass %s.\n", schema_struct->objectclass_list[i].name);
			data->error_string = "Internal error. Too many records searching for schema objectclass";
			return -1;
		}

		/* Add inherited classes eliminating duplicates */
		/* fill in required and optional attribute lists */
		for (j = 0; j < (*srch)->num_elements; j++) {
			int is_aux, is_class;

			is_aux = 0;
			is_class = 0;
			if (schema_attr_cmp((*srch)->elements[j].name, "systemAuxiliaryclass") == 0) {
				is_aux = SCHEMA_FLAG_AUXCLASS;
				is_class = 1;
			}
			if (schema_attr_cmp((*srch)->elements[j].name, "subClassOf") == 0) {
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

				if (schema_attr_cmp((*srch)->elements[j].name, "mustContain") == 0 ||
					schema_attr_cmp((*srch)->elements[j].name, "SystemMustContain") == 0) {
					if (add_attribute_uniq(&schema_struct->must,
								&schema_struct->must_num,
								SCHEMA_FLAG_RESET,
								&(*srch)->elements[j],
								schema_struct) != 0) {
						return -1;
					}
				}

				if (schema_attr_cmp((*srch)->elements[j].name, "mayContain") == 0 ||
				    schema_attr_cmp((*srch)->elements[j].name, "SystemMayContain") == 0) {

					if (add_attribute_uniq(&schema_struct->may,
								&schema_struct->may_num,
								SCHEMA_FLAG_RESET,
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

/* add_record */
static int schema_add_record(struct ldb_module *module, const struct ldb_message *msg)
{
	struct private_data *data = (struct private_data *)module->private_data;
	struct schema_structures *entry_structs;
	unsigned int i;
	int ret;

	/* First implementation:
		Build up a list of required and optional attributes from each objectclass
		Check all the required attributes are present and all the other attributes
		are optional attributes
		Throw an error in case a check fail
		Free all structures and commit the change
	*/

	if (msg->dn[0] == '@') { /* do not check on our control entries */
		return ldb_next_add_record(module, msg);
	}

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
	ret = get_attr_list_recursive(module, module->ldb, entry_structs);
	if (ret != 0) {
		talloc_free(entry_structs);
		return ret;
	}

	/* now check all required attributes are present */
	for (i = 0; i < entry_structs->must_num; i++) {
		struct attribute_list *attr;

		attr = schema_find_attribute(entry_structs->check_list,
					     entry_structs->check_list_num,
					     entry_structs->must[i].name);

		if (attr == NULL) { /* not found */
			ldb_debug(module->ldb, LDB_DEBUG_ERROR,
				  "The required attribute %s is missing.\n",
				  entry_structs->must[i].name);

			data->error_string = "Objectclass violation, a required attribute is missing";
			talloc_free(entry_structs);
			return -1;
		}

		/* mark the attribute as checked */
		attr->flags = SCHEMA_FLAG_CHECKED;
	}

	/* now check all others atribs are at least optional */
	for (i = 0; i < entry_structs->check_list_num; i++) {

		if (entry_structs->check_list[i].flags != SCHEMA_FLAG_CHECKED) {
			struct attribute_list *attr;

			attr = schema_find_attribute(entry_structs->may,
						     entry_structs->may_num,
						     entry_structs->check_list[i].name);

			if (attr == NULL) { /* not found */
				ldb_debug(module->ldb, LDB_DEBUG_ERROR,
					  "The attribute %s is not referenced by any objectclass.\n",
					  entry_structs->check_list[i].name);

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
	unsigned int i;
	int ret;

	/* First implementation:
		Retrieve the ldap entry and get the objectclasses,
		add msg contained objectclasses if any.
		Build up a list of required and optional attributes from each objectclass
		Check all required one for the defined objectclass and all its parent
		objectclasses.
		Check all other the attributes are optional or required.
		Throw an error in case a check fail.
		Free all structures and commit the change.
	*/

	if (msg->dn[0] == '@') { /* do not check on our control entries */
		return ldb_next_modify_record(module, msg);
	}

	/* allocate object structs */
	entry_structs = talloc_zero(module, struct schema_structures);
	if (!entry_structs) {
		return -1;
	}

	/* allocate modification entry structs */
	modify_structs = talloc_zero(entry_structs, struct schema_structures);
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
	ret = get_attr_list_recursive(module, module->ldb, modify_structs);
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
	ret = get_attr_list_recursive(module, module->ldb, entry_structs);
	if (ret != 0) {
		talloc_free(entry_structs);
		return ret;
	}

	/* now check all entries are present either as required or optional atributes of entry objectclasses */
	/* if they are required and we are going to delete them then throw an error */
	/* just mark them if being proved valid attribs */
	for (i = 0; i < modify_structs->check_list_num; i++) {
		struct attribute_list *attr;

		attr = schema_find_attribute(entry_structs->must,
					     entry_structs->must_num,
					     modify_structs->check_list[i].name);

		if (attr == NULL) { /* not found */

			attr = schema_find_attribute(entry_structs->may,
						     entry_structs->may_num,
						     modify_structs->check_list[i].name);

			if (attr != NULL) { /* found*/
				modify_structs->check_list[i].flags |= SCHEMA_FLAG_CHECKED;
			}

			break; /* not found, go on */
		}

		if ((modify_structs->check_list[i].flags & SCHEMA_FLAG_MOD_MASK) == SCHEMA_FLAG_MOD_DELETE) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR,
				  "Trying to delete the required attribute %s.\n",
				  modify_structs->check_list[i].name);

			data->error_string = "Objectclass violation: trying to delete a required attribute";
			talloc_free(entry_structs);
			return -1;
		}

		modify_structs->check_list[i].flags |= SCHEMA_FLAG_CHECKED;
	}

	/* now check all new objectclasses required attributes are present */
	for (i = 0; i < modify_structs->must_num; i++) {
		struct attribute_list *attr;

		attr = schema_find_attribute(modify_structs->check_list,
					     modify_structs->check_list_num,
					     modify_structs->must[i].name);


		if (attr == NULL) { /* not found */
			ldb_debug(module->ldb, LDB_DEBUG_ERROR,
				  "The required attribute %s is missing.\n",
				  modify_structs->must[i].name);

			data->error_string = "Objectclass violation, a required attribute is missing";
			talloc_free(entry_structs);
			return -1;
		}

		if ((modify_structs->check_list[i].flags & SCHEMA_FLAG_MOD_MASK) == SCHEMA_FLAG_MOD_DELETE) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR,
				  "Trying to delete the required attribute %s.\n",
				  modify_structs->must[i].name);

			data->error_string = "Objectclass violation: trying to delete a required attribute";
			talloc_free(entry_structs);
			return -1;
		}

		attr->flags |= SCHEMA_FLAG_CHECKED;
	}

	/* now check all others attributes are at least optional */
	for (i = 0; i < modify_structs->check_list_num; i++) {

		if ((modify_structs->check_list[i].flags & SCHEMA_FLAG_CHECKED) == 0 &&
		    (modify_structs->check_list[i].flags & SCHEMA_FLAG_MOD_MASK) != SCHEMA_FLAG_MOD_DELETE) {
			struct attribute_list *attr;

			attr = schema_find_attribute(modify_structs->may,
						     modify_structs->may_num,
						     modify_structs->check_list[i].name);


			if (attr == NULL) { /* not found */
				ldb_debug(module->ldb, LDB_DEBUG_ERROR,
					  "The attribute %s is not referenced by any objectclass.\n",
					  modify_structs->check_list[i].name);

				data->error_string = "Objectclass violation, an invalid attribute name was found";
				talloc_free(entry_structs);
				return -1;
			}

			modify_structs->check_list[i].flags |= SCHEMA_FLAG_CHECKED;

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

#ifdef HAVE_DLOPEN_DISABLED
struct ldb_module *init_module(struct ldb_context *ldb, const char *options[])
#else
struct ldb_module *schema_module_init(struct ldb_context *ldb, const char *options[])
#endif
{
	struct ldb_module *ctx;
	struct private_data *data;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx) {
		return NULL;
	}

	data = talloc(ctx, struct private_data);
	if (data == NULL) {
		talloc_free(ctx);
		return NULL;
	}

	data->error_string = NULL;
	ctx->private_data = data;
	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &schema_ops;

	return ctx;
}
