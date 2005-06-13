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
#define SCHEMA_FLAG_MOD_MASK	0x003
#define SCHEMA_FLAG_MOD_ADD	0x001
#define SCHEMA_FLAG_MOD_REPLACE	0x002
#define SCHEMA_FLAG_MOD_DELETE	0x003
#define SCHEMA_FLAG_AUXILIARY 	0x010
#define SCHEMA_FLAG_ABSTRACT	0x020
#define SCHEMA_FLAG_STRUCTURAL	0x040
#define SCHEMA_FLAG_CHECKED  	0x100


/* TODO: check attributes syntaxes
	 check there's only one structrual class (or a chain of structural classes)
*/

struct private_data {
	const char *error_string;
};

struct schema_attribute {
	int flags;
	char *name;
};

struct schema_attribute_list {
	struct schema_attribute *attr;
	int num;
};

struct schema_structures {
	struct schema_attribute_list entry_attrs;
	struct schema_attribute_list objectclasses;
	struct schema_attribute_list required_attrs;
	struct schema_attribute_list optional_attrs;
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

static struct schema_attribute *schema_find_attribute(struct schema_attribute_list *list, const char *attr_name)
{
	unsigned int i;
	for (i = 0; i < list->num; i++) {
		if (ldb_attr_cmp(list->attr[i].name, attr_name) == 0) {
			return &(list->attr[i]);
		}
	}
	return NULL;
}

/* get all the attributes and objectclasses found in msg and put them in schema_structure
   attributes go in the entry_attrs structure for later checking
   objectclasses go in the objectclasses structure */
static int get_msg_attributes(struct schema_structures *ss, const struct ldb_message *msg, int flag_mask)
{
	int i, j, k, l;

	ss->entry_attrs.attr = talloc_realloc(ss, ss->entry_attrs.attr,
					      struct schema_attribute,
					      ss->entry_attrs.num + msg->num_elements);
	if (ss->entry_attrs.attr == NULL) {
		return -1;
	}

	for (i = 0, j = ss->entry_attrs.num; i < msg->num_elements; i++) {

		if (schema_attr_cmp(msg->elements[i].name, "objectclass") == 0) {

			ss->objectclasses.attr = talloc_realloc(ss, ss->objectclasses.attr,
								struct schema_attribute,
								ss->objectclasses.num + msg->elements[i].num_values);
			if (ss->objectclasses.attr == NULL) {
				return -1;
			}

			for (k = 0, l = ss->objectclasses.num; k < msg->elements[i].num_values; k++) {
				ss->objectclasses.attr[l].name = msg->elements[i].values[k].data;
				ss->objectclasses.attr[l].flags = msg->elements[i].flags & flag_mask;
				l++;
			}
			ss->objectclasses.num += msg->elements[i].num_values;
		}

		ss->entry_attrs.attr[j].flags = msg->elements[i].flags & flag_mask;
		ss->entry_attrs.attr[j].name = talloc_reference(ss->entry_attrs.attr,
							    msg->elements[i].name);
		if (ss->entry_attrs.attr[j].name == NULL) {
			return -1;
		}
		j++;
	}
	ss->entry_attrs.num += msg->num_elements;

	return 0;
}

static int get_entry_attributes(struct ldb_context *ldb, const char *dn, struct schema_structures *ss)
{
	char *filter = talloc_asprintf(ss, "dn=%s", dn);
	struct ldb_message **srch;
	int ret;

	ret = ldb_search(ldb, NULL, LDB_SCOPE_SUBTREE, filter, NULL, &srch);
	if (ret != 1) {
		return ret;
	}
	talloc_steal(ss, srch);

	/* set flags to 0 as flags on search have undefined values */
	ret = get_msg_attributes(ss, *srch, 0);
	if (ret != 0) {
		talloc_free(srch);
		return ret;
	}

	return 0;
}

/* add all attributes in el avoiding duplicates in schema_attribute_list */
static int add_attribute_uniq(void *mem_ctx, struct schema_attribute_list *list, int flags, struct ldb_message_element *el)
{
	int i, j, vals;

	vals = el->num_values;
	list->attr = talloc_realloc(mem_ctx, list->attr, struct schema_attribute, list->num + vals);
	if (list->attr == NULL) {
		return -1;
	}
	for (i = 0, j = 0; i < vals; i++) {
		int c, found, len;

		found = 0;
		for (c = 0; c < list->num; c++) {
			len = strlen(list->attr[c].name);
			if (len == el->values[i].length) {
				if (schema_attr_cmp(list->attr[c].name, el->values[i].data) == 0) {
					found = 1;
					break;
				}
			}
		}
		if (!found) {
			list->attr[j + list->num].name = el->values[i].data;
			list->attr[j + list->num].flags = flags;
			j++;
		}
	}
	list->num += j;

	return 0;
}


/* we need to get all attributes referenced by the entry objectclasses,
   recursively get parent objectlasses attributes */
static int get_attr_list_recursive(struct ldb_module *module, struct schema_structures *schema_struct)
{
	struct private_data *data = (struct private_data *)module->private_data;
	struct ldb_message **srch;
	int i, j;
	int ret;

	for (i = 0; i < schema_struct->objectclasses.num; i++) {
		char *filter;

		if ((schema_struct->objectclasses.attr[i].flags & SCHEMA_FLAG_MOD_MASK) == SCHEMA_FLAG_MOD_DELETE) {
			continue;
		}
		filter = talloc_asprintf(schema_struct, "lDAPDisplayName=%s", schema_struct->objectclasses.attr[i].name);
		if (filter == NULL) {
			return -1;
		}

		ret = ldb_search(module->ldb, NULL, LDB_SCOPE_SUBTREE, filter, NULL, &srch);
		if (ret != 1) {
			return ret;
		}
		talloc_steal(schema_struct, srch);

		if (ret <= 0) {
			/* Schema DB Error: Error occurred retrieving Object Class Description */
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Error retrieving Objectclass %s.\n", schema_struct->objectclasses.attr[i].name);
			data->error_string = "Internal error. Error retrieving schema objectclass";
			return -1;
		}
		if (ret > 1) {
			/* Schema DB Error: Too Many Records */
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Too many records found retrieving Objectclass %s.\n", schema_struct->objectclasses.attr[i].name);
			data->error_string = "Internal error. Too many records searching for schema objectclass";
			return -1;
		}

		/* Add inherited classes eliminating duplicates */
		/* fill in required_attrs and optional_attrs attribute lists */
		for (j = 0; j < (*srch)->num_elements; j++) {
			int is_aux, is_class;

			is_aux = 0;
			is_class = 0;
			if (schema_attr_cmp((*srch)->elements[j].name, "systemAuxiliaryclass") == 0) {
				is_aux = SCHEMA_FLAG_AUXILIARY;
				is_class = 1;
			}
			if (schema_attr_cmp((*srch)->elements[j].name, "subClassOf") == 0) {
				is_class = 1;
			}

			if (is_class) {
				if (add_attribute_uniq(schema_struct,
							&schema_struct->objectclasses,
							is_aux,
							&(*srch)->elements[j]) != 0) {
					return -1;
				}
			} else {

				if (schema_attr_cmp((*srch)->elements[j].name, "mustContain") == 0 ||
					schema_attr_cmp((*srch)->elements[j].name, "SystemMustContain") == 0) {
					if (add_attribute_uniq(schema_struct,
								&schema_struct->required_attrs,
								SCHEMA_FLAG_RESET,
								&(*srch)->elements[j]) != 0) {
						return -1;
					}
				}

				if (schema_attr_cmp((*srch)->elements[j].name, "mayContain") == 0 ||
				    schema_attr_cmp((*srch)->elements[j].name, "SystemMayContain") == 0) {

					if (add_attribute_uniq(schema_struct,
								&schema_struct->optional_attrs,
								SCHEMA_FLAG_RESET,
								&(*srch)->elements[j]) != 0) {
						return -1;
					}
				}
			}
		}
	}

	return 0;
}

/* search */
static int schema_search(struct ldb_module *module, const char *base,
		       enum ldb_scope scope, const char *expression,
		       const char * const *attrs, struct ldb_message ***res)
{
	return ldb_next_search(module, base, scope, expression, attrs, res); 
}

static int schema_search_bytree(struct ldb_module *module, const char *base,
				enum ldb_scope scope, struct ldb_parse_tree *tree,
				const char * const *attrs, struct ldb_message ***res)
{
	return ldb_next_search_bytree(module, base, scope, tree, attrs, res); 
}

/* add_record */
static int schema_add_record(struct ldb_module *module, const struct ldb_message *msg)
{
	struct private_data *data = (struct private_data *)module->private_data;
	struct schema_structures *entry_structs;
	unsigned int i;
	int ret;

	/* First implementation:
		Build up a list of required_attrs and optional_attrs attributes from each objectclass
		Check all the required_attrs attributes are present and all the other attributes
		are optional_attrs attributes
		Throw an error in case a check fail
		Free all structures and commit the change
	*/

	if (msg->dn[0] == '@') { /* do not check on our control entries */
		return ldb_next_add_record(module, msg);
	}

	entry_structs = talloc_zero(module, struct schema_structures);
	if (!entry_structs) {
		return -1;
	}

	ret = get_msg_attributes(entry_structs, msg, SCHEMA_FLAG_MOD_MASK);
	if (ret != 0) {
		talloc_free(entry_structs);
		return ret;
	}

	ret = get_attr_list_recursive(module, entry_structs);
	if (ret != 0) {
		talloc_free(entry_structs);
		return ret;
	}

	/* now check all required_attrs attributes are present */
	for (i = 0; i < entry_structs->required_attrs.num; i++) {
		struct schema_attribute *attr;

		attr = schema_find_attribute(&entry_structs->entry_attrs,
					     entry_structs->required_attrs.attr[i].name);

		if (attr == NULL) { /* not found */
			ldb_debug(module->ldb, LDB_DEBUG_ERROR,
				  "The required_attrs attribute %s is missing.\n",
				  entry_structs->required_attrs.attr[i].name);

			data->error_string = "Objectclass violation, a required attribute is missing";
			talloc_free(entry_structs);
			return -1;
		}

		/* mark the attribute as checked */
		attr->flags = SCHEMA_FLAG_CHECKED;
	}

	/* now check all others atribs are at least optional_attrs */
	for (i = 0; i < entry_structs->entry_attrs.num; i++) {

		if (entry_structs->entry_attrs.attr[i].flags != SCHEMA_FLAG_CHECKED) {
			struct schema_attribute *attr;

			attr = schema_find_attribute(&entry_structs->optional_attrs,
						     entry_structs->entry_attrs.attr[i].name);

			if (attr == NULL) { /* not found */
				ldb_debug(module->ldb, LDB_DEBUG_ERROR,
					  "The attribute %s is not referenced by any objectclass.\n",
					  entry_structs->entry_attrs.attr[i].name);

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
	struct schema_structures *entry_structs;
	unsigned int i;
	int ret;

	/* First implementation:
		Retrieve the ldap entry and get the objectclasses,
		add msg contained objectclasses if any.
		Build up a list of required_attrs and optional_attrs attributes from each objectclass
		Check all the attributes are optional_attrs or required_attrs.
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

	/* now search for the stored entry objectclasses and attributes*/
	ret = get_entry_attributes(module->ldb, msg->dn, entry_structs);
	if (ret != 0) {
		talloc_free(entry_structs);
		return ret;
	}

	/* get list of values to modify */
	ret = get_msg_attributes(entry_structs, msg, SCHEMA_FLAG_MOD_MASK);
	if (ret != 0) {
		talloc_free(entry_structs);
		return ret;
	}

	ret = get_attr_list_recursive(module, entry_structs);
	if (ret != 0) {
		talloc_free(entry_structs);
		return ret;
	}

	/* now check all required_attrs attributes are present */
	for (i = 0; i < entry_structs->required_attrs.num; i++) {
		struct schema_attribute *attr;

		attr = schema_find_attribute(&entry_structs->entry_attrs,
					     entry_structs->required_attrs.attr[i].name);

		if (attr == NULL) { /* not found */
			ldb_debug(module->ldb, LDB_DEBUG_ERROR,
				  "The required_attrs attribute %s is missing.\n",
				  entry_structs->required_attrs.attr[i].name);

			data->error_string = "Objectclass violation, a required attribute is missing";
			talloc_free(entry_structs);
			return -1;
		}

		/* check we are not trying to delete a required attribute */
		/* TODO: consider multivalued attrs */
		if ((attr->flags & SCHEMA_FLAG_MOD_DELETE) != 0) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR,
				  "Trying to delete the required attribute %s.\n",
				  attr->name);

			data->error_string = "Objectclass violation, a required attribute cannot be removed";
			talloc_free(entry_structs);
			return -1;
		}

		/* mark the attribute as checked */
		attr->flags = SCHEMA_FLAG_CHECKED;
	}

	/* now check all others atribs are at least optional_attrs */
	for (i = 0; i < entry_structs->entry_attrs.num; i++) {

		if (entry_structs->entry_attrs.attr[i].flags != SCHEMA_FLAG_CHECKED) {
			struct schema_attribute *attr;

			attr = schema_find_attribute(&entry_structs->optional_attrs,
						     entry_structs->entry_attrs.attr[i].name);

			if (attr == NULL) { /* not found */
				ldb_debug(module->ldb, LDB_DEBUG_ERROR,
					  "The attribute %s is not referenced by any objectclass.\n",
					  entry_structs->entry_attrs.attr[i].name);

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

static int schema_destructor(void *module_ctx)
{
/* 	struct ldb_module *ctx = module_ctx; */
	/* put your clean-up functions here */
	return 0;
}

static const struct ldb_module_ops schema_ops = {
	.name          = "schema",
	.search        = schema_search,
	.search_bytree = schema_search_bytree,
	.add_record    = schema_add_record,
	.modify_record = schema_modify_record,
	.delete_record = schema_delete_record,
	.rename_record = schema_rename_record,
	.named_lock    = schema_named_lock,
	.named_unlock  = schema_named_unlock,
	.errstring     = schema_errstring,
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

	talloc_set_destructor (ctx, schema_destructor);

	return ctx;
}
