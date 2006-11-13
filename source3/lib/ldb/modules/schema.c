/* 
   ldb database library

   Copyright (C) Simo Sorce  2004-2005

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
#include "ldb/include/includes.h"

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
	int i, j, anum, cnum;

	ss->entry_attrs.attr = talloc_realloc(ss, ss->entry_attrs.attr,
					      struct schema_attribute,
					      ss->entry_attrs.num + msg->num_elements);
	if (ss->entry_attrs.attr == NULL) {
		return -1;
	}

	for (i = 0, anum = ss->entry_attrs.num; i < msg->num_elements; i++) {

		if (ldb_attr_cmp(msg->elements[i].name, "objectclass") == 0) {

			ss->objectclasses.attr = talloc_realloc(ss, ss->objectclasses.attr,
								struct schema_attribute,
								ss->objectclasses.num + msg->elements[i].num_values);
			if (ss->objectclasses.attr == NULL) {
				return -1;
			}

			for (j = 0, cnum = ss->objectclasses.num; j < msg->elements[i].num_values; j++) {
				ss->objectclasses.attr[cnum+j].name = (char *)msg->elements[i].values[j].data;
				ss->objectclasses.attr[cnum+j].flags = msg->elements[i].flags & flag_mask;
			}
			ss->objectclasses.num += msg->elements[i].num_values;
		}

		/* TODO: Check for proper attribute Syntax ! */

		ss->entry_attrs.attr[anum+i].flags = msg->elements[i].flags & flag_mask;
		ss->entry_attrs.attr[anum+i].name = talloc_reference(ss->entry_attrs.attr,
							    msg->elements[i].name);
		if (ss->entry_attrs.attr[anum+i].name == NULL) {
			return -1;
		}
	}
	ss->entry_attrs.num += msg->num_elements;

	return 0;
}

static int get_entry_attributes(struct ldb_context *ldb, const struct ldb_dn *dn, struct schema_structures *ss)
{
	struct ldb_result *srch;
	int ret;

	ret = ldb_search(ldb, dn, LDB_SCOPE_BASE, NULL, NULL, &srch);
	if (ret != 1) {
		return ret;
	}
	talloc_steal(ss, srch);

	/* set flags to 0 as flags on search have undefined values */
	ret = get_msg_attributes(ss, *(srch->msgs), 0);
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
				if (ldb_attr_cmp(list->attr[c].name, 
						 (char *)el->values[i].data) == 0) {
					found = 1;
					break;
				}
			}
		}
		if (!found) {
			list->attr[j + list->num].name = (char *)el->values[i].data;
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
	struct ldb_result *srch;
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
		if (ret != LDB_SUCCESS) {
			/* Schema DB Error: Error occurred retrieving
			   Object Class Description */
			ldb_debug_set(module->ldb, LDB_DEBUG_ERROR, 
				      "Error retrieving Objectclass %s.\n", 
				      schema_struct->objectclasses.attr[i].name);
			return -1;
		}

		talloc_steal(schema_struct, srch);

		if (srch->count > 1) {
			/* Schema DB Error: Too Many Records */
			ldb_debug_set(module->ldb, LDB_DEBUG_ERROR, 
				      "Too many records found retrieving Objectclass %s.\n", 
				      schema_struct->objectclasses.attr[i].name);
			return -1;
		}

		/* Add inherited classes eliminating duplicates */
		/* fill in required_attrs and optional_attrs attribute lists */
		for (j = 0; j < srch->msgs[0]->num_elements; j++) {
			int is_aux, is_class;

			is_aux = 0;
			is_class = 0;
			if (ldb_attr_cmp(srch->msgs[0]->elements[j].name, "systemAuxiliaryclass") == 0) {
				is_aux = SCHEMA_FLAG_AUXILIARY;
				is_class = 1;
			}
			if (ldb_attr_cmp(srch->msgs[0]->elements[j].name, "auxiliaryClass") == 0) {
				is_aux = SCHEMA_FLAG_AUXILIARY;
				is_class = 1;
			}
			if (ldb_attr_cmp(srch->msgs[0]->elements[j].name, "subClassOf") == 0) {
				is_class = 1;
			}

			if (is_class) {
				if (add_attribute_uniq(schema_struct,
							&schema_struct->objectclasses,
							is_aux,
							&srch->msgs[0]->elements[j]) != 0) {
					return -1;
				}
			} else {

				if (ldb_attr_cmp(srch->msgs[0]->elements[j].name, "mustContain") == 0 ||
					ldb_attr_cmp(srch->msgs[0]->elements[j].name, "SystemMustContain") == 0) {
					if (add_attribute_uniq(schema_struct,
								&schema_struct->required_attrs,
								SCHEMA_FLAG_RESET,
								&srch->msgs[0]->elements[j]) != 0) {
						return -1;
					}
				}

				if (ldb_attr_cmp(srch->msgs[0]->elements[j].name, "mayContain") == 0 ||
				    ldb_attr_cmp(srch->msgs[0]->elements[j].name, "SystemMayContain") == 0) {

					if (add_attribute_uniq(schema_struct,
								&schema_struct->optional_attrs,
								SCHEMA_FLAG_RESET,
								&srch->msgs[0]->elements[j]) != 0) {
						return -1;
					}
				}
			}
		}
	}

	return 0;
}

/* add_record */
static int schema_add(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.add.message;
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

	/* do not check on our control entries */
	if (ldb_dn_is_special(msg->dn)) {
		return ldb_next_request(module, req);
	}

	/* TODO: check parent exists */

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
			ldb_debug_set(module->ldb, LDB_DEBUG_ERROR, 
				      "The required_attrs attribute %s is missing.\n",
				      entry_structs->required_attrs.attr[i].name);
			talloc_free(entry_structs);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
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
				ldb_debug_set(module->ldb, LDB_DEBUG_ERROR, 
					      "The attribute %s is not referenced by any objectclass.\n",
					      entry_structs->entry_attrs.attr[i].name);
				talloc_free(entry_structs);
				return LDB_ERR_OBJECT_CLASS_VIOLATION;
			}
		}
	}

	talloc_free(entry_structs);

	return ldb_next_request(module, req);
}

/* modify_record */
static int schema_modify(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.mod.message;
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

	/* do not check on our control entries */
	if (ldb_dn_is_special(msg->dn)) {
		return ldb_next_request(module, req);
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
			ldb_debug_set(module->ldb, LDB_DEBUG_ERROR, 
				      "The required_attrs attribute %s is missing.\n",
				      entry_structs->required_attrs.attr[i].name);
			talloc_free(entry_structs);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
		}

		/* check we are not trying to delete a required attribute */
		/* TODO: consider multivalued attrs */
		if ((attr->flags & SCHEMA_FLAG_MOD_DELETE) != 0) {
			ldb_debug_set(module->ldb, LDB_DEBUG_ERROR, 
				      "Trying to delete the required attribute %s.\n",
				      attr->name);
			talloc_free(entry_structs);
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
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
				ldb_debug_set(module->ldb, LDB_DEBUG_ERROR, 
					      "The attribute %s is not referenced by any objectclass.\n",
					      entry_structs->entry_attrs.attr[i].name);
				talloc_free(entry_structs);
				return LDB_ERR_OBJECT_CLASS_VIOLATION;
			}
		}
	}

	talloc_free(entry_structs);

	return ldb_next_request(module, req);
}

static int schema_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_ADD:
		return schema_add(module, req);

	case LDB_MODIFY:
		return schema_modify(module, req);

	default:
		return ldb_next_request(module, req);

	}
}

static const struct ldb_module_ops schema_ops = {
	.name              = "schema",
	.request           = schema_request
};

int ldb_schema_init(void)
{
	return ldb_register_module(&schema_ops);
}
