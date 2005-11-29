/* 
   ldb database library - map backend

   Copyright (C) Jelmer Vernooij 2005

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

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "ldb/modules/ldb_map.h"

/*
 - special attribute 'isMapped'
 - add/modify
 	- split up ldb_message into fallback and mapped parts if is_mappable
 - search: 
 	- search local one for not isMapped entries
	- remove remote attributes from ldb_parse_tree
	- search remote one
	 - per record, search local one for additional data (by dn)
	 - test if (full expression) is now true
 - delete
 	- delete both
 - rename
 	- rename locally and remotely
*/

static struct ldb_val map_convert_local_dn(struct ldb_module *map,
					   TALLOC_CTX *ctx,
					   const struct ldb_val *val);
static struct ldb_val map_convert_remote_dn(struct ldb_module *map,
					    TALLOC_CTX *ctx,
					    const struct ldb_val *val);
static struct ldb_val map_convert_local_objectclass(struct ldb_module *map,
						    TALLOC_CTX *ctx,
						    const struct ldb_val *val);
static struct ldb_val map_convert_remote_objectclass(struct ldb_module *map,
						     TALLOC_CTX *ctx,
						     const struct ldb_val *val);

static const struct ldb_map_attribute builtin_attribute_maps[] = {
	{
		.local_name = "dn",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				.remote_name = "dn",
				.convert_local = map_convert_local_dn,
				.convert_remote = map_convert_remote_dn,
			},
		},
	},
	{
		.local_name = "objectclass",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				.remote_name = "objectclass",
				.convert_local = map_convert_local_objectclass,
				.convert_remote = map_convert_remote_objectclass,
			},
		},
	},
	{
		.local_name = NULL,
	}
};

static const struct ldb_map_objectclass *map_find_objectclass_remote(struct ldb_map_context *privdat, const char *name)
{
	int i;
	for (i = 0; privdat->objectclass_maps[i].remote_name; i++) {
		if (!ldb_attr_cmp(privdat->objectclass_maps[i].remote_name, name))
			return &privdat->objectclass_maps[i];
	}

	return NULL;
}

struct map_private {
	struct ldb_map_context context;
};

static struct ldb_map_context *map_get_privdat(struct ldb_module *module)
{
	return &((struct map_private *)module->private_data)->context;
}

/* Check whether the given attribute can fit into the specified 
 * message, obeying objectClass restrictions */
static int map_msg_valid_attr(struct ldb_module *module, const struct ldb_message *msg, const char *attr)
{
	struct ldb_map_context *map = module->private_data;
	int i, j;
	struct ldb_message_element *el = ldb_msg_find_element(msg, "objectClass");

	if (el == NULL) {
		ldb_debug(module->ldb, LDB_DEBUG_FATAL, "Can't find objectClass");
		return 0;
	}

	for (i = 0; i < el->num_values; i++) {
		const struct ldb_map_objectclass *class = map_find_objectclass_remote(map, (char *)el->values[i].data);

		if (!class) 
			continue;
		
		for (j = 0; class->musts[j]; j++) {
			if (!ldb_attr_cmp(class->musts[j], attr))
				return 1;
		}

		for (j = 0; class->mays[j]; j++) {
			if (!ldb_attr_cmp(class->mays[j], attr))
				return 1;
		}
	}

	return 0;
} 


/* find an attribute by the local name */
static const struct ldb_map_attribute *map_find_attr_local(struct ldb_map_context *privdat, const char *attr)
{
	int i;

	for (i = 0; privdat->attribute_maps[i].local_name; i++) {
		if (!ldb_attr_cmp(privdat->attribute_maps[i].local_name, attr)) 
			return &privdat->attribute_maps[i];
	}

	return NULL;
}

/* Check if a given attribute can be created by doing mapping from a local attribute to a remote one */
static int map_msg_can_map_attr(struct ldb_module *module, const struct ldb_message *msg, const char *attr_name)
{
	struct ldb_map_context *privdat = module->private_data;
	int i,j;

	for (i = 0; privdat->attribute_maps[i].local_name; i++) {
		switch (privdat->attribute_maps[i].type) {
		case MAP_IGNORE: /* No remote name at all */
			continue;
		case MAP_KEEP:
			if (ldb_attr_cmp(attr_name, privdat->attribute_maps[i].local_name) == 0)
				goto found;
			break;
		case MAP_RENAME:
		case MAP_CONVERT:
			if (ldb_attr_cmp(attr_name, privdat->attribute_maps[i].u.rename.remote_name) == 0)
				goto found;
			break;
		case MAP_GENERATE:
			for (j = 0; privdat->attribute_maps[i].u.generate.remote_names[j]; j++) {
				if (ldb_attr_cmp(attr_name, privdat->attribute_maps[i].u.generate.remote_names[j]) == 0)
					goto found;
			}
			break;
		}
	}

	return 0;

found:

	if (ldb_msg_find_element(msg, privdat->attribute_maps[i].local_name))
		return 1;

	return 0;
}



/* find an attribute by the remote name */
static const struct ldb_map_attribute *map_find_attr_remote(struct ldb_map_context *privdat, const char *attr)
{
	int i;

	for (i = 0; privdat->attribute_maps[i].local_name; i++) {
		if (privdat->attribute_maps[i].type == MAP_IGNORE)
			continue;

		if (privdat->attribute_maps[i].type == MAP_GENERATE)
			continue;

		if (privdat->attribute_maps[i].type == MAP_KEEP &&
			ldb_attr_cmp(privdat->attribute_maps[i].local_name, attr) == 0)
			return &privdat->attribute_maps[i];

		if ((privdat->attribute_maps[i].type == MAP_RENAME ||
			privdat->attribute_maps[i].type == MAP_CONVERT) &&
			ldb_attr_cmp(privdat->attribute_maps[i].u.rename.remote_name, attr) == 0) 
			return &privdat->attribute_maps[i];

	}

	return NULL;
}

static struct ldb_parse_tree *ldb_map_parse_tree(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_parse_tree *tree)
{
	int i;
	const struct ldb_map_attribute *attr;
	struct ldb_parse_tree *new_tree;
	enum ldb_map_attr_type map_type;
	struct ldb_val value, newvalue;
	struct ldb_map_context *privdat = map_get_privdat(module);

	if (tree == NULL)
		return NULL;
	

	/* Find attr in question and:
	 *  - if it has a convert_operator function, run that
	 *  - otherwise, replace attr name with required[0] */

	if (tree->operation == LDB_OP_AND || 
		tree->operation == LDB_OP_OR) {
		
		new_tree = talloc_memdup(ctx, tree, sizeof(*tree));
		new_tree->u.list.elements = talloc_array(new_tree, struct ldb_parse_tree *, tree->u.list.num_elements);
		new_tree->u.list.num_elements = 0;
		for (i = 0; i < tree->u.list.num_elements; i++) {
			struct ldb_parse_tree *child = ldb_map_parse_tree(module, new_tree, tree->u.list.elements[i]);
			
			if (child) {
				new_tree->u.list.elements[i] = child;
				new_tree->u.list.num_elements++;
			}
		}

		return new_tree;
	}
		
	if (tree->operation == LDB_OP_NOT) {
		struct ldb_parse_tree *child;
		
		new_tree = talloc_memdup(ctx, tree, sizeof(*tree));
		child = ldb_map_parse_tree(module, new_tree, tree->u.isnot.child);

		if (!child) {
			talloc_free(new_tree);
			return NULL;
		}

		new_tree->u.isnot.child = child;
		return new_tree;
	}

	/* tree->operation is LDB_OP_EQUALITY, LDB_OP_SUBSTRING, LDB_OP_GREATER,
	 * LDB_OP_LESS, LDB_OP_APPROX, LDB_OP_PRESENT or LDB_OP_EXTENDED
	 *
	 * (all have attr as the first element)
	 */

	attr = map_find_attr_local(privdat, tree->u.equality.attr);

	if (!attr) {
		ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Unable to find local attribute '%s', removing from parse tree\n", tree->u.equality.attr);
		map_type = MAP_IGNORE;
	} else {
		map_type = attr->type;
	}

	if (attr && attr->convert_operator) {
		/* Run convert_operator */
		return attr->convert_operator(privdat, module, tree);
	}

	if (map_type == MAP_IGNORE) {
		ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Not mapping search on ignored attribute '%s'\n", tree->u.equality.attr);
		return NULL;
	}

	if (map_type == MAP_GENERATE) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Can't do conversion for MAP_GENERATE in map_parse_tree without convert_operator for '%s'\n", tree->u.equality.attr);
		return NULL;
	}

	if (tree->operation == LDB_OP_EQUALITY) {
		value = tree->u.equality.value;
	} else if (tree->operation == LDB_OP_LESS || tree->operation == LDB_OP_GREATER ||
			   tree->operation == LDB_OP_APPROX) {
		value = tree->u.comparison.value;
	} else if (tree->operation == LDB_OP_EXTENDED) {
		value = tree->u.extended.value;
	}
	
	new_tree = talloc_memdup(ctx, tree, sizeof(*tree));

	if (map_type == MAP_KEEP) {
		new_tree->u.equality.attr = talloc_strdup(new_tree, tree->u.equality.attr);
	} else { /* MAP_RENAME / MAP_CONVERT */
		new_tree->u.equality.attr = talloc_strdup(new_tree, attr->u.rename.remote_name);
	}

	if (new_tree->operation == LDB_OP_PRESENT) 
		return new_tree;
		
	if (new_tree->operation == LDB_OP_SUBSTRING) {
		new_tree->u.substring.chunks = NULL; /* FIXME! */
		return new_tree;
	}

	if (map_type == MAP_CONVERT) {
		if (!attr->u.convert.convert_local)
			return NULL;
		newvalue = attr->u.convert.convert_local(module, new_tree, &value);
	} else {
		newvalue = ldb_val_dup(new_tree, &value);
	}

	if (new_tree->operation == LDB_OP_EQUALITY) {
		new_tree->u.equality.value = newvalue;
	} else if (new_tree->operation == LDB_OP_LESS || new_tree->operation == LDB_OP_GREATER ||
			   new_tree->operation == LDB_OP_APPROX) {
		new_tree->u.comparison.value = newvalue;
	} else if (new_tree->operation == LDB_OP_EXTENDED) {
		new_tree->u.extended.value = newvalue;
		new_tree->u.extended.rule_id = talloc_strdup(new_tree, tree->u.extended.rule_id);
	}
	
	return new_tree;
}

/* Remote DN -> Local DN */
static struct ldb_dn *map_remote_dn(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_dn *dn)
{
	struct ldb_dn *newdn;
	int i;

	if (dn == NULL)
		return NULL;

	newdn = talloc_memdup(ctx, dn, sizeof(*dn));
	if (!newdn) 
		return NULL;

	newdn->components = talloc_array(newdn, struct ldb_dn_component, newdn->comp_num); 

	if (!newdn->components)
		return NULL;

	/* For each rdn, map the attribute name and possibly the 
	 * complete rdn */
	
	for (i = 0; i < dn->comp_num; i++) {
		const struct ldb_map_attribute *attr = map_find_attr_remote(module->private_data, dn->components[i].name);
		enum ldb_map_attr_type map_type;

		/* Unknown attribute - leave this dn as is and hope the best... */
		if (!attr) map_type = MAP_KEEP;
		else map_type = attr->type;
			
		switch (map_type) { 
		case MAP_IGNORE:
		case MAP_GENERATE:
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Local MAP_IGNORE or MAP_GENERATE attribute '%s' used in DN!", dn->components[i].name);
			talloc_free(newdn);
			return NULL;

		case MAP_KEEP:
			newdn->components[i].name = talloc_strdup(newdn->components, dn->components[i].name);
			newdn->components[i].value = ldb_val_dup(newdn->components, &dn->components[i].value);
			break;
			
		case MAP_CONVERT:
			newdn->components[i].name = talloc_strdup(newdn->components, attr->local_name);
			newdn->components[i].value = attr->u.convert.convert_remote(module, ctx, &dn->components[i].value);
			break;
			
		case MAP_RENAME:
			newdn->components[i].name = talloc_strdup(newdn->components, attr->local_name);
			newdn->components[i].value = ldb_val_dup(newdn->components, &dn->components[i].value);
			break;
		}
	}
	return newdn;
}

/* Local DN -> Remote DN */
static struct ldb_dn *map_local_dn(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_dn *dn)
{	
	struct ldb_dn *newdn;
	int i;

	if (dn == NULL)
		return NULL;

	newdn = talloc_memdup(ctx, dn, sizeof(*dn));
	if (!newdn) 
		return NULL;

	newdn->components = talloc_array(newdn, struct ldb_dn_component, newdn->comp_num); 

	if (!newdn->components)
		return NULL;

	/* For each rdn, map the attribute name and possibly the 
	 * complete rdn using an equality convert_operator call */
	
	for (i = 0; i < dn->comp_num; i++) {
		const struct ldb_map_attribute *attr = map_find_attr_local(module->private_data, dn->components[i].name);
		enum ldb_map_attr_type map_type;

		/* Unknown attribute - leave this dn as is and hope the best... */
		if (!attr) map_type = MAP_KEEP; else map_type = attr->type;
		
		switch (map_type) 
		{
			case MAP_IGNORE: 
			case MAP_GENERATE:
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Local MAP_IGNORE/MAP_GENERATE attribute '%s' used in DN!", dn->components[i].name);
			talloc_free(newdn);
			return NULL;

			case MAP_CONVERT: 
				newdn->components[i].name = talloc_strdup(newdn->components, attr->u.convert.remote_name);
				if (attr->u.convert.convert_local == NULL) {
					ldb_debug(module->ldb, LDB_DEBUG_ERROR, "convert_local not set for attribute '%s' used in DN!", dn->components[i].name);
					talloc_free(newdn);
					return NULL;
				}
				newdn->components[i].value = attr->u.convert.convert_local(module, newdn->components, &dn->components[i].value);
			break;
			
			case MAP_RENAME:
				newdn->components[i].name = talloc_strdup(newdn->components, attr->u.rename.remote_name);
				newdn->components[i].value = ldb_val_dup(newdn->components, &dn->components[i].value);
			break;

			case MAP_KEEP:
				newdn->components[i].name = talloc_strdup(newdn->components, dn->components[i].name);
				newdn->components[i].value = ldb_val_dup(newdn->components, &dn->components[i].value);
			continue;
		}
	}

	return newdn;
}

/* Loop over ldb_map_attribute array and add remote_names */
static const char **ldb_map_attrs(struct ldb_module *module, const char *const attrs[])
{
	int i;
	const char **ret;
	int ar_size = 0, last_element = 0;
	struct ldb_map_context *privdat = map_get_privdat(module);

	if (attrs == NULL) 
		return NULL;

	/* Start with good guess of number of elements */
	for (i = 0; attrs[i]; i++);

	ret = talloc_array(module, const char *, i);
	ar_size = i;

	for (i = 0; attrs[i]; i++) {
		int j;
		const struct ldb_map_attribute *attr = map_find_attr_local(privdat, attrs[i]);
		enum ldb_map_attr_type map_type;

		if (!attr) {
			ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Local attribute '%s' does not have a definition!\n", attrs[i]);
			map_type = MAP_IGNORE;
		} else map_type = attr->type;

		switch (map_type)
		{ 
			case MAP_IGNORE: break;
			case MAP_KEEP: 
				if (last_element >= ar_size) {
					ret = talloc_realloc(module, ret, const char *, ar_size+1);
					ar_size++;
				}
				ret[last_element] = attr->local_name;
				last_element++;
				break;

			case MAP_RENAME:
			case MAP_CONVERT:
				if (last_element >= ar_size) {
					ret = talloc_realloc(module, ret, const char *, ar_size+1);
					ar_size++;
				}
				ret[last_element] = attr->u.rename.remote_name;
				last_element++;
				break;

			case MAP_GENERATE:
				/* Add remote_names[] for this attribute to the list of 
				 * attributes to request from the remote server */
				for (j = 0; attr->u.generate.remote_names[j]; j++) {
					if (last_element >= ar_size) {
						ret = talloc_realloc(module, ret, const char *, ar_size+1);
						ar_size++;
					}
					ret[last_element] = attr->u.generate.remote_names[j];			
					last_element++;
				}
				break;
		} 
	}
	
	if (last_element >= ar_size) {
		ret = talloc_realloc(module, ret, const char *, ar_size+1);
		ar_size++;
	}

	ret[last_element] = NULL;

	return ret;
}

static const char **available_local_attributes(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_map_context *privdat = map_get_privdat(module);
	int i, j;
	int count = 0;
	const char **ret = talloc_array(module, const char *, 1);

	ret[0] = NULL;

	for (i = 0; privdat->attribute_maps[i].local_name; i++) {
		int avail = 0;
		const struct ldb_map_attribute *attr = &privdat->attribute_maps[i];

		/* If all remote attributes for this attribute are present, add the 
		 * local one to the list */
		
		switch (attr->type) {
		case MAP_IGNORE: break;
		case MAP_KEEP: 
				avail = (ldb_msg_find_ldb_val(msg, attr->local_name) != NULL); 
				break;
				
		case MAP_RENAME:
		case MAP_CONVERT:
				avail = (ldb_msg_find_ldb_val(msg, attr->u.rename.remote_name) != NULL);
				break;

		case MAP_GENERATE:
				avail = 1;
				for (j = 0; attr->u.generate.remote_names[j]; j++) {
					avail &= (ldb_msg_find_ldb_val(msg, attr->u.generate.remote_names[j]) != NULL);
				}
				break;
		}

		if (!avail)
			continue;

		ret = talloc_realloc(module, ret, const char *, count+2);
		ret[count] = attr->local_name;
		ret[count+1] = NULL;
		count++;
	}

	return ret;
}

/* Used for search */
static struct ldb_message *ldb_map_message_incoming(struct ldb_module *module, const char * const*attrs, const struct ldb_message *mi)
{
	int i, j;
	struct ldb_message *msg = talloc_zero(module, struct ldb_message);
	struct ldb_message_element *elm, *oldelm;
	struct ldb_map_context *privdat = map_get_privdat(module);
	const char **newattrs = NULL;

	msg->dn = map_remote_dn(module, module, mi->dn);

	/* Loop over attrs, find in ldb_map_attribute array and 
	 * run generate() */

	if (attrs == NULL) {
		/* Generate list of the local attributes that /can/ be generated
		 * using the specific remote attributes */

		attrs = newattrs = available_local_attributes(module, mi);
	}

	for (i = 0; attrs[i]; i++) {
		const struct ldb_map_attribute *attr = map_find_attr_local(privdat, attrs[i]);
		enum ldb_map_attr_type map_type;

		if (!attr) {
			ldb_debug(module->ldb, LDB_DEBUG_WARNING, "Unable to find local attribute '%s' when generating incoming message\n", attrs[i]);
			map_type = MAP_IGNORE;
		} else map_type = attr->type;

		switch (map_type) {
			case MAP_IGNORE:break;
			case MAP_RENAME:
				ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Renaming remote attribute %s to %s", attr->u.rename.remote_name, attr->local_name);
				oldelm = ldb_msg_find_element(mi, attr->u.rename.remote_name);
				if (!oldelm)
					continue;

				elm = talloc(msg, struct ldb_message_element);
				elm->name = talloc_strdup(elm, attr->local_name);
				elm->num_values = oldelm->num_values;
				elm->values = talloc_array(elm, struct ldb_val, elm->num_values);
				for (j = 0; j < oldelm->num_values; j++)
					elm->values[j] = ldb_val_dup(elm, &oldelm->values[j]);

				ldb_msg_add(msg, elm, oldelm->flags);
				break;
				
			case MAP_CONVERT:
				ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Converting remote attribute %s to %s", attr->u.rename.remote_name, attr->local_name);
				oldelm = ldb_msg_find_element(mi, attr->u.rename.remote_name);
				if (!oldelm) 
					continue;

				elm = talloc(msg, struct ldb_message_element);
				elm->name = talloc_strdup(elm, attr->local_name);
				elm->num_values = oldelm->num_values;
				elm->values = talloc_array(elm, struct ldb_val, elm->num_values);

				for (j = 0; j < oldelm->num_values; j++)
					elm->values[j] = attr->u.convert.convert_remote(module, elm, &oldelm->values[j]);

				ldb_msg_add(msg, elm, oldelm->flags);
				break;

			case MAP_KEEP:
				ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Keeping remote attribute %s", attr->local_name);
				oldelm = ldb_msg_find_element(mi, attr->local_name);
				if (!oldelm) continue;
				
				elm = talloc(msg, struct ldb_message_element);

				elm->num_values = oldelm->num_values;
				elm->values = talloc_array(elm, struct ldb_val, elm->num_values);
				for (j = 0; j < oldelm->num_values; j++)
					elm->values[j] = ldb_val_dup(elm, &oldelm->values[j]);

				elm->name = talloc_strdup(elm, oldelm->name);

				ldb_msg_add(msg, elm, oldelm->flags);
				break;

			case MAP_GENERATE:
				ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Generating local attribute %s", attr->local_name);
				if (!attr->u.generate.generate_local)
					continue;

				elm = attr->u.generate.generate_local(module, msg, attr->local_name, mi);
				if (!elm) 
					continue;

				ldb_msg_add(msg, elm, elm->flags);
				break;
			default: 
				ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Unknown attr->type for %s", attr->local_name);
				break;
		}
	}

	talloc_free(newattrs);

	return msg;
}

/*
  rename a record
*/
static int map_rename(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_dn *olddn = req->op.rename.olddn;
	const struct ldb_dn *newdn = req->op.rename.newdn;
	struct ldb_map_context *privdat = map_get_privdat(module);
	struct ldb_dn *n_olddn, *n_newdn;
	int ret;

	n_olddn = map_local_dn(module, module, olddn);
	n_newdn = map_local_dn(module, module, newdn);

	ret = ldb_rename(privdat->mapped_ldb, n_olddn, n_newdn);
	if (ret != -1) {
		ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Mapped record renamed");
		ldb_next_request(module, req);
	} else {
		ret = ldb_next_request(module, req);
	
		if (ret != -1) {
			ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Fallback record renamed");
		}
	}

	
	talloc_free(n_olddn);
	talloc_free(n_newdn);
	
	return ret;
}

/*
  delete a record
*/
static int map_delete(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_dn *dn = req->op.del.dn;
	struct ldb_map_context *privdat = map_get_privdat(module);
	struct ldb_dn *newdn;
	int ret;

	newdn = map_local_dn(module, module, dn);

	ret = ldb_delete(privdat->mapped_ldb, newdn);
	if (ret != -1) {
		ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Mapped record deleted");
	} else {
		ret = ldb_next_request(module, req);
		if (ret != -1) {
			ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Fallback record deleted");
		}
	}

	req->op.del.dn = newdn;
	ret = ldb_next_request(module, req);
	req->op.del.dn = dn;

	talloc_free(newdn);

	return ret;
}

/* search fallback database */
static int map_search_fb(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_parse_tree *tree = req->op.search.tree;
	struct ldb_parse_tree t_and, t_not, t_present, *childs[2];
	int ret;
	char *ismapped;

	t_present.operation = LDB_OP_PRESENT;
	ismapped = talloc_strdup(module, "isMapped");
	t_present.u.present.attr = ismapped;

	t_not.operation = LDB_OP_NOT;
	t_not.u.isnot.child = &t_present;

	childs[0] = &t_not;
	childs[1] = tree;
	t_and.operation = LDB_OP_AND;
	t_and.u.list.num_elements = 2;
	t_and.u.list.elements = childs;

	req->op.search.tree = &t_and;
	ret = ldb_next_request(module, req);
	req->op.search.tree = tree;

	talloc_free(ismapped);

	return ret;
}

/* Search in the database against which we are mapping */
static int map_search_mp(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_dn *base = req->op.search.base;
	enum ldb_scope scope = req->op.search.scope;
	struct ldb_parse_tree *tree = req->op.search.tree;
	const char * const *attrs = req->op.search.attrs;
	struct ldb_result *res;
	struct ldb_request new_req;
	struct ldb_parse_tree *new_tree;
	struct ldb_dn *new_base;
	struct ldb_result *newres;
	const char **newattrs;
	int mpret, ret;
	struct ldb_map_context *privdat = map_get_privdat(module);
	int i;

	/*- search mapped database */

	new_tree = ldb_map_parse_tree(module, module, tree);
	if (new_tree == NULL) {
		/* All attributes used in the parse tree are 
		 * local, apparently. Fall back to enumerating the complete remote 
		 * database... Rather a slow search then no results. */
		new_tree = talloc_zero(module, struct ldb_parse_tree);
		new_tree->operation = LDB_OP_PRESENT;
		new_tree->u.present.attr = talloc_strdup(new_tree, "dn");
		return 0;
	}
		
	newattrs = ldb_map_attrs(module, attrs); 
	new_base = map_local_dn(module, module, base);

	memset((char *)&(new_req), 0, sizeof(new_req));
	new_req.operation = LDB_REQ_SEARCH;
	new_req.op.search.base = new_base;
	new_req.op.search.scope = scope;
	new_req.op.search.tree = new_tree;
	new_req.op.search.attrs = newattrs;

	mpret = ldb_request(privdat->mapped_ldb, req);

	newres = new_req.op.search.res;

	talloc_free(new_base);
	talloc_free(new_tree);
	talloc_free(newattrs);

	if (mpret != LDB_SUCCESS) {
		ldb_set_errstring(module, talloc_strdup(module, ldb_errstring(privdat->mapped_ldb)));
		return mpret;
	}

	/*
	 - per returned record, search fallback database for additional data (by dn)
	 - test if (full expression) is now true
	*/

	res = talloc(module, struct ldb_result);
	req->op.search.res = res;
	res->msgs = talloc_array(module, struct ldb_message *, newres->count);
	res->count = newres->count;

	ret = 0;

	for (i = 0; i < mpret; i++) {
		struct ldb_request mergereq;
		struct ldb_message *merged;
		struct ldb_result *extrares = NULL;
		int extraret;

		/* Always get special DN's from the fallback database */
		if (ldb_dn_is_special(newres->msgs[i]->dn))
			continue;

		merged = ldb_map_message_incoming(module, attrs, newres->msgs[i]);
		
		/* Merge with additional data from fallback database */
		memset((char *)&(mergereq), 0, sizeof(mergereq)); /* zero off the request structure */
		mergereq.operation = LDB_REQ_SEARCH;
		mergereq.op.search.base = merged->dn;
		mergereq.op.search.scope = LDB_SCOPE_BASE;
		mergereq.op.search.tree = ldb_parse_tree(module, "");
		mergereq.op.search.attrs = NULL;

		extraret = ldb_next_request(module, &mergereq);

		extrares = mergereq.op.search.res;

		if (extraret == -1) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Error searching for extra data!\n");
		} else if (extraret > 1) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "More than one result for extra data!\n");
			talloc_free(newres);
			return -1;
		} else if (extraret == 0) {
			ldb_debug(module->ldb, LDB_DEBUG_TRACE, "No extra data found for remote DN: %s", ldb_dn_linearize(merged, merged->dn));
		}
		
		if (extraret == 1) {
			int j;
			ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Extra data found for remote DN: %s", ldb_dn_linearize(merged, merged->dn));
			for (j = 0; j < extrares->msgs[0]->num_elements; j++) {
				ldb_msg_add(merged, &(extrares->msgs[0]->elements[j]), extrares->msgs[0]->elements[j].flags);
			}
		}
		
		if (ldb_match_msg(module->ldb, merged, tree, base, scope) != 0) {
			res->msgs[ret] = merged;
			ret++;
		} else {
			ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Discarded merged message because it did not match");
		}
	}

	talloc_free(newres);

	res->count = ret;
	return LDB_SUCCESS;
}


/*
  search for matching records using a ldb_parse_tree
*/
static int map_search_bytree(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_dn *base = req->op.search.base;
	struct ldb_result *fbres, *mpres, *res;
	int i, ret;

	ret = map_search_fb(module, req);
	if (ret != LDB_SUCCESS)
		return ret;

	/* special dn's are never mapped.. */
	if (ldb_dn_is_special(base)) {
		return ret;
	}

	fbres = req->op.search.res;

	ret = map_search_mp(module, req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	mpres = req->op.search.res;

	/* Merge results */
	res = talloc(module, struct ldb_result);
	res->msgs = talloc_array(res, struct ldb_message *, fbres->count + mpres->count);

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Merging %d mapped and %d fallback messages", mpres->count, fbres->count);

	for (i = 0; i < fbres->count; i++) {
		res->msgs[i] = talloc_steal(res->msgs, fbres->msgs[i]);
	}
	for (i = 0; i < mpres->count; i++) {
		res->msgs[fbres->count + i] = talloc_steal(res->msgs, mpres->msgs[i]);
	}

	res->count = fbres->count + mpres->count;
	return LDB_SUCCESS;
}

static int msg_contains_objectclass(const struct ldb_message *msg, const char *name)
{
	struct ldb_message_element *el = ldb_msg_find_element(msg, "objectClass");
	int i;
	
	for (i = 0; i < el->num_values; i++) {
		if (ldb_attr_cmp((char *)el->values[i].data, name) == 0) {
			return 1;
		}
	}

	return 0;
}

/*
  add a record
*/
static int map_add(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.add.message;
	struct ldb_map_context *privdat = map_get_privdat(module);
	struct ldb_message *fb, *mp;
	struct ldb_message_element *ocs;
	int ret;
	int i;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "ldb_map_add");

	if (ldb_dn_is_special(msg->dn)) {
		ldb_debug(module->ldb, LDB_DEBUG_TRACE, "ldb_map_add: Added fallback record");
		return ldb_next_request(module, req);
	}

	mp = talloc_zero(module, struct ldb_message);
	mp->dn = map_local_dn(module, mp, msg->dn);

	fb = talloc_zero(module, struct ldb_message);
	fb->dn = talloc_reference(fb, msg->dn);

	/* We add objectClass, so 'top' should be no problem */
	ldb_msg_add_string(mp, "objectClass", "top");
	
	/* make a list of remote objectclasses that can be used 
	 *   given the attributes that are available and add to 
	 *   mp_msg */
	for (i = 0; privdat->objectclass_maps[i].local_name; i++) {
		int j, has_musts, has_baseclasses;
		
		/* Add this objectClass to the list if all musts are present */
		for (j = 0; privdat->objectclass_maps[i].musts[j]; j++) {
			if (!map_msg_can_map_attr(module, msg, privdat->objectclass_maps[i].musts[j])) {
				ldb_debug(module->ldb, LDB_DEBUG_TRACE, "map_add: Not adding objectClass %s because it is not possible to create remote attribute %s", privdat->objectclass_maps[i].local_name, privdat->objectclass_maps[i].musts[j]);
				break;
			}
		}

		has_musts = (privdat->objectclass_maps[i].musts[j] == NULL);

		/* Check if base classes are present as well */
		for (j = 0; privdat->objectclass_maps[i].base_classes[j]; j++) {
			if (!msg_contains_objectclass(mp, privdat->objectclass_maps[i].base_classes[j])) {
				ldb_debug(module->ldb, LDB_DEBUG_TRACE, "map_add: Not adding objectClass %s of missing base class %s", privdat->objectclass_maps[i].local_name, privdat->objectclass_maps[i].base_classes[j]);
				break;
			}
		}

		has_baseclasses = (privdat->objectclass_maps[i].base_classes[j] == NULL);
		
		/* Apparently, it contains all required elements */
		if (has_musts && has_baseclasses) {
			ldb_msg_add_string(mp, "objectClass", privdat->objectclass_maps[i].remote_name);	
			ldb_debug(module->ldb, LDB_DEBUG_TRACE, "map_add: Adding objectClass %s", privdat->objectclass_maps[i].remote_name);
		}
	}

	ocs = ldb_msg_find_element(mp, "objectClass");
	if (ocs->num_values == 1) { /* Only top */
		ldb_debug(module->ldb, LDB_DEBUG_TRACE, "ldb_map_add: Added fallback record");
		return ldb_next_request(module, req);
	}
	
	/*
	 * - try to map as much attributes as possible where allowed and add them to mp_msg
	 * - add other attributes to fb_msg
	 */
	for (i = 0; i < msg->num_elements; i++) {
		const struct ldb_map_attribute *attr;
		struct ldb_message_element *elm = NULL;
		int j, k;
		int mapped = 0;

		if (ldb_attr_cmp(msg->elements[i].name, "objectClass") == 0)
			continue;

		/* Loop over all attribute_maps with msg->elements[i].name as local_name */
		for (k = 0; privdat->attribute_maps[k].local_name; k++) {
			if (ldb_attr_cmp(msg->elements[i].name, privdat->attribute_maps[k].local_name) != 0)
				continue;

			attr = &privdat->attribute_maps[k];

			/* Decide whether or not we need to map or fallback */
			switch (attr->type) {
			case MAP_GENERATE:
				ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Generating from %s", attr->local_name);
				attr->u.generate.generate_remote(module, attr->local_name, msg, mp, fb);
				mapped++;
				continue;
			case MAP_KEEP:
				if (!map_msg_valid_attr(module, mp, attr->local_name))
					continue;
				break;
			case MAP_IGNORE: continue; 
			case MAP_CONVERT:
			case MAP_RENAME: 
				 if (!map_msg_valid_attr(module, mp, attr->u.rename.remote_name))
					 continue;
				 break;
			}

			switch (attr->type) {
			case MAP_KEEP:
				ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Keeping %s", attr->local_name);
				elm = talloc(fb, struct ldb_message_element);

				elm->num_values = msg->elements[i].num_values;
				elm->values = talloc_array(elm, struct ldb_val, elm->num_values);

				for (j = 0; j < elm->num_values; j++) {
					elm->values[j] = ldb_val_dup(elm, &msg->elements[i].values[j]);
				}

				elm->name = talloc_strdup(elm, msg->elements[i].name);
				break;

			case MAP_RENAME:
				ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Renaming %s -> %s", attr->local_name, attr->u.rename.remote_name);
				elm = talloc(mp, struct ldb_message_element);

				elm->name = talloc_strdup(elm, attr->u.rename.remote_name);
				elm->num_values = msg->elements[i].num_values;
				elm->values = talloc_array(elm, struct ldb_val, elm->num_values);

				for (j = 0; j < elm->num_values; j++) {
					elm->values[j] = ldb_val_dup(elm, &msg->elements[i].values[j]);
				}
				break;

			case MAP_CONVERT:
				if (attr->u.convert.convert_local == NULL)
					continue;
				ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Converting %s -> %s", attr->local_name, attr->u.convert.remote_name);
				elm = talloc(mp, struct ldb_message_element);

				elm->name = talloc_strdup(elm, attr->u.rename.remote_name);
				elm->num_values = msg->elements[i].num_values;
				elm->values = talloc_array(elm, struct ldb_val, elm->num_values);

				for (j = 0; j < elm->num_values; j++) {
					elm->values[j] = attr->u.convert.convert_local(module, mp, &msg->elements[i].values[j]);
				}

				break;

			case MAP_GENERATE:
			case MAP_IGNORE:
				ldb_debug(module->ldb, LDB_DEBUG_FATAL, "This line should never be reached");
				continue;
			} 
			
			ldb_msg_add(mp, elm, 0);
			mapped++;
		} 
		
		if (mapped == 0) {
			ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Fallback storing %s", msg->elements[i].name);
			elm = talloc(fb, struct ldb_message_element);

			elm->num_values = msg->elements[i].num_values;
			elm->values = talloc_reference(elm, msg->elements[i].values);
			elm->name = talloc_strdup(elm, msg->elements[i].name);

			ldb_msg_add(fb, elm, 0);
		}
	}

	ret = ldb_add(privdat->mapped_ldb, mp);
	if (ret == -1) {
		ldb_debug(module->ldb, LDB_DEBUG_WARNING, "Adding mapped record failed: %s", ldb_errstring(privdat->mapped_ldb));
		return -1;
	}

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "ldb_map_add: Added mapped record");

	ldb_msg_add_string(fb, "isMapped", "TRUE");

	req->op.add.message = fb;
	ret = ldb_next_request(module, req);
	req->op.add.message = msg;
	if (ret == -1) {
		ldb_debug(module->ldb, LDB_DEBUG_WARNING, "Adding fallback record failed: %s", ldb_errstring(module->ldb));
		return -1;
	}

	talloc_free(fb);
	talloc_free(mp);

	return ret;
}


/*
  modify a record
*/
static int map_modify(struct ldb_module *module, struct ldb_request *req)
{
	const struct ldb_message *msg = req->op.mod.message;
	struct ldb_map_context *privdat = map_get_privdat(module);
	struct ldb_message *fb, *mp;
	struct ldb_message_element *elm;
	int fb_ret, mp_ret;
	int i,j;

	ldb_debug(module->ldb, LDB_DEBUG_TRACE, "ldb_map_modify");

	if (ldb_dn_is_special(msg->dn))
		return ldb_next_request(module, req);

	fb = talloc_zero(module, struct ldb_message);
	fb->dn = talloc_reference(fb, msg->dn);

	mp = talloc_zero(module, struct ldb_message);
	mp->dn = map_local_dn(module, mp, msg->dn);

	/* Loop over mi and call generate_remote for each attribute */
	for (i = 0; i < msg->num_elements; i++) {
		const struct ldb_map_attribute *attr;
		int k;
		int mapped = 0;

		if (ldb_attr_cmp(msg->elements[i].name, "isMapped") == 0)
			continue;

		for (k = 0; privdat->attribute_maps[k].local_name; k++) 
		{
			if (ldb_attr_cmp(privdat->attribute_maps[k].local_name, msg->elements[i].name) != 0)
				continue;

			attr = &privdat->attribute_maps[k];

			switch (attr->type) {
			case MAP_IGNORE: continue;
			case MAP_RENAME:
				 elm = talloc(mp, struct ldb_message_element);

				 elm->name = talloc_strdup(elm, attr->u.rename.remote_name);
				 elm->num_values = msg->elements[i].num_values;
				 elm->values = talloc_array(elm, struct ldb_val, elm->num_values);
				 for (j = 0; j < elm->num_values; j++) {
					 elm->values[j] = msg->elements[i].values[j];
				 }

				 ldb_msg_add(mp, elm, msg->elements[i].flags);
				 mapped++;
				 continue;

			case MAP_CONVERT:
				 if (!attr->u.convert.convert_local)
					 continue;
				 elm = talloc(mp, struct ldb_message_element);

				 elm->name = talloc_strdup(elm, attr->u.rename.remote_name);
				 elm->num_values = msg->elements[i].num_values;
				 elm->values = talloc_array(elm, struct ldb_val, elm->num_values);

				 for (j = 0; j < elm->num_values; j++) {
					 elm->values[j] = attr->u.convert.convert_local(module, mp, &msg->elements[i].values[j]);
				 }

				 ldb_msg_add(mp, elm, msg->elements[i].flags);
				 mapped++;
				 continue;

			case MAP_KEEP:
				 elm = talloc(mp, struct ldb_message_element);

				 elm->num_values = msg->elements[i].num_values;
				 elm->values = talloc_array(elm, struct ldb_val, elm->num_values);
				 for (j = 0; j < elm->num_values; j++) {
					 elm->values[j] = msg->elements[i].values[j];
				 }

				 elm->name = talloc_strdup(elm, msg->elements[i].name);

				 ldb_msg_add(mp, elm, msg->elements[i].flags);	
				 mapped++;
				 continue;

			case MAP_GENERATE:
				 attr->u.generate.generate_remote(module, attr->local_name, msg, mp, fb);
				 mapped++;
				 continue;
			} 
		}

		if (mapped == 0) {/* Add to fallback message */
			elm = talloc(fb, struct ldb_message_element);

			elm->num_values = msg->elements[i].num_values;
			elm->values = talloc_reference(elm, msg->elements[i].values);
			elm->name = talloc_strdup(elm, msg->elements[i].name);
			
			ldb_msg_add(fb, elm, msg->elements[i].flags);	
		}
	}

	if (fb->num_elements > 0) {
		ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Modifying fallback record with %d elements", fb->num_elements);
		req->op.mod.message = fb;
		fb_ret = ldb_next_request(module, req);
		if (fb_ret == -1) {
			ldb_msg_add_string(fb, "isMapped", "TRUE");
			req->operation = LDB_REQ_ADD;
			req->op.add.message = fb;
			fb_ret = ldb_next_request(module, req);
			req->operation = LDB_REQ_MODIFY;
		}
		req->op.mod.message = msg;
	} else fb_ret = 0;
	talloc_free(fb);

	if (mp->num_elements > 0) {
		ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Modifying mapped record with %d elements", mp->num_elements);
		mp_ret = ldb_modify(privdat->mapped_ldb, mp);
	} else mp_ret = 0;
	talloc_free(mp);

	return (mp_ret == -1 || fb_ret == -1)?-1:0;
}


static int map_request(struct ldb_module *module, struct ldb_request *req)
{
	switch (req->operation) {

	case LDB_REQ_SEARCH:
		return map_search_bytree(module, req);

	case LDB_REQ_ADD:
		return map_add(module, req);

	case LDB_REQ_MODIFY:
		return map_modify(module, req);

	case LDB_REQ_DELETE:
		return map_delete(module, req);

	case LDB_REQ_RENAME:
		return map_rename(module, req);

	default:
		return ldb_next_request(module, req);

	}
}


static const struct ldb_module_ops map_ops = {
	.name              = "map",
	.request           = map_request
};

static char *map_find_url(struct ldb_context *ldb, const char *name)
{
	const char * const attrs[] = { "@MAP_URL" , NULL};
	struct ldb_result *result = NULL;
	struct ldb_dn *mods;
	char *url;
	int ret;

	mods = ldb_dn_string_compose(ldb, NULL, "@MAP=%s", name);
	if (mods == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Can't construct DN");
		return NULL;
	}

	ret = ldb_search(ldb, mods, LDB_SCOPE_BASE, "", attrs, &result);
	talloc_free(mods);
	if (ret != LDB_SUCCESS || result->count == 0) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Not enough results found looking for @MAP");
		return NULL;
	}

	url = talloc_strdup(ldb, ldb_msg_find_string(result->msgs[0], "@MAP_URL", NULL));

	talloc_free(result);

	return url;
}

/* the init function */
struct ldb_module *ldb_map_init(struct ldb_context *ldb, const struct ldb_map_attribute *attrs, const struct ldb_map_objectclass *ocls, const char *name)
{
	int i, j;
	struct ldb_module *ctx;
	struct map_private *data;
	char *url;

	ctx = talloc(ldb, struct ldb_module);
	if (!ctx)
		return NULL;

	data = talloc(ctx, struct map_private);
	if (!data) {
		talloc_free(ctx);
		return NULL;
	}

	data->context.mapped_ldb = ldb_init(data);
	ldb_set_debug(data->context.mapped_ldb, ldb->debug_ops.debug, ldb->debug_ops.context);
	url = map_find_url(ldb, name);

	if (!url) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "@MAP=%s not set!\n", name);
		return NULL;
	}

	if (ldb_connect(data->context.mapped_ldb, url, 0, NULL) != 0) {
		ldb_debug(ldb, LDB_DEBUG_FATAL, "Unable to open mapped database for %s at '%s'\n", name, url);
		return NULL;
	}

	talloc_free(url);

	/* Get list of attribute maps */
	j = 0;
	data->context.attribute_maps = NULL;

	for (i = 0; attrs[i].local_name; i++) {
		data->context.attribute_maps = talloc_realloc(data, data->context.attribute_maps, struct ldb_map_attribute, j+1);
		data->context.attribute_maps[j] = attrs[i];
		j++;
	}

	for (i = 0; builtin_attribute_maps[i].local_name; i++) {
		data->context.attribute_maps = talloc_realloc(data, data->context.attribute_maps, struct ldb_map_attribute, j+1);
		data->context.attribute_maps[j] = builtin_attribute_maps[i];
		j++;
	}

	data->context.attribute_maps = talloc_realloc(data, data->context.attribute_maps, struct ldb_map_attribute, j+1);
	memset(&data->context.attribute_maps[j], 0, sizeof(struct ldb_map_attribute));

	data->context.objectclass_maps = ocls;
	ctx->private_data = data;
	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &map_ops;

	return ctx;
}

static struct ldb_val map_convert_local_dn(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct ldb_dn *dn, *newdn;
	struct ldb_val *newval;

	dn = ldb_dn_explode(ctx, (char *)val->data);

	newdn = map_local_dn(module, ctx, dn);

	talloc_free(dn);

	newval = talloc(ctx, struct ldb_val);
	newval->data = (uint8_t *)ldb_dn_linearize(ctx, newdn);
	if (newval->data) {
		newval->length = strlen((char *)newval->data);
	} else {
		newval->length = 0;
	}

	talloc_free(newdn);

	return *newval;
}

static struct ldb_val map_convert_remote_dn(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct ldb_dn *dn, *newdn;
	struct ldb_val *newval;

	dn = ldb_dn_explode(ctx, (char *)val->data);

	newdn = map_remote_dn(module, ctx, dn);

	talloc_free(dn);

	newval = talloc(ctx, struct ldb_val);
	newval->data = (uint8_t *)ldb_dn_linearize(ctx, newdn);
	if (newval->data) {
		newval->length = strlen((char *)newval->data);
	} else {
		newval->length = 0;
	}

	talloc_free(newdn);

	return *newval;
}

static struct ldb_val map_convert_local_objectclass(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	int i;
	struct ldb_map_context *map = module->private_data;

	for (i = 0; map->objectclass_maps[i].local_name; i++) {
		if (!strcmp(map->objectclass_maps[i].local_name, (char *)val->data)) {
			struct ldb_val newval;
			newval.data = (uint8_t*)talloc_strdup(ctx, map->objectclass_maps[i].remote_name);
			newval.length = strlen((char *)newval.data);

			return ldb_val_dup(ctx, &newval);
		}
	}

	return ldb_val_dup(ctx, val); 
}

static struct ldb_val map_convert_remote_objectclass(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	int i;
	struct ldb_map_context *map = module->private_data;

	for (i = 0; map->objectclass_maps[i].remote_name; i++) {
		if (!strcmp(map->objectclass_maps[i].remote_name, (char *)val->data)) {
			struct ldb_val newval;
			newval.data = (uint8_t*)talloc_strdup(ctx, map->objectclass_maps[i].local_name);
			newval.length = strlen((char *)newval.data);

			return ldb_val_dup(ctx, &newval);
		}
	}

	return ldb_val_dup(ctx, val); 
}

