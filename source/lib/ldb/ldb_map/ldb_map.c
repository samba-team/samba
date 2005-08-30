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
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_private.h"
#include "lib/ldb/ldb_map/ldb_map.h"

/* TODO:
 *  - objectclass hint in ldb_map_attribute 
 *     for use when multiple remote attributes (independant of each other)
 *     map to one local attribute. E.g.: (uid, gidNumber) -> unixName
 *     (use MAP_GENERATE instead ?) 
 */

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

static const struct ldb_map_attribute builtin_attribute_maps[];

struct map_private {
	struct ldb_map_context context;
	const char *last_err_string;
};

static struct ldb_map_context *map_get_privdat(struct ldb_module *module)
{
	return &((struct map_private *)module->private_data)->context;
}

static const struct ldb_map_objectclass *map_find_objectclass_local(struct ldb_map_context *privdat, const char *name)
{
	int i;
	for (i = 0; privdat->objectclass_maps[i].local_name; i++) {
		if (!ldb_attr_cmp(privdat->objectclass_maps[i].local_name, name))
			return &privdat->objectclass_maps[i];
	}

	return NULL;
}

/* Decide whether a add/modify should be pushed to the 
 * remote LDAP server. We currently only do this if we see an objectClass we know */
static BOOL map_is_mappable(struct ldb_map_context *privdat, const struct ldb_message *msg)
{
	int i;
	struct ldb_message_element *el = ldb_msg_find_element(msg, "objectClass");

	/* No objectClass... */
	if (el == NULL) {
		return False;
	}

	for (i = 0; i < el->num_values; i++) {
		if (map_find_objectclass_local(privdat, (char *)el->values[i].data))
			return True;
	}

	return False;
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
		ldb_debug(module->ldb, LDB_DEBUG_WARNING, "Unable to find local attribute '%s', leaving as is\n", tree->u.equality.attr);
		map_type = MAP_KEEP;
	} else {
		map_type = attr->type;
	}

	if (attr && attr->convert_operator) {
		/* Run convert_operator */
		return attr->convert_operator(privdat, module, tree);
	}

	if (map_type == MAP_IGNORE) {
		ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Search on ignored attribute '%s'\n", tree->u.equality.attr);
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
		newvalue = attr->u.convert.convert_local(privdat, new_tree, &value);
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
static struct ldb_dn *map_remote_dn(struct ldb_map_context *privdat, TALLOC_CTX *ctx, const struct ldb_dn *dn)
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
		const struct ldb_map_attribute *attr = map_find_attr_remote(privdat, dn->components[i].name);
		enum ldb_map_attr_type map_type;

		/* Unknown attribute - leave this dn as is and hope the best... */
		if (!attr) map_type = MAP_KEEP;
		else map_type = attr->type;
			
		switch (map_type) { 
		case MAP_IGNORE:
		case MAP_GENERATE:
			DEBUG(0, ("Local MAP_IGNORE or MAP_GENERATE attribute '%s' used in DN!", dn->components[i].name));
			talloc_free(newdn);
			return NULL;

		case MAP_KEEP:
			newdn->components[i].name = talloc_strdup(newdn->components, dn->components[i].name);
			newdn->components[i].value = ldb_val_dup(newdn->components, &dn->components[i].value);
			break;
			
		case MAP_CONVERT:
			newdn->components[i].name = talloc_strdup(newdn->components, attr->local_name);
			newdn->components[i].value = attr->u.convert.convert_remote(privdat, ctx, &dn->components[i].value);
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
static struct ldb_dn *map_local_dn(struct ldb_map_context *privdat, TALLOC_CTX *ctx, const struct ldb_dn *dn)
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
		const struct ldb_map_attribute *attr = map_find_attr_local(privdat, dn->components[i].name);
		enum ldb_map_attr_type map_type;

		/* Unknown attribute - leave this dn as is and hope the best... */
		if (!attr) map_type = MAP_KEEP; else map_type = attr->type;
		
		switch (map_type) 
		{
			case MAP_IGNORE: 
			case MAP_GENERATE:
			DEBUG(0, ("Local MAP_IGNORE/MAP_GENERATE attribute '%s' used in DN!", dn->components[i].name));
			talloc_free(newdn);
			return NULL;

			case MAP_CONVERT: 
				newdn->components[i].name = talloc_strdup(newdn->components, attr->u.convert.remote_name);
				newdn->components[i].value = attr->u.convert.convert_local(privdat, newdn->components, &dn->components[i].value);
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
			ldb_debug(module->ldb, LDB_DEBUG_WARNING, "Local attribute '%s' does not have a definition!\n", attrs[i]);
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
		BOOL avail = False;
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
				avail = True;
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

	msg->dn = map_remote_dn(privdat, module, mi->dn);

	ldb_msg_add_string(module->ldb, msg, "mappedFromDn", ldb_dn_linearize(msg, mi->dn));

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
				oldelm = ldb_msg_find_element(mi, attr->u.rename.remote_name);
				if (!oldelm) continue;

				elm = talloc(msg, struct ldb_message_element);
				elm->name = talloc_strdup(elm, attr->local_name);
				elm->num_values = oldelm->num_values;
				elm->values = talloc_reference(elm, oldelm->values);

				ldb_msg_add(module->ldb, msg, elm, oldelm->flags);
				break;
				
			case MAP_CONVERT:
				oldelm = ldb_msg_find_element(mi, attr->u.rename.remote_name);
				if (!oldelm) continue;

				elm = talloc(msg, struct ldb_message_element);
				elm->name = talloc_strdup(elm, attr->local_name);
				elm->num_values = oldelm->num_values;
				elm->values = talloc_array(elm, struct ldb_val, elm->num_values);

				for (j = 0; j < oldelm->num_values; j++)
					elm->values[j] = attr->u.convert.convert_remote(privdat, elm, &oldelm->values[j]);

				ldb_msg_add(module->ldb, msg, elm, oldelm->flags);
				break;

			case MAP_KEEP:
				oldelm = ldb_msg_find_element(mi, attr->local_name);
				if (!oldelm) continue;
				
				elm = talloc(msg, struct ldb_message_element);

				elm->num_values = oldelm->num_values;
				elm->values = talloc_reference(elm, oldelm->values);
				elm->name = talloc_strdup(elm, oldelm->name);

				ldb_msg_add(module->ldb, msg, elm, oldelm->flags);
				break;

			case MAP_GENERATE:
				elm = attr->u.generate.generate_local(privdat, msg, attr->local_name, mi);
				if (!elm) continue;

				ldb_msg_add(module->ldb, msg, elm, elm->flags);
				break;
			default: 
				ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Unknown attr->type for %s", attr->local_name);
				break;
		}
	}

	talloc_free(newattrs);

	return msg;
}

/* Used for add, modify */
static int ldb_map_message_outgoing(struct ldb_module *module, const struct ldb_message *mo, struct ldb_message **fb, struct ldb_message **mp)
{
	struct ldb_map_context *privdat = map_get_privdat(module);
	struct ldb_message *msg = talloc_zero(module, struct ldb_message);
	struct ldb_message_element *elm;
	int i,j;

	*fb = talloc_zero(module, struct ldb_message);
	(*fb)->dn = talloc_reference(*fb, mo->dn);

	*mp = msg;

	msg->private_data = mo->private_data;
	
	msg->dn = map_local_dn(privdat, module, mo->dn);

	/* Loop over mi and call generate_remote for each attribute */
	for (i = 0; i < mo->num_elements; i++) {
		const struct ldb_map_attribute *attr = map_find_attr_local(privdat, mo->elements[i].name);
		enum ldb_map_attr_type map_type;

		if (!attr) {
			ldb_debug(module->ldb, LDB_DEBUG_WARNING, "Undefined local attribute '%s', ignoring\n", mo->elements[i].name);
			map_type = MAP_IGNORE;
			continue;
		} else map_type = attr->type;

		switch (map_type) {
		case MAP_IGNORE: /* Add to fallback message */
			elm = talloc(*fb, struct ldb_message_element);

			elm->num_values = mo->elements[i].num_values;
			elm->values = talloc_reference(elm, mo->elements[i].values);
			elm->name = talloc_strdup(elm, mo->elements[i].name);
			
			ldb_msg_add(module->ldb, *fb, elm, mo->elements[i].flags);	
			break;
		case MAP_RENAME:
			elm = talloc(msg, struct ldb_message_element);

			elm->name = talloc_strdup(elm, attr->u.rename.remote_name);
			elm->num_values = mo->elements[i].num_values;
			elm->values = talloc_reference(elm, mo->elements[i].values);

			ldb_msg_add(module->ldb, msg, elm, mo->elements[i].flags);
			break;

		case MAP_CONVERT:
			elm = talloc(msg, struct ldb_message_element);

			elm->name = talloc_strdup(elm, attr->u.rename.remote_name);
			elm->num_values = mo->elements[i].num_values;
			elm->values = talloc_array(elm, struct ldb_val, elm->num_values);
			
			for (j = 0; j < elm->num_values; j++) {
				elm->values[j] = attr->u.convert.convert_local(privdat, msg, &mo->elements[i].values[j]);
			}

			ldb_msg_add(module->ldb, msg, elm, mo->elements[i].flags);
			break;

		case MAP_KEEP:
			elm = talloc(msg, struct ldb_message_element);

			elm->num_values = mo->elements[i].num_values;
			elm->values = talloc_reference(elm, mo->elements[i].values);
			elm->name = talloc_strdup(elm, mo->elements[i].name);
			
			ldb_msg_add(module->ldb, msg, elm, mo->elements[i].flags);	
			break;

		case MAP_GENERATE:
			attr->u.generate.generate_remote(privdat, attr->local_name, mo, msg);
			break;
		} 
	}

	return 0;
}


/*
  rename a record
*/
static int map_rename(struct ldb_module *module, const struct ldb_dn *olddn, const struct ldb_dn *newdn)
{
	struct ldb_map_context *privdat = map_get_privdat(module);
	struct ldb_dn *n_olddn, *n_newdn;
	int ret;

	ret = ldb_next_rename_record(module, olddn, newdn);
	
	n_olddn = map_local_dn(privdat, module, olddn);
	n_newdn = map_local_dn(privdat, module, newdn);

	ret = ldb_rename(privdat->mapped_ldb, n_olddn, n_newdn);

	talloc_free(n_olddn);
	talloc_free(n_newdn);
	
	return ret;
}

/*
  delete a record
*/
static int map_delete(struct ldb_module *module, const struct ldb_dn *dn)
{
	struct ldb_map_context *privdat = map_get_privdat(module);
	struct ldb_dn *newdn;
	int ret;

	ret = ldb_next_delete_record(module, dn);
	
	newdn = map_local_dn(privdat, module, dn);

	ret = ldb_delete(privdat->mapped_ldb, newdn);

	talloc_free(newdn);

	return ret;
}

/* search fallback database */
static int map_search_bytree_fb(struct ldb_module *module, const struct ldb_dn *base,
			      enum ldb_scope scope, struct ldb_parse_tree *tree,
			      const char * const *attrs, struct ldb_message ***res)
{
	int ret;
	struct ldb_parse_tree t_and, t_not, t_present, *childs[2];

	t_present.operation = LDB_OP_PRESENT;
	t_present.u.present.attr = talloc_strdup(NULL, "isMapped");

	t_not.operation = LDB_OP_NOT;
	t_not.u.isnot.child = &t_present;

	childs[0] = &t_not;
	childs[1] = tree;
	t_and.operation = LDB_OP_AND;
	t_and.u.list.num_elements = 2;
	t_and.u.list.elements = childs;
	
	ret = ldb_next_search_bytree(module, base, scope, &t_and, attrs, res);

	talloc_free(t_present.u.present.attr);

	return ret;
}

static int map_search_bytree_mp(struct ldb_module *module, const struct ldb_dn *base,
			      enum ldb_scope scope, struct ldb_parse_tree *tree,
			      const char * const *attrs, struct ldb_message ***res)
{
	struct ldb_parse_tree *new_tree;
	struct ldb_dn *new_base;
	struct ldb_message **newres;
	const char **newattrs;
	int mpret, ret;
	struct ldb_map_context *privdat = map_get_privdat(module);
	int i;

	/*- search mapped database */

	new_tree = ldb_map_parse_tree(module, module, tree);
	newattrs = ldb_map_attrs(module, attrs); 
	new_base = map_local_dn(privdat, module, base);

	mpret = ldb_search_bytree(privdat->mapped_ldb, new_base, scope, new_tree, newattrs, &newres);

	talloc_free(new_base);
	talloc_free(new_tree);
	talloc_free(newattrs);

	if (mpret == -1) {
		struct map_private *map_private = module->private_data;
		map_private->last_err_string = ldb_errstring(privdat->mapped_ldb);
		return -1;
	}

	/*
	 - per returned record, search fallback database for additional data (by dn)
	 - test if (full expression) is now true
	*/

	*res = talloc_array(module, struct ldb_message *, mpret);

	ret = 0;

	for (i = 0; i < mpret; i++) {
		struct ldb_message *merged = ldb_map_message_incoming(module, attrs, newres[i]);
		struct ldb_message **extrares = NULL;
		int extraret;
		
		/* Merge with additional data from local database */
		extraret = ldb_next_search(module, merged->dn, LDB_SCOPE_BASE, "", NULL, &extrares);

		if (extraret == -1) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Error searching for extra data!\n");
		} else if (extraret > 1) {
			ldb_debug(module->ldb, LDB_DEBUG_ERROR, "More than one result for extra data!\n");
			talloc_free(newres);
			return -1;
		} else if (extraret == 0) {
			ldb_debug(module->ldb, LDB_DEBUG_TRACE, "No extra data found for remote DN");
		}
		
		if (extraret == 1) {
			int j;
			ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Extra data found for remote DN");
			for (j = 0; j < extrares[0]->num_elements; j++) {
				ldb_msg_add(module->ldb, merged, &(extrares[0]->elements[j]), extrares[0]->elements[j].flags);
			}

			ldb_msg_add_string(module->ldb, merged, "extraMapped", "TRUE");
		} else {
			ldb_msg_add_string(module->ldb, merged, "extraMapped", "FALSE");
		}
		
		if (ldb_match_msg(module->ldb, merged, tree, base, scope)) {
			(*res)[ret] = merged;
			ret++;
		} else {
			ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Discarded merged message because it did not match");
		}
	}

	talloc_free(newres);

	return ret;
}


/*
  search for matching records using a ldb_parse_tree
*/
static int map_search_bytree(struct ldb_module *module, const struct ldb_dn *base,
			      enum ldb_scope scope, struct ldb_parse_tree *tree,
			      const char * const *attrs, struct ldb_message ***res)
{
	struct ldb_message **fbres, **mpres;
	int i;
	int ret_fb, ret_mp;

	ret_fb = map_search_bytree_fb(module, base, scope, tree, attrs, &fbres);
	if (ret_fb == -1) 
		return -1;

	ret_mp = map_search_bytree_mp(module, base, scope, tree, attrs, &mpres);
	if (ret_mp == -1) {
		return -1;
	}

	/* Merge results */
	*res = talloc_array(module, struct ldb_message *, ret_fb + ret_mp);

	for (i = 0; i < ret_fb; i++) (*res)[i] = fbres[i];
	for (i = 0; i < ret_mp; i++) (*res)[ret_fb+i] = mpres[i];

	return ret_fb + ret_mp;
}
/*
  search for matching records
*/
static int map_search(struct ldb_module *module, const struct ldb_dn *base,
		       enum ldb_scope scope, const char *expression,
		       const char * const *attrs, struct ldb_message ***res)
{
	struct map_private *map = module->private_data;
	struct ldb_parse_tree *tree;
	int ret;

	tree = ldb_parse_tree(NULL, expression);
	if (tree == NULL) {
		map->last_err_string = "expression parse failed";
		return -1;
	}

	ret = map_search_bytree(module, base, scope, tree, attrs, res);
	talloc_free(tree);
	return ret;
}

/*
  add a record
*/
static int map_add(struct ldb_module *module, const struct ldb_message *msg)
{
	int ret;
	struct ldb_map_context *privdat = map_get_privdat(module);
	struct ldb_message *fb, *mp;

	if (!map_is_mappable(privdat, msg)) {
		return ldb_next_add_record(module, msg);
	}

	if (ldb_map_message_outgoing(module, msg, &fb, &mp) == -1)
		return -1;
		
	ldb_msg_add_string(module->ldb, fb, "isMapped", "TRUE");

	ret = ldb_next_add_record(module, fb);
	if (ret == -1) {
		ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Adding fallback record failed");
		return -1;
	}
		
	ret = ldb_add(privdat->mapped_ldb, mp);
	if (ret == -1) {
		ldb_debug(module->ldb, LDB_DEBUG_TRACE, "Adding mapped record failed");
		return -1;
	}

	talloc_free(fb);
	talloc_free(mp);

	return ret;
}


/*
  modify a record
*/
static int map_modify(struct ldb_module *module, const struct ldb_message *msg)
{
	struct ldb_map_context *privdat = map_get_privdat(module);
	struct ldb_message *fb, *mp;
	int ret;

	if (!map_is_mappable(privdat, msg))
		return ldb_next_modify_record(module, msg);
		

	if (ldb_map_message_outgoing(module, msg, &fb, &mp) == -1)
		return -1;
		
	ldb_msg_add_string(module->ldb, fb, "isMapped", "TRUE");

	ret = ldb_next_modify_record(module, fb);

	ret = ldb_modify(privdat->mapped_ldb, mp);

	talloc_free(fb);
	talloc_free(mp);

	return ret;
}

static int map_lock(struct ldb_module *module, const char *lockname)
{
	return ldb_next_named_lock(module, lockname);
}

static int map_unlock(struct ldb_module *module, const char *lockname)
{
	return ldb_next_named_unlock(module, lockname);
}

/*
  return extended error information
*/
static const char *map_errstring(struct ldb_module *module)
{
	struct map_private *map = module->private_data;
	
	if (map->last_err_string)
		return map->last_err_string;

	return ldb_next_errstring(module);
}

static const struct ldb_module_ops map_ops = {
	.name          = "map",
	.search        = map_search,
	.search_bytree = map_search_bytree,
	.add_record    = map_add,
	.modify_record = map_modify,
	.delete_record = map_delete,
	.rename_record = map_rename,
	.named_lock    = map_lock,
	.named_unlock  = map_unlock,
	.errstring     = map_errstring
};

static char *map_find_url(struct ldb_context *ldb, const char *name)
{
	const char * const attrs[] = { "@MAP_URL" , NULL};
	struct ldb_message **msg = NULL;
	struct ldb_dn *mods;
	char *url;
	int ret;

	mods = ldb_dn_string_compose(ldb, NULL, "@MAP=%s", name);
	if (mods == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Can't construct DN");
		return NULL;
	}

	ret = ldb_search(ldb, mods, LDB_SCOPE_BASE, "", attrs, &msg);
	talloc_free(mods);
	if (ret < 1) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "Not enough results found looking for @MAP");
		return NULL;
	}

	url = talloc_strdup(ldb, ldb_msg_find_string(msg[0], "@MAP_URL", NULL));

	talloc_free(msg);

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

	data->last_err_string = NULL;

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
	ZERO_STRUCT(data->context.attribute_maps[j].local_name);

	data->context.objectclass_maps = ocls;
	ctx->private_data = data;
	ctx->ldb = ldb;
	ctx->prev = ctx->next = NULL;
	ctx->ops = &map_ops;

	return ctx;
}

static struct ldb_val map_convert_local_dn(struct ldb_map_context *map, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct ldb_dn *dn, *newdn;;
	struct ldb_val *newval;

	dn = ldb_dn_explode(ctx, (char *)val->data);

	newdn = map_local_dn(map, ctx, dn);

	talloc_free(dn);

	newval = talloc(ctx, struct ldb_val);
	newval->data = (uint8_t *)ldb_dn_linearize(ctx, newdn);
	newval->length = strlen((char *)newval->data);

	talloc_free(newdn);

	return *newval;
}

static struct ldb_val map_convert_remote_dn(struct ldb_map_context *map, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct ldb_dn *dn, *newdn;;
	struct ldb_val *newval;

	dn = ldb_dn_explode(ctx, (char *)val->data);

	newdn = map_remote_dn(map, ctx, dn);

	talloc_free(dn);

	newval = talloc(ctx, struct ldb_val);
	newval->data = (uint8_t *)ldb_dn_linearize(ctx, newdn);
	newval->length = strlen((char *)newval->data);

	talloc_free(newdn);

	return *newval;
}

static struct ldb_val map_convert_local_objectclass(struct ldb_map_context *map, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	int i;

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

static struct ldb_val map_convert_remote_objectclass(struct ldb_map_context *map, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	int i;

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

static const struct ldb_map_attribute builtin_attribute_maps[] = {
	{
		.local_name = "dn",
		.type = MAP_CONVERT,
		.u.convert.remote_name = "dn",
		.u.convert.convert_local = map_convert_local_dn,
		.u.convert.convert_remote = map_convert_remote_dn,
	},
	{
		.local_name = "objectclass",
		.type = MAP_CONVERT,
		.u.convert.remote_name = "objectclass",
		.u.convert.convert_local = map_convert_local_objectclass,
		.u.convert.convert_remote = map_convert_remote_objectclass,
	},
	{
		.local_name = NULL,
	}
};

