/* 
   ldb database library

   Copyright (C) Simo Sorce  2004-2006

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
 *  Name: ldb
 *
 *  Component: ldb schema module
 *
 *  Description: add schema check functionality
 *
 *  Author: Simo Sorce
 *
 *  License: GNU GPL v2 or Later
 */

#include "includes.h"
#include "libcli/ldap/ldap.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "lib/util/dlinklist.h"
#include "schema_syntax.h"

/* Syntax-Table

   see ldap_server/devdocs/AD-syntaxes.txt
*/

enum schema_class_type {
	SCHEMA_CT_88		= 0,
	SCHEMA_CT_STRUCTURAL	= 1,
	SCHEMA_CT_ABSTRACT	= 2,
	SCHEMA_CT_AUXILIARY	= 3
};

struct schema_attribute {
	char *OID;				/* attributeID     */
	char *name;				/* lDAPDisplayName */
	enum schema_internal_syntax syntax;	/* generated from attributeSyntax, oMSyntax, oMObjectClass */
	bool single;				/* isSingleValued  */
	int min;				/* rangeLower      */
	int max;				/* rangeUpper      */
	int systemflag;				/* systemFlag      */
	int searchflag;				/* searchFlag      */
	bool isdefunct;				/* isDefunct       */
};

struct schema_class {
	char *OID;				/* governsID             */
	char *name;				/* lDAPDisplayName       */
	enum schema_class_type type;		/* objectClassCategory   */
	bool systemOnly;			/* systemOnly            */
	bool isdefunct;				/* isDefunct             */
	int systemflag;				/* systemFlag            */
	char *defobjcat;			/* defaultObjectCategory */
	struct schema_class *parent;		/* subClassOf            */
	struct schema_class **sysaux;		/* systemAuxiliaryClass  */
	struct schema_class **aux;		/* auxiliaryClass        */
	struct schema_class **sysposssup;	/* systemPossSuperiors   */
	struct schema_class **posssup;		/* possSuperiors         */
	struct schema_class **possinf;		/* possibleInferiors     */
	struct schema_attribute **sysmust;	/* systemMustContain     */
	struct schema_attribute **must;		/* MustContain           */
	struct schema_attribute **sysmay;	/* systemMayContain      */
	struct schema_attribute **may;		/* MayContain            */
};

/* TODO: ditcontentrules */

struct schema_private_data {
	struct ldb_dn *schema_dn;
	struct schema_attribute **attrs;
	struct schema_store *attrs_store;
	int num_attributes;
	struct schema_class **class;
	struct schema_store *class_store;
	int num_classes;
};

struct schema_class_dlist {
	struct schema_class *class;
	struct schema_class_dlist *prev;
	struct schema_class_dlist *next;
	enum schema_class_type role;
};

struct schema_context {

	enum sc_op { SC_ADD, SC_MOD, SC_DEL, SC_RENAME } op;
	enum sc_step { SC_INIT, SC_ADD_CHECK_PARENT, SC_ADD_TEMP, SC_DEL_CHECK_CHILDREN } step;

	struct schema_private_data *data;

	struct ldb_module *module;
	struct ldb_request *orig_req;
	struct ldb_request *down_req;

	struct ldb_request *parent_req;
	struct ldb_reply *parent_res;

	struct schema_class_dlist *class_list;
	struct schema_class **sup_list;
	struct schema_class **aux_list;
};

/* FIXME: I'd really like to use an hash table here */
struct schema_link {
	const char *name;
	void *object;
};

struct schema_store {
	struct schema_link *store;
	int num_links;
};

static struct schema_store *schema_store_new(TALLOC_CTX *mem_ctx)
{
	struct schema_store *ht;
	
	ht = talloc(mem_ctx, struct schema_store);
	if (!ht) return NULL;

	ht->store = NULL;
	ht->num_links = 0;

	return ht;
}
	
static int schema_store_add(struct schema_store *ht, const char *key, void *object)
{
	ht->store = talloc_realloc(ht, ht->store, struct schema_link, ht->num_links + 1);
	if (!ht->store) return LDB_ERR_OPERATIONS_ERROR;

	ht->store[ht->num_links].name = key;
	ht->store[ht->num_links].object = object;

	ht->num_links++;

	return LDB_SUCCESS;
}

static void *schema_store_find(struct schema_store *ht, const char *key)
{
	int i;

	for (i = 0; i < ht->num_links; i++) {
		if (strcasecmp(ht->store[i].name, key) == 0) {
			return ht->store[i].object;
		}
	}

	return NULL;
}

#define SCHEMA_CHECK_VALUE(mem, val, mod) \
		do { if (mem == val) { \
			ret = LDB_ERR_OPERATIONS_ERROR; \
			ldb_asprintf_errstring(mod->ldb, \
				"schema module: Memory allocation or attribute error on %s", #mem); \
			goto done; } } while(0)

struct schema_class **schema_get_class_list(struct ldb_module *module,
					    struct schema_private_data *data,
					    struct ldb_message_element *el)
{
	struct schema_class **list;
	int i;
	
	list = talloc_array(data, struct schema_class *, el->num_values + 1);
	if (!list) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Out of Memory");
		return NULL;
	}
	
	for (i = 0; i < el->num_values; i++) {
		list[i] = (struct schema_class *)schema_store_find(data->class_store,
								  (char *)el->values[i].data);
		if (!list[i]) {
			ldb_debug_set(module->ldb,
					LDB_DEBUG_ERROR,
					"Class %s referenced but not found in schema\n",
					(char *)el->values[i].data);
			return NULL;
		}
	}
	list[i] = NULL;

	return list;
}

struct schema_attribute **schema_get_attrs_list(struct ldb_module *module,
						struct schema_private_data *data,
						struct ldb_message_element *el)
{
	struct schema_attribute **list;
	int i;

	list = talloc_array(data, struct schema_attribute *, el->num_values + 1);
	if (!list) {
		ldb_debug(module->ldb, LDB_DEBUG_ERROR, "Out of Memory");
		return NULL;
	}
	
	for (i = 0; i < el->num_values; i++) {
		list[i] = (struct schema_attribute *)schema_store_find(data->attrs_store,
								      (char *)el->values[i].data);
		if (!list[i]) {
			ldb_debug_set(module->ldb,
					LDB_DEBUG_ERROR,
					"Attriobute %s referenced but not found in schema\n",
					(char *)el->values[i].data);
			return NULL;
		}
	}
	list[i] = NULL;

	return list;
}

static int schema_init_attrs(struct ldb_module *module, struct schema_private_data *data)
{
	static const char *schema_attrs[] = {	"attributeID",
						"lDAPDisplayName",
						"attributeSyntax",
						"oMSyntax",
						"oMObjectClass",
						"isSingleValued",
						"rangeLower",
						"rangeUpper",
						"searchFlag",
						"systemFlag",
						"isDefunct",
						NULL };
	struct ldb_result *res;
	int ret, i;

	ret = ldb_search(module->ldb,
			 data->schema_dn,
			 LDB_SCOPE_SUBTREE,
			 "(objectClass=attributeSchema)",
			 schema_attrs,
			 &res);

	if (ret != LDB_SUCCESS) {
		goto done;
	}

	data->num_attributes = res->count;
	data->attrs = talloc_array(data, struct schema_attribute *, res->count);
	SCHEMA_CHECK_VALUE(data->attrs, NULL, module);

	data->attrs_store = schema_store_new(data);
	SCHEMA_CHECK_VALUE(data->attrs_store, NULL, module);
	
	for (i = 0; i < res->count; i++) {
		const char *tmp_single;
		const char *attr_syntax;
		uint32_t om_syntax;
		const struct ldb_val *om_class;

		data->attrs[i] = talloc(data->attrs, struct schema_attribute);
		SCHEMA_CHECK_VALUE(data->attrs[i], NULL, module);

		data->attrs[i]->OID = talloc_strdup(data->attrs[i],
						ldb_msg_find_attr_as_string(res->msgs[i], "attributeID", NULL));
		SCHEMA_CHECK_VALUE(data->attrs[i]->OID, NULL, module);
		
		data->attrs[i]->name = talloc_strdup(data->attrs[i],
						ldb_msg_find_attr_as_string(res->msgs[i], "lDAPDisplayName", NULL));
		SCHEMA_CHECK_VALUE(data->attrs[i]->name, NULL, module);

		/* once we have both the OID and the attribute name, add the pointer to the store */
		schema_store_add(data->attrs_store, data->attrs[i]->OID, data->attrs[i]);
		schema_store_add(data->attrs_store, data->attrs[i]->name, data->attrs[i]);

		attr_syntax = ldb_msg_find_attr_as_string(res->msgs[i], "attributeSyntax", NULL);
		SCHEMA_CHECK_VALUE(attr_syntax, NULL, module);
		
		om_syntax = ldb_msg_find_attr_as_uint(res->msgs[i], "oMSyntax", 0);
		/* 0 is not a valid oMSyntax */
		SCHEMA_CHECK_VALUE(om_syntax, 0, module);

		om_class = ldb_msg_find_ldb_val(res->msgs[i], "oMObjectClass");

		ret = map_schema_syntax(om_syntax, attr_syntax, om_class, &data->attrs[i]->syntax);
		if (ret != LDB_SUCCESS) {
			ldb_asprintf_errstring(module->ldb,
				"schema module: invalid om syntax value on %s",
				data->attrs[i]->name);
			goto done;
		}
		
		tmp_single = ldb_msg_find_attr_as_string(res->msgs[i], "isSingleValued", NULL);
		SCHEMA_CHECK_VALUE(tmp_single, NULL, module);
		if (strcmp(tmp_single, "TRUE") == 0) {
			data->attrs[i]->single = 1;
		} else {
			data->attrs[i]->single = 0;
		}

		/* the following are optional */
		data->attrs[i]->min = ldb_msg_find_attr_as_int(res->msgs[i], "rangeLower", INT_MIN);
		data->attrs[i]->max = ldb_msg_find_attr_as_int(res->msgs[i], "rangeUpper", INT_MAX);
		data->attrs[i]->systemflag = ldb_msg_find_attr_as_int(res->msgs[i], "systemFlag", 0);
		data->attrs[i]->searchflag = ldb_msg_find_attr_as_int(res->msgs[i], "searchFlag", 0);
		data->attrs[i]->isdefunct = ldb_msg_find_attr_as_bool(res->msgs[i], "isDefunct", False);
	}

done:
	talloc_free(res);
	return ret;
}

static int schema_init_classes(struct ldb_module *module, struct schema_private_data *data)
{
	static const char *schema_attrs[] = {	"governsID",
						"lDAPDisplayName",
						"objectClassCategory",
						"defaultObjectCategory",
						"systemOnly",
						"systemFlag",
						"isDefunct",
						"subClassOf",
						"systemAuxiliaryClass",
						"auxiliaryClass",
						"systemPossSuperiors",
						"possSuperiors",
						"possibleInferiors",
						"systemMustContain",
						"MustContain", 
						"systemMayContain",
						"MayContain",
						NULL };
	struct ldb_result *res;
	int ret, i;

	ret = ldb_search(module->ldb,
			 data->schema_dn,
			 LDB_SCOPE_SUBTREE,
			 "(objectClass=classSchema)",
			 schema_attrs,
			 &res);

	if (ret != LDB_SUCCESS) {
		goto done;
	}

	data->num_classes = res->count;
	data->class = talloc_array(data, struct schema_class *, res->count);
	SCHEMA_CHECK_VALUE(data->class, NULL, module);

	data->class_store = schema_store_new(data);
	SCHEMA_CHECK_VALUE(data->class_store, NULL, module);

	for (i = 0; i < res->count; i++) {
		struct ldb_message_element *el;

		data->class[i] = talloc(data->class, struct schema_class);
		SCHEMA_CHECK_VALUE(data->class[i], NULL, module);

		data->class[i]->OID = talloc_strdup(data->class[i],
						ldb_msg_find_attr_as_string(res->msgs[i], "governsID", NULL));
		SCHEMA_CHECK_VALUE(data->class[i]->OID, NULL, module);

		data->class[i]->name = talloc_strdup(data->class[i],
						ldb_msg_find_attr_as_string(res->msgs[i], "lDAPDisplayName", NULL));
		SCHEMA_CHECK_VALUE(data->class[i]->name, NULL, module);

		/* once we have both the OID and the class name, add the pointer to the store */
		schema_store_add(data->class_store, data->class[i]->OID, data->class[i]);
		schema_store_add(data->class_store, data->class[i]->name, data->class[i]);

		data->class[i]->type = ldb_msg_find_attr_as_int(res->msgs[i], "objectClassCategory", -1);
		/* 0 should not be a valid value, but turn out it is so test with -1 */
		SCHEMA_CHECK_VALUE(data->class[i]->type, -1, module);

		data->class[i]->defobjcat = talloc_strdup(data->class[i],
						ldb_msg_find_attr_as_string(res->msgs[i],
									"defaultObjectCategory", NULL));
/*		SCHEMA_CHECK_VALUE(data->class[i]->defobjcat, NULL, module);
*/
		/* the following attributes are all optional */

		data->class[i]->systemOnly = ldb_msg_find_attr_as_bool(res->msgs[i], "systemOnly", False);
		data->class[i]->systemflag = ldb_msg_find_attr_as_int(res->msgs[i], "systemFlag", 0);
		data->class[i]->isdefunct = ldb_msg_find_attr_as_bool(res->msgs[i], "isDefunct", False);

		/* attributes are loaded first, so we can just go an query the attributes repo */
		
		el = ldb_msg_find_element(res->msgs[i], "systemMustContain");
		if (el) {
			data->class[i]->sysmust = schema_get_attrs_list(module, data, el);
			SCHEMA_CHECK_VALUE(data->class[i]->sysmust, NULL, module);
		}

		el = ldb_msg_find_element(res->msgs[i], "MustContain");
		if (el) {
			data->class[i]->must = schema_get_attrs_list(module, data, el);
			SCHEMA_CHECK_VALUE(data->class[i]->must, NULL, module);
		}

		el = ldb_msg_find_element(res->msgs[i], "systemMayContain");
		if (el) {
			data->class[i]->sysmay = schema_get_attrs_list(module, data, el);
			SCHEMA_CHECK_VALUE(data->class[i]->sysmay, NULL, module);
		}

		el = ldb_msg_find_element(res->msgs[i], "MayContain");
		if (el) {
			data->class[i]->may = schema_get_attrs_list(module, data, el);
			SCHEMA_CHECK_VALUE(data->class[i]->may, NULL, module);
		}

	}

	/* subClassOf, systemAuxiliaryClass, auxiliaryClass, systemPossSuperiors
	 * must be filled in a second loop, when all class objects are allocated
	 * or we may not find a class that has not yet been parsed */
	for (i = 0; i < res->count; i++) {
		struct ldb_message_element *el;
		const char *attr;

		/* this is single valued anyway */
		attr = ldb_msg_find_attr_as_string(res->msgs[i], "subClassOf", NULL);
		SCHEMA_CHECK_VALUE(attr, NULL, module);
		data->class[i]->parent = schema_store_find(data->class_store, attr);
		SCHEMA_CHECK_VALUE(data->class[i]->parent, NULL, module);

		/* the following attributes are all optional */

		data->class[i]->sysaux = NULL;
		el = ldb_msg_find_element(res->msgs[i], "systemAuxiliaryClass");
		if (el) {
			data->class[i]->sysaux = schema_get_class_list(module, data, el); 
			SCHEMA_CHECK_VALUE(data->class[i]->sysaux, NULL, module);
		}

		data->class[i]->aux = NULL;
		el = ldb_msg_find_element(res->msgs[i], "auxiliaryClass");
		if (el) {
			data->class[i]->aux = schema_get_class_list(module, data, el); 
			SCHEMA_CHECK_VALUE(data->class[i]->aux, NULL, module);
		}

		data->class[i]->sysposssup = NULL;
		el = ldb_msg_find_element(res->msgs[i], "systemPossSuperiors");
		if (el) {
			data->class[i]->sysposssup = schema_get_class_list(module, data, el); 
			SCHEMA_CHECK_VALUE(data->class[i]->sysposssup, NULL, module);
		}

		data->class[i]->posssup = NULL;
		el = ldb_msg_find_element(res->msgs[i], "possSuperiors");
		if (el) {
			data->class[i]->posssup = schema_get_class_list(module, data, el); 
			SCHEMA_CHECK_VALUE(data->class[i]->posssup, NULL, module);
		}

		data->class[i]->possinf = NULL;
		el = ldb_msg_find_element(res->msgs[i], "possibleInferiors");
		if (el) {
			data->class[i]->possinf = schema_get_class_list(module, data, el); 
			SCHEMA_CHECK_VALUE(data->class[i]->possinf, NULL, module);
		}
	}

done:
	talloc_free(res);
	return ret;
}

static struct ldb_handle *schema_init_handle(struct ldb_request *req, struct ldb_module *module, enum sc_op op)
{
	struct schema_context *sctx;
	struct ldb_handle *h;

	h = talloc_zero(req, struct ldb_handle);
	if (h == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		return NULL;
	}

	h->module = module;

	sctx = talloc_zero(h, struct schema_context);
	if (sctx == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		talloc_free(h);
		return NULL;
	}

	h->private_data = (void *)sctx;

	h->state = LDB_ASYNC_INIT;
	h->status = LDB_SUCCESS;

	sctx->op = op;
	sctx->step = SC_INIT;
	sctx->data = module->private_data;
	sctx->module = module;
	sctx->orig_req = req;

	return h;
}

static int schema_add_check_parent(struct ldb_context *ldb, void *context, struct ldb_reply *ares)
{
	struct schema_context *sctx;

	if (!context || !ares) {
		ldb_set_errstring(ldb, "NULL Context or Result in callback");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	sctx = talloc_get_type(context, struct schema_context);

	/* we are interested only in the single reply (base search) we receive here */
	if (ares->type == LDB_REPLY_ENTRY) {
		if (sctx->parent_res != NULL) {
			ldb_set_errstring(ldb, "Too many results");
			talloc_free(ares);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		sctx->parent_res = talloc_steal(sctx, ares);
	} else {
		talloc_free(ares);
	}

	return LDB_SUCCESS;
}

static int schema_add_build_parent_req(struct schema_context *sctx)
{
	static const char * const parent_attrs[] = { "objectClass", NULL };
	int ret;

	sctx->parent_req = talloc_zero(sctx, struct ldb_request);
	if (sctx->parent_req == NULL) {
		ldb_debug(sctx->module->ldb, LDB_DEBUG_ERROR, "Out of Memory!\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	sctx->parent_req->operation = LDB_SEARCH;
	sctx->parent_req->op.search.scope = LDB_SCOPE_BASE;
	sctx->parent_req->op.search.base = ldb_dn_get_parent(sctx->parent_req, sctx->orig_req->op.add.message->dn);
	sctx->parent_req->op.search.tree = ldb_parse_tree(sctx->parent_req, "(objectClass=*)");
	sctx->parent_req->op.search.attrs = parent_attrs;
	sctx->parent_req->controls = NULL;
	sctx->parent_req->context = sctx;
	sctx->parent_req->callback = schema_add_check_parent;
	ret = ldb_set_timeout_from_prev_req(sctx->module->ldb, sctx->orig_req, sctx->parent_req);

	return ret;
}

static struct schema_class_dlist *schema_add_get_dlist_entry_with_class(struct schema_class_dlist *list, struct schema_class *class)
{
	struct schema_class_dlist *temp;

	for (temp = list; temp && (temp->class != class); temp = temp->next) /* noop */ ;
	return temp;
}

static int schema_add_class_to_dlist(struct schema_class_dlist *list, struct schema_class *class, enum schema_class_type role)
{
	struct schema_class_dlist *entry;
	struct schema_class_dlist *temp;
	int ret;

	/* see if this class is usable */
	if (class->isdefunct) {
		return LDB_ERR_NO_SUCH_ATTRIBUTE;
	}

	/* see if this class already exist in the class list */
	if (schema_add_get_dlist_entry_with_class(list, class)) {
		return LDB_SUCCESS;
	}

	/* this is a new class go on and add to the list */
	entry = talloc_zero(list, struct schema_class_dlist);
	if (!entry) return LDB_ERR_OPERATIONS_ERROR;
	entry->class = class;
	entry->role = class->type;

	/* If parent is top (list is guaranteed to start always with top) */
	if (class->parent == list->class) {
		/* if the hierarchy role is structural try to add it just after top */
		if (role == SCHEMA_CT_STRUCTURAL) {
			/* but check no other class at after top has a structural role */
			if (list->next && (list->next->role == SCHEMA_CT_STRUCTURAL)) {
				return LDB_ERR_OBJECT_CLASS_VIOLATION;
			}
			DLIST_ADD_AFTER(list, entry, list);
		} else {
			DLIST_ADD_END(list, entry, struct schema_class_dlist *);
		}
		return LDB_SUCCESS;
	}

	/* search if parent has already been added */
	temp = schema_add_get_dlist_entry_with_class(list->next, class->parent);
	if (temp == NULL) {
		ret = schema_add_class_to_dlist(list, class->parent, role);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		temp = schema_add_get_dlist_entry_with_class(list->next, class->parent);
	}
	if (!temp) { /* parent not found !? */
		return LDB_ERR_OPERATIONS_ERROR;
	}

	DLIST_ADD_AFTER(list, entry, temp);
	if (role == SCHEMA_CT_STRUCTURAL || role == SCHEMA_CT_AUXILIARY) {
		temp = entry;
		do {
			temp->role = role;
			temp = temp->prev;
			/* stop when hierarchy base is met or when base class parent is top */
		} while (temp->class == temp->next->class->parent &&
			 temp->next->class->parent != list->class);

		/* if we have not reached the head of the list
		 * and role is structural */
		if (temp != list && role == SCHEMA_CT_STRUCTURAL) {
			struct schema_class_dlist *hfirst, *hlast;

			/* check if the list second entry is structural */
			if (list->next->role == SCHEMA_CT_STRUCTURAL) {
				/* we have a confilict here */
				return LDB_ERR_OBJECT_CLASS_VIOLATION;
			}
			/* we have to move this hierarchy of classes
			 * so that the base of the structural hierarchy is right after top */
			 
			hfirst = temp->next;
			hlast = entry;
			/* now hfirst - hlast are the boundaries of the structural hierarchy */
			
			/* extract the structural hierachy from the list */
			hfirst->prev->next = hlast->next;
			if (hlast->next) hlast->next->prev = hfirst->prev;
			
			/* insert the structural hierarchy just after top */
			list->next->prev = hlast;
			hlast->next = list->next;
			list->next = hfirst;
			hfirst->prev = list;
		}	
	}

	return LDB_SUCCESS;
}

/* merge source list into dest list and remove duplicates */
static int schema_merge_class_list(TALLOC_CTX *mem_ctx, struct schema_class ***dest, struct schema_class **source)
{
	struct schema_class **list = *dest;
	int i, j, n, f;

	n = 0;	
	if (list) for (n = 0; list[n]; n++) /* noop */ ;
	f = n;

	for (i = 0; source[i]; i++) {
		for (j = 0; j < f; j++) {
			if (list[j] == source[i]) {
				break;
			}
		}
		if (j < f) { /* duplicate found */
			continue;
		}

		list = talloc_realloc(mem_ctx, list, struct schema_class *, n + 2);
		if (!list) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
		list[n] = source[i];
		n++;
		list[n] = NULL;
	}

	*dest = list;

	return LDB_SUCCESS;
}

/* validate and modify the objectclass attribute to sort and add parents */
static int schema_add_build_objectclass_list(struct schema_context *sctx)
{
	struct schema_class_dlist *temp;
	struct ldb_message_element * el;
	struct schema_class *class;
	int ret, i, an;

	/* First of all initialize list, it must start with class top */
	sctx->class_list = talloc_zero(sctx, struct schema_class_dlist);
	if (!sctx->class_list) return LDB_ERR_OPERATIONS_ERROR;

	sctx->class_list->class = schema_store_find(sctx->data->class_store, "top");
	if (!sctx->class_list->class) return LDB_ERR_OPERATIONS_ERROR;

	el = ldb_msg_find_element(sctx->orig_req->op.add.message, "objectClass");
	if (!el) {
		return LDB_ERR_OBJECT_CLASS_VIOLATION;
	}

	for (i = 0; i < el->num_values; i++) {

		class = schema_store_find(sctx->data->class_store, (char *)el->values[i].data);
		if (!class) {
			return LDB_ERR_NO_SUCH_ATTRIBUTE;
		}
		
		ret = schema_add_class_to_dlist(sctx->class_list, class, class->type);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	/* now check if there is any class role that is still not STRUCTURAL or AUXILIARY */
	/* build also the auxiliary class list and the possible superiors list */ 
	temp = sctx->class_list->next; /* top is special, skip it */
	an = 0;

	while (temp) {
		if (temp->role == SCHEMA_CT_ABSTRACT || temp->role == SCHEMA_CT_88) {
			return LDB_ERR_OBJECT_CLASS_VIOLATION;
		}
		if (temp->class->sysaux) {
			ret = schema_merge_class_list(sctx, &sctx->aux_list, temp->class->sysaux);
			if (ret != LDB_SUCCESS) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}
		if (temp->class->aux) {
			ret = schema_merge_class_list(sctx, &sctx->aux_list, temp->class->aux);
			if (ret != LDB_SUCCESS) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}
		if (temp->class->sysposssup) {
			ret = schema_merge_class_list(sctx, &sctx->sup_list, temp->class->sysposssup);
			if (ret != LDB_SUCCESS) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}
		if (temp->class->posssup) {
			ret = schema_merge_class_list(sctx, &sctx->sup_list, temp->class->posssup);
			if (ret != LDB_SUCCESS) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}
		temp = temp->next;
	}

	/* complete sup_list with material from the aux classes */
	for (i = 0; sctx->aux_list && sctx->aux_list[i]; i++) {
		if (sctx->aux_list[i]->sysposssup) {
			ret = schema_merge_class_list(sctx, &sctx->sup_list, sctx->aux_list[i]->sysposssup);
			if (ret != LDB_SUCCESS) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}
		if (sctx->aux_list[i]->posssup) {
			ret = schema_merge_class_list(sctx, &sctx->sup_list, sctx->aux_list[i]->posssup);
			if (ret != LDB_SUCCESS) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}
	}

	if (!sctx->sup_list) return LDB_ERR_NAMING_VIOLATION;

	return LDB_SUCCESS;
}

static int schema_add_check_container_constraints(struct schema_context *sctx)
{
	struct schema_class **parent_possinf = NULL;
	struct schema_class **parent_classes;
	struct schema_class_dlist *temp;
	struct ldb_message_element *el;
	int i, j, ret;

	el = ldb_msg_find_element(sctx->parent_res->message, "objectClass");
	if (!el) {
		/* what the .. */
		return LDB_ERR_OPERATIONS_ERROR;
	}

	parent_classes = talloc_array(sctx, struct schema_class *, el->num_values + 1);

	for (i = 0; i < el->num_values; i++) {

		parent_classes[i] = schema_store_find(sctx->data->class_store, (const char *)el->values[i].data);
		if (!parent_classes[i]) { /* should not be possible */
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if (parent_classes[i]->possinf) {
			ret = schema_merge_class_list(sctx, &parent_possinf, parent_classes[i]->possinf);
			if (ret != LDB_SUCCESS) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}

		/* check also embedded auxiliary classes possinf */
		for (j = 0; parent_classes[i]->sysaux && parent_classes[i]->sysaux[j]; j++) {
			if (parent_classes[i]->sysaux[j]->possinf) {
				ret = schema_merge_class_list(sctx, &parent_possinf, parent_classes[i]->sysaux[j]->possinf);
				if (ret != LDB_SUCCESS) {
					return LDB_ERR_OPERATIONS_ERROR;
				}
			}
		}
		for (j = 0; parent_classes[i]->aux && parent_classes[i]->aux[j]; j++) {
			if (parent_classes[i]->aux[j]->possinf) {
				ret = schema_merge_class_list(sctx, &parent_possinf, parent_classes[i]->aux[j]->possinf);
				if (ret != LDB_SUCCESS) {
					return LDB_ERR_OPERATIONS_ERROR;
				}
			}
		}
	}

	/* foreach parent objectclass,
	 *   check parent possible inferiors match all of the child objectclasses
	 *    and that
	 *   poss Superiors of the child objectclasses mathes one of the parent classes
	 */

	temp = sctx->class_list->next; /* skip top it is special */
	while (temp) {

		for (i = 0; parent_possinf[i]; i++) {
			if (temp->class == parent_possinf[i]) {
				break;
			}
		}
		if (parent_possinf[i] == NULL) {
			/* class not found in possible inferiors */
			return LDB_ERR_NAMING_VIOLATION;
		}

		temp = temp->next;
	}

	for (i = 0; parent_classes[i]; i++) {
		for (j = 0; sctx->sup_list[j]; j++) {
			if (sctx->sup_list[j] == parent_classes[i]) {
				break;
			}
		}
		if (sctx->sup_list[j]) { /* possible Superiors match one of the parent classes */
			return LDB_SUCCESS;
		}
	}

	/* no parent classes matched superiors */
	return LDB_ERR_NAMING_VIOLATION;
}

static int schema_add_build_down_req(struct schema_context *sctx)
{
	struct schema_class_dlist *temp;
	struct ldb_message *msg;
	char *oc;
	int ret;

	sctx->down_req = talloc(sctx, struct ldb_request);
	if (!sctx->down_req) {
		ldb_set_errstring(sctx->module->ldb, "Out of memory!");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*(sctx->down_req) = *(sctx->orig_req); /* copy the request */
	msg = ldb_msg_copy_shallow(sctx->down_req, sctx->orig_req->op.add.message);
	if (!msg) {
		ldb_set_errstring(sctx->module->ldb, "Out of memory!");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* rebuild the objectclass list */
	ldb_msg_remove_attr(msg, "objectClass");
	ret = ldb_msg_add_empty(msg, "objectClass", 0, NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* Add the complete list of classes back to the message */
	for (temp = sctx->class_list; temp; temp = temp->next) {
		ret = ldb_msg_add_string(msg, "objectClass", temp->class->name);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	/* objectCategory can be set only by the system */
	if (ldb_msg_find_element(msg, "objectCategory")) {
		return LDB_ERR_CONSTRAINT_VIOLATION;
	}

	/* the OC is mandatory, every class defines it */
	/* use the one defined in the structural class that defines the object */
	for (temp = sctx->class_list->next; temp; temp = temp->next) {
		if (!temp->next) break;
		if (temp->next->role != SCHEMA_CT_STRUCTURAL) break;
	}
/*	oc = talloc_strdup(msg, temp->class->defobjcat);
	ret = ldb_msg_add_string(msg, "objectCategory", oc);
*/
	sctx->down_req->op.add.message = msg;

	return LDB_SUCCESS;
}

static int schema_check_attributes_syntax(struct schema_context *sctx)
{
	struct ldb_message *msg;
	struct schema_attribute *attr;
	int i, ret;

	msg = sctx->orig_req->op.add.message;
	for (i = 0; i < msg->num_elements; i++) {
		attr = schema_store_find(sctx->data->attrs_store, msg->elements[i].name);
		if (attr == NULL) {
			return LDB_ERR_NO_SUCH_ATTRIBUTE;
		}
		ret = schema_validate(sctx->module->ldb, &msg->elements[i], attr->syntax, attr->single, attr->min, attr->max);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return LDB_SUCCESS;
}

static int schema_add_continue(struct ldb_handle *h)
{
	struct schema_context *sctx;
	int ret;

	sctx = talloc_get_type(h->private_data, struct schema_context);

	switch (sctx->step) {
	case SC_INIT:

		/* First of all check that a parent exists for this entry */
		ret = schema_add_build_parent_req(sctx);
		if (ret != LDB_SUCCESS) {
			break;
		}

		sctx->step = SC_ADD_CHECK_PARENT;
		return ldb_next_request(sctx->module, sctx->parent_req);

	case SC_ADD_CHECK_PARENT:

		/* parent search done, check result and go on */
		if (sctx->parent_res == NULL) {
			/* we must have a parent */
			ret = LDB_ERR_NO_SUCH_OBJECT;
			break;
		}

		/* Check objectclasses are ok */
		ret = schema_add_build_objectclass_list(sctx);
	       	if (ret != LDB_SUCCESS) {
			break;
		}

		/* check the parent is of the right type for this object */
		ret = schema_add_check_container_constraints(sctx);
	       	if (ret != LDB_SUCCESS) {
			break;
		}

		/* check attributes syntax */
		
		ret = schema_check_attributes_syntax(sctx);
		if (ret != LDB_SUCCESS) {
			break;
		}

		ret = schema_add_build_down_req(sctx);
		if (ret != LDB_SUCCESS) {
			break;
		}
		sctx->step = SC_ADD_TEMP;

		return ldb_next_request(sctx->module, sctx->down_req);

	default:
		ret = LDB_ERR_OPERATIONS_ERROR;
		break;
	}

	/* this is reached only in case of error */
	/* FIXME: fire an async reply ? */
	h->status = ret;
	h->state = LDB_ASYNC_DONE;
	return ret;
}

static int schema_add(struct ldb_module *module, struct ldb_request *req)
{
	struct schema_context *sctx;
	struct ldb_handle *h;

	if (ldb_dn_is_special(req->op.add.message->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	h = schema_init_handle(req, module, SC_ADD);
	if (!h) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	sctx = talloc_get_type(h->private_data, struct schema_context);
	sctx->orig_req->handle = h;
	return schema_add_continue(h);
}


static int schema_modify(struct ldb_module *module, struct ldb_request *req)
{
	if (ldb_dn_is_special(req->op.mod.message->dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	return ldb_next_request(module, req);	
}

static int schema_delete(struct ldb_module *module, struct ldb_request *req)
{
	if (ldb_dn_is_special(req->op.del.dn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}
	
	/* First of all check no children exists for this entry */

	return ldb_next_request(module, req);
}

static int schema_rename(struct ldb_module *module, struct ldb_request *req)
{
	if (ldb_dn_is_special(req->op.rename.olddn) &&
	    ldb_dn_is_special(req->op.rename.newdn)) { /* do not manipulate our control entries */
		return ldb_next_request(module, req);
	}

	return ldb_next_request(module, req);
}

static int schema_wait_loop(struct ldb_handle *handle) {
	struct schema_context *sctx;
	int ret;
    
	if (!handle || !handle->private_data) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (handle->state == LDB_ASYNC_DONE) {
		return handle->status;
	}

	handle->state = LDB_ASYNC_PENDING;
	handle->status = LDB_SUCCESS;

	sctx = talloc_get_type(handle->private_data, struct schema_context);

	switch (sctx->step) {
	case SC_ADD_CHECK_PARENT:
		ret = ldb_wait(sctx->parent_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (sctx->parent_req->handle->status != LDB_SUCCESS) {
			handle->status = sctx->parent_req->handle->status;
			goto done;
		}

		if (sctx->parent_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		return schema_add_continue(handle);

	case SC_ADD_TEMP:
		ret = ldb_wait(sctx->down_req->handle, LDB_WAIT_NONE);

		if (ret != LDB_SUCCESS) {
			handle->status = ret;
			goto done;
		}
		if (sctx->down_req->handle->status != LDB_SUCCESS) {
			handle->status = sctx->down_req->handle->status;
			goto done;
		}

		if (sctx->down_req->handle->state != LDB_ASYNC_DONE) {
			return LDB_SUCCESS;
		}

		break;

	default:
		ret = LDB_ERR_OPERATIONS_ERROR;
		goto done;
	}

	ret = LDB_SUCCESS;

done:
	handle->state = LDB_ASYNC_DONE;
	return ret;
}

static int schema_wait_all(struct ldb_handle *handle) {

	int ret;

	while (handle->state != LDB_ASYNC_DONE) {
		ret = schema_wait_loop(handle);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	return handle->status;
}

static int schema_wait(struct ldb_handle *handle, enum ldb_wait_type type)
{
	if (type == LDB_WAIT_ALL) {
		return schema_wait_all(handle);
	} else {
		return schema_wait_loop(handle);
	}
}

static int schema_init(struct ldb_module *module)
{
	static const char *schema_attrs[] = { "schemaNamingContext", NULL };
	struct schema_private_data *data;
	struct ldb_result *res;
	int ret;

	/* need to let the partition module to register first */
	ret = ldb_next_init(module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	data = ldb_get_opaque(module->ldb, "schema_instance");
	if (data) {
		module->private_data = data;
		return LDB_SUCCESS;
	}

	data = talloc_zero(module->ldb, struct schema_private_data);
	if (data == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* find the schema partition */
	ret = ldb_search(module->ldb,
			 ldb_dn_new(module, module->ldb, NULL),
			 LDB_SCOPE_BASE,
			 "(objectClass=*)",
			 schema_attrs,
			 &res);

	if (res->count != 1) {
		/* FIXME: return a clear error string */
		talloc_free(data);
		talloc_free(res);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	data->schema_dn = ldb_msg_find_attr_as_dn(module->ldb, data, res->msgs[0], "schemaNamingContext");
	if (data->schema_dn == NULL) {
		/* FIXME: return a clear error string */
		talloc_free(data);
		talloc_free(res);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	talloc_free(res);

	ret = schema_init_attrs(module, data);
	if (ret != LDB_SUCCESS) {
		talloc_free(data);
		return ret;
	}

	ret = schema_init_classes(module, data);
	if (ret != LDB_SUCCESS) {
		talloc_free(data);
		return ret;
	}

	module->private_data = data;
	ldb_set_opaque(module->ldb, "schema_instance", data);

	return LDB_SUCCESS;
}

static const struct ldb_module_ops schema_ops = {
	.name          = "schema",
	.init_context  = schema_init,
	.add           = schema_add,
	.modify        = schema_modify,
	.del           = schema_delete,
	.rename        = schema_rename,
	.wait          = schema_wait
};

int ldb_schema_init(void)
{
	return ldb_register_module(&schema_ops);
}
