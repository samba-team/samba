/* 
   ldb database module

   LDAP semantics mapping module

   Copyright (C) Jelmer Vernooij 2005
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006

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
   This module relies on ldb_map to do all the real work, but performs
   some of the trivial mappings between AD semantics and that provided
   by OpenLDAP and similar servers.
*/

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/modules/ldb_map.h"

#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/ndr/libndr.h"

struct entryUUID_private {
	struct ldb_result *objectclass_res;	
	struct ldb_dn **base_dns;
};

static struct ldb_val encode_guid(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct GUID guid;
	NTSTATUS status = GUID_from_string((char *)val->data, &guid);
	struct ldb_val out = data_blob(NULL, 0);

	if (!NT_STATUS_IS_OK(status)) {
		return out;
	}
	status = ndr_push_struct_blob(&out, ctx, &guid, 
				      (ndr_push_flags_fn_t)ndr_push_GUID);
	if (!NT_STATUS_IS_OK(status)) {
		return out;
	}

	return out;
}

static struct ldb_val guid_always_string(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct GUID *guid;
	NTSTATUS status;
	struct ldb_val out = data_blob(NULL, 0);
	if (val->length >= 32 && val->data[val->length] == '\0') {
		ldb_handler_copy(module->ldb, ctx, val, &out);
	} else {
		guid = talloc(ctx, struct GUID);
		if (guid == NULL) {
			return out;
		}
		status = ndr_pull_struct_blob(val, guid, guid, 
					      (ndr_pull_flags_fn_t)ndr_pull_GUID);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(guid);
			return out;
		}
		out = data_blob_string_const(GUID_string(ctx, guid));
		talloc_free(guid);
	}
	return out;
}

/* The backend holds binary sids, so just copy them back */
static struct ldb_val val_copy(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct ldb_val out = data_blob(NULL, 0);
	ldb_handler_copy(module->ldb, ctx, val, &out);

	return out;
}

/* Ensure we always convert sids into binary, so the backend doesn't have to know about both forms */
static struct ldb_val sid_always_binary(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct ldb_val out = data_blob(NULL, 0);
	const struct ldb_attrib_handler *handler = ldb_attrib_handler(module->ldb, "objectSid");
	
	if (handler->canonicalise_fn(module->ldb, ctx, val, &out) != LDB_SUCCESS) {
		return data_blob(NULL, 0);
	}

	return out;
}

static struct ldb_val objectCategory_always_dn(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	int i;
	struct map_private *map_private;
	struct entryUUID_private *entryUUID_private;
	struct ldb_result *list;

	if (ldb_dn_validate(ldb_dn_new(ctx, module->ldb, (const char *)val->data))) {
		return *val;
	}
	map_private = talloc_get_type(module->private_data, struct map_private);

	entryUUID_private = talloc_get_type(map_private->caller_private, struct entryUUID_private);
	list = entryUUID_private->objectclass_res;

	for (i=0; list && (i < list->count); i++) {
		if (ldb_attr_cmp((const char *)val->data, ldb_msg_find_attr_as_string(list->msgs[i], "lDAPDisplayName", NULL)) == 0) {
			char *dn = ldb_dn_alloc_linearized(ctx, list->msgs[i]->dn);
			return data_blob_string_const(dn);
		}
	}
	return *val;
}

static struct ldb_val class_to_oid(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	int i;
	struct map_private *map_private;
	struct entryUUID_private *entryUUID_private;
	struct ldb_result *list;

	map_private = talloc_get_type(module->private_data, struct map_private);

	entryUUID_private = talloc_get_type(map_private->caller_private, struct entryUUID_private);
	list = entryUUID_private->objectclass_res;

	for (i=0; list && (i < list->count); i++) {
		if (ldb_attr_cmp((const char *)val->data, ldb_msg_find_attr_as_string(list->msgs[i], "lDAPDisplayName", NULL)) == 0) {
			const char *oid = ldb_msg_find_attr_as_string(list->msgs[i], "governsID", NULL);
			return data_blob_string_const(oid);
		}
	}
	return *val;
}

static struct ldb_val class_from_oid(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	int i;
	struct map_private *map_private;
	struct entryUUID_private *entryUUID_private;
	struct ldb_result *list;

	map_private = talloc_get_type(module->private_data, struct map_private);

	entryUUID_private = talloc_get_type(map_private->caller_private, struct entryUUID_private);
	list = entryUUID_private->objectclass_res;

	for (i=0; list && (i < list->count); i++) {
		if (ldb_attr_cmp((const char *)val->data, ldb_msg_find_attr_as_string(list->msgs[i], "governsID", NULL)) == 0) {
			const char *oc = ldb_msg_find_attr_as_string(list->msgs[i], "lDAPDisplayName", NULL);
			return data_blob_string_const(oc);
		}
	}
	return *val;
}


static struct ldb_val normalise_to_signed32(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	long long int signed_ll = strtoll((const char *)val->data, NULL, 10);
	if (signed_ll >= 0x80000000LL) {
		union {
			int32_t signed_int;
			uint32_t unsigned_int;
		} u = {
			.unsigned_int = strtoul((const char *)val->data, NULL, 10)
		};

		struct ldb_val out = data_blob_string_const(talloc_asprintf(ctx, "%d", u.signed_int));
		return out;
	}
	return val_copy(module, ctx, val);
}

static struct ldb_val usn_to_entryCSN(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct ldb_val out;
	unsigned long long usn = strtoull((const char *)val->data, NULL, 10);
	time_t t = (usn >> 24);
	out = data_blob_string_const(talloc_asprintf(ctx, "%s#%06x#00#000000", ldb_timestring(ctx, t), (unsigned int)(usn & 0xFFFFFF)));
	return out;
}

static unsigned long long entryCSN_to_usn_int(TALLOC_CTX *ctx, const struct ldb_val *val) 
{
	char *entryCSN = talloc_strdup(ctx, (const char *)val->data);
	char *mod_per_sec;
	time_t t;
	unsigned long long usn;
	char *p;
	if (!entryCSN) {
		return 0;
	}
	p = strchr(entryCSN, '#');
	if (!p) {
		return 0;
	}
	p[0] = '\0';
	p++;
	mod_per_sec = p;

	p = strchr(p, '#');
	if (!p) {
		return 0;
	}
	p[0] = '\0';
	p++;

	usn = strtol(mod_per_sec, NULL, 16);

	t = ldb_string_to_time(entryCSN);
	
	usn = usn | ((unsigned long long)t <<24);
	return usn;
}

static struct ldb_val entryCSN_to_usn(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct ldb_val out;
	unsigned long long usn = entryCSN_to_usn_int(ctx, val);
	out = data_blob_string_const(talloc_asprintf(ctx, "%lld", usn));
	return out;
}

static struct ldb_val usn_to_timestamp(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct ldb_val out;
	unsigned long long usn = strtoull((const char *)val->data, NULL, 10);
	time_t t = (usn >> 24);
	out = data_blob_string_const(ldb_timestring(ctx, t));
	return out;
}

static struct ldb_val timestamp_to_usn(struct ldb_module *module, TALLOC_CTX *ctx, const struct ldb_val *val)
{
	struct ldb_val out;
	time_t t;
	unsigned long long usn;

	t = ldb_string_to_time((const char *)val->data);
	
	usn = ((unsigned long long)t <<24);

	out = data_blob_string_const(talloc_asprintf(ctx, "%lld", usn));
	return out;
}


const struct ldb_map_attribute entryUUID_attributes[] = 
{
	/* objectGUID */
	{
		.local_name = "objectGUID",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				.remote_name = "entryUUID", 
				.convert_local = guid_always_string,
				.convert_remote = encode_guid,
			},
		},
	},
	/* objectSid */
	{
		.local_name = "objectSid",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				.remote_name = "objectSid", 
				.convert_local = sid_always_binary,
				.convert_remote = val_copy,
			},
		},
	},
	{
		.local_name = "whenCreated",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				 .remote_name = "createTimestamp"
			 }
		}
	},
	{
		.local_name = "whenChanged",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				 .remote_name = "modifyTimestamp"
			 }
		}
	},
	{
		.local_name = "sambaPassword",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				 .remote_name = "userPassword"
			 }
		}
	},
	{
		.local_name = "allowedChildClassesEffective",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				.remote_name = "allowedChildClassesEffective", 
				.convert_local = class_to_oid,
				.convert_remote = class_from_oid,
			},
		},
	},
	{
		.local_name = "objectCategory",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				.remote_name = "objectCategory", 
				.convert_local = objectCategory_always_dn,
				.convert_remote = val_copy,
			},
		},
	},
	{
		.local_name = "distinguishedName",
		.type = MAP_RENAME,
		.u = {
			.rename = {
				 .remote_name = "entryDN"
			 }
		}
	},
	{
		.local_name = "groupType",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				 .remote_name = "groupType",
				 .convert_local = normalise_to_signed32,
				 .convert_remote = val_copy,
			 },
		}
	},
	{
		.local_name = "sAMAccountType",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				 .remote_name = "sAMAccountType",
				 .convert_local = normalise_to_signed32,
				 .convert_remote = val_copy,
			 },
		}
	},
	{
		.local_name = "usnChanged",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				 .remote_name = "entryCSN",
				 .convert_local = usn_to_entryCSN,
				 .convert_remote = entryCSN_to_usn
			 },
		},
	},
	{
		.local_name = "usnCreated",
		.type = MAP_CONVERT,
		.u = {
			.convert = {
				 .remote_name = "createTimestamp",
				 .convert_local = usn_to_timestamp,
				 .convert_remote = timestamp_to_usn,
			 },
		},
	},
	{
		.local_name = "*",
		.type = MAP_KEEP,
	},
	{
		.local_name = NULL,
	}
};

/* These things do not show up in wildcard searches in OpenLDAP, but
 * we need them to show up in the AD-like view */
const char * const wildcard_attributes[] = {
	"objectGUID", 
	"whenCreated", 
	"whenChanged",
	"usnCreated",
	"usnChanged",
	NULL
};

static struct ldb_dn *find_schema_dn(struct ldb_context *ldb, TALLOC_CTX *mem_ctx) 
{
	const char *rootdse_attrs[] = {"schemaNamingContext", NULL};
	struct ldb_dn *schema_dn;
	struct ldb_dn *basedn = ldb_dn_new(mem_ctx, ldb, NULL);
	struct ldb_result *rootdse_res;
	int ldb_ret;
	if (!basedn) {
		return NULL;
	}
	
	/* Search for rootdse */
	ldb_ret = ldb_search(ldb, basedn, LDB_SCOPE_BASE, NULL, rootdse_attrs, &rootdse_res);
	if (ldb_ret != LDB_SUCCESS) {
		return NULL;
	}
	
	talloc_steal(mem_ctx, rootdse_res);

	if (rootdse_res->count != 1) {
		ldb_asprintf_errstring(ldb, "Failed to find rootDSE: count %d", rootdse_res->count);
		return NULL;
	}
	
	/* Locate schema */
	schema_dn = ldb_msg_find_attr_as_dn(ldb, mem_ctx, rootdse_res->msgs[0], "schemaNamingContext");
	if (!schema_dn) {
		return NULL;
	}

	talloc_free(rootdse_res);
	return schema_dn;
}

static int fetch_objectclass_schema(struct ldb_context *ldb, struct ldb_dn *schemadn,
			      TALLOC_CTX *mem_ctx, 
			      struct ldb_result **objectclass_res)
{
	TALLOC_CTX *local_ctx = talloc_new(mem_ctx);
	int ret;
	const char *attrs[] = {
		"lDAPDisplayName",
		"governsID",
		NULL
	};

	if (!local_ctx) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	
	/* Downlaod schema */
	ret = ldb_search(ldb, schemadn, LDB_SCOPE_SUBTREE, 
			 "objectClass=classSchema", 
			 attrs, objectclass_res);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	talloc_steal(mem_ctx, objectclass_res);

	return ret;
}


static int get_remote_rootdse(struct ldb_context *ldb, void *context, 
		       struct ldb_reply *ares) 
{
	struct entryUUID_private *entryUUID_private;
	entryUUID_private = talloc_get_type(context,
					    struct entryUUID_private);
	if (ares->type == LDB_REPLY_ENTRY) {
		int i;
		struct ldb_message_element *el = ldb_msg_find_element(ares->message, "namingContexts");
		entryUUID_private->base_dns = talloc_realloc(entryUUID_private, entryUUID_private->base_dns, struct ldb_dn *, 
							     el->num_values + 1);
		for (i=0; i < el->num_values; i++) {
			if (!entryUUID_private->base_dns) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
			entryUUID_private->base_dns[i] = ldb_dn_new(entryUUID_private->base_dns, ldb, (const char *)el->values[i].data);
			if ( ! ldb_dn_validate(entryUUID_private->base_dns[i])) {
				return LDB_ERR_OPERATIONS_ERROR;
			}
		}
		entryUUID_private->base_dns[i] = NULL;
	}

	return LDB_SUCCESS;
}

static int find_base_dns(struct ldb_module *module, 
			  struct entryUUID_private *entryUUID_private) 
{
	int ret;
	struct ldb_request *req;
	const char *naming_context_attr[] = {
		"namingContexts",
		NULL
	};
	req = talloc(entryUUID_private, struct ldb_request);
	if (req == NULL) {
		ldb_set_errstring(module->ldb, "Out of Memory");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->operation = LDB_SEARCH;
	req->op.search.base = ldb_dn_new(req, module->ldb, NULL);
	req->op.search.scope = LDB_SCOPE_BASE;

	req->op.search.tree = ldb_parse_tree(req, "objectClass=*");
	if (req->op.search.tree == NULL) {
		ldb_set_errstring(module->ldb, "Unable to parse search expression");
		talloc_free(req);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	req->op.search.attrs = naming_context_attr;
	req->controls = NULL;
	req->context = entryUUID_private;
	req->callback = get_remote_rootdse;
	ldb_set_timeout(module->ldb, req, 0); /* use default timeout */

	ret = ldb_next_request(module, req);
	
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}
	
	talloc_free(req);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

/* the context init function */
static int entryUUID_init(struct ldb_module *module)
{
        int ret;
	struct map_private *map_private;
	struct entryUUID_private *entryUUID_private;
	struct ldb_dn *schema_dn;

	ret = ldb_map_init(module, entryUUID_attributes, NULL, wildcard_attributes, NULL);
        if (ret != LDB_SUCCESS)
                return ret;

	map_private = talloc_get_type(module->private_data, struct map_private);

	entryUUID_private = talloc_zero(map_private, struct entryUUID_private);
	map_private->caller_private = entryUUID_private;

	schema_dn = find_schema_dn(module->ldb, map_private);
	if (!schema_dn) {
		/* Perhaps no schema yet */
		return LDB_SUCCESS;
	}
	
	ret = fetch_objectclass_schema(module->ldb, schema_dn, entryUUID_private, 
				       &entryUUID_private->objectclass_res);
	if (ret != LDB_SUCCESS) {
		ldb_asprintf_errstring(module->ldb, "Failed to fetch objectClass schema elements: %s\n", ldb_errstring(module->ldb));
		return ret;
	}	

	ret = find_base_dns(module, entryUUID_private);

	return ldb_next_init(module);
}

static int get_seq(struct ldb_context *ldb, void *context, 
		   struct ldb_reply *ares) 
{
	unsigned long long *max_seq = context;
	unsigned long long seq;
	if (ares->type == LDB_REPLY_ENTRY) {
		struct ldb_message_element *el = ldb_msg_find_element(ares->message, "contextCSN");
		if (el) {
			seq = entryCSN_to_usn_int(ares, &el->values[0]);
			*max_seq = MAX(seq, *max_seq);
		}
	}

	return LDB_SUCCESS;
}

static int entryUUID_sequence_number(struct ldb_module *module, struct ldb_request *req)
{
	int i, ret;
	struct map_private *map_private;
	struct entryUUID_private *entryUUID_private;
	unsigned long long max_seq = 0;
	struct ldb_request *search_req;
	map_private = talloc_get_type(module->private_data, struct map_private);

	entryUUID_private = talloc_get_type(map_private->caller_private, struct entryUUID_private);

	/* Search the baseDNs for a sequence number */
	for (i=0; entryUUID_private && 
		     entryUUID_private->base_dns && 
		     entryUUID_private->base_dns[i];
		i++) {
		static const char *contextCSN_attr[] = {
			"contextCSN", NULL
		};
		search_req = talloc(req, struct ldb_request);
		if (search_req == NULL) {
			ldb_set_errstring(module->ldb, "Out of Memory");
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		search_req->operation = LDB_SEARCH;
		search_req->op.search.base = entryUUID_private->base_dns[i];
		search_req->op.search.scope = LDB_SCOPE_BASE;
		
		search_req->op.search.tree = ldb_parse_tree(search_req, "objectClass=*");
		if (search_req->op.search.tree == NULL) {
			ldb_set_errstring(module->ldb, "Unable to parse search expression");
			talloc_free(search_req);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		
		search_req->op.search.attrs = contextCSN_attr;
		search_req->controls = NULL;
		search_req->context = &max_seq;
		search_req->callback = get_seq;
		ldb_set_timeout(module->ldb, search_req, 0); /* use default timeout */
		
		ret = ldb_next_request(module, search_req);
		
		if (ret == LDB_SUCCESS) {
			ret = ldb_wait(search_req->handle, LDB_WAIT_ALL);
		}
		
		talloc_free(search_req);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	switch (req->op.seq_num.type) {
	case LDB_SEQ_HIGHEST_SEQ:
		req->op.seq_num.seq_num = max_seq;
		break;
	case LDB_SEQ_NEXT:
		req->op.seq_num.seq_num = max_seq;
		req->op.seq_num.seq_num++;
		break;
	case LDB_SEQ_HIGHEST_TIMESTAMP:
	{
		req->op.seq_num.seq_num = (max_seq >> 24);
		break;
	}
	}
	req->op.seq_num.flags = 0;
	req->op.seq_num.flags |= LDB_SEQ_TIMESTAMP_SEQUENCE;
	req->op.seq_num.flags |= LDB_SEQ_GLOBAL_SEQUENCE;
	return LDB_SUCCESS;
}

static struct ldb_module_ops entryUUID_ops = {
	.name		   = "entryUUID",
	.init_context	   = entryUUID_init,
	.sequence_number   = entryUUID_sequence_number
};

/* the init function */
int ldb_entryUUID_module_init(void)
{
	struct ldb_module_ops ops = ldb_map_get_ops();
	entryUUID_ops.add	= ops.add;
	entryUUID_ops.modify	= ops.modify;
	entryUUID_ops.del	= ops.del;
	entryUUID_ops.rename	= ops.rename;
	entryUUID_ops.search	= ops.search;
	entryUUID_ops.wait	= ops.wait;
	return ldb_register_module(&entryUUID_ops);
}
