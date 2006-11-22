/* 
   Unix SMB/CIFS implementation.
   Registry interface
   Copyright (C) Jelmer Vernooij  2004.
   
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

#include "includes.h"
#include "registry.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "db_wrap.h"
#include "librpc/gen_ndr/winreg.h"

struct ldb_key_data 
{
	struct ldb_dn *dn;
	struct ldb_message **subkeys, **values;
	int subkey_count, value_count;
};

static int ldb_free_hive (struct registry_hive *hive)
{
	talloc_free(hive->backend_data);
	hive->backend_data = NULL;
	return 0;
}

static void reg_ldb_unpack_value(TALLOC_CTX *mem_ctx, struct ldb_message *msg, const char **name, uint32_t *type, DATA_BLOB *data)
{
	const struct ldb_val *val;
	*name = talloc_strdup(mem_ctx, ldb_msg_find_attr_as_string(msg, "value", NULL));
	*type = ldb_msg_find_attr_as_uint(msg, "type", 0);
	val = ldb_msg_find_ldb_val(msg, "data");

	switch (*type)
	{
	case REG_SZ:
	case REG_EXPAND_SZ:
		data->length = convert_string_talloc(mem_ctx, CH_UTF8, CH_UTF16, val->data, val->length, (void **)&data->data);
		break;

	case REG_DWORD: {
		uint32_t tmp = strtoul((char *)val->data, NULL, 0);
		*data = data_blob_talloc(mem_ctx, &tmp, 4);
		}
		break;

	default:
		*data = data_blob_talloc(mem_ctx, val->data, val->length);
		break;
	}
}

static struct ldb_message *reg_ldb_pack_value(struct ldb_context *ctx, TALLOC_CTX *mem_ctx, const char *name, uint32_t type, DATA_BLOB data)
{
	struct ldb_val val;
	struct ldb_message *msg = talloc_zero(mem_ctx, struct ldb_message);
	char *type_s;

	ldb_msg_add_string(msg, "value", talloc_strdup(mem_ctx, name));

	switch (type) {
	case REG_SZ:
	case REG_EXPAND_SZ:
		val.length = convert_string_talloc(mem_ctx, CH_UTF16, CH_UTF8, (void *)data.data, data.length, (void **)&val.data);
		ldb_msg_add_value(msg, "data", &val, NULL);
		break;

	case REG_DWORD:
		ldb_msg_add_string(msg, "data", talloc_asprintf(mem_ctx, "0x%x", IVAL(data.data, 0)));
		break;
	default:
		ldb_msg_add_value(msg, "data", &data, NULL);
	}


	type_s = talloc_asprintf(mem_ctx, "%u", type);
	ldb_msg_add_string(msg, "type", type_s); 

	return msg;
}


static int reg_close_ldb_key(struct registry_key *key)
{
	struct ldb_key_data *kd = talloc_get_type(key->backend_data, struct ldb_key_data);
/*	struct ldb_context *c = key->hive->backend_data; */

	if (kd->subkeys) {
		talloc_free(kd->subkeys); 
		kd->subkeys = NULL;
	}

	if (kd->values) {
		talloc_free(kd->values); 
		kd->values = NULL;
	}
	return 0;
}

static struct ldb_dn *reg_path_to_ldb(TALLOC_CTX *mem_ctx, const struct registry_key *from, const char *path, const char *add)
{
	TALLOC_CTX *local_ctx;
	struct ldb_dn *ret;
	char *mypath = talloc_strdup(mem_ctx, path);
	char *begin;
	struct ldb_key_data *kd = talloc_get_type(from->backend_data, struct ldb_key_data);
	struct ldb_context *ldb = talloc_get_type(from->hive->backend_data, struct ldb_context);

	local_ctx = talloc_new(mem_ctx);

	if (add) {
		ret = ldb_dn_new(mem_ctx, ldb, add);
	} else {
		ret = ldb_dn_new(mem_ctx, ldb, NULL);
	}
	if ( ! ldb_dn_validate(ret)) {
		talloc_free(ret);
		talloc_free(local_ctx);
		return NULL;
	}

	while(mypath) {
		char *keyname;

		begin = strrchr(mypath, '\\');

		if (begin) keyname = begin + 1;
		else keyname = mypath;

		if(strlen(keyname)) {
			ldb_dn_add_base_fmt(ret, "key=%s", keyname);
		}

		if(begin) {
			*begin = '\0';
		} else {
			break;
		}
	}

	ldb_dn_add_base(ret, kd->dn);

	talloc_free(local_ctx);

	return ret;
}


static WERROR ldb_get_subkey_by_id(TALLOC_CTX *mem_ctx, const struct registry_key *k, int idx, struct registry_key **subkey)
{
	struct ldb_context *c = talloc_get_type(k->hive->backend_data, struct ldb_context);
	struct ldb_message_element *el;
	struct ldb_key_data *kd = talloc_get_type(k->backend_data, struct ldb_key_data);
	struct ldb_key_data *newkd;

	/* Do a search if necessary */
	if (kd->subkeys == NULL) {
		struct ldb_result *res;
		int ret;

		ret = ldb_search(c, kd->dn, LDB_SCOPE_ONELEVEL, "(key=*)", NULL, &res);

		if (ret != LDB_SUCCESS) {
			DEBUG(0, ("Error getting subkeys for '%s': %s\n", ldb_dn_linearize(mem_ctx, kd->dn), ldb_errstring(c)));
			return WERR_FOOBAR;
		}

		kd->subkey_count = res->count;
		kd->subkeys = talloc_steal(kd, res->msgs);
		talloc_free(res);
	} 

	if (idx >= kd->subkey_count) return WERR_NO_MORE_ITEMS;

	el = ldb_msg_find_element(kd->subkeys[idx], "key");
	
	*subkey = talloc(mem_ctx, struct registry_key);
	talloc_set_destructor(*subkey, reg_close_ldb_key);
	(*subkey)->name = talloc_strdup(mem_ctx, (char *)el->values[0].data);
	(*subkey)->backend_data = newkd = talloc_zero(*subkey, struct ldb_key_data);
	(*subkey)->last_mod = 0; /* TODO: we need to add this to the
				    ldb backend properly */
	newkd->dn = ldb_dn_copy(mem_ctx, kd->subkeys[idx]->dn);

	return WERR_OK;
}

static WERROR ldb_get_value_by_id(TALLOC_CTX *mem_ctx, const struct registry_key *k, int idx, struct registry_value **value)
{
	struct ldb_context *c = talloc_get_type(k->hive->backend_data, struct ldb_context);
	struct ldb_key_data *kd = talloc_get_type(k->backend_data, struct ldb_key_data);

	/* Do the search if necessary */
	if (kd->values == NULL) {
		struct ldb_result *res;
		int ret;

		ret = ldb_search(c, kd->dn, LDB_SCOPE_ONELEVEL, "(value=*)", NULL, &res);

		if (ret != LDB_SUCCESS) {
			DEBUG(0, ("Error getting values for '%s': %s\n", ldb_dn_linearize(mem_ctx, kd->dn), ldb_errstring(c)));
			return WERR_FOOBAR;
		}
		kd->value_count = res->count;
		kd->values = talloc_steal(kd, res->msgs);
		talloc_free(res);
	}

	if(idx >= kd->value_count) return WERR_NO_MORE_ITEMS;

	*value = talloc(mem_ctx, struct registry_value);

	reg_ldb_unpack_value(mem_ctx, kd->values[idx], &(*value)->name, &(*value)->data_type, &(*value)->data);

	return WERR_OK;
}

static WERROR ldb_open_key(TALLOC_CTX *mem_ctx, const struct registry_key *h, const char *name, struct registry_key **key)
{
	struct ldb_context *c = talloc_get_type(h->hive->backend_data, struct ldb_context);
	struct ldb_result *res;
	struct ldb_dn *ldap_path;
	int ret;
	struct ldb_key_data *newkd;

	ldap_path = reg_path_to_ldb(mem_ctx, h, name, NULL);

	ret = ldb_search(c, ldap_path, LDB_SCOPE_BASE, "(key=*)", NULL, &res);

	if (ret != LDB_SUCCESS) {
		DEBUG(0, ("Error opening key '%s': %s\n", ldb_dn_linearize(ldap_path, ldap_path), ldb_errstring(c)));
		return WERR_FOOBAR;
	} else if (res->count == 0) {
		talloc_free(res);
		return WERR_BADFILE;
	}

	*key = talloc(mem_ctx, struct registry_key);
	talloc_set_destructor(*key, reg_close_ldb_key);
	(*key)->name = talloc_strdup(mem_ctx, strrchr(name, '\\')?strchr(name, '\\'):name);
	(*key)->backend_data = newkd = talloc_zero(*key, struct ldb_key_data);
	newkd->dn = ldb_dn_copy(mem_ctx, res->msgs[0]->dn); 

	talloc_free(res);

	return WERR_OK;
}

static WERROR ldb_open_hive(struct registry_hive *hive, struct registry_key **k)
{
	struct ldb_key_data *kd;
	struct ldb_context *wrap;

	if (!hive->location) return WERR_INVALID_PARAM;

	wrap = ldb_wrap_connect(hive, hive->location, hive->session_info, hive->credentials, 0, NULL);

	if(!wrap) {
		DEBUG(1, ("ldb_open_hive: unable to connect\n"));
		return WERR_FOOBAR;
	}

	ldb_set_debug_stderr(wrap);
	hive->backend_data = wrap;

	*k = talloc_zero(hive, struct registry_key);
	talloc_set_destructor (*k, reg_close_ldb_key);
	talloc_set_destructor (hive, ldb_free_hive);
	(*k)->name = talloc_strdup(*k, "");
	(*k)->backend_data = kd = talloc_zero(*k, struct ldb_key_data);
	kd->dn = ldb_dn_new(*k, wrap, "hive=NONE");
	

	return WERR_OK;
}

static WERROR ldb_add_key (TALLOC_CTX *mem_ctx, const struct registry_key *parent, const char *name, uint32_t access_mask, struct security_descriptor *sd, struct registry_key **newkey)
{
	struct ldb_context *ctx = talloc_get_type(parent->hive->backend_data, struct ldb_context);
	struct ldb_message *msg;
	struct ldb_key_data *newkd;
	int ret;

	msg = ldb_msg_new(mem_ctx);

	msg->dn = reg_path_to_ldb(msg, parent, name, NULL);

	ldb_msg_add_string(msg, "key", talloc_strdup(mem_ctx, name));

	ret = ldb_add(ctx, msg);
	if (ret < 0) {
		DEBUG(1, ("ldb_msg_add: %s\n", ldb_errstring(ctx)));
		return WERR_FOOBAR;
	}

	*newkey = talloc_zero(mem_ctx, struct registry_key);
	(*newkey)->name = talloc_strdup(mem_ctx, name);

	(*newkey)->backend_data = newkd = talloc_zero(*newkey, struct ldb_key_data);
	newkd->dn = talloc_steal(newkd, msg->dn);

	return WERR_OK;
}

static WERROR ldb_del_key (const struct registry_key *key, const char *child)
{
	struct ldb_context *ctx = talloc_get_type(key->hive->backend_data, struct ldb_context);
	int ret;
	struct ldb_key_data *kd = talloc_get_type(key->backend_data, struct ldb_key_data);
	struct ldb_dn *childdn;

	childdn = ldb_dn_copy(ctx, kd->dn);
	ldb_dn_add_child_fmt(childdn, "key=%s", child);

	ret = ldb_delete(ctx, childdn);

	talloc_free(childdn);

	if (ret < 0) {
		DEBUG(1, ("ldb_del_key: %s\n", ldb_errstring(ctx)));
		return WERR_FOOBAR;
	}

	return WERR_OK;
}

static WERROR ldb_del_value (const struct registry_key *key, const char *child)
{
	int ret;
	struct ldb_context *ctx = talloc_get_type(key->hive->backend_data, struct ldb_context);
	struct ldb_key_data *kd = talloc_get_type(key->backend_data, struct ldb_key_data);
	struct ldb_dn *childdn;

	childdn = ldb_dn_copy(ctx, kd->dn);
	ldb_dn_add_child_fmt(childdn, "value=%s", child);

	ret = ldb_delete(ctx, childdn);

	talloc_free(childdn);

	if (ret < 0) {
		DEBUG(1, ("ldb_del_value: %s\n", ldb_errstring(ctx)));
		return WERR_FOOBAR;
	}

	return WERR_OK;
}

static WERROR ldb_set_value (const struct registry_key *parent, const char *name, uint32_t type, DATA_BLOB data)
{
	struct ldb_context *ctx = talloc_get_type(parent->hive->backend_data, struct ldb_context);
	struct ldb_message *msg;
	struct ldb_key_data *kd = talloc_get_type(parent->backend_data, struct ldb_key_data);
	int ret;
	TALLOC_CTX *mem_ctx = talloc_init("ldb_set_value");

	msg = reg_ldb_pack_value(ctx, mem_ctx, name, type, data);

	msg->dn = ldb_dn_copy(msg, kd->dn);
	ldb_dn_add_child_fmt(msg->dn, "value=%s", name);

	ret = ldb_add(ctx, msg);
	if (ret < 0) {
		ret = ldb_modify(ctx, msg);
		if (ret < 0) {
			DEBUG(1, ("ldb_msg_add: %s\n", ldb_errstring(ctx)));
			talloc_free(mem_ctx);
			return WERR_FOOBAR;
		}
	}
	
	talloc_free(mem_ctx);
	return WERR_OK;
}

static struct hive_operations reg_backend_ldb = {
	.name = "ldb",
	.add_key = ldb_add_key,
	.del_key = ldb_del_key,
	.open_hive = ldb_open_hive,
	.open_key = ldb_open_key,
	.get_value_by_index = ldb_get_value_by_id,
	.get_subkey_by_index = ldb_get_subkey_by_id,
	.set_value = ldb_set_value,
	.del_value = ldb_del_value,
};

NTSTATUS registry_ldb_init(void)
{
	return registry_register(&reg_backend_ldb);
}
