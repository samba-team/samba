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

struct ldb_key_data 
{
	const char *dn;
	struct ldb_message **subkeys, **values;
	int subkey_count, value_count;
};

static int ldb_close_hive (void *_hive)
{
	struct registry_hive *hive = _hive;
	ldb_close (hive->backend_data);
	return 0;
}

static void reg_ldb_unpack_value(TALLOC_CTX *mem_ctx, struct ldb_message *msg, char **name, uint32 *type, void **data, int *len)
{
	const struct ldb_val *val;
	*name = talloc_strdup(mem_ctx, ldb_msg_find_string(msg, "value", NULL));
	*type = ldb_msg_find_uint(msg, "type", 0);
	val = ldb_msg_find_ldb_val(msg, "data");
	*data = talloc_memdup(mem_ctx, val->data, val->length);
	*len = val->length;
}

static struct ldb_message *reg_ldb_pack_value(struct ldb_context *ctx, TALLOC_CTX *mem_ctx, const char *name, uint32 type, void *data, int len)
{
	struct ldb_val val;
	struct ldb_message *msg = talloc_zero_p(mem_ctx, struct ldb_message);
	char *type_s;

	ldb_msg_add_string(ctx, msg, "value", talloc_strdup(mem_ctx, name));
	val.length = len;
	val.data = data;
	ldb_msg_add_value(ctx, msg, "data", &val);

	type_s = talloc_asprintf(mem_ctx, "%u", type);
	ldb_msg_add_string(ctx, msg, "type", type_s); 

	return msg;
}


static int reg_close_ldb_key (void *data)
{
	struct registry_key *key = data;
	struct ldb_key_data *kd = key->backend_data;
	struct ldb_context *c = key->hive->backend_data;

	if (kd->subkeys) {
		ldb_search_free(c, kd->subkeys); 
		kd->subkeys = NULL;
	}

	if (kd->values) {
		ldb_search_free(c, kd->values); 
		kd->values = NULL;
	}
	return 0;
}

static char *reg_path_to_ldb(TALLOC_CTX *mem_ctx, struct registry_key *from, const char *path, const char *add)
{
	char *ret = talloc_strdup(mem_ctx, "");
	char *mypath = talloc_strdup(mem_ctx, path);
	char *begin;
	struct ldb_key_data *kd = from->backend_data;

	if(add) 
		ret = talloc_asprintf_append(ret, "%s", add);

	while(mypath) {
		char *keyname;
		begin = strrchr(mypath, '\\');

		if(begin) keyname = begin + 1;
		else keyname = mypath;

		if(strlen(keyname))
			ret = talloc_asprintf_append(ret, "key=%s,", keyname);
			
		if(begin) {
			*begin = '\0';
		} else {
			break;
		}
	}

	ret = talloc_asprintf_append(ret, "%s", kd->dn);

	return ret;
}


static WERROR ldb_get_subkey_by_id(TALLOC_CTX *mem_ctx, struct registry_key *k, int idx, struct registry_key **subkey)
{
	struct ldb_context *c = k->hive->backend_data;
	struct ldb_message_element *el;
	struct ldb_key_data *kd = k->backend_data, *newkd;

	/* Do a search if necessary */
	if (kd->subkeys == NULL) {
		kd->subkey_count = ldb_search(c, kd->dn, LDB_SCOPE_ONELEVEL, "(key=*)", NULL, &kd->subkeys);

		if(kd->subkey_count < 0) {
			DEBUG(0, ("Error getting subkeys for '%s': %s\n", kd->dn, ldb_errstring(c)));
			return WERR_FOOBAR;
		}
	} 

	if (idx >= kd->subkey_count) return WERR_NO_MORE_ITEMS;

	el = ldb_msg_find_element(kd->subkeys[idx], "key");
	
	*subkey = talloc_p(mem_ctx, struct registry_key);
	talloc_set_destructor(*subkey, reg_close_ldb_key);
	(*subkey)->name = talloc_strdup(mem_ctx, el->values[0].data);
	(*subkey)->backend_data = newkd = talloc_zero_p(*subkey, struct ldb_key_data);
	newkd->dn = talloc_strdup(mem_ctx, kd->subkeys[idx]->dn);

	return WERR_OK;
}

static WERROR ldb_get_value_by_id(TALLOC_CTX *mem_ctx, struct registry_key *k, int idx, struct registry_value **value)
{
	struct ldb_context *c = k->hive->backend_data;
	struct ldb_key_data *kd = k->backend_data;

	/* Do the search if necessary */
	if (kd->values == NULL) {
		kd->value_count = ldb_search(c, kd->dn, LDB_SCOPE_ONELEVEL, "(value=*)", NULL,&kd->values);

		if(kd->value_count < 0) {
			DEBUG(0, ("Error getting values for '%s': %s\n", kd->dn, ldb_errstring(c)));
			return WERR_FOOBAR;
		}
	}

	if(idx >= kd->value_count) return WERR_NO_MORE_ITEMS;

	*value = talloc_p(mem_ctx, struct registry_value);

	reg_ldb_unpack_value(mem_ctx, kd->values[idx], &(*value)->name, &(*value)->data_type, &(*value)->data_blk, &(*value)->data_len);

	return WERR_OK;
}

static WERROR ldb_open_key(TALLOC_CTX *mem_ctx, struct registry_key *h, const char *name, struct registry_key **key)
{
	struct ldb_context *c = h->hive->backend_data;
	struct ldb_message **msg;
	char *ldap_path;
	int ret;
	struct ldb_key_data *newkd;

	ldap_path = reg_path_to_ldb(mem_ctx, h, name, NULL);

	ret = ldb_search(c, ldap_path, LDB_SCOPE_BASE, "(key=*)", NULL,&msg);

	if(ret == 0) {
		return WERR_NO_MORE_ITEMS;
	} else if(ret < 0) {
		DEBUG(0, ("Error opening key '%s': %s\n", ldap_path, ldb_errstring(c)));
		return WERR_FOOBAR;
	}

	*key = talloc_p(mem_ctx, struct registry_key);
	talloc_set_destructor(*key, reg_close_ldb_key);
	(*key)->name = talloc_strdup(mem_ctx, strrchr(name, '\\')?strchr(name, '\\'):name);
	(*key)->backend_data = newkd = talloc_zero_p(*key, struct ldb_key_data);
	newkd->dn = talloc_strdup(mem_ctx, msg[0]->dn); 

	ldb_search_free(c, msg);

	return WERR_OK;
}

static WERROR ldb_open_hive(struct registry_hive *hive, struct registry_key **k)
{
	struct ldb_context *c;
	struct ldb_key_data *kd;
	struct ldb_wrap *wrap;

	if (!hive->location) return WERR_INVALID_PARAM;
	wrap = ldb_wrap_connect(hive, hive->location, 0, NULL);

	c = wrap->ldb;

	if(!c) {
		DEBUG(1, ("ldb_open_hive: %s\n", ldb_errstring(hive->backend_data)));
		return WERR_FOOBAR;
	}
	ldb_set_debug_stderr(c);
	hive->backend_data = c;

	*k = talloc_zero_p(hive, struct registry_key);
	talloc_set_destructor (*k, reg_close_ldb_key);
	talloc_set_destructor (hive, ldb_close_hive);
	(*k)->name = talloc_strdup(*k, "");
	(*k)->backend_data = kd = talloc_zero_p(*k, struct ldb_key_data);
	kd->dn = talloc_strdup(*k, "hive=");
	

	return WERR_OK;
}

static WERROR ldb_add_key (TALLOC_CTX *mem_ctx, struct registry_key *parent, const char *name, uint32_t access_mask, struct security_descriptor *sd, struct registry_key **newkey)
{
	struct ldb_context *ctx = parent->hive->backend_data;
	struct ldb_message msg;
	struct ldb_key_data *newkd;
	int ret;

	ZERO_STRUCT(msg);

	msg.dn = reg_path_to_ldb(mem_ctx, parent, name, NULL);

	ldb_msg_add_string(ctx, &msg, "key", talloc_strdup(mem_ctx, name));

	ret = ldb_add(ctx, &msg);
	if (ret < 0) {
		DEBUG(1, ("ldb_msg_add: %s\n", ldb_errstring(parent->hive->backend_data)));
		return WERR_FOOBAR;
	}

	*newkey = talloc_zero_p(mem_ctx, struct registry_key);
	(*newkey)->name = talloc_strdup(mem_ctx, name);

	(*newkey)->backend_data = newkd = talloc_zero_p(*newkey, struct ldb_key_data);
	newkd->dn = msg.dn; 

	return WERR_OK;
}

static WERROR ldb_del_key (struct registry_key *key, const char *child)
{
	int ret;
	struct ldb_key_data *kd = key->backend_data;
	char *childdn = talloc_asprintf(NULL, "key=%s,%s", child, kd->dn);

	ret = ldb_delete(key->hive->backend_data, childdn);

	talloc_destroy(childdn);

	if (ret < 0) {
		DEBUG(1, ("ldb_del_key: %s\n", ldb_errstring(key->hive->backend_data)));
		return WERR_FOOBAR;
	}

	return WERR_OK;
}

static WERROR ldb_del_value (struct registry_key *key, const char *child)
{
	int ret;
	struct ldb_key_data *kd = key->backend_data;
	char *childdn = talloc_asprintf(NULL, "value=%s,%s", child, kd->dn);

	ret = ldb_delete(key->hive->backend_data, childdn);

	talloc_destroy(childdn);

	if (ret < 0) {
		DEBUG(1, ("ldb_del_value: %s\n", ldb_errstring(key->hive->backend_data)));
		return WERR_FOOBAR;
	}

	return WERR_OK;
}

static WERROR ldb_set_value (struct registry_key *parent, const char *name, uint32 type, void *data, int len)
{
	struct ldb_context *ctx = parent->hive->backend_data;
	struct ldb_message *msg;
	struct ldb_key_data *kd = parent->backend_data;
	int ret;
	TALLOC_CTX *mem_ctx = talloc_init("ldb_set_value");

	msg = reg_ldb_pack_value(ctx, mem_ctx, name, type, data, len);

	msg->dn = talloc_asprintf(mem_ctx, "value=%s,%s", name, kd->dn);

	ret = ldb_add(ctx, msg);
	if (ret < 0) {
		ret = ldb_modify(ctx, msg);
		if (ret < 0) {
			DEBUG(1, ("ldb_msg_add: %s\n", ldb_errstring(parent->hive->backend_data)));
			talloc_destroy(mem_ctx);
			return WERR_FOOBAR;
		}
	}
	
	talloc_destroy(mem_ctx);
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
