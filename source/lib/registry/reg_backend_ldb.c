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

static char *reg_path_to_ldb(TALLOC_CTX *mem_ctx, const char *path, const char *add)
{
	char *ret = talloc_strdup(mem_ctx, "");
	char *mypath = strdup(path);
	char *end = mypath, *begin;

	if(add) 
		ret = talloc_asprintf_append(ret, "%s", add);

	while(end) {
		char *keyname;
		begin = strrchr(end, '\\');

		if(begin) keyname = begin + 1;
		else keyname = mypath;

		if(strlen(keyname))
			ret = talloc_asprintf_append(ret, "key=%s,", keyname);
			
		if(begin) {
			*begin = '\0';
			end = begin-1;
		} else {
			end = NULL;
		}
	}

	SAFE_FREE(mypath);

	ret[strlen(ret)-1] = '\0';

	if(strlen(ret) == 0) return NULL;
	
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
	struct ldb_message_element *el;
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
	
	el = ldb_msg_find_element(kd->values[idx], "value");
	
	*value = talloc_p(mem_ctx, struct registry_value);
	(*value)->name = talloc_strdup(mem_ctx, el->values[0].data);
	(*value)->backend_data = talloc_strdup(mem_ctx, kd->values[idx]->dn);

	return WERR_OK;
}

static WERROR ldb_open_key(TALLOC_CTX *mem_ctx, struct registry_key *h, const char *name, struct registry_key **key)
{
	struct ldb_context *c = h->hive->backend_data;
	struct ldb_message **msg;
	char *ldap_path;
	int ret;
	struct ldb_key_data *kd = h->backend_data, *newkd;
	ldap_path = talloc_asprintf(mem_ctx, "%s%s%s", 
								reg_path_to_ldb(mem_ctx, name, NULL), 
								kd->dn?",":"",
								kd->dn?kd->dn:"");

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

	if (!hive->location) return WERR_INVALID_PARAM;
	c = ldb_connect(hive->location, 0, NULL);

	if(!c) {
		DEBUG(1, ("ldb_open_hive: %s\n", ldb_errstring(hive->backend_data)));
		return WERR_FOOBAR;
	}
	ldb_set_debug_stderr(c);
	hive->backend_data = c;

	hive->root = talloc_zero_p(hive, struct registry_key);
	talloc_set_destructor (hive->root, reg_close_ldb_key);
	hive->root->name = talloc_strdup(hive->root, "");
	hive->root->backend_data = kd = talloc_zero_p(hive->root, struct ldb_key_data);
	kd->dn = talloc_strdup(hive->root, "key=root");
	

	return WERR_OK;
}

static WERROR ldb_add_key (TALLOC_CTX *mem_ctx, struct registry_key *parent, const char *name, uint32_t access_mask, SEC_DESC *sd, struct registry_key **newkey)
{
	struct ldb_context *ctx = parent->hive->backend_data;
	struct ldb_message msg;
	struct ldb_key_data *newkd;
	int ret;

	ZERO_STRUCT(msg);

	msg.dn = reg_path_to_ldb(mem_ctx, parent->path, talloc_asprintf(mem_ctx, "key=%s,", name));

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

static WERROR ldb_del_key (struct registry_key *key)
{
	int ret;
	struct ldb_key_data *kd = key->backend_data;

	ret = ldb_delete(key->hive->backend_data, kd->dn);

	if (ret < 0) {
		DEBUG(1, ("ldb_del_key: %s\n", ldb_errstring(key->hive->backend_data)));
		return WERR_FOOBAR;
	}

	return WERR_OK;
}

static WERROR ldb_close_hive (struct registry_hive *hive)
{
	ldb_close (hive->backend_data);
	return WERR_OK;
}

static struct hive_operations reg_backend_ldb = {
	.name = "ldb",
	.add_key = ldb_add_key,
	.del_key = ldb_del_key,
	.open_hive = ldb_open_hive,
	.close_hive = ldb_close_hive,
	.open_key = ldb_open_key,
	.get_value_by_index = ldb_get_value_by_id,
	.get_subkey_by_index = ldb_get_subkey_by_id,
};

NTSTATUS registry_ldb_init(void)
{
	return registry_register(&reg_backend_ldb);
}
