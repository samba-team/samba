/* 
   Unix SMB/CIFS implementation.
   Registry interface
   Copyright (C) Jelmer Vernooij					  2004.
   
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
#include <gconf/gconf-client.h>

static WERROR gerror_to_werror(GError *error)
{
	if(error == NULL) return WERR_OK;
	/* FIXME */
	return WERR_FOOBAR;
}

static WERROR reg_open_gconf_hive(struct registry_hive *h, struct registry_key **k)
{
	g_type_init();
	h->backend_data = (void *)gconf_client_get_default();
	if(!h->backend_data) return WERR_FOOBAR;
	
	*k = talloc(h, struct registry_key);
	(*k)->name = talloc_strdup(*k, "");
	(*k)->path = talloc_strdup(*k, "");
	(*k)->backend_data = talloc_strdup(*k, "/");
	return WERR_OK;
}

static WERROR gconf_open_key (TALLOC_CTX *mem_ctx, struct registry_key *h, const char *name, struct registry_key **key) 
{
	struct registry_key *ret;
	char *fullpath;
	
	fullpath = talloc_asprintf(mem_ctx, "%s%s%s", 
							   (char *)h->backend_data, 
							   strlen((char *)h->backend_data) == 1?"":"/",
							   reg_path_win2unix(talloc_strdup(mem_ctx, name)));

	/* Check if key exists */
	if(!gconf_client_dir_exists((GConfClient *)h->hive->backend_data, fullpath, NULL)) {
		return WERR_DEST_NOT_FOUND;
	}

	ret = talloc(mem_ctx, struct registry_key);
	ret->backend_data = fullpath;

	*key = ret;
	return WERR_OK;
}

static WERROR gconf_get_value_by_id(TALLOC_CTX *mem_ctx, struct registry_key *p, int idx, struct registry_value **val)
{
	GSList *entries;
	GSList *cur;
	GConfEntry *entry;
	GConfValue *value;
	struct registry_value *newval;
	char *fullpath = p->backend_data;
	const char *tmp;
	int i;
	cur = entries = gconf_client_all_entries((GConfClient*)p->hive->backend_data, fullpath, NULL);

	for(i = 0; i < idx && cur; i++) cur = cur->next;

	if(!cur) return WERR_NO_MORE_ITEMS;

	entry = cur->data;
	value = gconf_entry_get_value(entry);
		
	newval = talloc(mem_ctx, struct registry_value);
	newval->name = talloc_strdup(mem_ctx, strrchr(gconf_entry_get_key(entry), '/')+1);
	if(value) {
		switch(value->type) {
		case GCONF_VALUE_INVALID: 
			newval->data_type = REG_NONE;
			break;

		case GCONF_VALUE_STRING:
			newval->data_type = REG_SZ;
			tmp = gconf_value_get_string(value);
			newval->data_len = convert_string_talloc(mem_ctx, CH_UTF8, CH_UTF16, tmp, strlen(tmp), &(newval->data_blk));
			break;

		case GCONF_VALUE_INT:
			newval->data_type = REG_DWORD;
			newval->data_blk = talloc(mem_ctx, long);
			*((long *)newval->data_blk) = gconf_value_get_int(value);
			newval->data_len = sizeof(long);
			break;

		case GCONF_VALUE_FLOAT:
			newval->data_blk = talloc(mem_ctx, double);
			newval->data_type = REG_BINARY;
			*((double *)newval->data_blk) = gconf_value_get_float(value);
			newval->data_len = sizeof(double);
			break;

		case GCONF_VALUE_BOOL:
			newval->data_blk = talloc(mem_ctx, BOOL);
			newval->data_type = REG_BINARY;
			*((BOOL *)newval->data_blk) = gconf_value_get_bool(value);
			newval->data_len = sizeof(BOOL);
			break;

		default:
			newval->data_type = REG_NONE;
			DEBUG(0, ("Not implemented..\n"));
			break;
		}
	} else newval->data_type = REG_NONE; 

	g_slist_free(entries);
	*val = newval;
	return WERR_OK;
}

static WERROR gconf_get_subkey_by_id(TALLOC_CTX *mem_ctx, struct registry_key *p, int idx, struct registry_key **sub) 
{
	GSList *dirs;
	GSList *cur;
	int i;
	char *fullpath = p->backend_data;
	cur = dirs = gconf_client_all_dirs((GConfClient*)p->hive->backend_data, fullpath,NULL);

	for(i = 0; i < idx && cur; i++) cur = cur->next;
	
	if(!cur) return WERR_NO_MORE_ITEMS;
	
	*sub = talloc(mem_ctx, struct registry_key);	
	(*sub)->name = talloc_strdup(mem_ctx, strrchr((char *)cur->data, '/')+1);
	(*sub)->backend_data = talloc_strdup(mem_ctx, cur->data);

	g_slist_free(dirs);
	return WERR_OK;
}

static WERROR gconf_set_value(struct registry_key *key, const char *valname, uint32_t type, void *data, int len)
{
	GError *error = NULL;
	char *valpath;
	asprintf(&valpath, "%s/%s", key->path, valname);
	
	switch(type) {
	case REG_SZ:
	case REG_EXPAND_SZ:
		gconf_client_set_string((GConfClient *)key->hive->backend_data, valpath, data, &error);
		SAFE_FREE(valpath);
		return gerror_to_werror(error);

	case REG_DWORD:
		gconf_client_set_int((GConfClient *)key->hive->backend_data, valpath, 
 *((int *)data), &error);
		SAFE_FREE(valpath);
		return gerror_to_werror(error);
	default:
		DEBUG(0, ("Unsupported type: %d\n", type));
		SAFE_FREE(valpath);
		return WERR_NOT_SUPPORTED;
	}

	return WERR_NOT_SUPPORTED;
}

static struct hive_operations reg_backend_gconf = {
	.name = "gconf",
	.open_hive = reg_open_gconf_hive,
	.open_key = gconf_open_key,
	.get_subkey_by_index = gconf_get_subkey_by_id,
	.get_value_by_index = gconf_get_value_by_id,
	.set_value = gconf_set_value,
	
	/* Note: 
	 * since GConf uses schemas for what keys and values are allowed, there 
	 * is no way of 'emulating' add_key and del_key here.
	 */
};

NTSTATUS registry_gconf_init(void)
{
	return registry_register(&reg_backend_gconf);
}
