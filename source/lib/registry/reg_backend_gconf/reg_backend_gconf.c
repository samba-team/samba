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
#include "lib/registry/common/registry.h"
#include <gconf/gconf-client.h>

static BOOL reg_open_gconf(REG_HANDLE *h, const char *location, BOOL try_complete_load) 
{
	h->backend_data = (void *)gconf_client_get_default();
	return True;
}

static BOOL reg_close_gconf(REG_HANDLE *h) 
{
	return True;
}

static REG_KEY *gconf_open_key (REG_HANDLE *h, const char *name) 
{
	char *fullpath = reg_path_win2unix(strdup(name));

	/* Check if key exists */
	if(!gconf_client_dir_exists((GConfClient *)h->backend_data, fullpath, NULL)) {
		free(fullpath);
		return NULL;
	}
	free(fullpath);

	return reg_key_new_abs(name, h, NULL);
}

static BOOL gconf_fetch_values(REG_KEY *p, int *count, REG_VAL ***vals)
{
	GSList *entries;
	GSList *cur;
	REG_VAL **ar = malloc(sizeof(REG_VAL *));
	char *fullpath = strdup(reg_key_get_path(p));
	fullpath = reg_path_win2unix(fullpath);
	cur = entries = gconf_client_all_entries((GConfClient*)p->handle->backend_data, fullpath, NULL);
	free(fullpath);

	(*count) = 0;
	while(cur) {
		GConfEntry *entry = cur->data;
		GConfValue *value = gconf_entry_get_value(entry);
		REG_VAL *newval = reg_val_new(p, NULL);
		newval->name = strdup(strrchr(gconf_entry_get_key(entry), '/')+1);
		if(value) {
			switch(value->type) {
			case GCONF_VALUE_INVALID: 
				newval->data_type = REG_NONE;
				break;

			case GCONF_VALUE_STRING:
				newval->data_type = REG_SZ;
				newval->data_blk = strdup(gconf_value_get_string(value));
				newval->data_len = strlen(newval->data_blk);
				break;

			case GCONF_VALUE_INT:
				newval->data_type = REG_DWORD;
				newval->data_blk = malloc(sizeof(long));
				*((long *)newval->data_blk) = gconf_value_get_int(value);
				newval->data_len = sizeof(long);
				break;

			case GCONF_VALUE_FLOAT:
				newval->data_blk = malloc(sizeof(double));
				newval->data_type = REG_BINARY;
				*((double *)newval->data_blk) = gconf_value_get_float(value);
				newval->data_len = sizeof(double);
				break;

			case GCONF_VALUE_BOOL:
				newval->data_blk = malloc(sizeof(BOOL));
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

		ar[(*count)] = newval;
		ar = realloc(ar, sizeof(REG_VAL *) * ((*count)+2));
		(*count)++;
		g_free(cur->data);
		cur = cur->next;
	}

	g_slist_free(entries);
	*vals = ar;
	return True;
}

static BOOL gconf_fetch_subkeys(REG_KEY *p, int *count, REG_KEY ***subs) 
{
	GSList *dirs;
	GSList *cur;
	REG_KEY **ar = malloc(sizeof(REG_KEY *));
	char *fullpath = strdup(reg_key_get_path(p));
	fullpath = reg_path_win2unix(fullpath);
	cur = dirs = gconf_client_all_dirs((GConfClient*)p->handle->backend_data, fullpath,NULL);
	free(fullpath);

	(*count) = 0;
	while(cur) {
		ar[(*count)] = reg_key_new_abs(reg_path_unix2win((char *)cur->data), p->handle, NULL);
		ar = realloc(ar, sizeof(REG_KEY *) * ((*count)+2));
		(*count)++;
		g_free(cur->data);
		cur = cur->next;
	}

	g_slist_free(dirs);
	*subs = ar;
	return True;
}

static BOOL gconf_update_value(REG_VAL *val, int type, void *data, int len)
{
	GError *error = NULL;
	char *keypath = reg_path_win2unix(strdup(reg_key_get_path(val->parent)));
	char *valpath;
	if(val->name)asprintf(&valpath, "%s/%s", keypath, val->name);
	else valpath = strdup(keypath);
	free(keypath);
	
	switch(type) {
	case REG_SZ:
	case REG_EXPAND_SZ:
		gconf_client_set_string((GConfClient *)val->handle->backend_data, valpath, data, &error);
		free(valpath);
		return (error == NULL);

	case REG_DWORD:
		gconf_client_set_int((GConfClient *)val->handle->backend_data, valpath, 
 *((int *)data), &error);
		free(valpath);
		return (error == NULL);
	default:
		DEBUG(0, ("Unsupported type: %d\n", type));
		free(valpath);
		return False;
	}
	return False;
}

static REG_OPS reg_backend_gconf = {
	.name = "gconf",
	.open_registry = reg_open_gconf,
	.close_registry = reg_close_gconf,
	.open_key = gconf_open_key,
	.fetch_subkeys = gconf_fetch_subkeys,
	.fetch_values = gconf_fetch_values,
	.update_value = gconf_update_value,
	
	/* Note: 
	 * since GConf uses schemas for what keys and values are allowed, there 
	 * is no way of 'emulating' add_key and del_key here.
	 */
};

NTSTATUS reg_gconf_init(void)
{
	return register_backend("registry", &reg_backend_gconf);
}
