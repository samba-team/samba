/* 
   Unix SMB/CIFS implementation.
   Transparent registry backend handling
   Copyright (C) Jelmer Vernooij			2003-2004.

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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

/* List of available backends */
static struct reg_init_function_entry *backends = NULL;

static struct reg_init_function_entry *reg_find_backend_entry(const char *name);

/* Register new backend */
NTSTATUS registry_register(void *_function)  
{
	REG_OPS *functions = _function;
	struct reg_init_function_entry *entry = backends;

	if (!functions || !functions->name) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(5,("Attempting to register registry backend %s\n", functions->name));

	/* Check for duplicates */
	if (reg_find_backend_entry(functions->name)) {
		DEBUG(0,("There already is a registry backend registered with the name %s!\n", functions->name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	entry = malloc(sizeof(struct reg_init_function_entry));
	entry->functions = functions;

	DLIST_ADD(backends, entry);
	DEBUG(5,("Successfully added registry backend '%s'\n", functions->name));
	return NT_STATUS_OK;
}

/* Find a backend in the list of available backends */
static struct reg_init_function_entry *reg_find_backend_entry(const char *name)
{
	struct reg_init_function_entry *entry = backends;

	while(entry) {
		if (strcmp(entry->functions->name, name)==0) return entry;
		entry = entry->next;
	}

	return NULL;
}

/* Open a registry file/host/etc */
REG_HANDLE *reg_open(const char *backend, const char *location, BOOL try_full_load)
{
	struct reg_init_function_entry *entry;
	static BOOL reg_first_init = True;
	TALLOC_CTX *mem_ctx;
	REG_HANDLE *ret;

	if(reg_first_init) {
		if (!NT_STATUS_IS_OK(register_subsystem("registry", registry_register))) {
			return False;
		}

		static_init_reg;
		reg_first_init = False;
	}

	entry = reg_find_backend_entry(backend);
	
	if (!entry) {
		DEBUG(0, ("No such registry backend '%s' loaded!\n", backend));
		return NULL;
	}
	
	mem_ctx = talloc_init(backend);
	ret = talloc(mem_ctx, sizeof(REG_HANDLE));
	ZERO_STRUCTP(ret);	
	ret->location = location?talloc_strdup(mem_ctx, location):NULL;
	ret->functions = entry->functions;
	ret->backend_data = NULL;
	ret->mem_ctx = mem_ctx;

	if(!entry->functions->open_registry) {
		return ret;
	}
	
	if(entry->functions->open_registry(ret, location, try_full_load))
		return ret;

	talloc_destroy(mem_ctx);
	return NULL;
}

/* Open a key 
 * First tries to use the open_key function from the backend
 * then falls back to get_subkey_by_name and later get_subkey_by_index 
 */
REG_KEY *reg_open_key(REG_KEY *parent, const char *name)
{
	char *fullname;
	REG_KEY *ret = NULL;
	TALLOC_CTX *mem_ctx;

	if(!parent) {
		DEBUG(0, ("Invalid parent key specified"));
		return NULL;
	}

	if(!parent->handle->functions->open_key && 
	   (parent->handle->functions->get_subkey_by_name || 
	   parent->handle->functions->get_subkey_by_index)) {
		char *orig = strdup(name), 
			 *curbegin = orig, 
			 *curend = strchr(orig, '\\');
		REG_KEY *curkey = parent;

		while(curbegin && *curbegin) {
			if(curend)*curend = '\0';
			curkey = reg_key_get_subkey_by_name(curkey, curbegin);
			if(!curkey) {
				SAFE_FREE(orig);
				return NULL;
			}
			if(!curend) break;
			curbegin = curend + 1;
			curend = strchr(curbegin, '\\');
		}
		SAFE_FREE(orig);
		
		return curkey;
	}

	mem_ctx = talloc_init("mem_ctx");

	fullname = talloc_asprintf(mem_ctx, "%s%s%s", parent->path, parent->path[strlen(parent->path)-1] == '\\'?"":"\\", name);


	if(!parent->handle->functions->open_key) {
		DEBUG(0, ("Registry backend doesn't have get_subkey_by_name nor open_key!\n"));
		return NULL;
	}

	ret = parent->handle->functions->open_key(parent->handle, fullname);

	if(ret) {
		ret->handle = parent->handle;
		ret->path = fullname;
		talloc_steal(mem_ctx, ret->mem_ctx, fullname);
	}

	talloc_destroy(mem_ctx);

	return ret;
}

REG_VAL *reg_key_get_value_by_index(REG_KEY *key, int idx)
{
	REG_VAL *ret;

	if(!key) return NULL;

	if(!key->handle->functions->get_value_by_index) {
		if(!key->cache_values)
			key->handle->functions->fetch_values(key, &key->cache_values_count, &key->cache_values);
		
		if(idx < key->cache_values_count && idx >= 0) {
			ret = reg_val_dup(key->cache_values[idx]);
		} else {
			return NULL;
		}
	} else {
		ret = key->handle->functions->get_value_by_index(key, idx);
	}
	
	if(ret) {
		ret->parent = key;
		ret->handle = key->handle;
	}

	return ret;
}

int reg_key_num_subkeys(REG_KEY *key)
{
	if(!key) return 0;
	
	if(!key->handle->functions->num_subkeys) {
		if(!key->cache_subkeys) 
			key->handle->functions->fetch_subkeys(key, &key->cache_subkeys_count, &key->cache_subkeys);

		return key->cache_subkeys_count;
	}

	return key->handle->functions->num_subkeys(key);
}

int reg_key_num_values(REG_KEY *key)
{
	
	if(!key) return 0;
	
	if(!key->handle->functions->num_values) {
		if(!key->handle->functions->fetch_values) {
			DEBUG(1, ("Backend '%s' doesn't support enumerating values\n", key->handle->functions->name));
			return 0;
		}
		
		if(!key->cache_values) 
			key->handle->functions->fetch_values(key, &key->cache_values_count, &key->cache_values);

		return key->cache_values_count;
	}

	
	return key->handle->functions->num_values(key);
}

REG_KEY *reg_key_get_subkey_by_index(REG_KEY *key, int idx)
{
	REG_KEY *ret = NULL;

	if(!key) return NULL;

	if(!key->handle->functions->get_subkey_by_index) {
		if(!key->cache_subkeys) 
			key->handle->functions->fetch_subkeys(key, &key->cache_subkeys_count, &key->cache_subkeys);

		if(idx < key->cache_subkeys_count) {
			ret = reg_key_dup(key->cache_subkeys[idx]);
		} else {
			/* No such key ! */
			return NULL;
		}
	} else {
		ret = key->handle->functions->get_subkey_by_index(key, idx);
	}

	if(ret && !ret->path) {
		ret->path = talloc_asprintf(ret->mem_ctx, "%s%s%s", key->path, key->path[strlen(key->path)-1] == '\\'?"":"\\", ret->name);
		ret->handle = key->handle;
	}

	return ret;
}

REG_KEY *reg_key_get_subkey_by_name(REG_KEY *key, const char *name)
{
	int i, max;
	REG_KEY *ret = NULL;

	if(!key) return NULL;

	if(key->handle->functions->get_subkey_by_name) {
		ret = key->handle->functions->get_subkey_by_name(key,name);
	} else {
		max = reg_key_num_subkeys(key);
		for(i = 0; i < max; i++) {
			REG_KEY *v = reg_key_get_subkey_by_index(key, i);
			if(v && !strcmp(v->name, name)) {
				ret = v;
				break;
			}
			reg_key_free(v);
		}
	}

	if(ret && !ret->path) {
		ret->path = talloc_asprintf(ret->mem_ctx, "%s%s%s", key->path, key->path[strlen(key->path)-1] == '\\'?"":"\\", ret->name);
		ret->handle = key->handle;
	}
		
	return ret; 
}

REG_VAL *reg_key_get_value_by_name(REG_KEY *key, const char *name)
{
	int i, max;
	REG_VAL *ret = NULL;

	if(!key) return NULL;

	if(key->handle->functions->get_value_by_name) {
		ret = key->handle->functions->get_value_by_name(key,name);
	} else {
		max = reg_key_num_values(key);
		for(i = 0; i < max; i++) {
			REG_VAL *v = reg_key_get_value_by_index(key, i);
			if(v && StrCaseCmp(v->name, name)) {
				ret = v;
				break;
			}
			reg_val_free(v);
		}
	}
	
	if(ret) {
		ret->parent = key;
		ret->handle = key->handle;
	}
	
	return ret;
}

BOOL reg_key_del(REG_KEY *key)
{
	if(key->handle->functions->del_key) {
		if(key->handle->functions->del_key(key)) {
			/* Invalidate cache */
			key->cache_subkeys = NULL;
			key->cache_subkeys_count = 0;
			return True;
		}
	}

	return False;
}

BOOL reg_sync(REG_HANDLE *h, const char *location)
{
	if(!h->functions->sync)
		return True;

	return h->functions->sync(h, location);
}

BOOL reg_key_del_recursive(REG_KEY *key)
{
	BOOL succeed = True;
	int i;
	
	/* Delete all values for specified key */
	for(i = 0; i < reg_key_num_values(key); i++) {
		if(!reg_val_del(reg_key_get_value_by_index(key, i)))
			succeed = False;
	}

	/* Delete all keys below this one */
	for(i = 0; i < reg_key_num_subkeys(key); i++) {
		if(!reg_key_del_recursive(reg_key_get_subkey_by_index(key, i)))
			succeed = False;
	}

	if(succeed)reg_key_del(key);

	return succeed;
}

BOOL reg_val_del(REG_VAL *val)
{
	if (!val->handle->functions->del_value) {
		DEBUG(1, ("Backend '%s' doesn't support method del_value\n", val->handle->functions->name));
		return False;
	}
	
	if(val->handle->functions->del_value(val)) {
		val->parent->cache_values = NULL;
		val->parent->cache_values_count = 0;
		return True;
	} 
	return False;
}

BOOL reg_key_add_name_recursive(REG_KEY *parent, const char *path)
{
	REG_KEY *cur, *prevcur = parent;
	char *begin = (char *)path, *end;

	while(1) { 
		end = strchr(begin, '\\');
		if(end) *end = '\0';
		cur = reg_key_get_subkey_by_name(prevcur, begin);
		if(!cur) {
			if(!reg_key_add_name(prevcur, begin)) { printf("foo\n"); return False; }
			cur = reg_key_get_subkey_by_name(prevcur, begin);
			if(!cur) {
				DEBUG(0, ("Can't find key after adding it : %s\n", begin));
				return False;
			}
		}
		
		if(!end) break;
		*end = '\\';
		begin = end+1;
		prevcur = cur;
	}
	return True;
}

BOOL reg_key_add_name(REG_KEY *parent, const char *name)
{
	if (!parent) return False;
	
	if (!parent->handle->functions->add_key) {
		DEBUG(1, ("Backend '%s' doesn't support method add_key\n", parent->handle->functions->name));
		return False;
	}

	if(parent->handle->functions->add_key(parent, name)) {
		parent->cache_subkeys = NULL;
		parent->cache_subkeys_count = 0;
		return True;
	} 
	return False;
}

BOOL reg_val_update(REG_VAL *val, int type, void *data, int len)
{
	/* A 'real' update function has preference */
	if (val->handle->functions->update_value) 
		return val->handle->functions->update_value(val, type, data, len);

	/* Otherwise, just remove and add again */
	if (val->handle->functions->add_value && 
		val->handle->functions->del_value) {
		REG_VAL *new;
		if(!val->handle->functions->del_value(val)) 
			return False;
		
		new = val->handle->functions->add_value(val->parent, val->name, type, data, len);
		memcpy(val, new, sizeof(REG_VAL));
		val->parent->cache_values = NULL;
		val->parent->cache_values_count = 0;
		return True;
	}
		
	DEBUG(1, ("Backend '%s' doesn't support method update_value\n", val->handle->functions->name));
	return False;
}

void reg_free(REG_HANDLE *h)
{
	if(!h->functions->close_registry) return;

	h->functions->close_registry(h);
}

REG_KEY *reg_get_root(REG_HANDLE *h) 
{
	REG_KEY *ret = NULL;
	if(h->functions->open_root_key) {
		ret = h->functions->open_root_key(h);
	} else if(h->functions->open_key) {
		ret = h->functions->open_key(h, "\\");
	} else {
		DEBUG(0, ("Backend '%s' has neither open_root_key nor open_key method implemented\n", h->functions->name));
	}

	if(ret) {
		ret->handle = h;
		ret->path = talloc_strdup(ret->mem_ctx, "\\");
	}

	return ret;
}

REG_VAL *reg_key_add_value(REG_KEY *key, const char *name, int type, void *value, size_t vallen)
{
	REG_VAL *ret;
	if(!key->handle->functions->add_value)
		return NULL;

	ret = key->handle->functions->add_value(key, name, type, value, vallen);
	ret->parent = key;
	ret->handle = key->handle;

	/* Invalidate the cache */
	key->cache_values = NULL;
	key->cache_values_count = 0;
	return ret;
}
