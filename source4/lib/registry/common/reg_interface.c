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
	struct registry_ops *functions = _function;
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
	struct reg_init_function_entry *entry;
	static BOOL reg_first_init = True;
	NTSTATUS status;

	if(reg_first_init) {
		status = register_subsystem("registry", registry_register);
		if (NT_STATUS_IS_ERR(status)) {
			DEBUG(0, ("Error registering registry subsystem: %s\n", nt_errstr(status)));
			/* Don't try the initialisation again */
			reg_first_init = False;
			return NULL;
		}

		static_init_registry;
		reg_first_init = False;
	}

	entry = backends;

	while(entry) {
		if (strcmp(entry->functions->name, name)==0) return entry;
		entry = entry->next;
	}

	return NULL;
}

/* Check whether a certain backend is present */
BOOL reg_has_backend(const char *backend)
{
	return reg_find_backend_entry(backend) != NULL?True:False;
}

/* Open a registry file/host/etc */
WERROR reg_open(const char *backend, const char *location, const char *credentials, REG_HANDLE **h)
{
	struct reg_init_function_entry *entry;
	TALLOC_CTX *mem_ctx;
	REG_HANDLE *ret;
	NTSTATUS status;
	WERROR werr;
	
	entry = reg_find_backend_entry(backend);
	
	if (!entry) {
		DEBUG(0, ("No such registry backend '%s' loaded!\n", backend));
		return WERR_GENERAL_FAILURE;
	}
	
	mem_ctx = talloc_init(backend);
	ret = talloc(mem_ctx, sizeof(REG_HANDLE));
	ZERO_STRUCTP(ret);	
	ret->location = location?talloc_strdup(mem_ctx, location):NULL;
	ret->credentials = credentials?talloc_strdup(mem_ctx, credentials):NULL;
	ret->functions = entry->functions;
	ret->backend_data = NULL;
	ret->mem_ctx = mem_ctx;
	*h = ret;

	if(!entry->functions->open_registry) {
		return WERR_OK;
	}
	
	werr = entry->functions->open_registry(ret, location, credentials);

	if(W_ERROR_IS_OK(werr)) 
		return WERR_OK;

	talloc_destroy(mem_ctx);
	return werr;
}

/* Open a key by name (including the hive name!) */
WERROR reg_open_key_abs(REG_HANDLE *handle, const char *name, REG_KEY **result)
{
	REG_KEY *hive;
	WERROR error;
	int i, hivelength;

	if(strchr(name, '\\')) hivelength = strchr(name, '\\')-name;
	else hivelength = strlen(name);

	for(i = 0; W_ERROR_IS_OK(error); i++) {
		error = reg_get_hive(handle, i, &hive);
		if(W_ERROR_IS_OK(error) && !strncmp(reg_key_name(hive), name, hivelength)) {
			return reg_open_key(hive, name, result);
		}
	}

	return error;
}

/* Open a key 
 * First tries to use the open_key function from the backend
 * then falls back to get_subkey_by_name and later get_subkey_by_index 
 */
WERROR reg_open_key(REG_KEY *parent, const char *name, REG_KEY **result)
{
	char *fullname;
	WERROR error;
	TALLOC_CTX *mem_ctx;

	if(!parent) {
		DEBUG(0, ("Invalid parent key specified"));
		return WERR_INVALID_PARAM;
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
			error = reg_key_get_subkey_by_name(curkey, curbegin, result);
			if(!W_ERROR_IS_OK(error)) {
				SAFE_FREE(orig);
				return error;
			}
			if(!curend) break;
			curbegin = curend + 1;
			curend = strchr(curbegin, '\\');
		}
		SAFE_FREE(orig);
		
		*result = curkey;
		return WERR_OK;
	}

	if(!parent->handle->functions->open_key) {
		DEBUG(0, ("Registry backend doesn't have get_subkey_by_name nor open_key!\n"));
		return WERR_NOT_SUPPORTED;
	}

	mem_ctx = talloc_init("mem_ctx");

	fullname = talloc_asprintf(mem_ctx, "%s%s%s", 
						reg_key_get_path(parent), 
						strlen(reg_key_get_path(parent))?"\\":"", 
						name);

	error = parent->handle->functions->open_key(parent->handle, 
												parent->hive, fullname, result);

	if(!W_ERROR_IS_OK(error)) {
		talloc_destroy(mem_ctx);
		return error;
	}
		
	(*result)->handle = parent->handle;
	(*result)->path = talloc_asprintf((*result)->mem_ctx, "%s\\%s", 
								 reg_key_get_path_abs(parent), (*result)->name);
	(*result)->hive = parent->hive;
	talloc_steal(mem_ctx, (*result)->mem_ctx, fullname);

	talloc_destroy(mem_ctx);

	return WERR_OK;
}

WERROR reg_key_get_value_by_index(REG_KEY *key, int idx, REG_VAL **val)
{
	if(!key) return WERR_INVALID_PARAM;

	if(key->handle->functions->get_value_by_index) {
		WERROR status = key->handle->functions->get_value_by_index(key, idx, val);
		if(!W_ERROR_IS_OK(status)) 
			return status;

	} else if(key->handle->functions->fetch_values) {
		if(!key->cache_values)
			key->handle->functions->fetch_values(key, 
								&key->cache_values_count, &key->cache_values);
		
		if(idx < key->cache_values_count && idx >= 0) {
			*val = reg_val_dup(key->cache_values[idx]);
		} else {
			return WERR_NO_MORE_ITEMS;
		}
	} else {
		return WERR_NOT_SUPPORTED;
	}
	
	(*val)->parent = key;
	(*val)->handle = key->handle;
	return WERR_OK;
}

WERROR reg_key_num_subkeys(REG_KEY *key, int *count)
{
	if(!key) return WERR_INVALID_PARAM;
	
	if(key->handle->functions->num_subkeys) {
		return key->handle->functions->num_subkeys(key, count);
	}

	if(key->handle->functions->fetch_subkeys) {
		if(!key->cache_subkeys) 
			key->handle->functions->fetch_subkeys(key, 
							&key->cache_subkeys_count, &key->cache_subkeys);

		*count = key->cache_subkeys_count;
		return WERR_OK;
	}

	if(key->handle->functions->get_subkey_by_index) {
		int i;
		WERROR error;
		REG_KEY *dest;
		for(i = 0; W_ERROR_IS_OK(error = key->handle->functions->get_subkey_by_index(key, i, &dest)); i++) {
			reg_key_free(dest);
		}

		*count = i;
		if(W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) return WERR_OK;
		return error;
	}

	return WERR_NOT_SUPPORTED;
}

WERROR reg_key_num_values(REG_KEY *key, int *count)
{
	
	if(!key) return WERR_INVALID_PARAM;
	
	if(!key->handle->functions->num_values) {
		if(!key->handle->functions->fetch_values) {
			DEBUG(1, ("Backend '%s' doesn't support enumerating values\n", key->handle->functions->name));
			return WERR_NOT_SUPPORTED;
		}
		
		if(!key->cache_values) 
			key->handle->functions->fetch_values(key, &key->cache_values_count, &key->cache_values);

		*count = key->cache_values_count;
		return WERR_OK;
	}

	
	return key->handle->functions->num_values(key, count);
}

WERROR reg_key_get_subkey_by_index(REG_KEY *key, int idx, REG_KEY **subkey)
{
	if(!key) return WERR_INVALID_PARAM;

	if(key->handle->functions->get_subkey_by_index) {
		WERROR status = key->handle->functions->get_subkey_by_index(key, idx, subkey);
		if(!NT_STATUS_IS_OK(status)) return status;
	} else if(key->handle->functions->fetch_subkeys) {
		if(!key->cache_subkeys) 
			key->handle->functions->fetch_subkeys(key, 
								&key->cache_subkeys_count, &key->cache_subkeys);

		if(idx < key->cache_subkeys_count) {
			*subkey = reg_key_dup(key->cache_subkeys[idx]);
		} else {
			return WERR_NO_MORE_ITEMS;
		}
	} else {
		return WERR_NOT_SUPPORTED;
	}

	(*subkey)->path = talloc_asprintf((*subkey)->mem_ctx, "%s\\%s", 
									reg_key_get_path_abs(key), (*subkey)->name);
	(*subkey)->handle = key->handle;
	(*subkey)->hive = key->hive;


	return WERR_OK;;
}

WERROR reg_key_get_subkey_by_name(REG_KEY *key, const char *name, REG_KEY **subkey)
{
	int i;
	WERROR error = WERR_OK;

	if(!key) return WERR_INVALID_PARAM;

	if(key->handle->functions->get_subkey_by_name) {
		error = key->handle->functions->get_subkey_by_name(key,name,subkey);
	} else if(key->handle->functions->get_subkey_by_index || key->handle->functions->fetch_subkeys) {
		for(i = 0; W_ERROR_IS_OK(error); i++) {
			error = reg_key_get_subkey_by_index(key, i, subkey);
			if(W_ERROR_IS_OK(error) && !strcmp((*subkey)->name, name)) {
				return error;
			}
			reg_key_free(*subkey);
		}
	} else {
		return WERR_NOT_SUPPORTED;
	}

	if(!W_ERROR_IS_OK(error)) return error;

	(*subkey)->path = talloc_asprintf((*subkey)->mem_ctx, "%s\\%s", reg_key_get_path_abs(key), (*subkey)->name);
	(*subkey)->handle = key->handle;
	(*subkey)->hive = key->hive;

	return WERR_OK; 
}

WERROR reg_key_get_value_by_name(REG_KEY *key, const char *name, REG_VAL **val)
{
	int i;
	WERROR error = WERR_OK;

	if(!key) return WERR_INVALID_PARAM;

	if(key->handle->functions->get_value_by_name) {
		error = key->handle->functions->get_value_by_name(key,name, val);
	} else {
		for(i = 0; W_ERROR_IS_OK(error); i++) {
			error = reg_key_get_value_by_index(key, i, val);
			if(W_ERROR_IS_OK(error) && StrCaseCmp((*val)->name, name)) {
				break;
			}
			reg_val_free(*val);
		}
	}

	if(!W_ERROR_IS_OK(error) && !W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS))
		return error;
	
	(*val)->parent = key;
	(*val)->handle = key->handle;
	
	return WERR_OK;
}

WERROR reg_key_del(REG_KEY *key)
{
	WERROR error;
	if(!key) return WERR_INVALID_PARAM;
	
	
	if(!key->handle->functions->del_key)
		return WERR_NOT_SUPPORTED;
	
	error = key->handle->functions->del_key(key);
	if(!W_ERROR_IS_OK(error)) return error;

	/* Invalidate cache */
	key->cache_subkeys = NULL;
	key->cache_subkeys_count = 0;
	return WERR_OK;
}

WERROR reg_sync(REG_KEY *h, const char *location)
{
	if(!h->handle->functions->sync_key)
		return WERR_OK;

	return h->handle->functions->sync_key(h, location);
}

WERROR reg_key_del_recursive(REG_KEY *key)
{
	WERROR error = WERR_OK;
	int i;
	
	/* Delete all values for specified key */
	for(i = 0; W_ERROR_IS_OK(error); i++) {
		REG_VAL *val;
		error = reg_key_get_value_by_index(key, i, &val);
		if(!W_ERROR_IS_OK(error) && !W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) 
			return error;

		if(W_ERROR_IS_OK(error)) {
			error = reg_val_del(val);
			if(!W_ERROR_IS_OK(error)) return error;
		}
	}

	error = WERR_OK;

	/* Delete all keys below this one */
	for(i = 0; W_ERROR_IS_OK(error); i++) {
		REG_KEY *subkey;

		error = reg_key_get_subkey_by_index(key, i, &subkey);
		if(!W_ERROR_IS_OK(error)) return error;

		error = reg_key_del_recursive(subkey);
		if(!W_ERROR_IS_OK(error)) return error;
	}

	return reg_key_del(key);
}

WERROR reg_val_del(REG_VAL *val)
{
	WERROR error;
	if (!val) return WERR_INVALID_PARAM;

	if (!val->handle->functions->del_value) {
		DEBUG(1, ("Backend '%s' doesn't support method del_value\n", val->handle->functions->name));
		return WERR_NOT_SUPPORTED;
	}
	
	error = val->handle->functions->del_value(val);

	if(!W_ERROR_IS_OK(error)) return error;

	val->parent->cache_values = NULL;
	val->parent->cache_values_count = 0;

	return WERR_OK;
}

WERROR reg_key_add_name_recursive_abs(REG_HANDLE *handle, const char *name)
{
	REG_KEY *hive;
	WERROR error;
	int i, hivelength;

	if(strchr(name, '\\')) hivelength = strchr(name, '\\')-name;
	else hivelength = strlen(name);

	for(i = 0; W_ERROR_IS_OK(error); i++) {
		error = reg_get_hive(handle, i, &hive);
		if(W_ERROR_IS_OK(error) && !strncmp(reg_key_name(hive), name, hivelength)) {
			return reg_key_add_name_recursive(hive, name);
		}
	}

	return error;
}

WERROR reg_key_add_name_recursive(REG_KEY *parent, const char *path)
{
	REG_KEY *cur, *prevcur = parent;
	WERROR error;
	/* FIXME: we should never write to a 'const char *' !!! --metze */
	char *begin = (char *)path, *end;

	while(1) { 
		end = strchr(begin, '\\');
		if(end) *end = '\0';
		
		error = reg_key_get_subkey_by_name(prevcur, begin, &cur);

		/* Key is not there, add it */
		if(W_ERROR_EQUAL(error, WERR_DEST_NOT_FOUND)) {
			error = reg_key_add_name(prevcur, begin, 0, NULL, &cur);
			if(!W_ERROR_IS_OK(error)) return error;
		}

		if(!W_ERROR_IS_OK(error)) {
			if(end) *end = '\\';
			return error;
		}
		
		if(!end) break;
		*end = '\\';
		begin = end+1;
		prevcur = cur;
	}
	return WERR_OK;
}

WERROR reg_key_add_name(REG_KEY *parent, const char *name, uint32_t access_mask, SEC_DESC *desc, REG_KEY **newkey)
{
	WERROR error;
	
	if (!parent) return WERR_INVALID_PARAM;
	
	if (!parent->handle->functions->add_key) {
		DEBUG(1, ("Backend '%s' doesn't support method add_key\n", parent->handle->functions->name));
		return WERR_NOT_SUPPORTED;
	}

	error = parent->handle->functions->add_key(parent, name, access_mask, desc, newkey);

	if(!W_ERROR_IS_OK(error)) return error;
	
	(*newkey)->handle = parent->handle;
	(*newkey)->backend_data = talloc_asprintf((*newkey)->mem_ctx, "%s\\%s", reg_key_get_path(parent), name);

	parent->cache_subkeys = NULL;
	parent->cache_subkeys_count = 0;
	return WERR_OK;
}

WERROR reg_val_update(REG_VAL *val, int type, void *data, int len)
{
	WERROR error;
	
	/* A 'real' update function has preference */
	if (val->handle->functions->update_value) 
		return val->handle->functions->update_value(val, type, data, len);

	/* Otherwise, just remove and add again */
	if (val->handle->functions->add_value && 
		val->handle->functions->del_value) {
		REG_VAL *new;
		if(!W_ERROR_IS_OK(error = val->handle->functions->del_value(val))) 
			return error;
		
		error = val->handle->functions->add_value(val->parent, val->name, type, data, len);
		if(!W_ERROR_IS_OK(error)) return error;
		memcpy(val, new, sizeof(REG_VAL));
		val->parent->cache_values = NULL;
		val->parent->cache_values_count = 0;
		return WERR_OK;
	}
		
	DEBUG(1, ("Backend '%s' doesn't support method update_value\n", val->handle->functions->name));
	return WERR_NOT_SUPPORTED;
}

void reg_free(REG_HANDLE *h)
{
	if(!h->functions->close_registry) return;

	h->functions->close_registry(h);
}

WERROR reg_get_hive(REG_HANDLE *h, int hivenum, REG_KEY **key) 
{
	WERROR ret;
	
	if(h->functions->get_hive) {
		ret = h->functions->get_hive(h, hivenum, key);
	} else if(h->functions->open_key) {
		if(hivenum == 0) ret = h->functions->open_key(h, hivenum, "", key);
		else ret = WERR_NO_MORE_ITEMS;
	} else {
		DEBUG(0, ("Backend '%s' has neither open_root_key nor open_key or get_hive method implemented\n", h->functions->name));
		ret = WERR_NOT_SUPPORTED;
	}

	if(W_ERROR_IS_OK(ret)) {
		(*key)->handle = h;
		if(!(*key)->path) {
			(*key)->path = talloc_strdup((*key)->mem_ctx, (*key)->name);
		}
		(*key)->hive = hivenum;
	}

	return ret;
}

WERROR reg_key_add_value(REG_KEY *key, const char *name, int type, void *value, size_t vallen)
{
	WERROR ret = WERR_OK;
	if(!key->handle->functions->add_value)
		return WERR_NOT_SUPPORTED;

	ret = key->handle->functions->add_value(key, name, type, value, vallen);

	if(!W_ERROR_IS_OK(ret)) return ret;

	/* Invalidate the cache */
	key->cache_values = NULL;
	key->cache_values_count = 0;
	return ret;
}

WERROR reg_save(REG_HANDLE *h, const char *location)
{
	/* FIXME */	
	return WERR_NOT_SUPPORTED;
}

WERROR reg_key_get_parent(REG_KEY *key, REG_KEY **parent)
{
	char *parent_name;
	char *last;
	REG_KEY *root;
	WERROR error;

	error = reg_get_hive(key->handle, key->hive, &root);
	if(!W_ERROR_IS_OK(error)) return error;

	parent_name = strdup(reg_key_get_path(key));
	last = strrchr(parent_name, '\\');

	if(!last) {
		SAFE_FREE(parent_name);
		return WERR_FOOBAR;
	}
	*last = '\0';

	error = reg_open_key(root, parent_name, parent);
	SAFE_FREE(parent_name);
	return error;
}
