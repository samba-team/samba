/* 
   Unix SMB/CIFS implementation.
   Transparent registry backend handling
   Copyright (C) Jelmer Vernooij			2003-2004.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "lib/util/dlinklist.h"
#include "lib/registry/registry.h"
#include "build.h"

/**
 * @file
 * @brief Main registry functions
 */

/* List of available backends */
static struct reg_init_function_entry *backends = NULL;

static struct reg_init_function_entry *reg_find_backend_entry(const char *name);

/** Register a new backend. */
_PUBLIC_ NTSTATUS registry_register(const void *_hive_ops)
{
	const struct hive_operations *hive_ops = _hive_ops;
	struct reg_init_function_entry *entry = backends;

	DEBUG(5,("Attempting to register registry backend %s\n", hive_ops->name));

	/* Check for duplicates */
	if (reg_find_backend_entry(hive_ops->name)) {
		DEBUG(0,("There already is a registry backend registered with the name %s!\n", hive_ops->name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	entry = talloc(talloc_autofree_context(), struct reg_init_function_entry);
	entry->hive_functions = hive_ops;

	DLIST_ADD(backends, entry);
	DEBUG(5,("Successfully added registry backend '%s'\n", hive_ops->name));
	return NT_STATUS_OK;
}

/** Find a backend in the list of available backends */
static struct reg_init_function_entry *reg_find_backend_entry(const char *name)
{
	struct reg_init_function_entry *entry;

	entry = backends;

	while(entry) {
		if (strcmp(entry->hive_functions->name, name) == 0) return entry;
		entry = entry->next;
	}

	return NULL;
}

/** Initialize the registry subsystem */
_PUBLIC_ NTSTATUS registry_init(void)
{
	init_module_fn static_init[] = STATIC_registry_MODULES;
	init_module_fn *shared_init = load_samba_modules(NULL, "registry");

	run_init_functions(static_init);
	run_init_functions(shared_init);

	talloc_free(shared_init);
	
	return NT_STATUS_OK;
}

/** Check whether a certain backend is present. */
_PUBLIC_ BOOL reg_has_backend(const char *backend)
{
	return reg_find_backend_entry(backend) != NULL?True:False;
}

const struct reg_predefined_key reg_predefined_keys[] = {
	{HKEY_CLASSES_ROOT,"HKEY_CLASSES_ROOT" },
	{HKEY_CURRENT_USER,"HKEY_CURRENT_USER" },
	{HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE" },
	{HKEY_PERFORMANCE_DATA, "HKEY_PERFORMANCE_DATA" },
	{HKEY_USERS, "HKEY_USERS" },
	{HKEY_CURRENT_CONFIG, "HKEY_CURRENT_CONFIG" },
	{HKEY_DYN_DATA, "HKEY_DYN_DATA" },
	{HKEY_PERFORMANCE_TEXT, "HKEY_PERFORMANCE_TEXT" },
	{HKEY_PERFORMANCE_NLSTEXT, "HKEY_PERFORMANCE_NLSTEXT" },
	{ 0, NULL }
};

/** Obtain a list of predefined keys. */
_PUBLIC_ int reg_list_predefs(TALLOC_CTX *mem_ctx, char ***predefs, uint32_t **hkeys)
{
	int i;
	*predefs = talloc_array(mem_ctx, char *, ARRAY_SIZE(reg_predefined_keys));
	*hkeys = talloc_array(mem_ctx, uint32_t, ARRAY_SIZE(reg_predefined_keys));

	for (i = 0; reg_predefined_keys[i].name; i++) {
		(*predefs)[i] = talloc_strdup(mem_ctx, reg_predefined_keys[i].name);
		(*hkeys)[i] = reg_predefined_keys[i].handle;
	}

	return i;
}

/** Obtain name of specific hkey. */
_PUBLIC_ const char *reg_get_predef_name(uint32_t hkey)
{
	int i;
	for (i = 0; reg_predefined_keys[i].name; i++) {
		if (reg_predefined_keys[i].handle == hkey) return reg_predefined_keys[i].name;
	}

	return NULL;
}

/** Get predefined key by name. */
_PUBLIC_ WERROR reg_get_predefined_key_by_name(struct registry_context *ctx, const char *name, struct registry_key **key)
{
	int i;
	
	for (i = 0; reg_predefined_keys[i].name; i++) {
		if (!strcasecmp(reg_predefined_keys[i].name, name)) return reg_get_predefined_key(ctx, reg_predefined_keys[i].handle, key);
	}

	DEBUG(1, ("No predefined key with name '%s'\n", name));
	
	return WERR_BADFILE;
}

/** Get predefined key by id. */
_PUBLIC_ WERROR reg_get_predefined_key(struct registry_context *ctx, uint32_t hkey, struct registry_key **key)
{
	WERROR ret = ctx->get_predefined_key(ctx, hkey, key);

	if (W_ERROR_IS_OK(ret)) {
		(*key)->name = talloc_strdup(*key, reg_get_predef_name(hkey));
		(*key)->path = ""; 
	}

	return ret;
}

/** Open a registry file/host/etc */
_PUBLIC_ WERROR reg_open_hive(TALLOC_CTX *parent_ctx, const char *backend, const char *location, struct auth_session_info *session_info, struct cli_credentials *credentials, struct registry_key **root)
{
	struct registry_hive *rethive;
	struct registry_key *retkey = NULL;
	struct reg_init_function_entry *entry;
	WERROR werr;

	entry = reg_find_backend_entry(backend);
	
	if (!entry) {
		DEBUG(0, ("No such registry backend '%s' loaded!\n", backend));
		return WERR_GENERAL_FAILURE;
	}

	if(!entry->hive_functions || !entry->hive_functions->open_hive) {
		return WERR_NOT_SUPPORTED;
	}
	
	rethive = talloc(parent_ctx, struct registry_hive);
	rethive->location = location?talloc_strdup(rethive, location):NULL;
	rethive->session_info = talloc_reference(rethive, session_info);
	rethive->credentials = talloc_reference(rethive, credentials);
	rethive->functions = entry->hive_functions;
	rethive->backend_data = NULL;

	werr = entry->hive_functions->open_hive(rethive, &retkey);

	if(!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	if(!retkey) {
		DEBUG(0, ("Backend %s didn't provide root key!\n", backend));
		return WERR_GENERAL_FAILURE;
	}

	rethive->root = retkey;

	retkey->hive = rethive;
	retkey->name = NULL;
	retkey->path = talloc_strdup(retkey, "");
	
	*root = retkey;

	return WERR_OK;
}

/**
 * Open a key 
 * First tries to use the open_key function from the backend
 * then falls back to get_subkey_by_name and later get_subkey_by_index 
 */
_PUBLIC_ WERROR reg_open_key(TALLOC_CTX *mem_ctx, struct registry_key *parent, const char *name, struct registry_key **result)
{
	WERROR error;

	if(!parent) {
		DEBUG(0, ("Invalid parent key specified for open of '%s'\n", name));
		return WERR_INVALID_PARAM;
	}

	if(!parent->hive->functions->open_key && 
	   (parent->hive->functions->get_subkey_by_name || 
	   parent->hive->functions->get_subkey_by_index)) {
		char *orig = strdup(name), 
			 *curbegin = orig, 
			 *curend = strchr(orig, '\\');
		struct registry_key *curkey = parent;

		while(curbegin && *curbegin) {
			if(curend)*curend = '\0';
			error = reg_key_get_subkey_by_name(mem_ctx, curkey, curbegin, &curkey);
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

	if(!parent->hive->functions->open_key) {
		DEBUG(0, ("Registry backend doesn't have get_subkey_by_name nor open_key!\n"));
		return WERR_NOT_SUPPORTED;
	}

	error = parent->hive->functions->open_key(mem_ctx, parent, name, result);

	if(!W_ERROR_IS_OK(error)) return error;
		
	(*result)->hive = parent->hive;
	(*result)->path = ((parent->hive->root == parent)?talloc_strdup(mem_ctx, name):talloc_asprintf(mem_ctx, "%s\\%s", parent->path, name));
	(*result)->hive = parent->hive;

	return WERR_OK;
}

/**
 * Get value by index
 */
_PUBLIC_ WERROR reg_key_get_value_by_index(TALLOC_CTX *mem_ctx, const struct registry_key *key, int idx, struct registry_value **val)
{
	if(!key) return WERR_INVALID_PARAM;

	if(key->hive->functions->get_value_by_index) {
		WERROR status = key->hive->functions->get_value_by_index(mem_ctx, key, idx, val);
		if(!W_ERROR_IS_OK(status)) 
			return status;
	} else {
		return WERR_NOT_SUPPORTED;
	}
	
	return WERR_OK;
}

/** 
 * Get the number of subkeys.
 */
_PUBLIC_ WERROR reg_key_num_subkeys(const struct registry_key *key, uint32_t *count)
{
	if(!key) return WERR_INVALID_PARAM;
	
	if(key->hive->functions->num_subkeys) {
		return key->hive->functions->num_subkeys(key, count);
	}

	if(key->hive->functions->get_subkey_by_index) {
		int i;
		WERROR error;
		struct registry_key *dest = NULL;
		TALLOC_CTX *mem_ctx = talloc_init("num_subkeys");
		
		for(i = 0; W_ERROR_IS_OK(error = reg_key_get_subkey_by_index(mem_ctx, key, i, &dest)); i++);
		talloc_free(mem_ctx);

		*count = i;
		if(W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) error = WERR_OK;
		return error;
	}

	return WERR_NOT_SUPPORTED;
}

/**
 * Get the number of values of a key.
 */
_PUBLIC_ WERROR reg_key_num_values(const struct registry_key *key, uint32_t *count)
{
	
	if(!key) return WERR_INVALID_PARAM;

	if (key->hive->functions->num_values) {
		return key->hive->functions->num_values(key, count);
	}

	if(key->hive->functions->get_value_by_index) {
		int i;
		WERROR error;
		struct registry_value *dest;
		TALLOC_CTX *mem_ctx = talloc_init("num_subkeys");
		
		for(i = 0; W_ERROR_IS_OK(error = key->hive->functions->get_value_by_index(mem_ctx, key, i, &dest)); i++);
		talloc_free(mem_ctx);

		*count = i;
		if(W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) error = WERR_OK;
		return error;
	}

	return WERR_NOT_SUPPORTED;
}

/**
 * Get subkey by index.
 */
_PUBLIC_ WERROR reg_key_get_subkey_by_index(TALLOC_CTX *mem_ctx, const struct registry_key *key, int idx, struct registry_key **subkey)
{
	if(!key) return WERR_INVALID_PARAM;

	if(key->hive->functions->get_subkey_by_index) {
		WERROR status = key->hive->functions->get_subkey_by_index(mem_ctx, key, idx, subkey);
		if(!NT_STATUS_IS_OK(status)) return status;
	} else {
		return WERR_NOT_SUPPORTED;
	}

	if(key->hive->root == key) 
		(*subkey)->path = talloc_strdup(mem_ctx, (*subkey)->name);
	else 
		(*subkey)->path = talloc_asprintf(mem_ctx, "%s\\%s", key->path, (*subkey)->name);

	(*subkey)->hive = key->hive;
	return WERR_OK;;
}

/**
 * Get subkey by name.
 */
WERROR reg_key_get_subkey_by_name(TALLOC_CTX *mem_ctx, const struct registry_key *key, const char *name, struct registry_key **subkey)
{
	int i;
	WERROR error = WERR_OK;

	if(!key) return WERR_INVALID_PARAM;

	if(key->hive->functions->get_subkey_by_name) {
		error = key->hive->functions->get_subkey_by_name(mem_ctx, key,name,subkey);
	} else if(key->hive->functions->open_key) {
		error = key->hive->functions->open_key(mem_ctx, key, name, subkey);
	} else if(key->hive->functions->get_subkey_by_index) {
		for(i = 0; W_ERROR_IS_OK(error); i++) {
			error = reg_key_get_subkey_by_index(mem_ctx, key, i, subkey);
			if(W_ERROR_IS_OK(error) && !strcasecmp((*subkey)->name, name)) {
				break;
			}
		}

		if (W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) 
			error = WERR_DEST_NOT_FOUND;
	} else {
		return WERR_NOT_SUPPORTED;
	}

	if(!W_ERROR_IS_OK(error)) return error;

	(*subkey)->path = talloc_asprintf(mem_ctx, "%s\\%s", key->path, (*subkey)->name);
	(*subkey)->hive = key->hive;

	return WERR_OK; 
}

/**
 * Get value by name.
 */
_PUBLIC_ WERROR reg_key_get_value_by_name(TALLOC_CTX *mem_ctx, const struct registry_key *key, const char *name, struct registry_value **val)
{
	int i;
	WERROR error = WERR_OK;

	if(!key) return WERR_INVALID_PARAM;

	if(key->hive->functions->get_value_by_name) {
		error = key->hive->functions->get_value_by_name(mem_ctx, key,name, val);
	} else {
		for(i = 0; W_ERROR_IS_OK(error); i++) {
			error = reg_key_get_value_by_index(mem_ctx, key, i, val);
			if(W_ERROR_IS_OK(error) && !strcasecmp((*val)->name, name)) {
				break;
			}
		}
	}

	if (W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS))
		return WERR_DEST_NOT_FOUND;

	return error;
}

/**
 * Delete a key.
 */
_PUBLIC_ WERROR reg_key_del(struct registry_key *parent, const char *name)
{
	WERROR error;
	if(!parent) return WERR_INVALID_PARAM;
	
	
	if(!parent->hive->functions->del_key)
		return WERR_NOT_SUPPORTED;
	
	error = parent->hive->functions->del_key(parent, name);
	if(!W_ERROR_IS_OK(error)) return error;

	return WERR_OK;
}

/**
 * Add a key.
 */
_PUBLIC_ WERROR reg_key_add_name(TALLOC_CTX *mem_ctx, const struct registry_key *parent, const char *name, uint32_t access_mask, struct security_descriptor *desc, struct registry_key **newkey)
{
	WERROR error;
	
	if (!parent) return WERR_INVALID_PARAM;
	
	if (!parent->hive->functions->add_key) {
		DEBUG(1, ("Backend '%s' doesn't support method add_key\n", parent->hive->functions->name));
		return WERR_NOT_SUPPORTED;
	}

	error = parent->hive->functions->add_key(mem_ctx, parent, name, access_mask, desc, newkey);

	if(!W_ERROR_IS_OK(error)) return error;

	if (!*newkey) {
		DEBUG(0, ("Backend returned WERR_OK, but didn't specify key!\n"));
		return WERR_GENERAL_FAILURE;
	}
	
	(*newkey)->hive = parent->hive;

	return WERR_OK;
}

/**
 * Set a value.
 */
_PUBLIC_ WERROR reg_val_set(struct registry_key *key, const char *value, uint32_t type, DATA_BLOB data)
{
	/* A 'real' set function has preference */
	if (key->hive->functions->set_value) 
		return key->hive->functions->set_value(key, value, type, data);

	DEBUG(1, ("Backend '%s' doesn't support method set_value\n", key->hive->functions->name));
	return WERR_NOT_SUPPORTED;
}

/**
 * Get the security descriptor on a key.
 */
_PUBLIC_ WERROR reg_get_sec_desc(TALLOC_CTX *ctx, const struct registry_key *key, struct security_descriptor **secdesc)
{
	/* A 'real' set function has preference */
	if (key->hive->functions->key_get_sec_desc) 
		return key->hive->functions->key_get_sec_desc(ctx, key, secdesc);

	DEBUG(1, ("Backend '%s' doesn't support method get_sec_desc\n", key->hive->functions->name));
	return WERR_NOT_SUPPORTED;
}

/**
 * Delete a value.
 */
_PUBLIC_ WERROR reg_del_value(const struct registry_key *key, const char *valname)
{
	WERROR ret = WERR_OK;
	if(!key->hive->functions->del_value)
		return WERR_NOT_SUPPORTED;

	ret = key->hive->functions->del_value(key, valname);

	if(!W_ERROR_IS_OK(ret)) return ret;

	return ret;
}

/**
 * Flush a key to disk.
 */
_PUBLIC_ WERROR reg_key_flush(const struct registry_key *key)
{
	if (!key) {
		return WERR_INVALID_PARAM;
	}
	
	if (key->hive->functions->flush_key) {
		return key->hive->functions->flush_key(key);
	}
	
	/* No need for flushing, apparently */
	return WERR_OK;
}

/**
 * Get the maximum name and data lengths of the subkeys.
 */
_PUBLIC_ WERROR reg_key_subkeysizes(const struct registry_key *key, uint32_t *max_subkeylen, uint32_t *max_subkeysize)
{
	int i = 0; 
	struct registry_key *subkey;
	WERROR error;
	TALLOC_CTX *mem_ctx = talloc_init("subkeysize");

	*max_subkeylen = *max_subkeysize = 0;

	do {
		error = reg_key_get_subkey_by_index(mem_ctx, key, i, &subkey);

		if (W_ERROR_IS_OK(error)) {
			*max_subkeysize = MAX(*max_subkeysize, 0xFF);
			*max_subkeylen = MAX(*max_subkeylen, strlen(subkey->name));
		}

		i++;
	} while (W_ERROR_IS_OK(error));

	talloc_free(mem_ctx);

	return WERR_OK;
}

/**
 * Get the maximum name and data lengths of the values.
 */
_PUBLIC_ WERROR reg_key_valuesizes(const struct registry_key *key, uint32_t *max_valnamelen, uint32_t *max_valbufsize)
{
	int i = 0; 
	struct registry_value *value;
	WERROR error;
	TALLOC_CTX *mem_ctx = talloc_init("subkeysize");

	*max_valnamelen = *max_valbufsize = 0;

	do {
		error = reg_key_get_value_by_index(mem_ctx, key, i, &value);

		if (W_ERROR_IS_OK(error)) {
			if (value->name) {
				*max_valnamelen = MAX(*max_valnamelen, strlen(value->name));
			}
			*max_valbufsize = MAX(*max_valbufsize, value->data.length);
		}

		i++;
	} while (W_ERROR_IS_OK(error));

	talloc_free(mem_ctx);

	return WERR_OK;
}
