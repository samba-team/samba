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
#include "dlinklist.h"
#include "registry.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

/* List of available backends */
static struct reg_init_function_entry *backends = NULL;

static struct reg_init_function_entry *reg_find_backend_entry(const char *name);

/* Register new backend */
NTSTATUS registry_register(const void *_hive_ops)  
{
	const struct hive_operations *hive_ops = _hive_ops;
	struct reg_init_function_entry *entry = backends;

	DEBUG(5,("Attempting to register registry backend %s\n", hive_ops->name));

	/* Check for duplicates */
	if (reg_find_backend_entry(hive_ops->name)) {
		DEBUG(0,("There already is a registry backend registered with the name %s!\n", hive_ops->name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	entry = talloc_p(NULL, struct reg_init_function_entry);
	entry->hive_functions = hive_ops;

	DLIST_ADD(backends, entry);
	DEBUG(5,("Successfully added registry backend '%s'\n", hive_ops->name));
	return NT_STATUS_OK;
}

/* Find a backend in the list of available backends */
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

/* Check whether a certain backend is present */
BOOL reg_has_backend(const char *backend)
{
	return reg_find_backend_entry(backend) != NULL?True:False;
}

static struct {
	uint32 hkey;
	const char *name;
} hkey_names[] = 
{
	{HKEY_CLASSES_ROOT,"HKEY_CLASSES_ROOT" },
	{HKEY_CURRENT_USER,"HKEY_CURRENT_USER" },
	{HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE" },
	{HKEY_PERFORMANCE_DATA, "HKEY_PERFORMANCE_DATA" },
	{HKEY_USERS, "HKEY_USERS" },
	{HKEY_CURRENT_CONFIG, "HKEY_CURRENT_CONFIG" },
	{HKEY_DYN_DATA, "HKEY_DYN_DATA" },
	{HKEY_PT, "HKEY_PT" },
	{HKEY_PN, "HKEY_PN" },
	{ 0, NULL }
};

int reg_list_hives(TALLOC_CTX *mem_ctx, char ***hives, uint32_t **hkeys)
{
	int i;
	*hives = talloc_array_p(mem_ctx, char *, ARRAY_SIZE(hkey_names));
	*hkeys = talloc_array_p(mem_ctx, uint32_t, ARRAY_SIZE(hkey_names));

	for (i = 0; hkey_names[i].name; i++) {
		(*hives)[i] = talloc_strdup(mem_ctx, hkey_names[i].name);
		(*hkeys)[i] = hkey_names[i].hkey;
	}

	return i;
}

const char *reg_get_hkey_name(uint32_t hkey)
{
	int i;
	for (i = 0; hkey_names[i].name; i++) {
		if (hkey_names[i].hkey == hkey) return hkey_names[i].name;
	}

	return NULL;
}

WERROR reg_get_hive_by_name(struct registry_context *ctx, const char *name, struct registry_key **key)
{
	int i;
	
	for (i = 0; hkey_names[i].name; i++) {
		if (!strcmp(hkey_names[i].name, name)) return reg_get_hive(ctx, hkey_names[i].hkey, key);
	}

	DEBUG(1, ("No hive with name '%s'\n", name));
	
	return WERR_BADFILE;
}

WERROR reg_close (struct registry_context *ctx)
{
	talloc_destroy(ctx);

	return WERR_OK;
}

WERROR reg_get_hive(struct registry_context *ctx, uint32_t hkey, struct registry_key **key)
{
	WERROR ret = ctx->get_hive(ctx, hkey, key);

	if (W_ERROR_IS_OK(ret)) {
		(*key)->name = talloc_strdup(*key, reg_get_hkey_name(hkey));
		(*key)->path = ""; 
	}

	return ret;
}

/* Open a registry file/host/etc */
WERROR reg_open_hive(struct registry_context *parent_ctx, const char *backend, const char *location, const char *credentials, struct registry_key **root)
{
	struct registry_hive *ret;
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
	
	ret = talloc_p(parent_ctx, struct registry_hive);
	ret->location = location?talloc_strdup(ret, location):NULL;
	ret->functions = entry->hive_functions;
	ret->backend_data = NULL;
	ret->reg_ctx = parent_ctx;

	werr = entry->hive_functions->open_hive(ret, &ret->root);

	if(!W_ERROR_IS_OK(werr)) {
		return werr;
	}
	
	if(!ret->root) {
		DEBUG(0, ("Backend %s didn't provide root key!\n", backend));
		return WERR_GENERAL_FAILURE;
	}

	ret->root->hive = ret;
	ret->root->name = NULL;
	ret->root->path = talloc_strdup(ret, "");
	
	*root = ret->root;

	return WERR_OK;
}

/* Open a key by name (including the hive name!) */
WERROR reg_open_key_abs(TALLOC_CTX *mem_ctx, struct registry_context *handle, const char *name, struct registry_key **result)
{
	struct registry_key *hive;
	WERROR error;
	int hivelength;
	char *hivename;

	if(strchr(name, '\\')) hivelength = strchr(name, '\\')-name;
	else hivelength = strlen(name);

	hivename = strndup(name, hivelength);
	error = reg_get_hive_by_name(handle, hivename, &hive);
	SAFE_FREE(hivename);

	if(!W_ERROR_IS_OK(error)) {
		return error;
	}

	return reg_open_key(mem_ctx, hive, name, result);
}

/* Open a key 
 * First tries to use the open_key function from the backend
 * then falls back to get_subkey_by_name and later get_subkey_by_index 
 */
WERROR reg_open_key(TALLOC_CTX *mem_ctx, struct registry_key *parent, const char *name, struct registry_key **result)
{
	char *fullname;
	WERROR error;

	if(!parent) {
		DEBUG(0, ("Invalid parent key specified"));
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


	fullname = ((parent->hive->root == parent)?talloc_strdup(mem_ctx, name):talloc_asprintf(mem_ctx, "%s\\%s", parent->path, name));

	error = parent->hive->functions->open_key(mem_ctx, parent->hive, fullname, result);

	if(!W_ERROR_IS_OK(error)) return error;
		
	(*result)->hive = parent->hive;
	(*result)->path = fullname;
	(*result)->hive = parent->hive;

	return WERR_OK;
}

WERROR reg_key_get_value_by_index(TALLOC_CTX *mem_ctx, struct registry_key *key, int idx, struct registry_value **val)
{
	if(!key) return WERR_INVALID_PARAM;

	if(key->hive->functions->get_value_by_index) {
		WERROR status = key->hive->functions->get_value_by_index(mem_ctx, key, idx, val);
		if(!W_ERROR_IS_OK(status)) 
			return status;
	} else {
		return WERR_NOT_SUPPORTED;
	}
	
	(*val)->parent = key;
	(*val)->hive = key->hive;
	return WERR_OK;
}

WERROR reg_key_num_subkeys(struct registry_key *key, int *count)
{
	if(!key) return WERR_INVALID_PARAM;
	
	if(key->hive->functions->num_subkeys) {
		return key->hive->functions->num_subkeys(key, count);
	}

	if(key->hive->functions->get_subkey_by_index) {
		int i;
		WERROR error;
		struct registry_key *dest;
		TALLOC_CTX *mem_ctx = talloc_init("num_subkeys");
		
		for(i = 0; W_ERROR_IS_OK(error = key->hive->functions->get_subkey_by_index(mem_ctx, key, i, &dest)); i++);
		talloc_destroy(mem_ctx);

		*count = i;
		if(W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) error = WERR_OK;
		return error;
	}

	return WERR_NOT_SUPPORTED;
}

WERROR reg_key_num_values(struct registry_key *key, int *count)
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
		talloc_destroy(mem_ctx);

		*count = i;
		if(W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) error = WERR_OK;
		return error;
	}

	return WERR_NOT_SUPPORTED;
}

WERROR reg_key_get_subkey_by_index(TALLOC_CTX *mem_ctx, struct registry_key *key, int idx, struct registry_key **subkey)
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

WERROR reg_key_get_subkey_by_name(TALLOC_CTX *mem_ctx, struct registry_key *key, const char *name, struct registry_key **subkey)
{
	int i;
	WERROR error = WERR_OK;

	if(!key) return WERR_INVALID_PARAM;

	if(key->hive->functions->get_subkey_by_name) {
		error = key->hive->functions->get_subkey_by_name(mem_ctx, key,name,subkey);
	} else if(key->hive->functions->open_key) {
		error = key->hive->functions->open_key(mem_ctx, key->hive, talloc_asprintf(mem_ctx, "%s\\%s", key->path, name), subkey);
	} else if(key->hive->functions->get_subkey_by_index) {
		for(i = 0; W_ERROR_IS_OK(error); i++) {
			error = reg_key_get_subkey_by_index(mem_ctx, key, i, subkey);
			if(W_ERROR_IS_OK(error) && !strcmp((*subkey)->name, name)) {
				return error;
			}
		}
	} else {
		return WERR_NOT_SUPPORTED;
	}

	if(!W_ERROR_IS_OK(error)) return error;

	(*subkey)->path = talloc_asprintf(mem_ctx, "%s\\%s", key->path, (*subkey)->name);
	(*subkey)->hive = key->hive;

	return WERR_OK; 
}

WERROR reg_key_get_value_by_name(TALLOC_CTX *mem_ctx, struct registry_key *key, const char *name, struct registry_value **val)
{
	int i;
	WERROR error = WERR_OK;

	if(!key) return WERR_INVALID_PARAM;

	if(key->hive->functions->get_value_by_name) {
		error = key->hive->functions->get_value_by_name(mem_ctx, key,name, val);
	} else {
		for(i = 0; W_ERROR_IS_OK(error); i++) {
			error = reg_key_get_value_by_index(mem_ctx, key, i, val);
			if(W_ERROR_IS_OK(error) && StrCaseCmp((*val)->name, name)) {
				break;
			}
		}
	}

	if(!W_ERROR_IS_OK(error) && !W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS))
		return error;
	
	(*val)->parent = key;
	(*val)->hive = key->hive;
	
	return WERR_OK;
}

WERROR reg_key_del(struct registry_key *key)
{
	WERROR error;
	if(!key) return WERR_INVALID_PARAM;
	
	
	if(!key->hive->functions->del_key)
		return WERR_NOT_SUPPORTED;
	
	error = key->hive->functions->del_key(key);
	if(!W_ERROR_IS_OK(error)) return error;

	return WERR_OK;
}

WERROR reg_key_del_recursive(struct registry_key *key)
{
	WERROR error = WERR_OK;
	int i;

	TALLOC_CTX *mem_ctx = talloc_init("del_recursive");
	
	/* Delete all values for specified key */
	for(i = 0; W_ERROR_IS_OK(error); i++) {
		struct registry_value *val;
		error = reg_key_get_value_by_index(mem_ctx, key, i, &val);
		if(!W_ERROR_IS_OK(error) && !W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) 
		{
			talloc_destroy(mem_ctx);			
			return error;
		}

		if(W_ERROR_IS_OK(error)) {
			error = reg_del_value(val);
			if(!W_ERROR_IS_OK(error)) {
				talloc_destroy(mem_ctx);
				return error;
			}
		}
	}

	error = WERR_OK;

	/* Delete all keys below this one */
	for(i = 0; W_ERROR_IS_OK(error); i++) {
		struct registry_key *subkey;

		error = reg_key_get_subkey_by_index(mem_ctx, key, i, &subkey);
		if(!W_ERROR_IS_OK(error)) { talloc_destroy(mem_ctx); return error; }

		error = reg_key_del_recursive(subkey);
		if(!W_ERROR_IS_OK(error)) { talloc_destroy(mem_ctx); return error; }
	}

	talloc_destroy(mem_ctx);
	return reg_key_del(key);
}

WERROR reg_key_add_name_recursive_abs(struct registry_context *handle, const char *name)
{
	struct registry_key *hive;
	WERROR error;
	int hivelength;
	char *hivename;

	if(strchr(name, '\\')) hivelength = strchr(name, '\\')-name;
	else hivelength = strlen(name);

	hivename = strndup(name, hivelength);
	error = reg_get_hive_by_name(handle, hivename, &hive);
	SAFE_FREE(hivename);

	if(!W_ERROR_IS_OK(error)) return error;

	return reg_key_add_name_recursive(hive, name);
}

WERROR reg_key_add_name_recursive(struct registry_key *parent, const char *path)
{
	struct registry_key *cur, *prevcur = parent;
	WERROR error = WERR_OK;
	char *dups, *begin, *end;
	TALLOC_CTX *mem_ctx = talloc_init("add_recursive");

	begin = dups = strdup(path);

	while(1) { 
		end = strchr(begin, '\\');
		if(end) *end = '\0';
		
		error = reg_key_get_subkey_by_name(mem_ctx, prevcur, begin, &cur);

		/* Key is not there, add it */
		if(W_ERROR_EQUAL(error, WERR_DEST_NOT_FOUND)) {
			error = reg_key_add_name(mem_ctx, prevcur, begin, 0, NULL, &cur);
			if(!W_ERROR_IS_OK(error)) break;
		}

		if(!W_ERROR_IS_OK(error)) {
			if(end) *end = '\\';
			break;
		}
		
		if(!end) { 
			error = WERR_OK; 
			break; 
		}

		*end = '\\';
		begin = end+1;
		prevcur = cur;
	}
	SAFE_FREE(dups);
	talloc_destroy(mem_ctx);
	return error;
}

WERROR reg_key_add_name(TALLOC_CTX *mem_ctx, struct registry_key *parent, const char *name, uint32_t access_mask, SEC_DESC *desc, struct registry_key **newkey)
{
	WERROR error;
	
	if (!parent) return WERR_INVALID_PARAM;
	
	if (!parent->hive->functions->add_key) {
		DEBUG(1, ("Backend '%s' doesn't support method add_key\n", parent->hive->functions->name));
		return WERR_NOT_SUPPORTED;
	}

	error = parent->hive->functions->add_key(mem_ctx, parent, name, access_mask, desc, newkey);

	if(!W_ERROR_IS_OK(error)) return error;
	
	(*newkey)->hive = parent->hive;
	(*newkey)->backend_data = talloc_asprintf(mem_ctx, "%s\\%s", parent->path, name);

	return WERR_OK;
}

WERROR reg_val_set(struct registry_key *key, const char *value, int type, void *data, int len)
{
	/* A 'real' set function has preference */
	if (key->hive->functions->set_value) 
		return key->hive->functions->set_value(key, value, type, data, len);

	DEBUG(1, ("Backend '%s' doesn't support method set_value\n", key->hive->functions->name));
	return WERR_NOT_SUPPORTED;
}



WERROR reg_del_value(struct registry_value *val)
{
	WERROR ret = WERR_OK;
	if(!val->hive->functions->del_value)
		return WERR_NOT_SUPPORTED;

	ret = val->hive->functions->del_value(val);

	if(!W_ERROR_IS_OK(ret)) return ret;

	return ret;
}

WERROR reg_save (struct registry_context *ctx, const char *location)
{
	return WERR_NOT_SUPPORTED;
}

WERROR reg_key_get_parent(TALLOC_CTX *mem_ctx, struct registry_key *key, struct registry_key **parent)
{
	char *parent_name;
	char *last;
	struct registry_key *root = NULL;
	WERROR error;

	parent_name = strdup(key->path);
	last = strrchr(parent_name, '\\');

	if(!last) {
		SAFE_FREE(parent_name);
		return WERR_FOOBAR;
	}
	*last = '\0';

	error = reg_open_key(mem_ctx, root, parent_name, parent);
	SAFE_FREE(parent_name);
	return error;
}

WERROR reg_key_flush(struct registry_key *key)
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

WERROR reg_key_subkeysizes(struct registry_key *key, uint32 *max_subkeylen, uint32 *max_subkeysize)
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

	talloc_destroy(mem_ctx);

	return WERR_OK;
}

WERROR reg_key_valuesizes(struct registry_key *key, uint32 *max_valnamelen, uint32 *max_valbufsize)
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
			*max_valbufsize = MAX(*max_valbufsize, value->data_len);
		}

		i++;
	} while (W_ERROR_IS_OK(error));

	talloc_destroy(mem_ctx);

	return WERR_OK;
}
