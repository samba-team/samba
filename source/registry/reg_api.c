/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Volker Lendecke 2006
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Attempt to wrap the existing API in a more winreg.idl-like way */

#include "includes.h"

static WERROR fill_value_cache(struct registry_key *key)
{
	if (key->values != NULL) {
		return WERR_OK;
	}

	if (!(key->values = TALLOC_ZERO_P(key, REGVAL_CTR))) {
		return WERR_NOMEM;
	}
	if (fetch_reg_values(key->key, key->values) == -1) {
		TALLOC_FREE(key->values);
		return WERR_BADFILE;
	}

	return WERR_OK;
}

static WERROR fill_subkey_cache(struct registry_key *key)
{
	if (key->subkeys != NULL) {
		return WERR_OK;
	}

	if (!(key->subkeys = TALLOC_ZERO_P(key, REGSUBKEY_CTR))) {
		return WERR_NOMEM;
	}

	if (fetch_reg_keys(key->key, key->subkeys) == -1) {
		TALLOC_FREE(key->subkeys);
		return WERR_NO_MORE_ITEMS;
	}

	return WERR_OK;
}

static int regkey_destructor(REGISTRY_KEY *key)
{
	return regdb_close();
}

static WERROR regkey_open_onelevel(TALLOC_CTX *mem_ctx, 
				   struct registry_key *parent,
				   const char *name,
				   const struct nt_user_token *token,
				   uint32 access_desired,
				   struct registry_key **pregkey)
{
	WERROR     	result = WERR_OK;
	struct registry_key *regkey;
	REGISTRY_KEY *key;
	REGSUBKEY_CTR	*subkeys = NULL;

	DEBUG(7,("regkey_open_onelevel: name = [%s]\n", name));

	SMB_ASSERT(strchr(name, '\\') == NULL);

	if (!(regkey = TALLOC_ZERO_P(mem_ctx, struct registry_key)) ||
	    !(regkey->token = dup_nt_token(regkey, token)) ||
	    !(regkey->key = TALLOC_ZERO_P(regkey, REGISTRY_KEY))) {
		result = WERR_NOMEM;
		goto done;
	}

	if ( !(W_ERROR_IS_OK(result = regdb_open())) ) {
		goto done;
	}

	key = regkey->key;
	talloc_set_destructor(key, regkey_destructor);
		
	/* initialization */
	
	key->type = REG_KEY_GENERIC;

	if (name[0] == '\0') {
		/*
		 * Open a copy of the parent key
		 */
		if (!parent) {
			result = WERR_BADFILE;
			goto done;
		}
		key->name = talloc_strdup(key, parent->key->name);
	}
	else {
		/*
		 * Normal subkey open
		 */
		key->name = talloc_asprintf(key, "%s%s%s",
					    parent ? parent->key->name : "",
					    parent ? "\\": "",
					    name);
	}

	if (key->name == NULL) {
		result = WERR_NOMEM;
		goto done;
	}

	/* Tag this as a Performance Counter Key */

	if( StrnCaseCmp(key->name, KEY_HKPD, strlen(KEY_HKPD)) == 0 )
		key->type = REG_KEY_HKPD;
	
	/* Look up the table of registry I/O operations */

	if ( !(key->hook = reghook_cache_find( key->name )) ) {
		DEBUG(0,("reg_open_onelevel: Failed to assigned a "
			 "REGISTRY_HOOK to [%s]\n", key->name ));
		result = WERR_BADFILE;
		goto done;
	}
	
	/* check if the path really exists; failed is indicated by -1 */
	/* if the subkey count failed, bail out */

	if ( !(subkeys = TALLOC_ZERO_P( key, REGSUBKEY_CTR )) ) {
		result = WERR_NOMEM;
		goto done;
	}

	if ( fetch_reg_keys( key, subkeys ) == -1 )  {
		result = WERR_BADFILE;
		goto done;
	}
	
	TALLOC_FREE( subkeys );

	if ( !regkey_access_check( key, access_desired, &key->access_granted,
				   token ) ) {
		result = WERR_ACCESS_DENIED;
		goto done;
	}

	*pregkey = regkey;
	result = WERR_OK;
	
done:
	if ( !W_ERROR_IS_OK(result) ) {
		TALLOC_FREE(regkey);
	}

	return result;
}

WERROR reg_openhive(TALLOC_CTX *mem_ctx, const char *hive,
		    uint32 desired_access,
		    const struct nt_user_token *token,
		    struct registry_key **pkey)
{
	SMB_ASSERT(hive != NULL);
	SMB_ASSERT(hive[0] != '\0');
	SMB_ASSERT(strchr(hive, '\\') == NULL);

	return regkey_open_onelevel(mem_ctx, NULL, hive, token, desired_access,
				    pkey);
}

WERROR reg_openkey(TALLOC_CTX *mem_ctx, struct registry_key *parent,
		   const char *name, uint32 desired_access,
		   struct registry_key **pkey)
{
	struct registry_key *direct_parent = parent;
	WERROR err;
	char *p, *path, *to_free;
	size_t len;

	if (!(path = SMB_STRDUP(name))) {
		return WERR_NOMEM;
	}
	to_free = path;

	len = strlen(path);

	if ((len > 0) && (path[len-1] == '\\')) {
		path[len-1] = '\0';
	}

	while ((p = strchr(path, '\\')) != NULL) {
		char *name_component;
		struct registry_key *tmp;

		if (!(name_component = SMB_STRNDUP(path, (p - path)))) {
			err = WERR_NOMEM;
			goto error;
		}

		err = regkey_open_onelevel(mem_ctx, direct_parent,
					   name_component, parent->token,
					   SEC_RIGHTS_ENUM_SUBKEYS, &tmp);
		SAFE_FREE(name_component);

		if (!W_ERROR_IS_OK(err)) {
			goto error;
		}
		if (direct_parent != parent) {
			TALLOC_FREE(direct_parent);
		}

		direct_parent = tmp;
		path = p+1;
	}

	err = regkey_open_onelevel(mem_ctx, direct_parent, path, parent->token,
				   desired_access, pkey);
 error:
	if (direct_parent != parent) {
		TALLOC_FREE(direct_parent);
	}
	SAFE_FREE(to_free);
	return err;
}

WERROR reg_enumkey(TALLOC_CTX *mem_ctx, struct registry_key *key,
		   uint32 idx, char **name, NTTIME *last_write_time)
{
	WERROR err;

	if (!(key->key->access_granted & SEC_RIGHTS_ENUM_SUBKEYS)) {
		return WERR_ACCESS_DENIED;
	}

	if (!W_ERROR_IS_OK(err = fill_subkey_cache(key))) {
		return err;
	}

	if (idx >= key->subkeys->num_subkeys) {
		return WERR_NO_MORE_ITEMS;
	}

	if (!(*name = talloc_strdup(mem_ctx, key->subkeys->subkeys[idx]))) {
		return WERR_NOMEM;
	}

	if (last_write_time) {
		*last_write_time = 0;
	}

	return WERR_OK;
}

WERROR reg_enumvalue(TALLOC_CTX *mem_ctx, struct registry_key *key,
		     uint32 idx, char **pname, struct registry_value **pval)
{
	struct registry_value *val;
	WERROR err;

	if (!(key->key->access_granted & SEC_RIGHTS_QUERY_VALUE)) {
		return WERR_ACCESS_DENIED;
	}

	if (!(W_ERROR_IS_OK(err = fill_value_cache(key)))) {
		return err;
	}

	if (idx >= key->values->num_values) {
		return WERR_NO_MORE_ITEMS;
	}

	err = registry_pull_value(mem_ctx, &val,
				  key->values->values[idx]->type,
				  key->values->values[idx]->data_p,
				  key->values->values[idx]->size,
				  key->values->values[idx]->size);
	if (!W_ERROR_IS_OK(err)) {
		return err;
	}

	if (pname
	    && !(*pname = talloc_strdup(
			 mem_ctx, key->values->values[idx]->valuename))) {
		SAFE_FREE(val);
		return WERR_NOMEM;
	}
		
	*pval = val;
	return WERR_OK;
}

WERROR reg_queryvalue(TALLOC_CTX *mem_ctx, struct registry_key *key,
		      const char *name, struct registry_value **pval)
{
	WERROR err;
	uint32 i;

	if (!(key->key->access_granted & SEC_RIGHTS_QUERY_VALUE)) {
		return WERR_ACCESS_DENIED;
	}

	if (!(W_ERROR_IS_OK(err = fill_value_cache(key)))) {
		return err;
	}

	for (i=0; i<key->values->num_values; i++) {
		if (strequal(key->values->values[i]->valuename, name)) {
			return reg_enumvalue(mem_ctx, key, i, NULL, pval);
		}
	}

	return WERR_BADFILE;
}

WERROR reg_queryinfokey(struct registry_key *key, uint32_t *num_subkeys,
			uint32_t *max_subkeylen, uint32_t *max_subkeysize, 
			uint32_t *num_values, uint32_t *max_valnamelen, 
			uint32_t *max_valbufsize, uint32_t *secdescsize,
			NTTIME *last_changed_time)
{
	uint32 i, max_size;
	size_t max_len;
	TALLOC_CTX *mem_ctx;
	WERROR err;
	struct security_descriptor *secdesc;

	if (!(key->key->access_granted & SEC_RIGHTS_QUERY_VALUE)) {
		return WERR_ACCESS_DENIED;
	}

	if (!W_ERROR_IS_OK(fill_subkey_cache(key)) ||
	    !W_ERROR_IS_OK(fill_value_cache(key))) {
		return WERR_BADFILE;
	}

	max_len = 0;
	for (i=0; i<key->subkeys->num_subkeys; i++) {
		max_len = MAX(max_len, strlen(key->subkeys->subkeys[i]));
	}

	*num_subkeys = key->subkeys->num_subkeys;
	*max_subkeylen = max_len;
	*max_subkeysize = 0;	/* Class length? */

	max_len = 0;
	max_size = 0;
	for (i=0; i<key->values->num_values; i++) {
		max_len = MAX(max_len,
			      strlen(key->values->values[i]->valuename));
		max_size = MAX(max_size, key->values->values[i]->size);
	}

	*num_values = key->values->num_values;
	*max_valnamelen = max_len;
	*max_valbufsize = max_size;

	if (!(mem_ctx = talloc_new(key))) {
		return WERR_NOMEM;
	}

	err = regkey_get_secdesc(mem_ctx, key->key, &secdesc);
	if (!W_ERROR_IS_OK(err)) {
		TALLOC_FREE(mem_ctx);
		return err;
	}

	*secdescsize = sec_desc_size(secdesc);
	TALLOC_FREE(mem_ctx);

	*last_changed_time = 0;

	return WERR_OK;
}

WERROR reg_createkey(TALLOC_CTX *ctx, struct registry_key *parent,
		     const char *subkeypath, uint32 desired_access,
		     struct registry_key **pkey,
		     enum winreg_CreateAction *paction)
{
	struct registry_key *key = parent;
	struct registry_key *create_parent;
	TALLOC_CTX *mem_ctx;
	char *path, *end;
	WERROR err;
	REGSUBKEY_CTR *subkeys;

	if (!(mem_ctx = talloc_new(ctx))) return WERR_NOMEM;

	if (!(path = talloc_strdup(mem_ctx, subkeypath))) {
		err = WERR_NOMEM;
		goto done;
	}

	while ((end = strchr(path, '\\')) != NULL) {
		struct registry_key *tmp;
		enum winreg_CreateAction action;

		*end = '\0';

		err = reg_createkey(mem_ctx, key, path,
				    SEC_RIGHTS_ENUM_SUBKEYS, &tmp, &action);
		if (!W_ERROR_IS_OK(err)) {
			goto done;
		}

		if (key != parent) {
			TALLOC_FREE(key);
		}

		key = tmp;
		path = end+1;
	}

	/*
	 * At this point, "path" contains the one-element subkey of "key". We
	 * can try to open it.
	 */

	err = reg_openkey(ctx, key, path, desired_access, pkey);
	if (W_ERROR_IS_OK(err)) {
		if (paction != NULL) {
			*paction = REG_OPENED_EXISTING_KEY;
		}
		goto done;
	}

	if (!W_ERROR_EQUAL(err, WERR_BADFILE)) {
		/*
		 * Something but "notfound" has happened, so bail out
		 */
		goto done;
	}

	/*
	 * We have to make a copy of the current key, as we opened it only
	 * with ENUM_SUBKEY access.
	 */

	err = reg_openkey(mem_ctx, key, "", SEC_RIGHTS_CREATE_SUBKEY,
			  &create_parent);
	if (!W_ERROR_IS_OK(err)) {
		goto done;
	}

	/*
	 * Actually create the subkey
	 */

	if (!(subkeys = TALLOC_ZERO_P(mem_ctx, REGSUBKEY_CTR))) {
		err = WERR_NOMEM;
		goto done;
	}

	err = fill_subkey_cache(create_parent);
	if (!W_ERROR_IS_OK(err)) goto done;

	err = regsubkey_ctr_addkey(create_parent->subkeys, path);
	if (!W_ERROR_IS_OK(err)) goto done;

	if (!store_reg_keys(create_parent->key, create_parent->subkeys)) {
		TALLOC_FREE(create_parent->subkeys);
		err = WERR_REG_IO_FAILURE;
		goto done;
	}

	/*
	 * Now open the newly created key
	 */

	err = reg_openkey(ctx, create_parent, path, desired_access, pkey);
	if (W_ERROR_IS_OK(err) && (paction != NULL)) {
		*paction = REG_CREATED_NEW_KEY;
	}

 done:
	TALLOC_FREE(mem_ctx);
	return err;
}
		     

WERROR reg_deletekey(struct registry_key *parent, const char *path)
{
	WERROR err;
	TALLOC_CTX *mem_ctx;
	char *name, *end;
	int num_subkeys;
	struct registry_key *tmp_key;

	if (!(mem_ctx = talloc_init("reg_createkey"))) return WERR_NOMEM;

	if (!(name = talloc_strdup(mem_ctx, path))) {
		err = WERR_NOMEM;
		goto error;
	}

	/* check if the key has subkeys */
	err = reg_openkey(mem_ctx, parent, name, REG_KEY_READ, &tmp_key);
	if (!W_ERROR_IS_OK(err)) {
		goto error;
	}
	if (!W_ERROR_IS_OK(err = fill_subkey_cache(tmp_key))) {
		goto error;
	}
	if (tmp_key->subkeys->num_subkeys > 0) {
		err = WERR_ACCESS_DENIED;
		goto error;
	}

	/* no subkeys - proceed with delete */
	if ((end = strrchr(name, '\\')) != NULL) {
		*end = '\0';

		err = reg_openkey(mem_ctx, parent, name,
				  SEC_RIGHTS_CREATE_SUBKEY, &tmp_key);
		if (!W_ERROR_IS_OK(err)) {
			goto error;
		}

		parent = tmp_key;
		name = end+1;
	}

	if (name[0] == '\0') {
		err = WERR_INVALID_PARAM;
		goto error;
	}

	if (!W_ERROR_IS_OK(err = fill_subkey_cache(parent))) {
		goto error;
	}

	num_subkeys = parent->subkeys->num_subkeys;

	if (regsubkey_ctr_delkey(parent->subkeys, name) == num_subkeys) {
		err = WERR_BADFILE;
		goto error;
	}

	if (!store_reg_keys(parent->key, parent->subkeys)) {
		TALLOC_FREE(parent->subkeys);
		err = WERR_REG_IO_FAILURE;
		goto error;
	}

	err = WERR_OK;
 error:
	TALLOC_FREE(mem_ctx);
	return err;
}

WERROR reg_setvalue(struct registry_key *key, const char *name,
		    const struct registry_value *val)
{
	WERROR err;
	DATA_BLOB value_data;
	int res;

	if (!(key->key->access_granted & SEC_RIGHTS_SET_VALUE)) {
		return WERR_ACCESS_DENIED;
	}

	if (!W_ERROR_IS_OK(err = fill_value_cache(key))) {
		return err;
	}

	err = registry_push_value(key, val, &value_data);
	if (!W_ERROR_IS_OK(err)) {
		return err;
	}

	res = regval_ctr_addvalue(key->values, name, val->type,
				  (char *)value_data.data, value_data.length);
	TALLOC_FREE(value_data.data);

	if (res == 0) {
		TALLOC_FREE(key->values);
		return WERR_NOMEM;
	}

	if (!store_reg_values(key->key, key->values)) {
		TALLOC_FREE(key->values);
		return WERR_REG_IO_FAILURE;
	}

	return WERR_OK;
}

WERROR reg_deletevalue(struct registry_key *key, const char *name)
{
	WERROR err;

	if (!(key->key->access_granted & SEC_RIGHTS_SET_VALUE)) {
		return WERR_ACCESS_DENIED;
	}

	if (!W_ERROR_IS_OK(err = fill_value_cache(key))) {
		return err;
	}

	regval_ctr_delvalue(key->values, name);

	if (!store_reg_values(key->key, key->values)) {
		TALLOC_FREE(key->values);
		return WERR_REG_IO_FAILURE;
	}

	return WERR_OK;
}

WERROR reg_deleteallvalues(struct registry_key *key)
{
	WERROR err;
	int i;

	if (!(key->key->access_granted & SEC_RIGHTS_SET_VALUE)) {
		return WERR_ACCESS_DENIED;
	}

	if (!W_ERROR_IS_OK(err = fill_value_cache(key))) {
		return err;
	}

	for (i=0; i<key->values->num_values; i++) {
		regval_ctr_delvalue(key->values, key->values->values[i]->valuename);
	}

	if (!store_reg_values(key->key, key->values)) {
		TALLOC_FREE(key->values);
		return WERR_REG_IO_FAILURE;
	}

	return WERR_OK;
}

/*
 * Utility function to open a complete registry path including the hive
 * prefix. This should become the replacement function for
 * regkey_open_internal.
 */

WERROR reg_open_path(TALLOC_CTX *mem_ctx, const char *orig_path,
		     uint32 desired_access, const struct nt_user_token *token,
		     struct registry_key **pkey)
{
	struct registry_key *hive, *key;
	char *path, *p;
	WERROR err;

	if (!(path = SMB_STRDUP(orig_path))) {
		return WERR_NOMEM;
	}

	p = strchr(path, '\\');

	if ((p == NULL) || (p[1] == '\0')) {
		/*
		 * No key behind the hive, just return the hive
		 */

		err = reg_openhive(mem_ctx, path, desired_access, token,
				   &hive);
		if (!W_ERROR_IS_OK(err)) {
			SAFE_FREE(path);
			return err;
		}
		SAFE_FREE(path);
		*pkey = hive;
		return WERR_OK;
	}

	*p = '\0';

	err = reg_openhive(mem_ctx, path, SEC_RIGHTS_ENUM_SUBKEYS, token,
			   &hive);
	if (!W_ERROR_IS_OK(err)) {
		SAFE_FREE(path);
		return err;
	}

	err = reg_openkey(mem_ctx, hive, p+1, desired_access, &key);

	TALLOC_FREE(hive);
	SAFE_FREE(path);

	if (!W_ERROR_IS_OK(err)) {
		return err;
	}

	*pkey = key;
	return WERR_OK;
}


/*
 * Utility function to delete a registry key with all its subkeys. 
 * Note that reg_deletekey returns ACCESS_DENIED when called on a 
 * key that has subkeys.
 */
WERROR reg_deletekey_recursive(TALLOC_CTX *ctx,
			       struct registry_key *parent, 
			       const char *path)
{
	TALLOC_CTX *mem_ctx = NULL;
	WERROR werr = WERR_OK;
	struct registry_key *key;
	char *subkey_name = NULL;

	mem_ctx = talloc_new(ctx);
	if (mem_ctx == NULL) {
		werr = WERR_NOMEM;
		goto done;
	}

	/* recurse through subkeys first */
	werr = reg_openkey(mem_ctx, parent, path, REG_KEY_WRITE, &key);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	while (W_ERROR_IS_OK(werr = reg_enumkey(mem_ctx, key, 0,
						&subkey_name, NULL))) 
	{
		werr = reg_deletekey_recursive(mem_ctx, key, subkey_name);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}
	}
	if (!W_ERROR_EQUAL(WERR_NO_MORE_ITEMS, werr)) {
		DEBUG(1, ("reg_deletekey_recursive: Error enumerating "
			  "subkeys: %s\n", dos_errstr(werr)));
		goto done;
	}

	/* now delete the actual key */
	werr = reg_deletekey(parent, path);
	
done:
	TALLOC_FREE(mem_ctx);
	return werr;
}
