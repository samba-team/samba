/*
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Volker Lendecke 2006
 *  Copyright (C) Michael Adam 2007-2010
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

/*
 * Here is a list of winreg.idl functions and corresponding implementations
 * provided here:
 *
 * 0x00		winreg_OpenHKCR
 * 0x01		winreg_OpenHKCU
 * 0x02		winreg_OpenHKLM
 * 0x03		winreg_OpenHKPD
 * 0x04		winreg_OpenHKU
 * 0x05		winreg_CloseKey
 * 0x06		winreg_CreateKey			reg_createkey
 * 0x07		winreg_DeleteKey			reg_deletekey
 * 0x08		winreg_DeleteValue			reg_deletevalue
 * 0x09		winreg_EnumKey				reg_enumkey
 * 0x0a		winreg_EnumValue			reg_enumvalue
 * 0x0b		winreg_FlushKey
 * 0x0c		winreg_GetKeySecurity			reg_getkeysecurity
 * 0x0d		winreg_LoadKey
 * 0x0e		winreg_NotifyChangeKeyValue
 * 0x0f		winreg_OpenKey				reg_openkey
 * 0x10		winreg_QueryInfoKey			reg_queryinfokey
 * 0x11		winreg_QueryValue			reg_queryvalue
 * 0x12		winreg_ReplaceKey
 * 0x13		winreg_RestoreKey			reg_restorekey
 * 0x14		winreg_SaveKey				reg_savekey
 * 0x15		winreg_SetKeySecurity			reg_setkeysecurity
 * 0x16		winreg_SetValue				reg_setvalue
 * 0x17		winreg_UnLoadKey
 * 0x18		winreg_InitiateSystemShutdown
 * 0x19		winreg_AbortSystemShutdown
 * 0x1a		winreg_GetVersion			reg_getversion
 * 0x1b		winreg_OpenHKCC
 * 0x1c		winreg_OpenHKDD
 * 0x1d		winreg_QueryMultipleValues		reg_querymultiplevalues
 * 0x1e		winreg_InitiateSystemShutdownEx
 * 0x1f		winreg_SaveKeyEx
 * 0x20		winreg_OpenHKPT
 * 0x21		winreg_OpenHKPN
 * 0x22		winreg_QueryMultipleValues2		reg_querymultiplevalues
 *
 */

#include "includes.h"
#include "registry.h"
#include "reg_api.h"
#include "reg_cachehook.h"
#include "reg_backend_db.h"
#include "reg_dispatcher.h"
#include "reg_objects.h"
#include "../librpc/gen_ndr/ndr_security.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY


/**********************************************************************
 * Helper functions
 **********************************************************************/

static WERROR fill_value_cache(struct registry_key *key)
{
	WERROR werr;

	if (key->values != NULL) {
		if (!reg_values_need_update(key->key, key->values)) {
			return WERR_OK;
		}
	}

	werr = regval_ctr_init(key, &(key->values));
	W_ERROR_NOT_OK_RETURN(werr);

	if (fetch_reg_values(key->key, key->values) == -1) {
		TALLOC_FREE(key->values);
		return WERR_BADFILE;
	}

	return WERR_OK;
}

static WERROR fill_subkey_cache(struct registry_key *key)
{
	WERROR werr;

	if (key->subkeys != NULL) {
		if (!reg_subkeys_need_update(key->key, key->subkeys)) {
			return WERR_OK;
		}
	}

	werr = regsubkey_ctr_init(key, &(key->subkeys));
	W_ERROR_NOT_OK_RETURN(werr);

	if (fetch_reg_keys(key->key, key->subkeys) == -1) {
		TALLOC_FREE(key->subkeys);
		return WERR_NO_MORE_ITEMS;
	}

	return WERR_OK;
}

static int regkey_destructor(struct registry_key_handle *key)
{
	return regdb_close();
}

static WERROR regkey_open_onelevel(TALLOC_CTX *mem_ctx, 
				   struct registry_key *parent,
				   const char *name,
				   const struct security_token *token,
				   uint32 access_desired,
				   struct registry_key **pregkey)
{
	WERROR     	result = WERR_OK;
	struct registry_key *regkey;
	struct registry_key_handle *key;
	struct regsubkey_ctr	*subkeys = NULL;

	DEBUG(7,("regkey_open_onelevel: name = [%s]\n", name));

	SMB_ASSERT(strchr(name, '\\') == NULL);

	if (!(regkey = TALLOC_ZERO_P(mem_ctx, struct registry_key)) ||
	    !(regkey->token = dup_nt_token(regkey, token)) ||
	    !(regkey->key = TALLOC_ZERO_P(regkey, struct registry_key_handle)))
	{
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

	if ( !(key->ops = reghook_cache_find( key->name )) ) {
		DEBUG(0,("reg_open_onelevel: Failed to assign "
			 "registry_ops to [%s]\n", key->name ));
		result = WERR_BADFILE;
		goto done;
	}

	/* check if the path really exists; failed is indicated by -1 */
	/* if the subkey count failed, bail out */

	result = regsubkey_ctr_init(key, &subkeys);
	if (!W_ERROR_IS_OK(result)) {
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
		    const struct security_token *token,
		    struct registry_key **pkey)
{
	SMB_ASSERT(hive != NULL);
	SMB_ASSERT(hive[0] != '\0');
	SMB_ASSERT(strchr(hive, '\\') == NULL);

	return regkey_open_onelevel(mem_ctx, NULL, hive, token, desired_access,
				    pkey);
}


/**********************************************************************
 * The API functions
 **********************************************************************/

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
					   KEY_ENUMERATE_SUB_KEYS, &tmp);
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

	if (!(key->key->access_granted & KEY_ENUMERATE_SUB_KEYS)) {
		return WERR_ACCESS_DENIED;
	}

	if (!W_ERROR_IS_OK(err = fill_subkey_cache(key))) {
		return err;
	}

	if (idx >= regsubkey_ctr_numkeys(key->subkeys)) {
		return WERR_NO_MORE_ITEMS;
	}

	if (!(*name = talloc_strdup(mem_ctx,
			regsubkey_ctr_specific_key(key->subkeys, idx))))
	{
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
	struct regval_blob *blob;
	WERROR err;

	if (!(key->key->access_granted & KEY_QUERY_VALUE)) {
		return WERR_ACCESS_DENIED;
	}

	if (!(W_ERROR_IS_OK(err = fill_value_cache(key)))) {
		return err;
	}

	if (idx >= regval_ctr_numvals(key->values)) {
		return WERR_NO_MORE_ITEMS;
	}

	blob = regval_ctr_specific_value(key->values, idx);

	val = talloc_zero(mem_ctx, struct registry_value);
	if (val == NULL) {
		return WERR_NOMEM;
	}

	val->type = regval_type(blob);
	val->data = data_blob_talloc(mem_ctx, regval_data_p(blob), regval_size(blob));

	if (pname
	    && !(*pname = talloc_strdup(
			 mem_ctx, regval_name(blob)))) {
		TALLOC_FREE(val);
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

	if (!(key->key->access_granted & KEY_QUERY_VALUE)) {
		return WERR_ACCESS_DENIED;
	}

	if (!(W_ERROR_IS_OK(err = fill_value_cache(key)))) {
		return err;
	}

	for (i=0; i < regval_ctr_numvals(key->values); i++) {
		struct regval_blob *blob;
		blob = regval_ctr_specific_value(key->values, i);
		if (strequal(regval_name(blob), name)) {
			return reg_enumvalue(mem_ctx, key, i, NULL, pval);
		}
	}

	return WERR_BADFILE;
}

WERROR reg_querymultiplevalues(TALLOC_CTX *mem_ctx,
			       struct registry_key *key,
			       uint32_t num_names,
			       const char **names,
			       uint32_t *pnum_vals,
			       struct registry_value **pvals)
{
	WERROR err;
	uint32_t i, n, found = 0;
	struct registry_value *vals;

	if (num_names == 0) {
		return WERR_OK;
	}

	if (!(key->key->access_granted & KEY_QUERY_VALUE)) {
		return WERR_ACCESS_DENIED;
	}

	if (!(W_ERROR_IS_OK(err = fill_value_cache(key)))) {
		return err;
	}

	vals = talloc_zero_array(mem_ctx, struct registry_value, num_names);
	if (vals == NULL) {
		return WERR_NOMEM;
	}

	for (n=0; n < num_names; n++) {
		for (i=0; i < regval_ctr_numvals(key->values); i++) {
			struct regval_blob *blob;
			blob = regval_ctr_specific_value(key->values, i);
			if (strequal(regval_name(blob), names[n])) {
				struct registry_value *v;
				err = reg_enumvalue(mem_ctx, key, i, NULL, &v);
				if (!W_ERROR_IS_OK(err)) {
					return err;
				}
				vals[n] = *v;
				found++;
			}
		}
	}

	*pvals = vals;
	*pnum_vals = found;

	return WERR_OK;
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

	if (!(key->key->access_granted & KEY_QUERY_VALUE)) {
		return WERR_ACCESS_DENIED;
	}

	if (!W_ERROR_IS_OK(fill_subkey_cache(key)) ||
	    !W_ERROR_IS_OK(fill_value_cache(key))) {
		return WERR_BADFILE;
	}

	max_len = 0;
	for (i=0; i< regsubkey_ctr_numkeys(key->subkeys); i++) {
		max_len = MAX(max_len,
			strlen(regsubkey_ctr_specific_key(key->subkeys, i)));
	}

	*num_subkeys = regsubkey_ctr_numkeys(key->subkeys);
	*max_subkeylen = max_len;
	*max_subkeysize = 0;	/* Class length? */

	max_len = 0;
	max_size = 0;
	for (i=0; i < regval_ctr_numvals(key->values); i++) {
		struct regval_blob *blob;
		blob = regval_ctr_specific_value(key->values, i);
		max_len = MAX(max_len, strlen(regval_name(blob)));
		max_size = MAX(max_size, regval_size(blob));
	}

	*num_values = regval_ctr_numvals(key->values);
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

	*secdescsize = ndr_size_security_descriptor(secdesc, 0);
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
				    KEY_ENUMERATE_SUB_KEYS, &tmp, &action);
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

	err = reg_openkey(mem_ctx, key, "", KEY_CREATE_SUB_KEY,
			  &create_parent);
	if (!W_ERROR_IS_OK(err)) {
		goto done;
	}

	/*
	 * Actually create the subkey
	 */

	err = fill_subkey_cache(create_parent);
	if (!W_ERROR_IS_OK(err)) goto done;

	err = create_reg_subkey(key->key, path);
	W_ERROR_NOT_OK_GOTO_DONE(err);

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
	char *name, *end;
	struct registry_key *tmp_key, *key;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	name = talloc_strdup(mem_ctx, path);
	if (name == NULL) {
		err = WERR_NOMEM;
		goto done;
	}

	/* check if the key has subkeys */
	err = reg_openkey(mem_ctx, parent, name, REG_KEY_READ, &key);
	W_ERROR_NOT_OK_GOTO_DONE(err);

	err = fill_subkey_cache(key);
	W_ERROR_NOT_OK_GOTO_DONE(err);

	if (regsubkey_ctr_numkeys(key->subkeys) > 0) {
		err = WERR_ACCESS_DENIED;
		goto done;
	}

	/* no subkeys - proceed with delete */
	end = strrchr(name, '\\');
	if (end != NULL) {
		*end = '\0';

		err = reg_openkey(mem_ctx, parent, name,
				  KEY_CREATE_SUB_KEY, &tmp_key);
		W_ERROR_NOT_OK_GOTO_DONE(err);

		parent = tmp_key;
		name = end+1;
	}

	if (name[0] == '\0') {
		err = WERR_INVALID_PARAM;
		goto done;
	}

	err = delete_reg_subkey(parent->key, name);

done:
	TALLOC_FREE(mem_ctx);
	return err;
}

WERROR reg_setvalue(struct registry_key *key, const char *name,
		    const struct registry_value *val)
{
	struct regval_blob *existing;
	WERROR err;
	int res;

	if (!(key->key->access_granted & KEY_SET_VALUE)) {
		return WERR_ACCESS_DENIED;
	}

	if (!W_ERROR_IS_OK(err = fill_value_cache(key))) {
		return err;
	}

	existing = regval_ctr_getvalue(key->values, name);

	if ((existing != NULL) &&
	    (regval_size(existing) == val->data.length) &&
	    (memcmp(regval_data_p(existing), val->data.data,
		    val->data.length) == 0)) {
		return WERR_OK;
	}

	res = regval_ctr_addvalue(key->values, name, val->type,
				  val->data.data, val->data.length);

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

static WERROR reg_value_exists(struct registry_key *key, const char *name)
{
	struct regval_blob *blob;

	blob = regval_ctr_getvalue(key->values, name);

	if (blob == NULL) {
		return WERR_BADFILE;
	} else {
		return WERR_OK;
	}
}

WERROR reg_deletevalue(struct registry_key *key, const char *name)
{
	WERROR err;

	if (!(key->key->access_granted & KEY_SET_VALUE)) {
		return WERR_ACCESS_DENIED;
	}

	if (!W_ERROR_IS_OK(err = fill_value_cache(key))) {
		return err;
	}

	err = reg_value_exists(key, name);
	if (!W_ERROR_IS_OK(err)) {
		return err;
	}

	regval_ctr_delvalue(key->values, name);

	if (!store_reg_values(key->key, key->values)) {
		TALLOC_FREE(key->values);
		return WERR_REG_IO_FAILURE;
	}

	return WERR_OK;
}

WERROR reg_getkeysecurity(TALLOC_CTX *mem_ctx, struct registry_key *key,
			  struct security_descriptor **psecdesc)
{
	return regkey_get_secdesc(mem_ctx, key->key, psecdesc);
}

WERROR reg_setkeysecurity(struct registry_key *key,
			  struct security_descriptor *psecdesc)
{
	return regkey_set_secdesc(key->key, psecdesc);
}

WERROR reg_getversion(uint32_t *version)
{
	if (version == NULL) {
		return WERR_INVALID_PARAM;
	}

	*version = 0x00000005; /* Windows 2000 registry API version */
	return WERR_OK;
}

/**********************************************************************
 * Higher level utility functions
 **********************************************************************/

WERROR reg_deleteallvalues(struct registry_key *key)
{
	WERROR err;
	int i;

	if (!(key->key->access_granted & KEY_SET_VALUE)) {
		return WERR_ACCESS_DENIED;
	}

	if (!W_ERROR_IS_OK(err = fill_value_cache(key))) {
		return err;
	}

	for (i=0; i < regval_ctr_numvals(key->values); i++) {
		struct regval_blob *blob;
		blob = regval_ctr_specific_value(key->values, i);
		regval_ctr_delvalue(key->values, regval_name(blob));
	}

	if (!store_reg_values(key->key, key->values)) {
		TALLOC_FREE(key->values);
		return WERR_REG_IO_FAILURE;
	}

	return WERR_OK;
}

/*
 * Utility function to delete a registry key with all its subkeys.
 * Note that reg_deletekey returns ACCESS_DENIED when called on a
 * key that has subkeys.
 */
static WERROR reg_deletekey_recursive_internal(struct registry_key *parent,
					       const char *path,
					       bool del_key)
{
	WERROR werr = WERR_OK;
	struct registry_key *key;
	char *subkey_name = NULL;
	uint32 i;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	/* recurse through subkeys first */
	werr = reg_openkey(mem_ctx, parent, path, REG_KEY_ALL, &key);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = fill_subkey_cache(key);
	W_ERROR_NOT_OK_GOTO_DONE(werr);

	/*
	 * loop from top to bottom for perfomance:
	 * this way, we need to rehash the regsubkey containers less
	 */
	for (i = regsubkey_ctr_numkeys(key->subkeys) ; i > 0; i--) {
		subkey_name = regsubkey_ctr_specific_key(key->subkeys, i-1);
		werr = reg_deletekey_recursive_internal(key, subkey_name, true);
		W_ERROR_NOT_OK_GOTO_DONE(werr);
	}

	if (del_key) {
		/* now delete the actual key */
		werr = reg_deletekey(parent, path);
	}

done:
	TALLOC_FREE(mem_ctx);
	return werr;
}

static WERROR reg_deletekey_recursive_trans(struct registry_key *parent,
					    const char *path,
					    bool del_key)
{
	WERROR werr;

	werr = regdb_transaction_start();
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0, ("reg_deletekey_recursive_trans: "
			  "error starting transaction: %s\n",
			  win_errstr(werr)));
		return werr;
	}

	werr = reg_deletekey_recursive_internal(parent, path, del_key);

	if (!W_ERROR_IS_OK(werr)) {
		WERROR werr2;

		DEBUG(1, (__location__ " failed to delete key '%s' from key "
			  "'%s': %s\n", path, parent->key->name,
			  win_errstr(werr)));

		werr2 = regdb_transaction_cancel();
		if (!W_ERROR_IS_OK(werr2)) {
			DEBUG(0, ("reg_deletekey_recursive_trans: "
				  "error cancelling transaction: %s\n",
				  win_errstr(werr2)));
			/*
			 * return the original werr or the
			 * error from cancelling the transaction?
			 */
		}
	} else {
		werr = regdb_transaction_commit();
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0, ("reg_deletekey_recursive_trans: "
				  "error committing transaction: %s\n",
				  win_errstr(werr)));
		}
	}

	return werr;
}

WERROR reg_deletekey_recursive(struct registry_key *parent,
			       const char *path)
{
	return reg_deletekey_recursive_trans(parent, path, true);
}

WERROR reg_deletesubkeys_recursive(struct registry_key *parent,
				   const char *path)
{
	return reg_deletekey_recursive_trans(parent, path, false);
}

