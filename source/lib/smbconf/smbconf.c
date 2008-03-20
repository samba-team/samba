/*
 *  Unix SMB/CIFS implementation.
 *  libnet smbconf registry Support
 *  Copyright (C) Michael Adam 2007-2008
 *  Copyright (C) Guenther Deschner 2007
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

#include "includes.h"
#include "smbconf_private.h"

/**********************************************************************
 *
 * Helper functions (mostly registry related)
 *
 **********************************************************************/

/**
 * add a string to a talloced array of strings.
 */
static WERROR smbconf_add_string_to_array(TALLOC_CTX *mem_ctx,
					  char ***array,
					  uint32_t count,
					  const char *string)
{
	char **new_array = NULL;

	if ((array == NULL) || (string == NULL)) {
		return WERR_INVALID_PARAM;
	}

	new_array = TALLOC_REALLOC_ARRAY(mem_ctx, *array, char *, count + 1);
	if (new_array == NULL) {
		return WERR_NOMEM;
	}

	new_array[count] = talloc_strdup(new_array, string);
	if (new_array[count] == NULL) {
		TALLOC_FREE(new_array);
		return WERR_NOMEM;
	}

	*array = new_array;

	return WERR_OK;
}

/**
 * Open a registry key specified by "path"
 */
static WERROR smbconf_reg_open_path(TALLOC_CTX *mem_ctx,
				    struct smbconf_ctx *ctx,
				    const char *path,
				    uint32 desired_access,
				    struct registry_key **key)
{
	WERROR werr = WERR_OK;

	if (ctx == NULL) {
		DEBUG(1, ("Error: configuration is not open!\n"));
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	if (ctx->token == NULL) {
		DEBUG(1, ("Error: token missing from smbconf_ctx. "
			  "was smbconf_init() called?\n"));
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	if (path == NULL) {
		DEBUG(1, ("Error: NULL path string given\n"));
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	werr = reg_open_path(mem_ctx, path, desired_access, ctx->token, key);

	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(1, ("Error opening registry path '%s': %s\n",
			  path, dos_errstr(werr)));
	}

done:
	return werr;
}

/**
 * Open a subkey of KEY_SMBCONF (i.e a service)
 */
static WERROR smbconf_reg_open_service_key(TALLOC_CTX *mem_ctx,
					   struct smbconf_ctx *ctx,
					   const char *servicename,
					   uint32 desired_access,
					   struct registry_key **key)
{
	WERROR werr = WERR_OK;
	char *path = NULL;

	if (servicename == NULL) {
		DEBUG(3, ("Error: NULL servicename given.\n"));
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	path = talloc_asprintf(mem_ctx, "%s\\%s", KEY_SMBCONF, servicename);
	if (path == NULL) {
		werr = WERR_NOMEM;
		goto done;
	}

	werr = smbconf_reg_open_path(mem_ctx, ctx, path, desired_access, key);

done:
	TALLOC_FREE(path);
	return werr;
}

/**
 * open the base key KEY_SMBCONF
 */
static WERROR smbconf_reg_open_base_key(TALLOC_CTX *mem_ctx,
					struct smbconf_ctx *ctx,
					uint32 desired_access,
					struct registry_key **key)
{
	return smbconf_reg_open_path(mem_ctx, ctx, KEY_SMBCONF, desired_access,
				     key);
}

/**
 * check if a value exists in a given registry key
 */
static bool smbconf_value_exists(struct registry_key *key, const char *param)
{
	bool ret = false;
	WERROR werr = WERR_OK;
	TALLOC_CTX *ctx = talloc_stackframe();
	struct registry_value *value = NULL;

	werr = reg_queryvalue(ctx, key, param, &value);
	if (W_ERROR_IS_OK(werr)) {
		ret = true;
	}

	TALLOC_FREE(ctx);
	return ret;
}

/**
 * create a subkey of KEY_SMBCONF
 */
static WERROR smbconf_reg_create_service_key(TALLOC_CTX *mem_ctx,
					     struct smbconf_ctx *ctx,
					     const char * subkeyname,
					     struct registry_key **newkey)
{
	WERROR werr = WERR_OK;
	struct registry_key *create_parent = NULL;
	TALLOC_CTX *create_ctx;
	enum winreg_CreateAction action = REG_ACTION_NONE;

	/* create a new talloc ctx for creation. it will hold
	 * the intermediate parent key (SMBCONF) for creation
	 * and will be destroyed when leaving this function... */
	if (!(create_ctx = talloc_stackframe())) {
		werr = WERR_NOMEM;
		goto done;
	}

	werr = smbconf_reg_open_base_key(create_ctx, ctx, REG_KEY_WRITE,
					 &create_parent);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = reg_createkey(mem_ctx, create_parent, subkeyname,
			     REG_KEY_WRITE, newkey, &action);
	if (W_ERROR_IS_OK(werr) && (action != REG_CREATED_NEW_KEY)) {
		DEBUG(10, ("Key '%s' already exists.\n", subkeyname));
		werr = WERR_ALREADY_EXISTS;
	}
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(5, ("Error creating key %s: %s\n",
			 subkeyname, dos_errstr(werr)));
	}

done:
	TALLOC_FREE(create_ctx);
	return werr;
}

/**
 * add a value to a key.
 */
static WERROR smbconf_reg_set_value(struct registry_key *key,
				    const char *valname,
				    const char *valstr)
{
	struct registry_value val;
	WERROR werr = WERR_OK;
	char *subkeyname;
	const char *canon_valname;
	const char *canon_valstr;

	if (!lp_canonicalize_parameter_with_value(valname, valstr,
						  &canon_valname,
						  &canon_valstr))
	{
		if (canon_valname == NULL) {
			DEBUG(5, ("invalid parameter '%s' given\n",
				  valname));
		} else {
			DEBUG(5, ("invalid value '%s' given for "
				  "parameter '%s'\n", valstr, valname));
		}
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	ZERO_STRUCT(val);

	val.type = REG_SZ;
	val.v.sz.str = CONST_DISCARD(char *, canon_valstr);
	val.v.sz.len = strlen(canon_valstr) + 1;

	if (registry_smbconf_valname_forbidden(canon_valname)) {
		DEBUG(5, ("Parameter '%s' not allowed in registry.\n",
			  canon_valname));
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	subkeyname = strrchr_m(key->key->name, '\\');
	if ((subkeyname == NULL) || (*(subkeyname +1) == '\0')) {
		DEBUG(5, ("Invalid registry key '%s' given as "
			  "smbconf section.\n", key->key->name));
		werr = WERR_INVALID_PARAM;
		goto done;
	}
	subkeyname++;
	if (!strequal(subkeyname, GLOBAL_NAME) &&
	    lp_parameter_is_global(valname))
	{
		DEBUG(5, ("Global paramter '%s' not allowed in "
			  "service definition ('%s').\n", canon_valname,
			  subkeyname));
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	werr = reg_setvalue(key, canon_valname, &val);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(5, ("Error adding value '%s' to "
			  "key '%s': %s\n",
			  canon_valname, key->key->name, dos_errstr(werr)));
	}

done:
	return werr;
}

/**
 * format a registry_value into a string.
 *
 * This is intended to be used for smbconf registry values,
 * which are ar stored as REG_SZ values, so the incomplete
 * handling should be ok.
 */
static char *smbconf_format_registry_value(TALLOC_CTX *mem_ctx,
					   struct registry_value *value)
{
	char *result = NULL;

	/* alternatively, create a new talloc context? */
	if (mem_ctx == NULL) {
		return result;
	}

	switch (value->type) {
	case REG_DWORD:
		result = talloc_asprintf(mem_ctx, "%d", value->v.dword);
		break;
	case REG_SZ:
	case REG_EXPAND_SZ:
		result = talloc_asprintf(mem_ctx, "%s", value->v.sz.str);
		break;
	case REG_MULTI_SZ: {
                uint32 j;
                for (j = 0; j < value->v.multi_sz.num_strings; j++) {
                        result = talloc_asprintf(mem_ctx, "%s \"%s\" ",
						 result,
						 value->v.multi_sz.strings[j]);
			if (result == NULL) {
				break;
			}
                }
                break;
        }
	case REG_BINARY:
                result = talloc_asprintf(mem_ctx, "binary (%d bytes)",
					 (int)value->v.binary.length);
                break;
        default:
                result = talloc_asprintf(mem_ctx, "<unprintable>");
                break;
        }
	return result;
}

/**
 * Get the values of a key as a list of value names
 * and a list of value strings (ordered)
 */
static WERROR smbconf_reg_get_values(TALLOC_CTX *mem_ctx,
				     struct registry_key *key,
				     uint32_t *num_values,
				     char ***value_names,
				     char ***value_strings)
{
	TALLOC_CTX *tmp_ctx = NULL;
	WERROR werr = WERR_OK;
	uint32_t count;
	struct registry_value *valvalue = NULL;
	char *valname = NULL;
	char **tmp_valnames = NULL;
	char **tmp_valstrings = NULL;

	if ((num_values == NULL) || (value_names == NULL) ||
	    (value_strings == NULL))
	{
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		werr = WERR_NOMEM;
		goto done;
	}

	for (count = 0;
	     W_ERROR_IS_OK(werr = reg_enumvalue(tmp_ctx, key, count, &valname,
						&valvalue));
	     count++)
	{
		char *valstring;

		werr = smbconf_add_string_to_array(tmp_ctx,
						   &tmp_valnames,
						   count, valname);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}

		valstring = smbconf_format_registry_value(tmp_ctx, valvalue);
		werr = smbconf_add_string_to_array(tmp_ctx, &tmp_valstrings,
						   count, valstring);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}
	}
	if (!W_ERROR_EQUAL(WERR_NO_MORE_ITEMS, werr)) {
		goto done;
	}

	werr = WERR_OK;

	*num_values = count;
	if (count > 0) {
		*value_names = talloc_move(mem_ctx, &tmp_valnames);
		*value_strings = talloc_move(mem_ctx, &tmp_valstrings);
	} else {
		*value_names = NULL;
		*value_strings = NULL;
	}

done:
	TALLOC_FREE(tmp_ctx);
	return werr;
}

static int smbconf_destroy_ctx(struct smbconf_ctx *ctx)
{
	return ctx->ops->close_conf(ctx);
}

static WERROR smbconf_global_check(struct smbconf_ctx *ctx)
{
	if (!smbconf_share_exists(ctx, GLOBAL_NAME)) {
		return smbconf_create_share(ctx, GLOBAL_NAME);
	}
	return WERR_OK;
}


/**********************************************************************
 *
 * smbconf operations: registry implementations
 *
 **********************************************************************/

/**
 * initialize the registry smbconf backend
 */
static WERROR smbconf_reg_init(struct smbconf_ctx *ctx)
{
	WERROR werr = WERR_OK;

	if (!registry_init_smbconf()) {
		werr = WERR_REG_IO_FAILURE;
		goto done;
	}

	werr = ntstatus_to_werror(registry_create_admin_token(ctx,
							      &(ctx->token)));
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(1, ("Error creating admin token\n"));
		goto done;
	}

done:
	return werr;
}

static WERROR smbconf_reg_open(struct smbconf_ctx *ctx)
{
	return regdb_open();
}

static int smbconf_reg_close(struct smbconf_ctx *ctx)
{
	return regdb_close();
}

/**
 * Get the change sequence number of the given service/parameter.
 * service and parameter strings may be NULL.
 */
static void smbconf_reg_get_csn(struct smbconf_ctx *ctx,
				struct smbconf_csn *csn,
				const char *service, const char *param)
{
	if (csn == NULL) {
		return;
	}
	csn->csn = (uint64_t)regdb_get_seqnum();
}

/**
 * Drop the whole configuration (restarting empty) - registry version
 */
static WERROR smbconf_reg_drop(struct smbconf_ctx *ctx)
{
	char *path, *p;
	WERROR werr = WERR_OK;
	struct registry_key *parent_key = NULL;
	struct registry_key *new_key = NULL;
	TALLOC_CTX* mem_ctx = talloc_stackframe();
	enum winreg_CreateAction action;

	path = talloc_strdup(mem_ctx, KEY_SMBCONF);
	if (path == NULL) {
		werr = WERR_NOMEM;
		goto done;
	}
	p = strrchr(path, '\\');
	*p = '\0';
	werr = smbconf_reg_open_path(mem_ctx, ctx, path, REG_KEY_WRITE,
				     &parent_key);

	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = reg_deletekey_recursive(mem_ctx, parent_key, p+1);

	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = reg_createkey(mem_ctx, parent_key, p+1, REG_KEY_WRITE,
			     &new_key, &action);

done:
	TALLOC_FREE(mem_ctx);
	return werr;
}

/**
 * get the list of share names defined in the configuration.
 * registry version.
 */
static WERROR smbconf_reg_get_share_names(struct smbconf_ctx *ctx,
					  TALLOC_CTX *mem_ctx,
					  uint32_t *num_shares,
					  char ***share_names)
{
	uint32_t count;
	uint32_t added_count = 0;
	TALLOC_CTX *tmp_ctx = NULL;
	WERROR werr = WERR_OK;
	struct registry_key *key = NULL;
	char *subkey_name = NULL;
	char **tmp_share_names = NULL;

	if ((num_shares == NULL) || (share_names == NULL)) {
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		werr = WERR_NOMEM;
		goto done;
	}

	/* make sure "global" is always listed first */
	if (smbconf_share_exists(ctx, GLOBAL_NAME)) {
		werr = smbconf_add_string_to_array(tmp_ctx, &tmp_share_names,
						   0, GLOBAL_NAME);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}
		added_count++;
	}

	werr = smbconf_reg_open_base_key(tmp_ctx, ctx,
					 SEC_RIGHTS_ENUM_SUBKEYS, &key);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	for (count = 0;
	     W_ERROR_IS_OK(werr = reg_enumkey(tmp_ctx, key, count,
					      &subkey_name, NULL));
	     count++)
	{
		if (strequal(subkey_name, GLOBAL_NAME)) {
			continue;
		}

		werr = smbconf_add_string_to_array(tmp_ctx,
						   &tmp_share_names,
						   added_count,
						   subkey_name);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}
		added_count++;
	}
	if (!W_ERROR_EQUAL(WERR_NO_MORE_ITEMS, werr)) {
		goto done;
	}
	werr = WERR_OK;

	*num_shares = added_count;
	if (added_count > 0) {
		*share_names = talloc_move(mem_ctx, &tmp_share_names);
	} else {
		*share_names = NULL;
	}

done:
	TALLOC_FREE(tmp_ctx);
	return werr;
}

/**
 * check if a share/service of a given name exists - registry version
 */
static bool smbconf_reg_share_exists(struct smbconf_ctx *ctx,
				     const char *servicename)
{
	bool ret = false;
	WERROR werr = WERR_OK;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct registry_key *key = NULL;

	werr = smbconf_reg_open_service_key(mem_ctx, ctx, servicename,
					    REG_KEY_READ, &key);
	if (W_ERROR_IS_OK(werr)) {
		ret = true;
	}

	TALLOC_FREE(mem_ctx);
	return ret;
}

/**
 * Add a service if it does not already exist - registry version
 */
static WERROR smbconf_reg_create_share(struct smbconf_ctx *ctx,
				       const char *servicename)
{
	WERROR werr;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct registry_key *key = NULL;

	werr = smbconf_reg_create_service_key(mem_ctx, ctx, servicename, &key);

	TALLOC_FREE(mem_ctx);
	return werr;
}

/**
 * get a definition of a share (service) from configuration.
 */
static WERROR smbconf_reg_get_share(struct smbconf_ctx *ctx,
				    TALLOC_CTX *mem_ctx,
				    const char *servicename,
				    uint32_t *num_params,
				    char ***param_names, char ***param_values)
{
	WERROR werr = WERR_OK;
	struct registry_key *key = NULL;

	werr = smbconf_reg_open_service_key(mem_ctx, ctx, servicename,
					    REG_KEY_READ, &key);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = smbconf_reg_get_values(mem_ctx, key, num_params,
				      param_names, param_values);

done:
	TALLOC_FREE(key);
	return werr;
}

/**
 * delete a service from configuration
 */
static WERROR smbconf_reg_delete_share(struct smbconf_ctx *ctx,
				       const char *servicename)
{
	WERROR werr = WERR_OK;
	struct registry_key *key = NULL;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	werr = smbconf_reg_open_base_key(mem_ctx, ctx, REG_KEY_WRITE, &key);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = reg_deletekey_recursive(key, key, servicename);

done:
	TALLOC_FREE(mem_ctx);
	return werr;
}

/**
 * set a configuration parameter to the value provided.
 */
static WERROR smbconf_reg_set_parameter(struct smbconf_ctx *ctx,
					const char *service,
					const char *param,
					const char *valstr)
{
	WERROR werr;
	struct registry_key *key = NULL;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	werr = smbconf_reg_open_service_key(mem_ctx, ctx, service,
					    REG_KEY_WRITE, &key);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = smbconf_reg_set_value(key, param, valstr);

done:
	TALLOC_FREE(mem_ctx);
	return werr;
}

/**
 * get the value of a configuration parameter as a string
 */
static WERROR smbconf_reg_get_parameter(struct smbconf_ctx *ctx,
					TALLOC_CTX *mem_ctx,
					const char *service,
					const char *param,
					char **valstr)
{
	WERROR werr = WERR_OK;
	struct registry_key *key = NULL;
	struct registry_value *value = NULL;

	werr = smbconf_reg_open_service_key(mem_ctx, ctx, service,
					    REG_KEY_READ, &key);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	if (!smbconf_value_exists(key, param)) {
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	werr = reg_queryvalue(mem_ctx, key, param, &value);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	*valstr = smbconf_format_registry_value(mem_ctx, value);

	if (*valstr == NULL) {
		werr = WERR_NOMEM;
	}

done:
	TALLOC_FREE(key);
	TALLOC_FREE(value);
	return werr;
}

/**
 * delete a parameter from configuration
 */
static WERROR smbconf_reg_delete_parameter(struct smbconf_ctx *ctx,
					   const char *service,
					   const char *param)
{
	struct registry_key *key = NULL;
	WERROR werr = WERR_OK;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	werr = smbconf_reg_open_service_key(mem_ctx, ctx, service,
					    REG_KEY_ALL, &key);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	if (!smbconf_value_exists(key, param)) {
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	werr = reg_deletevalue(key, param);

done:
	TALLOC_FREE(mem_ctx);
	return werr;
}

struct smbconf_ops smbconf_ops_reg = {
	.init			= smbconf_reg_init,
	.open_conf		= smbconf_reg_open,
	.close_conf		= smbconf_reg_close,
	.get_csn		= smbconf_reg_get_csn,
	.drop			= smbconf_reg_drop,
	.get_share_names	= smbconf_reg_get_share_names,
	.share_exists		= smbconf_reg_share_exists,
	.create_share		= smbconf_reg_create_share,
	.get_share		= smbconf_reg_get_share,
	.delete_share		= smbconf_reg_delete_share,
	.set_parameter		= smbconf_reg_set_parameter,
	.get_parameter		= smbconf_reg_get_parameter,
	.delete_parameter	= smbconf_reg_delete_parameter
};


/**********************************************************************
 *
 * The actual libsmbconf API functions that are exported.
 *
 **********************************************************************/

/**
 * Open the configuration.
 *
 * This should be the first function in a sequence of calls to smbconf
 * functions:
 *
 * Upon success, this creates and returns the conf context
 * that should be passed around in subsequent calls to the other
 * smbconf functions.
 *
 * After the work with the configuration is completed, smbconf_close()
 * should be called.
 */
WERROR smbconf_init(TALLOC_CTX *mem_ctx, struct smbconf_ctx **conf_ctx)
{
	WERROR werr = WERR_OK;
	struct smbconf_ctx *ctx;

	if (conf_ctx == NULL) {
		return WERR_INVALID_PARAM;
	}

	ctx = TALLOC_ZERO_P(mem_ctx, struct smbconf_ctx);
	if (ctx == NULL) {
		return WERR_NOMEM;
	}

	ctx->ops = &smbconf_ops_reg;

	werr = ctx->ops->init(ctx);
	if (!W_ERROR_IS_OK(werr)) {
		goto fail;
	}

	talloc_set_destructor(ctx, smbconf_destroy_ctx);

	*conf_ctx = ctx;
	return werr;

fail:
	TALLOC_FREE(ctx);
	return werr;
}

/**
 * Close the configuration.
 */
void smbconf_close(struct smbconf_ctx *ctx)
{
	/* this also closes the registry (by destructor): */
	TALLOC_FREE(ctx);
}

/**
 * Detect changes in the configuration.
 * The given csn struct is filled with the current csn.
 * smbconf_changed() can also be used for initial retrieval
 * of the csn.
 */
bool smbconf_changed(struct smbconf_ctx *ctx, struct smbconf_csn *csn,
		     const char *service, const char *param)
{
	struct smbconf_csn old_csn;

	if (csn == NULL) {
		return false;
	}

	old_csn = *csn;

	ctx->ops->get_csn(ctx, csn, service, param);
	return (csn->csn != old_csn.csn);
}

/**
 * Drop the whole configuration (restarting empty).
 */
WERROR smbconf_drop(struct smbconf_ctx *ctx)
{
	return ctx->ops->drop(ctx);
}

/**
 * Get the whole configuration as lists of strings with counts:
 *
 *  num_shares   : number of shares
 *  share_names  : list of length num_shares of share names
 *  num_params   : list of length num_shares of parameter counts for each share
 *  param_names  : list of lists of parameter names for each share
 *  param_values : list of lists of parameter values for each share
 */
WERROR smbconf_get_config(struct smbconf_ctx *ctx,
			  TALLOC_CTX *mem_ctx,
			  uint32_t *num_shares,
			  char ***share_names, uint32_t **num_params,
			  char ****param_names, char ****param_values)
{
	WERROR werr = WERR_OK;
	TALLOC_CTX *tmp_ctx = NULL;
	uint32_t tmp_num_shares;
	char **tmp_share_names;
	uint32_t *tmp_num_params;
	char ***tmp_param_names;
	char ***tmp_param_values;
	uint32_t count;

	if ((num_shares == NULL) || (share_names == NULL) ||
	    (num_params == NULL) || (param_names == NULL) ||
	    (param_values == NULL))
	{
		werr = WERR_INVALID_PARAM;
		goto done;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		werr = WERR_NOMEM;
		goto done;
	}

	werr = smbconf_get_share_names(ctx, tmp_ctx, &tmp_num_shares,
				       &tmp_share_names);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	tmp_num_params   = TALLOC_ARRAY(tmp_ctx, uint32_t, tmp_num_shares);
	tmp_param_names  = TALLOC_ARRAY(tmp_ctx, char **, tmp_num_shares);
	tmp_param_values = TALLOC_ARRAY(tmp_ctx, char **, tmp_num_shares);

	if ((tmp_num_params == NULL) || (tmp_param_names == NULL) ||
	    (tmp_param_values == NULL))
	{
		werr = WERR_NOMEM;
		goto done;
	}

	for (count = 0; count < tmp_num_shares; count++) {
		werr = smbconf_get_share(ctx, mem_ctx,
					 tmp_share_names[count],
					 &tmp_num_params[count],
					 &tmp_param_names[count],
					 &tmp_param_values[count]);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}
	}

	werr = WERR_OK;

	*num_shares = tmp_num_shares;
	if (tmp_num_shares > 0) {
		*share_names = talloc_move(mem_ctx, &tmp_share_names);
		*num_params = talloc_move(mem_ctx, &tmp_num_params);
		*param_names = talloc_move(mem_ctx, &tmp_param_names);
		*param_values = talloc_move(mem_ctx, &tmp_param_values);
	} else {
		*share_names = NULL;
		*num_params = NULL;
		*param_names = NULL;
		*param_values = NULL;
	}

done:
	TALLOC_FREE(tmp_ctx);
	return werr;
}

/**
 * get the list of share names defined in the configuration.
 */
WERROR smbconf_get_share_names(struct smbconf_ctx *ctx,
			       TALLOC_CTX *mem_ctx,
			       uint32_t *num_shares,
			       char ***share_names)
{
	return ctx->ops->get_share_names(ctx, mem_ctx, num_shares,
					 share_names);
}

/**
 * check if a share/service of a given name exists
 */
bool smbconf_share_exists(struct smbconf_ctx *ctx,
			  const char *servicename)
{
	if (servicename == NULL) {
		return false;
	}
	return ctx->ops->share_exists(ctx, servicename);
}

/**
 * Add a service if it does not already exist.
 */
WERROR smbconf_create_share(struct smbconf_ctx *ctx,
			    const char *servicename)
{
	if (smbconf_share_exists(ctx, servicename)) {
		return WERR_ALREADY_EXISTS;
	}

	return ctx->ops->create_share(ctx, servicename);
}

/**
 * get a definition of a share (service) from configuration.
 */
WERROR smbconf_get_share(struct smbconf_ctx *ctx,
			 TALLOC_CTX *mem_ctx,
			 const char *servicename, uint32_t *num_params,
			 char ***param_names, char ***param_values)
{
	if (!smbconf_share_exists(ctx, servicename)) {
		return WERR_NO_SUCH_SERVICE;
	}

	return ctx->ops->get_share(ctx, mem_ctx, servicename, num_params,
				   param_names, param_values);
}

/**
 * delete a service from configuration
 */
WERROR smbconf_delete_share(struct smbconf_ctx *ctx, const char *servicename)
{
	if (!smbconf_share_exists(ctx, servicename)) {
		return WERR_NO_SUCH_SERVICE;
	}

	return ctx->ops->delete_share(ctx, servicename);
}

/**
 * set a configuration parameter to the value provided.
 */
WERROR smbconf_set_parameter(struct smbconf_ctx *ctx,
			     const char *service,
			     const char *param,
			     const char *valstr)
{
	if (!smbconf_share_exists(ctx, service)) {
		return WERR_NO_SUCH_SERVICE;
	}

	return ctx->ops->set_parameter(ctx, service, param, valstr);
}

/**
 * Set a global parameter
 * (i.e. a parameter in the [global] service).
 *
 * This also creates [global] when it does not exist.
 */
WERROR smbconf_set_global_parameter(struct smbconf_ctx *ctx,
				    const char *param, const char *val)
{
	WERROR werr;

	werr = smbconf_global_check(ctx);
	if (W_ERROR_IS_OK(werr)) {
		werr = smbconf_set_parameter(ctx, GLOBAL_NAME, param, val);
	}

	return werr;
}

/**
 * get the value of a configuration parameter as a string
 */
WERROR smbconf_get_parameter(struct smbconf_ctx *ctx,
			     TALLOC_CTX *mem_ctx,
			     const char *service,
			     const char *param,
			     char **valstr)
{
	if (valstr == NULL) {
		return WERR_INVALID_PARAM;
	}

	if (!smbconf_share_exists(ctx, service)) {
		return WERR_NO_SUCH_SERVICE;
	}

	return ctx->ops->get_parameter(ctx, mem_ctx, service, param, valstr);
}

/**
 * Get the value of a global parameter.
 *
 * Create [global] if it does not exist.
 */
WERROR smbconf_get_global_parameter(struct smbconf_ctx *ctx,
				    TALLOC_CTX *mem_ctx,
				    const char *param,
				    char **valstr)
{
	WERROR werr;

	werr = smbconf_global_check(ctx);
	if (W_ERROR_IS_OK(werr)) {
		werr = smbconf_get_parameter(ctx, mem_ctx, GLOBAL_NAME, param,
					     valstr);
	}

	return werr;
}

/**
 * delete a parameter from configuration
 */
WERROR smbconf_delete_parameter(struct smbconf_ctx *ctx,
				const char *service, const char *param)
{
	if (!smbconf_share_exists(ctx, service)) {
		return WERR_NO_SUCH_SERVICE;
	}

	return ctx->ops->delete_parameter(ctx, service, param);
}

/**
 * Delete a global parameter.
 *
 * Create [global] if it does not exist.
 */
WERROR smbconf_delete_global_parameter(struct smbconf_ctx *ctx,
				       const char *param)
{
	WERROR werr;

	werr = smbconf_global_check(ctx);
	if (W_ERROR_IS_OK(werr)) {
		werr = smbconf_delete_parameter(ctx, GLOBAL_NAME, param);
	}

	return werr;
}
