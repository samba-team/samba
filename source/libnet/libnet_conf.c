/*
 *  Unix SMB/CIFS implementation.
 *  libnet smbconf registry Support
 *  Copyright (C) Michael Adam 2007
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

/*
 * Open a subkey of KEY_SMBCONF (i.e a service)
 * - variant without error output (q = quiet)-
 */
static WERROR libnet_smbconf_open_path_q(TALLOC_CTX *ctx,
					 const char *subkeyname,
					 uint32 desired_access,
					 struct registry_key **key)
{
	WERROR werr = WERR_OK;
	char *path = NULL;
	NT_USER_TOKEN *token;

	if (!(token = registry_create_admin_token(ctx))) {
		DEBUG(1, ("Error creating admin token\n"));
		goto done;
	}

	if (subkeyname == NULL) {
		path = talloc_strdup(ctx, KEY_SMBCONF);
	} else {
		path = talloc_asprintf(ctx, "%s\\%s", KEY_SMBCONF, subkeyname);
	}

	werr = reg_open_path(ctx, path, desired_access,
			     token, key);

done:
	TALLOC_FREE(path);
	return werr;
}

/*
 * check if a subkey of KEY_SMBCONF of a given name exists
 */
bool libnet_smbconf_key_exists(TALLOC_CTX *ctx, const char *subkeyname)
{
	bool ret = False;
	WERROR werr = WERR_OK;
	TALLOC_CTX *mem_ctx;
	struct registry_key *key;

	if (!(mem_ctx = talloc_new(ctx))) {
		d_fprintf(stderr, "ERROR: Out of memory...!\n");
		goto done;
	}

	werr = libnet_smbconf_open_path_q(mem_ctx, subkeyname, REG_KEY_READ, &key);
	if (W_ERROR_IS_OK(werr)) {
		ret = True;
	}

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

/*
 * Open a subkey of KEY_SMBCONF (i.e a service)
 * - variant with error output -
 */
WERROR libnet_smbconf_open_path(TALLOC_CTX *ctx, const char *subkeyname,
				uint32 desired_access,
				struct registry_key **key)
{
	WERROR werr = WERR_OK;

	werr = libnet_smbconf_open_path_q(ctx, subkeyname, desired_access, key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "Error opening registry path '%s\\%s': %s\n",
			  KEY_SMBCONF,
			  (subkeyname == NULL) ? "" : subkeyname,
			  dos_errstr(werr));
	}

	return werr;
}

/*
 * open the base key KEY_SMBCONF
 */
WERROR libnet_smbconf_open_basepath(TALLOC_CTX *ctx, uint32 desired_access,
			     	    struct registry_key **key)
{
	return libnet_smbconf_open_path(ctx, NULL, desired_access, key);
}

/*
 * create a subkey of KEY_SMBCONF
 */
WERROR libnet_reg_createkey_internal(TALLOC_CTX *ctx,
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
	if (!(create_ctx = talloc_new(ctx))) {
		werr = WERR_NOMEM;
		goto done;
	}

	werr = libnet_smbconf_open_basepath(create_ctx, REG_KEY_WRITE, &create_parent);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = reg_createkey(ctx, create_parent, subkeyname,
			     REG_KEY_WRITE, newkey, &action);
	if (W_ERROR_IS_OK(werr) && (action != REG_CREATED_NEW_KEY)) {
		d_fprintf(stderr, "Key '%s' already exists.\n", subkeyname);
		werr = WERR_ALREADY_EXISTS;
	}
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "Error creating key %s: %s\n",
			 subkeyname, dos_errstr(werr));
	}

done:
	TALLOC_FREE(create_ctx);
	return werr;
}

static WERROR do_modify_val_config(struct registry_key *key,
				   const char *val_name,
				   const char *val_data)
{
	struct registry_value val;

	ZERO_STRUCT(val);

	val.type = REG_SZ;
	val.v.sz.str = CONST_DISCARD(char *, val_data);
	val.v.sz.len = strlen(val_data) + 1;

	return reg_setvalue(key, val_name, &val);
}

WERROR libnet_smbconf_set_global_param(TALLOC_CTX *mem_ctx,
				       const char *param,
				       const char *val)
{
	WERROR werr;
	struct registry_key *key = NULL;

	if (!lp_include_registry_globals()) {
		return WERR_NOT_SUPPORTED;
	}

	if (!registry_init_regdb()) {
		return WERR_REG_IO_FAILURE;
	}

	if (!libnet_smbconf_key_exists(mem_ctx, GLOBAL_NAME)) {
		werr = libnet_reg_createkey_internal(mem_ctx,
						     GLOBAL_NAME, &key);
	} else {
		werr = libnet_smbconf_open_path(mem_ctx,
						GLOBAL_NAME,
						REG_KEY_WRITE, &key);
	}

	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	return do_modify_val_config(key, param, val);
}

bool libnet_smbconf_value_exists(TALLOC_CTX *ctx,
					struct registry_key *key,
					const char *param)
{
	bool ret = False;
	WERROR werr = WERR_OK;
	struct registry_value *value = NULL;

	werr = reg_queryvalue(ctx, key, param, &value);
	if (W_ERROR_IS_OK(werr)) {
		ret = True;
	}

	TALLOC_FREE(value);
	return ret;
}

