/*
 * Samba Unix/Linux SMB client library
 * Registry Editor
 * Copyright (C) Christopher Davis 2012
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Wrap s3 registry API calls to avoid conflicts with 'struct registry_key',
   etc, in s4 libregistry. */

#include "includes.h"
#include "registry.h"
#include "registry/reg_api.h"
#include "registry/reg_init_basic.h"
#include "registry/reg_util_token.h"

#include "regedit.h"

WERROR reg_openhive_wrap(TALLOC_CTX *ctx, const char *hive,
			 struct samba3_registry_key *pkey)
{
	struct security_token *token;
	WERROR rv;

	SMB_ASSERT(pkey->key == NULL);

	rv = ntstatus_to_werror(registry_create_admin_token(ctx, &token));
	if (!W_ERROR_IS_OK(rv)) {
		return rv;
	}

	return reg_openhive(ctx, hive, REG_KEY_READ | REG_KEY_WRITE, token,
			    &pkey->key);
}

WERROR reg_openkey_wrap(TALLOC_CTX *ctx, struct samba3_registry_key *parent,
			const char *name, struct samba3_registry_key *pkey)
{
	SMB_ASSERT(pkey->key == NULL);
	return reg_openkey(ctx, parent->key, name,
		REG_KEY_READ | REG_KEY_WRITE, &pkey->key);
}

WERROR reg_enumvalue_wrap(TALLOC_CTX *ctx, struct samba3_registry_key *key,
			  uint32_t idx, char **name, uint32_t *type,
			  DATA_BLOB *data)
{
	struct registry_value *val = NULL;
	WERROR rv;

	rv = reg_enumvalue(ctx, key->key, idx, name, &val);

	if (val && W_ERROR_IS_OK(rv)) {
		*type = (uint32_t)val->type;
		*data = val->data;
	}

	return rv;
}

WERROR reg_queryvalue_wrap(TALLOC_CTX *ctx, struct samba3_registry_key *key,
			   const char *name, uint32_t *type, DATA_BLOB *data)
{
	struct registry_value *val = NULL;
	WERROR rv;

	rv = reg_queryvalue(ctx, key->key, name, &val);

	if (val && W_ERROR_IS_OK(rv)) {
		*type = (uint32_t)val->type;
		*data = val->data;
	}

	return rv;
}

WERROR reg_enumkey_wrap(TALLOC_CTX *ctx, struct samba3_registry_key *key,
			uint32_t idx, char **name, NTTIME *last_write_time)
{
	return reg_enumkey(ctx, key->key, idx, name, last_write_time);
}

WERROR reg_createkey_wrap(TALLOC_CTX *ctx, struct samba3_registry_key *parent,
			  const char *subkeypath,
			  struct samba3_registry_key *pkey)
{
	enum winreg_CreateAction act;

	SMB_ASSERT(pkey->key == NULL);
	return reg_createkey(ctx, parent->key, subkeypath,
			     REG_KEY_READ | REG_KEY_WRITE, &pkey->key, &act);
}

WERROR reg_deletekey_wrap(struct samba3_registry_key *parent, const char *path)
{
	return reg_deletekey(parent->key, path);
}

WERROR reg_deletevalue_wrap(struct samba3_registry_key *key, const char *name)
{
	return reg_deletevalue(key->key, name);
}

WERROR reg_queryinfokey_wrap(struct samba3_registry_key *key,
			     uint32_t *num_subkeys, uint32_t *max_subkeylen,
			     uint32_t *max_subkeysize, uint32_t *num_values,
			     uint32_t *max_valnamelen,
			     uint32_t *max_valbufsize, uint32_t *secdescsize,
			     NTTIME *last_changed_time)
{
	return reg_queryinfokey(key->key, num_subkeys, max_subkeylen,
				max_subkeysize, num_values, max_valnamelen,
				max_valbufsize, secdescsize,
				last_changed_time);
}

WERROR reg_setvalue_wrap(struct samba3_registry_key *key, const char *name,
	uint32_t type, const DATA_BLOB data)
{
	struct registry_value val;

	val.type = type;
	val.data = data;

	return reg_setvalue(key->key, name, &val);
}

WERROR reg_init_wrap(void)
{
	return registry_init_basic();
}
