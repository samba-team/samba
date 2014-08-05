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

/* s3 registry backend, adapted from rpc backend */

#include "includes.h"
#include "lib/registry/registry.h"
#include "regedit.h"

struct samba3_key {
	struct registry_key key;
	struct samba3_registry_key s3key;
};

struct samba3_registry_context {
	struct registry_context context;
};

static struct registry_operations reg_backend_s3;

static struct {
	uint32_t hkey;
	const char *name;
} known_hives[] = {
	{ HKEY_LOCAL_MACHINE, "HKLM" },
	{ HKEY_CURRENT_USER, "HKCU" },
	{ HKEY_CLASSES_ROOT, "HKCR" },
	{ HKEY_PERFORMANCE_DATA, "HKPD" },
	{ HKEY_USERS, "HKU" },
	{ HKEY_DYN_DATA, "HKDD" },
	{ HKEY_CURRENT_CONFIG, "HKCC" },
	{ 0, NULL }
};

static WERROR samba3_get_predefined_key(struct registry_context *ctx,
				        uint32_t hkey_type,
				        struct registry_key **k)
{
	int n;
	const char *name;
	struct samba3_key *mykeydata;

	*k = NULL;
	name = NULL;

	for(n = 0; known_hives[n].hkey; n++) {
		if(known_hives[n].hkey == hkey_type) {
			name = known_hives[n].name;
			break;
		}
	}

	if (name == NULL) {
		DEBUG(1, ("No such hive %d\n", hkey_type));
		return WERR_NO_MORE_ITEMS;
	}

	mykeydata = talloc_zero(ctx, struct samba3_key);
	W_ERROR_HAVE_NO_MEMORY(mykeydata);
	mykeydata->key.context = ctx;
	*k = (struct registry_key *)mykeydata;

	return reg_openhive_wrap(ctx, name, &mykeydata->s3key);
}

static WERROR samba3_open_key(TALLOC_CTX *mem_ctx, struct registry_key *h,
			      const char *name, struct registry_key **key)
{
	struct samba3_key *parentkeydata, *mykeydata;

	parentkeydata = talloc_get_type(h, struct samba3_key);

	mykeydata = talloc_zero(mem_ctx, struct samba3_key);
	W_ERROR_HAVE_NO_MEMORY(mykeydata);
	mykeydata->key.context = h->context;
	*key = (struct registry_key *)mykeydata;

	return reg_openkey_wrap(mem_ctx, &parentkeydata->s3key,
				name, &mykeydata->s3key);
}

static WERROR samba3_get_value_by_index(TALLOC_CTX *mem_ctx,
				        const struct registry_key *parent,
				        uint32_t n,
				        const char **value_name,
				        uint32_t *type,
				        DATA_BLOB *data)
{
	struct samba3_key *mykeydata;

	mykeydata = talloc_get_type(parent, struct samba3_key);

	return reg_enumvalue_wrap(mem_ctx, &mykeydata->s3key, n,
				  discard_const(value_name), type, data);
}

static WERROR samba3_get_value_by_name(TALLOC_CTX *mem_ctx,
				       const struct registry_key *parent,
				       const char *value_name,
				       uint32_t *type,
				       DATA_BLOB *data)
{
	struct samba3_key *mykeydata;

	mykeydata = talloc_get_type(parent, struct samba3_key);

	return reg_queryvalue_wrap(mem_ctx, &mykeydata->s3key,
				   value_name, type, data);
}

static WERROR samba3_get_subkey_by_index(TALLOC_CTX *mem_ctx,
				         const struct registry_key *parent,
				         uint32_t n,
				         const char **name,
				         const char **keyclass,
				         NTTIME *last_changed_time)
{
	struct samba3_key *mykeydata;

	mykeydata = talloc_get_type(parent, struct samba3_key);

	*keyclass = NULL;

	return reg_enumkey_wrap(mem_ctx, &mykeydata->s3key, n,
				discard_const(name), last_changed_time);
}

static WERROR samba3_add_key(TALLOC_CTX *mem_ctx,
			     struct registry_key *parent, const char *path,
			     const char *key_class,
			     struct security_descriptor *sec,
			     struct registry_key **key)
{
	struct samba3_key *parentkd;
	struct samba3_key *newkd;

	parentkd = talloc_get_type(parent, struct samba3_key);
	newkd = talloc_zero(mem_ctx, struct samba3_key);

	W_ERROR_HAVE_NO_MEMORY(newkd);
	newkd->key.context = parent->context;
	*key = (struct registry_key *)newkd;

	return reg_createkey_wrap(mem_ctx, &parentkd->s3key, path,
				  &newkd->s3key);
}

static WERROR samba3_del_key(TALLOC_CTX *mem_ctx, struct registry_key *parent,
			     const char *name)
{
	struct samba3_key *mykeydata;

	mykeydata = talloc_get_type(parent, struct samba3_key);

	return reg_deletekey_wrap(&mykeydata->s3key, name);
}

static WERROR samba3_del_value(TALLOC_CTX *mem_ctx, struct registry_key *key,
                               const char *name)
{
	struct samba3_key *mykeydata = talloc_get_type(key, struct samba3_key);

        return reg_deletevalue_wrap(&mykeydata->s3key, name);
}

static WERROR samba3_set_value(struct registry_key *key, const char *name,
                               uint32_t type, const DATA_BLOB data)
{
	struct samba3_key *mykeydata = talloc_get_type(key, struct samba3_key);

        return reg_setvalue_wrap(&mykeydata->s3key, name, type, data);
}

static WERROR samba3_get_info(TALLOC_CTX *mem_ctx,
			      const struct registry_key *key,
			      const char **classname,
			      uint32_t *num_subkeys,
			      uint32_t *num_values,
			      NTTIME *last_changed_time,
			      uint32_t *max_subkeylen,
			      uint32_t *max_valnamelen,
			      uint32_t *max_valbufsize)
{
	struct samba3_key *mykeydata = talloc_get_type(key, struct samba3_key);
	uint32_t max_subkeysize, secdescsize;

	return reg_queryinfokey_wrap(&mykeydata->s3key, num_subkeys,
				     max_subkeylen, &max_subkeysize,
				     num_values, max_valnamelen,
				     max_valbufsize, &secdescsize,
				     last_changed_time);
}

static struct registry_operations reg_backend_s3 = {
	.name = "samba3",
	.open_key = samba3_open_key,
	.get_predefined_key = samba3_get_predefined_key,
	.enum_key = samba3_get_subkey_by_index,
	.enum_value = samba3_get_value_by_index,
	.get_value = samba3_get_value_by_name,
	.set_value = samba3_set_value,
	.delete_value = samba3_del_value,
	.create_key = samba3_add_key,
	.delete_key = samba3_del_key,
	.get_key_info = samba3_get_info,
};

WERROR reg_open_samba3(TALLOC_CTX *mem_ctx, struct registry_context **ctx)
{
	WERROR rv;
	struct samba3_registry_context *rctx;

	/* initialize s3 registry */
	rv = reg_init_wrap();
	if (!W_ERROR_IS_OK(rv)) {
		return rv;
	}

	rctx = talloc_zero(mem_ctx, struct samba3_registry_context);
	if (rctx == NULL) {
		return WERR_NOMEM;
	}

	*ctx = (struct registry_context *)rctx;
	(*ctx)->ops = &reg_backend_s3;

	return WERR_OK;
}
