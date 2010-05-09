/*
   Unix SMB/CIFS implementation.
   Transparent registry backend handling
   Copyright (C) Jelmer Vernooij			2003-2007.

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
#include "lib/registry/registry.h"
#include "librpc/gen_ndr/winreg.h"

_PUBLIC_ char *reg_val_data_string(TALLOC_CTX *mem_ctx, uint32_t type,
				   const DATA_BLOB data)
{
	char *ret = NULL;

	if (data.length == 0)
		return talloc_strdup(mem_ctx, "");

	switch (type) {
		case REG_EXPAND_SZ:
		case REG_SZ:
			convert_string_talloc(mem_ctx,
							  CH_UTF16, CH_UNIX, data.data, data.length,
							  (void **)&ret, NULL, false);
			break;
		case REG_DWORD:
		case REG_DWORD_BIG_ENDIAN:
			SMB_ASSERT(data.length == sizeof(uint32_t));
			ret = talloc_asprintf(mem_ctx, "0x%8.8x",
					      IVAL(data.data, 0));
			break;
		case REG_QWORD:
			SMB_ASSERT(data.length == sizeof(uint64_t));
			ret = talloc_asprintf(mem_ctx, "0x%16.16llx",
					      BVAL(data.data, 0));
			break;
		case REG_BINARY:
			ret = data_blob_hex_string_upper(mem_ctx, &data);
			break;
		case REG_NONE:
			/* "NULL" is the right return value */
			break;
		case REG_MULTI_SZ:
			/* FIXME: We don't support this yet */
			break;
		default:
			/* FIXME */
			/* Other datatypes aren't supported -> return "NULL" */
			break;
	}

	return ret;
}

/** Generate a string that describes a registry value */
_PUBLIC_ char *reg_val_description(TALLOC_CTX *mem_ctx, 
				   const char *name,
				   uint32_t data_type,
				   const DATA_BLOB data)
{
	return talloc_asprintf(mem_ctx, "%s = %s : %s", name?name:"<No Name>",
			       str_regtype(data_type),
			       reg_val_data_string(mem_ctx, data_type, data));
}

_PUBLIC_ bool reg_string_to_val(TALLOC_CTX *mem_ctx, const char *type_str,
				const char *data_str, uint32_t *type, DATA_BLOB *data)
{
	*type = regtype_by_string(type_str);

	if (*type == -1)
		return false;

	/* Convert data appropriately */

	switch (*type) {
		case REG_SZ:
		case REG_EXPAND_SZ:
			return convert_string_talloc(mem_ctx,
								 CH_UNIX, CH_UTF16, data_str,
								 strlen(data_str)+1,
								 (void **)&data->data,
								 &data->length, false);
			break;
		case REG_BINARY:
			*data = strhex_to_data_blob(mem_ctx, data_str);
			break;
		case REG_DWORD:
		case REG_DWORD_BIG_ENDIAN: {
			uint32_t tmp = strtol(data_str, NULL, 0);
			*data = data_blob_talloc(mem_ctx, NULL, sizeof(uint32_t));
			if (data->data == NULL) return false;
			SIVAL(data->data, 0, tmp);
			}
			break;
		case REG_QWORD: {
			uint64_t tmp = strtoll(data_str, NULL, 0);
			*data = data_blob_talloc(mem_ctx, NULL, sizeof(uint64_t));
			if (data->data == NULL) return false;
			SBVAL(data->data, 0, tmp);
			}
			break;
		case REG_NONE:
			ZERO_STRUCTP(data);
			break;
		case REG_MULTI_SZ:
			/* FIXME: We don't support this yet */
			return false;
		default:
			/* FIXME */
			/* Other datatypes aren't supported -> return no success */
			return false;
	}
	return true;
}

/** Open a key by name (including the predefined key name!) */
WERROR reg_open_key_abs(TALLOC_CTX *mem_ctx, struct registry_context *handle,
			const char *name, struct registry_key **result)
{
	struct registry_key *predef;
	WERROR error;
	size_t predeflength;
	char *predefname;

	if (strchr(name, '\\') != NULL)
		predeflength = strchr(name, '\\')-name;
	else
		predeflength = strlen(name);

	predefname = talloc_strndup(mem_ctx, name, predeflength);
	W_ERROR_HAVE_NO_MEMORY(predefname);
	error = reg_get_predefined_key_by_name(handle, predefname, &predef);
	talloc_free(predefname);

	if (!W_ERROR_IS_OK(error)) {
		return error;
	}

	if (strchr(name, '\\')) {
		return reg_open_key(mem_ctx, predef, strchr(name, '\\')+1,
				    result);
	} else {
		*result = predef;
		return WERR_OK;
	}
}

static WERROR get_abs_parent(TALLOC_CTX *mem_ctx, struct registry_context *ctx,
			     const char *path, struct registry_key **parent,
			     const char **name)
{
	char *parent_name;
	WERROR error;

	if (strchr(path, '\\') == NULL) {
		return WERR_FOOBAR;
	}

	parent_name = talloc_strndup(mem_ctx, path, strrchr(path, '\\')-path);
	W_ERROR_HAVE_NO_MEMORY(parent_name);
	error = reg_open_key_abs(mem_ctx, ctx, parent_name, parent);
	talloc_free(parent_name);
	if (!W_ERROR_IS_OK(error)) {
		return error;
	}

	*name = talloc_strdup(mem_ctx, strrchr(path, '\\')+1);
	W_ERROR_HAVE_NO_MEMORY(*name);

	return WERR_OK;
}

WERROR reg_key_del_abs(struct registry_context *ctx, const char *path)
{
	struct registry_key *parent;
	const char *n;
	TALLOC_CTX *mem_ctx = talloc_init("reg_key_del_abs");
	WERROR error;

	if (!strchr(path, '\\')) {
		return WERR_FOOBAR;
	}

	error = get_abs_parent(mem_ctx, ctx, path, &parent, &n);
	if (W_ERROR_IS_OK(error)) {
		error = reg_key_del(mem_ctx, parent, n);
	}

	talloc_free(mem_ctx);

	return error;
}

WERROR reg_key_add_abs(TALLOC_CTX *mem_ctx, struct registry_context *ctx,
		       const char *path, uint32_t access_mask,
		       struct security_descriptor *sec_desc,
		       struct registry_key **result)
{
	struct registry_key *parent;
	const char *n;
	WERROR error;

	*result = NULL;

	if (!strchr(path, '\\')) {
		return WERR_ALREADY_EXISTS;
	}

	error = get_abs_parent(mem_ctx, ctx, path, &parent, &n);
	if (!W_ERROR_IS_OK(error)) {
		DEBUG(2, ("Opening parent of %s failed with %s\n", path,
				  win_errstr(error)));
		return error;
	}

	error = reg_key_add_name(mem_ctx, parent, n, NULL, sec_desc, result);

	return error;
}
