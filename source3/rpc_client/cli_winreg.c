/*
 *  Unix SMB/CIFS implementation.
 *
 *  WINREG client routines
 *
 *  Copyright (c) 2011      Andreas Schneider <asn@samba.org>
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
#include "../librpc/gen_ndr/ndr_winreg_c.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "rpc_client/cli_winreg.h"
#include "../libcli/registry/util_reg.h"

NTSTATUS dcerpc_winreg_query_dword(TALLOC_CTX *mem_ctx,
				   struct dcerpc_binding_handle *h,
				   struct policy_handle *key_handle,
				   const char *value,
				   uint32_t *data,
				   WERROR *pwerr)
{
	struct winreg_String wvalue;
	enum winreg_Type type = REG_NONE;
	uint32_t value_len = 0;
	uint32_t data_size = 0;
	NTSTATUS status;
	DATA_BLOB blob;

	wvalue.name = value;

	status = dcerpc_winreg_QueryValue(h,
					  mem_ctx,
					  key_handle,
					  &wvalue,
					  &type,
					  NULL,
					  &data_size,
					  &value_len,
					  pwerr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(*pwerr)) {
		return status;
	}

	if (type != REG_DWORD) {
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (data_size != 4) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	blob = data_blob_talloc_zero(mem_ctx, data_size);
	if (blob.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	value_len = 0;

	status = dcerpc_winreg_QueryValue(h,
					  mem_ctx,
					  key_handle,
					  &wvalue,
					  &type,
					  blob.data,
					  &data_size,
					  &value_len,
					  pwerr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(*pwerr)) {
		return status;
	}

	if (data) {
		*data = IVAL(blob.data, 0);
	}

	return status;
}

NTSTATUS dcerpc_winreg_query_binary(TALLOC_CTX *mem_ctx,
				    struct dcerpc_binding_handle *h,
				    struct policy_handle *key_handle,
				    const char *value,
				    DATA_BLOB *data,
				    WERROR *pwerr)
{
	struct winreg_String wvalue;
	enum winreg_Type type = REG_NONE;
	uint32_t value_len = 0;
	uint32_t data_size = 0;
	NTSTATUS status;
	DATA_BLOB blob;

	ZERO_STRUCT(wvalue);
	wvalue.name = value;

	status = dcerpc_winreg_QueryValue(h,
					  mem_ctx,
					  key_handle,
					  &wvalue,
					  &type,
					  NULL,
					  &data_size,
					  &value_len,
					  pwerr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(*pwerr)) {
		return status;
	}

	if (type != REG_BINARY) {
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	blob = data_blob_talloc_zero(mem_ctx, data_size);
	if (blob.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	value_len = 0;

	status = dcerpc_winreg_QueryValue(h,
					  mem_ctx,
					  key_handle,
					  &wvalue,
					  &type,
					  blob.data,
					  &data_size,
					  &value_len,
					  pwerr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(*pwerr)) {
		return status;
	}

	if (data) {
		data->data = blob.data;
		data->length = blob.length;
	}

	return status;
}

NTSTATUS dcerpc_winreg_query_multi_sz(TALLOC_CTX *mem_ctx,
				      struct dcerpc_binding_handle *h,
				      struct policy_handle *key_handle,
				      const char *value,
				      const char ***data,
				      WERROR *pwerr)
{
	struct winreg_String wvalue;
	enum winreg_Type type = REG_NONE;
	uint32_t value_len = 0;
	uint32_t data_size = 0;
	NTSTATUS status;
	DATA_BLOB blob;

	wvalue.name = value;

	status = dcerpc_winreg_QueryValue(h,
					  mem_ctx,
					  key_handle,
					  &wvalue,
					  &type,
					  NULL,
					  &data_size,
					  &value_len,
					  pwerr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(*pwerr)) {
		return status;
	}

	if (type != REG_MULTI_SZ) {
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	blob = data_blob_talloc_zero(mem_ctx, data_size);
	if (blob.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	value_len = 0;

	status = dcerpc_winreg_QueryValue(h,
					  mem_ctx,
					  key_handle,
					  &wvalue,
					  &type,
					  blob.data,
					  &data_size,
					  &value_len,
					  pwerr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(*pwerr)) {
		return status;
	}

	if (data) {
		bool ok;

		ok = pull_reg_multi_sz(mem_ctx, &blob, data);
		if (!ok) {
			status = NT_STATUS_NO_MEMORY;
		}
	}

	return status;
}

NTSTATUS dcerpc_winreg_query_sz(TALLOC_CTX *mem_ctx,
				      struct dcerpc_binding_handle *h,
				      struct policy_handle *key_handle,
				      const char *value,
				      const char **data,
				      WERROR *pwerr)
{
	struct winreg_String wvalue;
	enum winreg_Type type = REG_NONE;
	uint32_t value_len = 0;
	uint32_t data_size = 0;
	NTSTATUS status;
	DATA_BLOB blob;

	wvalue.name = value;

	status = dcerpc_winreg_QueryValue(h,
					  mem_ctx,
					  key_handle,
					  &wvalue,
					  &type,
					  NULL,
					  &data_size,
					  &value_len,
					  pwerr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(*pwerr)) {
		return status;
	}

	if (type != REG_SZ) {
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	blob = data_blob_talloc_zero(mem_ctx, data_size);
	if (blob.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	value_len = 0;

	status = dcerpc_winreg_QueryValue(h,
					  mem_ctx,
					  key_handle,
					  &wvalue,
					  &type,
					  blob.data,
					  &data_size,
					  &value_len,
					  pwerr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(*pwerr)) {
		return status;
	}

	if (data) {
		bool ok;

		ok = pull_reg_sz(mem_ctx, &blob, data);
		if (!ok) {
			status = NT_STATUS_NO_MEMORY;
		}
	}

	return status;
}

NTSTATUS dcerpc_winreg_query_sd(TALLOC_CTX *mem_ctx,
				struct dcerpc_binding_handle *h,
				struct policy_handle *key_handle,
				const char *value,
				struct security_descriptor **data,
				WERROR *pwerr)
{
	NTSTATUS status;
	DATA_BLOB blob;

	status = dcerpc_winreg_query_binary(mem_ctx,
					    h,
					    key_handle,
					    value,
					    &blob,
					    pwerr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(*pwerr)) {
		return status;
	}

	if (data) {
		struct security_descriptor *sd;
		enum ndr_err_code ndr_err;

		sd = talloc_zero(mem_ctx, struct security_descriptor);
		if (sd == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		ndr_err = ndr_pull_struct_blob(&blob,
					       sd,
					       sd,
					       (ndr_pull_flags_fn_t) ndr_pull_security_descriptor);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(2, ("dcerpc_winreg_query_sd: Failed to marshall "
				  "security descriptor\n"));
			return NT_STATUS_NO_MEMORY;
		}

		*data = sd;
	}

	return status;
}

NTSTATUS dcerpc_winreg_set_dword(TALLOC_CTX *mem_ctx,
				 struct dcerpc_binding_handle *h,
				 struct policy_handle *key_handle,
				 const char *value,
				 uint32_t data,
				 WERROR *pwerr)
{
	struct winreg_String wvalue;
	DATA_BLOB blob;
	NTSTATUS status;

	ZERO_STRUCT(wvalue);
	wvalue.name = value;
	blob = data_blob_talloc_zero(mem_ctx, 4);
	SIVAL(blob.data, 0, data);

	status = dcerpc_winreg_SetValue(h,
					mem_ctx,
					key_handle,
					wvalue,
					REG_DWORD,
					blob.data,
					blob.length,
					pwerr);

	return status;
}

NTSTATUS dcerpc_winreg_set_sz(TALLOC_CTX *mem_ctx,
			      struct dcerpc_binding_handle *h,
			      struct policy_handle *key_handle,
			      const char *value,
			      const char *data,
			      WERROR *pwerr)
{
	struct winreg_String wvalue = { 0, };
	DATA_BLOB blob;
	NTSTATUS status;

	wvalue.name = value;
	if (data == NULL) {
		blob = data_blob_string_const("");
	} else {
		if (!push_reg_sz(mem_ctx, &blob, data)) {
			DEBUG(2, ("dcerpc_winreg_set_sz: Could not marshall "
				  "string %s for %s\n",
				  data, wvalue.name));
			return NT_STATUS_NO_MEMORY;
		}
	}

	status = dcerpc_winreg_SetValue(h,
					mem_ctx,
					key_handle,
					wvalue,
					REG_SZ,
					blob.data,
					blob.length,
					pwerr);

	return status;
}

NTSTATUS dcerpc_winreg_set_expand_sz(TALLOC_CTX *mem_ctx,
				     struct dcerpc_binding_handle *h,
				     struct policy_handle *key_handle,
				     const char *value,
				     const char *data,
				     WERROR *pwerr)
{
	struct winreg_String wvalue = { 0, };
	DATA_BLOB blob;
	NTSTATUS status;

	wvalue.name = value;
	if (data == NULL) {
		blob = data_blob_string_const("");
	} else {
		if (!push_reg_sz(mem_ctx, &blob, data)) {
			DEBUG(2, ("dcerpc_winreg_set_expand_sz: Could not marshall "
				  "string %s for %s\n",
				  data, wvalue.name));
			return NT_STATUS_NO_MEMORY;
		}
	}

	status = dcerpc_winreg_SetValue(h,
					mem_ctx,
					key_handle,
					wvalue,
					REG_EXPAND_SZ,
					blob.data,
					blob.length,
					pwerr);

	return status;
}

NTSTATUS dcerpc_winreg_set_multi_sz(TALLOC_CTX *mem_ctx,
				    struct dcerpc_binding_handle *h,
				    struct policy_handle *key_handle,
				    const char *value,
				    const char **data,
				    WERROR *pwerr)
{
	struct winreg_String wvalue = { 0, };
	DATA_BLOB blob;
	NTSTATUS status;

	wvalue.name = value;
	if (!push_reg_multi_sz(mem_ctx, &blob, data)) {
		DEBUG(2, ("dcerpc_winreg_set_multi_sz: Could not marshall "
			  "string multi sz for %s\n",
			  wvalue.name));
		return NT_STATUS_NO_MEMORY;
	}

	status = dcerpc_winreg_SetValue(h,
					mem_ctx,
					key_handle,
					wvalue,
					REG_MULTI_SZ,
					blob.data,
					blob.length,
					pwerr);

	return status;
}

NTSTATUS dcerpc_winreg_set_binary(TALLOC_CTX *mem_ctx,
				  struct dcerpc_binding_handle *h,
				  struct policy_handle *key_handle,
				  const char *value,
				  DATA_BLOB *data,
				  WERROR *pwerr)
{
	struct winreg_String wvalue = { 0, };
	NTSTATUS status;

	wvalue.name = value;

	status = dcerpc_winreg_SetValue(h,
					mem_ctx,
					key_handle,
					wvalue,
					REG_BINARY,
					data->data,
					data->length,
					pwerr);

	return status;
}

NTSTATUS dcerpc_winreg_set_sd(TALLOC_CTX *mem_ctx,
			      struct dcerpc_binding_handle *h,
			      struct policy_handle *key_handle,
			      const char *value,
			      const struct security_descriptor *data,
			      WERROR *pwerr)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;

	ndr_err = ndr_push_struct_blob(&blob,
				       mem_ctx,
				       data,
				       (ndr_push_flags_fn_t) ndr_push_security_descriptor);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(2, ("dcerpc_winreg_set_sd: Failed to marshall security "
			  "descriptor\n"));
		return NT_STATUS_NO_MEMORY;
	}

	return dcerpc_winreg_set_binary(mem_ctx,
					h,
					key_handle,
					value,
					&blob,
					pwerr);
}

NTSTATUS dcerpc_winreg_add_multi_sz(TALLOC_CTX *mem_ctx,
				    struct dcerpc_binding_handle *h,
				    struct policy_handle *key_handle,
				    const char *value,
				    const char *data,
				    WERROR *pwerr)
{
	const char **a = NULL;
	const char **p;
	uint32_t i;
	NTSTATUS status;

	status = dcerpc_winreg_query_multi_sz(mem_ctx,
					      h,
					      key_handle,
					      value,
					      &a,
					      pwerr);

	/* count the elements */
	for (p = a, i = 0; p && *p; p++, i++);

	p = talloc_realloc(mem_ctx, a, const char *, i + 2);
	if (p == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	p[i] = data;
	p[i + 1] = NULL;

	status = dcerpc_winreg_set_multi_sz(mem_ctx,
					    h,
					    key_handle,
					    value,
					    p,
					    pwerr);

	return status;
}

NTSTATUS dcerpc_winreg_enum_keys(TALLOC_CTX *mem_ctx,
				 struct dcerpc_binding_handle *h,
				 struct policy_handle *key_hnd,
				 uint32_t *pnum_subkeys,
				 const char ***psubkeys,
				 WERROR *pwerr)
{
	const char **subkeys;
	uint32_t num_subkeys, max_subkeylen, max_classlen;
	uint32_t num_values, max_valnamelen, max_valbufsize;
	uint32_t i;
	NTTIME last_changed_time;
	uint32_t secdescsize;
	struct winreg_String classname;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCT(classname);

	status = dcerpc_winreg_QueryInfoKey(h,
					    tmp_ctx,
					    key_hnd,
					    &classname,
					    &num_subkeys,
					    &max_subkeylen,
					    &max_classlen,
					    &num_values,
					    &max_valnamelen,
					    &max_valbufsize,
					    &secdescsize,
					    &last_changed_time,
					    pwerr);
	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}
	if (!W_ERROR_IS_OK(*pwerr)) {
		goto error;
	}

	subkeys = talloc_zero_array(tmp_ctx, const char *, num_subkeys + 2);
	if (subkeys == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto error;
	}

	if (num_subkeys == 0) {
		subkeys[0] = talloc_strdup(subkeys, "");
		if (subkeys[0] == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto error;
		}
		*pnum_subkeys = 0;
		if (psubkeys) {
			*psubkeys = talloc_move(mem_ctx, &subkeys);
		}

		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_OK;
	}

	for (i = 0; i < num_subkeys; i++) {
		char c = '\0';
		char n = '\0';
		char *name = NULL;
		struct winreg_StringBuf class_buf;
		struct winreg_StringBuf name_buf;
		NTTIME modtime;

		class_buf.name = &c;
		class_buf.size = max_classlen + 2;
		class_buf.length = 0;

		name_buf.name = &n;
		name_buf.size = max_subkeylen + 2;
		name_buf.length = 0;

		ZERO_STRUCT(modtime);

		status = dcerpc_winreg_EnumKey(h,
					       tmp_ctx,
					       key_hnd,
					       i,
					       &name_buf,
					       &class_buf,
					       &modtime,
					       pwerr);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(5, ("dcerpc_winreg_enum_keys: Could not enumerate keys: %s\n",
				  nt_errstr(status)));
			goto error;
		}

		if (W_ERROR_EQUAL(*pwerr, WERR_NO_MORE_ITEMS)) {
			*pwerr = WERR_OK;
			break;
		}
		if (!W_ERROR_IS_OK(*pwerr)) {
			DEBUG(5, ("dcerpc_winreg_enum_keys: Could not enumerate keys: %s\n",
				  win_errstr(*pwerr)));
			goto error;
		}

		if (name_buf.name == NULL) {
			*pwerr = WERR_INVALID_PARAMETER;
			goto error;
		}

		name = talloc_strdup(subkeys, name_buf.name);
		if (name == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto error;
		}

		subkeys[i] = name;
	}

	*pnum_subkeys = num_subkeys;
	if (psubkeys) {
		*psubkeys = talloc_move(mem_ctx, &subkeys);
	}

 error:
	TALLOC_FREE(tmp_ctx);

	return status;
}

NTSTATUS dcerpc_winreg_enumvals(TALLOC_CTX *mem_ctx,
					struct dcerpc_binding_handle *h,
					struct policy_handle *key_hnd,
					uint32_t *pnum_values,
					const char ***pnames,
					enum winreg_Type **_type,
					DATA_BLOB **pdata,
					WERROR *pwerr)
{
	TALLOC_CTX *tmp_ctx;
	uint32_t num_subkeys = 0, max_subkeylen = 0, max_classlen = 0;
	uint32_t num_values = 0, max_valnamelen = 0, max_valbufsize = 0;
	uint32_t secdescsize = 0;
	uint32_t i;
	NTTIME last_changed_time = 0;
	struct winreg_String classname;

	const char **enum_names = NULL;
	enum winreg_Type *enum_types = NULL;
	DATA_BLOB *enum_data_blobs = NULL;


	WERROR result = WERR_OK;
	NTSTATUS status = NT_STATUS_OK;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {

		status = NT_STATUS_NO_MEMORY;
		*pwerr = ntstatus_to_werror(status);
		return status;
	}

	ZERO_STRUCT(classname);

	status = dcerpc_winreg_QueryInfoKey(h,
					    tmp_ctx,
					    key_hnd,
					    &classname,
					    &num_subkeys,
					    &max_subkeylen,
					    &max_classlen,
					    &num_values,
					    &max_valnamelen,
					    &max_valbufsize,
					    &secdescsize,
					    &last_changed_time,
					    &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("dcerpc_winreg_enumvals: Could not query info: %s\n",
			  nt_errstr(status)));
		goto error;
	}
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("dcerpc_winreg_enumvals: Could not query info: %s\n",
			  win_errstr(result)));
		*pwerr = result;
		goto error;
	}

	if (num_values == 0) {
		*pnum_values = 0;
		TALLOC_FREE(tmp_ctx);
		*pwerr = WERR_OK;
		return status;
	}

	enum_names = talloc_zero_array(tmp_ctx, const char *, num_values);

	if (enum_names == NULL) {
		*pwerr = WERR_NOMEM;
		goto error;
	}

	enum_types = talloc_zero_array(tmp_ctx, enum winreg_Type, num_values);

	if (enum_types == NULL) {
		*pwerr = WERR_NOMEM;
		goto error;
	}

	enum_data_blobs = talloc_zero_array(tmp_ctx, DATA_BLOB, num_values);

	if (enum_data_blobs == NULL) {
		*pwerr = WERR_NOMEM;
		goto error;
	}

	for (i = 0; i < num_values; i++) {
		const char *name;
		struct winreg_ValNameBuf name_buf;
		enum winreg_Type type = REG_NONE;
		uint8_t *data;
		uint32_t data_size;
		uint32_t length;
		char n = '\0';


		name_buf.name = &n;
		name_buf.size = max_valnamelen + 2;
		name_buf.length = 0;

		data_size = max_valbufsize;
		data = NULL;
		if (data_size) {
			data = (uint8_t *) TALLOC(tmp_ctx, data_size);
		}
		length = 0;

		status = dcerpc_winreg_EnumValue(h,
						 tmp_ctx,
						 key_hnd,
						 i,
						 &name_buf,
						 &type,
						 data,
						 data_size ? &data_size : NULL,
						 &length,
						 &result);
		if (W_ERROR_EQUAL(result, WERR_NO_MORE_ITEMS) ) {
			result = WERR_OK;
			status = NT_STATUS_OK;
			break;
		}

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("dcerpc_winreg_enumvals: Could not enumerate values: %s\n",
				  nt_errstr(status)));
			goto error;
		}
		if (!W_ERROR_IS_OK(result)) {
			DEBUG(0, ("dcerpc_winreg_enumvals: Could not enumerate values: %s\n",
				  win_errstr(result)));
			*pwerr = result;
			goto error;
		}

		if (name_buf.name == NULL) {
			result = WERR_INVALID_PARAMETER;
			*pwerr = result;
			goto error;
		}

		name = talloc_strdup(enum_names, name_buf.name);
		if (name == NULL) {
			result = WERR_NOMEM;
			*pwerr = result;
			goto error;
		}
	/* place name, type and datablob in the enum return params */

		enum_data_blobs[i] = data_blob_talloc(enum_data_blobs, data, length);
		enum_names[i] = name;
		enum_types[i] = type;

	}
	/* move to the main mem context */
	*pnum_values = num_values;
	if (pnames) {
		*pnames = talloc_move(mem_ctx, &enum_names);
	}
	/* can this fail in any way? */
	if (_type) {
		*_type = talloc_move(mem_ctx, &enum_types);
	}

	if (pdata){
		*pdata = talloc_move(mem_ctx, &enum_data_blobs);
	}


	result = WERR_OK;

 error:
	TALLOC_FREE(tmp_ctx);
	*pwerr = result;

	return status;
}

NTSTATUS dcerpc_winreg_delete_subkeys_recursive(TALLOC_CTX *mem_ctx,
						struct dcerpc_binding_handle *h,
						struct policy_handle *hive_handle,
						uint32_t access_mask,
						const char *key,
						WERROR *pwerr)
{
	const char **subkeys = NULL;
	uint32_t num_subkeys = 0;
	struct policy_handle key_hnd;
	struct winreg_String wkey = { 0, };
	WERROR result = WERR_OK;
	NTSTATUS status = NT_STATUS_OK;
	uint32_t i;

	ZERO_STRUCT(key_hnd);
	wkey.name = key;

	DEBUG(2, ("dcerpc_winreg_delete_subkeys_recursive: delete key %s\n", key));
	/* open the key */
	status = dcerpc_winreg_OpenKey(h,
				       mem_ctx,
				       hive_handle,
				       wkey,
				       0,
				       access_mask,
				       &key_hnd,
				       &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("dcerpc_winreg_delete_subkeys_recursive: Could not open key %s: %s\n",
			  wkey.name, nt_errstr(status)));
		goto done;
	}
	if (!W_ERROR_IS_OK(result)) {
		DEBUG(0, ("dcerpc_winreg_delete_subkeys_recursive: Could not open key %s: %s\n",
			  wkey.name, win_errstr(result)));
		*pwerr = result;
		goto done;
	}

	status = dcerpc_winreg_enum_keys(mem_ctx,
					 h,
					 &key_hnd,
					 &num_subkeys,
					 &subkeys,
					 &result);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	if (!W_ERROR_IS_OK(result)) {
		goto done;
	}

	for (i = 0; i < num_subkeys; i++) {
		/* create key + subkey */
		char *subkey = talloc_asprintf(mem_ctx, "%s\\%s", key, subkeys[i]);
		if (subkey == NULL) {
			goto done;
		}

		DEBUG(2, ("dcerpc_winreg_delete_subkeys_recursive: delete subkey %s\n", subkey));
		status = dcerpc_winreg_delete_subkeys_recursive(mem_ctx,
								h,
								hive_handle,
								access_mask,
								subkey,
								&result);
		if (!W_ERROR_IS_OK(result)) {
			goto done;
		}
	}

	if (is_valid_policy_hnd(&key_hnd)) {
		WERROR ignore;
		dcerpc_winreg_CloseKey(h, mem_ctx, &key_hnd, &ignore);
	}

	wkey.name = key;

	status = dcerpc_winreg_DeleteKey(h,
					 mem_ctx,
					 hive_handle,
					 wkey,
					 &result);
	if (!NT_STATUS_IS_OK(status)) {
		*pwerr = result;
		goto done;
	}

done:
	if (is_valid_policy_hnd(&key_hnd)) {
		WERROR ignore;

		dcerpc_winreg_CloseKey(h, mem_ctx, &key_hnd, &ignore);
	}

	*pwerr = result;
	return status;
}

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
