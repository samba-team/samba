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
#include "rpc_client/cli_winreg.h"

NTSTATUS dcerpc_winreg_query_dword(TALLOC_CTX *mem_ctx,
				   struct dcerpc_binding_handle *h,
				   struct policy_handle *key_handle,
				   const char *value,
				   uint32_t *data,
				   WERROR *pwerr)
{
	struct winreg_String wvalue;
	enum winreg_Type type;
	uint32_t value_len = 0;
	uint32_t data_size = 0;
	WERROR result = WERR_OK;
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
					  &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(result)) {
		*pwerr = result;
		return status;
	}

	if (type != REG_DWORD) {
		*pwerr = WERR_INVALID_DATATYPE;
		return status;
	}

	if (data_size != 4) {
		*pwerr = WERR_INVALID_DATA;
		return status;
	}

	blob = data_blob_talloc(mem_ctx, NULL, data_size);
	if (blob.data == NULL) {
		*pwerr = WERR_NOMEM;
		return status;
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
					  &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(result)) {
		*pwerr = result;
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
	enum winreg_Type type;
	WERROR result = WERR_OK;
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
					  &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(result)) {
		*pwerr = result;
		return status;
	}

	if (type != REG_BINARY) {
		*pwerr = WERR_INVALID_DATATYPE;
		return status;
	}

	blob = data_blob_talloc(mem_ctx, NULL, data_size);
	if (blob.data == NULL) {
		*pwerr = WERR_NOMEM;
		return status;
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
					  &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(result)) {
		*pwerr = result;
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
	enum winreg_Type type;
	WERROR result = WERR_OK;
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
					  &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(result)) {
		*pwerr = result;
		return status;
	}

	if (type != REG_MULTI_SZ) {
		*pwerr = WERR_INVALID_DATATYPE;
		return status;
	}

	blob = data_blob_talloc(mem_ctx, NULL, data_size);
	if (blob.data == NULL) {
		*pwerr = WERR_NOMEM;
		return status;
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
					  &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(result)) {
		*pwerr = result;
		return status;
	}

	if (data) {
		bool ok;

		ok = pull_reg_multi_sz(mem_ctx, &blob, data);
		if (!ok) {
			*pwerr = WERR_NOMEM;
		}
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
	WERROR result = WERR_OK;
	NTSTATUS status;

	wvalue.name = value;
	blob = data_blob_talloc(mem_ctx, NULL, 4);
	SIVAL(blob.data, 0, data);

	status = dcerpc_winreg_SetValue(h,
					mem_ctx,
					key_handle,
					wvalue,
					REG_DWORD,
					blob.data,
					blob.length,
					&result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(result)) {
		*pwerr = result;
	}

	return status;
}

NTSTATUS dcerpc_winreg_set_sz(TALLOC_CTX *mem_ctx,
			      struct dcerpc_binding_handle *h,
			      struct policy_handle *key_handle,
			      const char *value,
			      const char *data,
			      WERROR *pwerr)
{
	struct winreg_String wvalue;
	DATA_BLOB blob;
	WERROR result = WERR_OK;
	NTSTATUS status;

	wvalue.name = value;
	if (data == NULL) {
		blob = data_blob_string_const("");
	} else {
		if (!push_reg_sz(mem_ctx, &blob, data)) {
			DEBUG(2, ("dcerpc_winreg_set_sz: Could not marshall "
				  "string %s for %s\n",
				  data, wvalue.name));
			*pwerr = WERR_NOMEM;
			return NT_STATUS_OK;
		}
	}

	status = dcerpc_winreg_SetValue(h,
					mem_ctx,
					key_handle,
					wvalue,
					REG_SZ,
					blob.data,
					blob.length,
					&result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(result)) {
		*pwerr = result;
	}

	return status;
}

NTSTATUS dcerpc_winreg_set_expand_sz(TALLOC_CTX *mem_ctx,
				     struct dcerpc_binding_handle *h,
				     struct policy_handle *key_handle,
				     const char *value,
				     const char *data,
				     WERROR *pwerr)
{
	struct winreg_String wvalue;
	DATA_BLOB blob;
	WERROR result = WERR_OK;
	NTSTATUS status;

	wvalue.name = value;
	if (data == NULL) {
		blob = data_blob_string_const("");
	} else {
		if (!push_reg_sz(mem_ctx, &blob, data)) {
			DEBUG(2, ("dcerpc_winreg_set_expand_sz: Could not marshall "
				  "string %s for %s\n",
				  data, wvalue.name));
			*pwerr = WERR_NOMEM;
			return NT_STATUS_OK;
		}
	}

	status = dcerpc_winreg_SetValue(h,
					mem_ctx,
					key_handle,
					wvalue,
					REG_EXPAND_SZ,
					blob.data,
					blob.length,
					&result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(result)) {
		*pwerr = result;
	}

	return status;
}

NTSTATUS dcerpc_winreg_set_multi_sz(TALLOC_CTX *mem_ctx,
				    struct dcerpc_binding_handle *h,
				    struct policy_handle *key_handle,
				    const char *value,
				    const char **data,
				    WERROR *pwerr)
{
	struct winreg_String wvalue;
	DATA_BLOB blob;
	WERROR result = WERR_OK;
	NTSTATUS status;

	wvalue.name = value;
	if (!push_reg_multi_sz(mem_ctx, &blob, data)) {
		DEBUG(2, ("dcerpc_winreg_set_multi_sz: Could not marshall "
			  "string multi sz for %s\n",
			  wvalue.name));
		*pwerr = WERR_NOMEM;
		return NT_STATUS_OK;
	}

	status = dcerpc_winreg_SetValue(h,
					mem_ctx,
					key_handle,
					wvalue,
					REG_MULTI_SZ,
					blob.data,
					blob.length,
					&result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!W_ERROR_IS_OK(result)) {
		*pwerr = result;
	}

	return status;
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
	WERROR result = WERR_OK;
	NTSTATUS status;

	status = dcerpc_winreg_query_multi_sz(mem_ctx,
					      h,
					      key_handle,
					      value,
					      &a,
					      &result);

	/* count the elements */
	for (p = a, i = 0; p && *p; p++, i++);

	p = TALLOC_REALLOC_ARRAY(mem_ctx, a, const char *, i + 2);
	if (p == NULL) {
		*pwerr = WERR_NOMEM;
		return NT_STATUS_OK;
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

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
