/* 
   Unix SMB/CIFS implementation.

   endpoint server for the winreg pipe

   Copyright (C) Jelmer Vernooij 2004
   
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
#include "rpc_server/dcerpc_server.h"
#include "lib/registry/registry.h"
#include "librpc/gen_ndr/ndr_winreg.h"
#include "rpc_server/common/common.h"
#include "librpc/gen_ndr/ndr_security.h"

enum handle_types { HTYPE_REGVAL, HTYPE_REGKEY };

static NTSTATUS dcerpc_winreg_bind(struct dcesrv_call_state *dce_call, 
								   const struct dcesrv_interface *iface)
{
	struct registry_context *ctx;
	WERROR err;

	err = reg_open_samba(dce_call->context,
			     &ctx, dce_call->conn->auth_state.session_info, NULL);

	if (!W_ERROR_IS_OK(err)) {
		DEBUG(0, ("Error opening registry: %s\n", win_errstr(err)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	dce_call->context->private = ctx;

	return NT_STATUS_OK;
}

#define DCESRV_INTERFACE_WINREG_BIND dcerpc_winreg_bind

static WERROR dcesrv_winreg_openhive(struct dcesrv_call_state *dce_call, 
									 TALLOC_CTX *mem_ctx, uint32_t hkey, 
									 struct policy_handle **outh)
{
	struct registry_context *ctx = dce_call->context->private;
	struct dcesrv_handle *h; 
	WERROR error;

	h = dcesrv_handle_new(dce_call->context, HTYPE_REGKEY); 

	error = reg_get_predefined_key(ctx, hkey, (struct registry_key **)&h->data);
	if (!W_ERROR_IS_OK(error)) {
		return error;
	}
	
	*outh = &h->wire_handle; 

	return error; 
}

#define func_winreg_OpenHive(k,n) static WERROR dcesrv_winreg_Open ## k (struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct winreg_Open ## k *r) \
{ \
	return dcesrv_winreg_openhive (dce_call, mem_ctx, n, &r->out.handle);\
}

func_winreg_OpenHive(HKCR,HKEY_CLASSES_ROOT)
func_winreg_OpenHive(HKCU,HKEY_CURRENT_USER)
func_winreg_OpenHive(HKLM,HKEY_LOCAL_MACHINE)
func_winreg_OpenHive(HKPD,HKEY_PERFORMANCE_DATA)
func_winreg_OpenHive(HKU,HKEY_USERS)
func_winreg_OpenHive(HKCC,HKEY_CURRENT_CONFIG)
func_winreg_OpenHive(HKDD,HKEY_DYN_DATA)
func_winreg_OpenHive(HKPT,HKEY_PERFORMANCE_TEXT)
func_winreg_OpenHive(HKPN,HKEY_PERFORMANCE_NLSTEXT)

/* 
  winreg_CloseKey 
*/
static WERROR dcesrv_winreg_CloseKey(struct dcesrv_call_state *dce_call, 
									 TALLOC_CTX *mem_ctx,
									 struct winreg_CloseKey *r)
{
	struct dcesrv_handle *h; 

	DCESRV_PULL_HANDLE_FAULT(h, r->in.handle, HTYPE_REGKEY);

	talloc_free(h);

	ZERO_STRUCTP(r->out.handle);

	return WERR_OK;
}

/* 
  winreg_CreateKey 
*/
static WERROR dcesrv_winreg_CreateKey(struct dcesrv_call_state *dce_call, 
									  TALLOC_CTX *mem_ctx, 
									  struct winreg_CreateKey *r)
{
	struct dcesrv_handle *h, *newh;
	WERROR error;
	struct security_descriptor sd;

	DCESRV_PULL_HANDLE_FAULT(h, r->in.handle, HTYPE_REGKEY);
	
	newh = dcesrv_handle_new(dce_call->context, HTYPE_REGKEY);

	/* the security descriptor is optional */
	if (r->in.secdesc != NULL) {
		DATA_BLOB sdblob;
		NTSTATUS status;
		sdblob.data = r->in.secdesc->sd.data;
		sdblob.length = r->in.secdesc->sd.len;
		if (sdblob.data == NULL) {
			return WERR_INVALID_PARAM;
		}
		status = ndr_pull_struct_blob_all(&sdblob, mem_ctx, &sd, 
						  (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);
		if (!NT_STATUS_IS_OK(status)) {
			return WERR_INVALID_PARAM;
		}
	}

	error = reg_key_add_name(newh, (struct registry_key *)h->data, 
							 r->in.name.name, NULL, r->in.secdesc?&sd:NULL, 
							 (struct registry_key **)&newh->data);
	if (W_ERROR_IS_OK(error)) {
		r->out.new_handle = &newh->wire_handle;
	} else {
		talloc_free(newh);
	}

	return error;
}


/* 
  winreg_DeleteKey 
*/
static WERROR dcesrv_winreg_DeleteKey(struct dcesrv_call_state *dce_call, 
									  TALLOC_CTX *mem_ctx,
									  struct winreg_DeleteKey *r)
{
	struct dcesrv_handle *h;

	DCESRV_PULL_HANDLE_FAULT(h, r->in.handle, HTYPE_REGKEY);
	
	return reg_key_del((struct registry_key *)h->data, r->in.key.name);
}


/* 
  winreg_DeleteValue 
*/
static WERROR dcesrv_winreg_DeleteValue(struct dcesrv_call_state *dce_call, 
										TALLOC_CTX *mem_ctx,
										struct winreg_DeleteValue *r)
{
	struct dcesrv_handle *h;
	struct registry_key *key;

	DCESRV_PULL_HANDLE_FAULT(h, r->in.handle, HTYPE_REGKEY);

	key = h->data;
	
	return reg_del_value(key, r->in.value.name);
}


/* 
  winreg_EnumKey 
*/
static WERROR dcesrv_winreg_EnumKey(struct dcesrv_call_state *dce_call, 
									TALLOC_CTX *mem_ctx,
									struct winreg_EnumKey *r)
{
	struct dcesrv_handle *h;
	const char *name;
	NTTIME last_mod;

	DCESRV_PULL_HANDLE_FAULT(h, r->in.handle, HTYPE_REGKEY);

	r->out.result = reg_key_get_subkey_by_index(mem_ctx, 
						(struct registry_key *)h->data, r->in.enum_index, 
						&name, NULL, &last_mod);

	if (W_ERROR_IS_OK(r->out.result)) {
		if (2*strlen_m_term(name) > r->in.name->size) {
			return WERR_MORE_DATA;
		}
		r->out.name->length = 2*strlen_m_term(name);
		r->out.name->name = name;
		r->out.keyclass = talloc_zero(mem_ctx, struct winreg_StringBuf);
		if (r->in.last_changed_time) {
			r->out.last_changed_time = &last_mod;
		}
	}
	
	return r->out.result;
}


/* 
  winreg_EnumValue 
*/
static WERROR dcesrv_winreg_EnumValue(struct dcesrv_call_state *dce_call, 
									  TALLOC_CTX *mem_ctx,
									  struct winreg_EnumValue *r)
{
	struct dcesrv_handle *h;
	struct registry_key *key;
	WERROR result;
	const char *data_name;
	uint32_t data_type;
	DATA_BLOB data;

	DCESRV_PULL_HANDLE_FAULT(h, r->in.handle, HTYPE_REGKEY);

	key = h->data;

	result = reg_key_get_value_by_index(mem_ctx, key, r->in.enum_index, 
										&data_name,
										&data_type, &data);
	if (!W_ERROR_IS_OK(result)) {
		return result;
	}

	/* the client can optionally pass a NULL for type, meaning they don't
	   want that back */
	if (r->in.type != NULL) {
		r->out.type = talloc(mem_ctx, enum winreg_Type);
		*r->out.type = data_type;
	}

	/* check the client has enough room for the value */
	if (r->in.value != NULL &&
	    r->in.size != NULL && 
	    data.length > *r->in.size) {
		return WERR_MORE_DATA;
	}
	
	/* and enough room for the name */
	if (r->in.name->size < 2*strlen_m_term(data_name)) {
		return WERR_MORE_DATA;		
	}

	r->out.name->name = data_name;
	r->out.name->length = 2*strlen_m_term(data_name);
	r->out.name->size = 2*strlen_m_term(data_name);

	if (r->in.value) {
		r->out.value = data.data;
	}

	if (r->in.size) {
		r->out.size = talloc(mem_ctx, uint32_t);
		*r->out.size = data.length;
		r->out.length = r->out.size;
	}
	
	return WERR_OK;
}


/* 
  winreg_FlushKey 
*/
static WERROR dcesrv_winreg_FlushKey(struct dcesrv_call_state *dce_call, 
									 TALLOC_CTX *mem_ctx, 
									 struct winreg_FlushKey *r)
{
	struct dcesrv_handle *h;

	DCESRV_PULL_HANDLE_FAULT(h, r->in.handle, HTYPE_REGKEY);

	return reg_key_flush(h->data);
}


/* 
  winreg_GetKeySecurity 
*/
static WERROR dcesrv_winreg_GetKeySecurity(struct dcesrv_call_state *dce_call, 
										   TALLOC_CTX *mem_ctx, 
										   struct winreg_GetKeySecurity *r)
{
	struct dcesrv_handle *h;

	DCESRV_PULL_HANDLE_FAULT(h, r->in.handle, HTYPE_REGKEY);

	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_LoadKey 
*/
static WERROR dcesrv_winreg_LoadKey(struct dcesrv_call_state *dce_call, 
									TALLOC_CTX *mem_ctx, 
									struct winreg_LoadKey *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_NotifyChangeKeyValue 
*/
static WERROR dcesrv_winreg_NotifyChangeKeyValue(
					struct dcesrv_call_state *dce_call, 
					TALLOC_CTX *mem_ctx, struct winreg_NotifyChangeKeyValue *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_OpenKey 
*/
static WERROR dcesrv_winreg_OpenKey(struct dcesrv_call_state *dce_call, 
									TALLOC_CTX *mem_ctx,
									struct winreg_OpenKey *r)
{
	struct dcesrv_handle *h, *newh;
	WERROR result;

	DCESRV_PULL_HANDLE_FAULT(h, r->in.parent_handle, HTYPE_REGKEY);

	if (r->in.keyname.name && strcmp(r->in.keyname.name, "") == 0) {
		newh = talloc_reference(dce_call->context, h);
		result = WERR_OK;
	} else {
		newh = dcesrv_handle_new(dce_call->context, HTYPE_REGKEY);
		result = reg_open_key(newh, (struct registry_key *)h->data, 
				      r->in.keyname.name, (struct registry_key **)&newh->data);
	}
	
	if (W_ERROR_IS_OK(result)) {
		r->out.handle = &newh->wire_handle; 
	} else {
		talloc_free(newh);
	}
	
	return result;
}


/* 
  winreg_QueryInfoKey 
*/
static WERROR dcesrv_winreg_QueryInfoKey(struct dcesrv_call_state *dce_call, 
										 TALLOC_CTX *mem_ctx,
										 struct winreg_QueryInfoKey *r)
{
	struct dcesrv_handle *h;
	struct registry_key *k;
	WERROR ret;
	const char *classname = NULL;

	DCESRV_PULL_HANDLE_FAULT(h, r->in.handle, HTYPE_REGKEY);

	k = h->data;

	ret = reg_key_get_info(mem_ctx, k, &classname, r->out.num_subkeys, 
						   r->out.num_values, r->out.last_changed_time);

	if (r->out.classname != NULL)
		r->out.classname->name = classname;

	return ret;
}


/* 
  winreg_QueryValue 
*/
static WERROR dcesrv_winreg_QueryValue(struct dcesrv_call_state *dce_call, 
									   TALLOC_CTX *mem_ctx,
									   struct winreg_QueryValue *r)
{
	struct dcesrv_handle *h;
	struct registry_key *key;
	uint32_t value_type;
	DATA_BLOB value_data;
	WERROR result;

	DCESRV_PULL_HANDLE_FAULT(h, r->in.handle, HTYPE_REGKEY);

	key = h->data;
	
	result = reg_key_get_value_by_name(mem_ctx, key, r->in.value_name.name, 
									   &value_type, &value_data);

	if (!W_ERROR_IS_OK(result)) { 
		return result;
	}

	/* Just asking for the size of the buffer */
	r->out.type = &value_type;
	r->out.length = talloc(mem_ctx, uint32_t);
	if (!r->out.length) {
		return WERR_NOMEM;
	}
	*r->out.length = value_data.length;
	if (r->in.data == NULL) {
		r->out.size = talloc(mem_ctx, uint32_t);
		*r->out.size = value_data.length;
	} else {
		r->out.size = r->in.size;
		r->out.data = value_data.data;
	}

	return WERR_OK;
}


/* 
  winreg_ReplaceKey 
*/
static WERROR dcesrv_winreg_ReplaceKey(struct dcesrv_call_state *dce_call, 
									   TALLOC_CTX *mem_ctx,
									   struct winreg_ReplaceKey *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_RestoreKey 
*/
static WERROR dcesrv_winreg_RestoreKey(struct dcesrv_call_state *dce_call, 
									   TALLOC_CTX *mem_ctx, 
									   struct winreg_RestoreKey *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_SaveKey 
*/
static WERROR dcesrv_winreg_SaveKey(struct dcesrv_call_state *dce_call, 
									TALLOC_CTX *mem_ctx, 
									struct winreg_SaveKey *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_SetKeySecurity 
*/
static WERROR dcesrv_winreg_SetKeySecurity(struct dcesrv_call_state *dce_call, 
										   TALLOC_CTX *mem_ctx, 
										   struct winreg_SetKeySecurity *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_SetValue 
*/
static WERROR dcesrv_winreg_SetValue(struct dcesrv_call_state *dce_call, 
									 TALLOC_CTX *mem_ctx, 
									 struct winreg_SetValue *r)
{
	struct dcesrv_handle *h;
	struct registry_key *key;
	WERROR result;
	DATA_BLOB data;

	DCESRV_PULL_HANDLE_FAULT(h, r->in.handle, HTYPE_REGKEY);

	key = h->data;
	
	data.data = r->in.data;
	data.length = r->in.size;
	result = reg_val_set(key, r->in.name.name, r->in.type, data);

	return result;
}


/* 
  winreg_UnLoadKey 
*/
static WERROR dcesrv_winreg_UnLoadKey(struct dcesrv_call_state *dce_call, 
									  TALLOC_CTX *mem_ctx, 
									  struct winreg_UnLoadKey *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_InitiateSystemShutdown 
*/
static WERROR dcesrv_winreg_InitiateSystemShutdown(
						struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						struct winreg_InitiateSystemShutdown *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_AbortSystemShutdown 
*/
static WERROR dcesrv_winreg_AbortSystemShutdown(
		struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		struct winreg_AbortSystemShutdown *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_GetVersion 
*/
static WERROR dcesrv_winreg_GetVersion(struct dcesrv_call_state *dce_call, 
									   TALLOC_CTX *mem_ctx, 
									   struct winreg_GetVersion *r)
{
	struct dcesrv_handle *h;

	DCESRV_PULL_HANDLE_FAULT(h, r->in.handle, HTYPE_REGKEY);

	r->out.version = talloc(mem_ctx, uint32_t);
	W_ERROR_HAVE_NO_MEMORY(r->out.version);

	*r->out.version = 5;

	return WERR_OK;
}


/* 
  winreg_QueryMultipleValues 
*/
static WERROR dcesrv_winreg_QueryMultipleValues(
	struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
	struct winreg_QueryMultipleValues *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_InitiateSystemShutdownEx 
*/
static WERROR dcesrv_winreg_InitiateSystemShutdownEx(
		struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		struct winreg_InitiateSystemShutdownEx *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_SaveKeyEx 
*/
static WERROR dcesrv_winreg_SaveKeyEx(struct dcesrv_call_state *dce_call, 
									  TALLOC_CTX *mem_ctx,
									  struct winreg_SaveKeyEx *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_QueryMultipleValues2 
*/
static WERROR dcesrv_winreg_QueryMultipleValues2(
		struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		struct winreg_QueryMultipleValues2 *r)
{
	return WERR_NOT_SUPPORTED;
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_winreg_s.c"
