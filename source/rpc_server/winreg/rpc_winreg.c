/* 
   Unix SMB/CIFS implementation.

   endpoint server for the winreg pipe

   Copyright (C) Jelmer Vernooij 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "rpc_server/common/common.h"

/**
 * General notes for the current implementation:
 * 
 * - All hives are currently openened as subkeys of one single registry file 
 *   (e.g. HKCR from \HKEY_CURRENT_USER, etc). This might be changed in 
 *   the future and we might want to make it possible to configure 
 *   what registries are behind which hives (e.g. 
 *   	\HKEY_CURRENT_USER -> gconf,
 *   	\HKEY_LOCAL_MACHINE -> tdb,
 *   	etc
 */

enum handle_types { HTYPE_REGKEY, HTYPE_REGVAL };

struct _privatedata {
	struct registry_context *registry;
};


/* this function is called when the client disconnects the endpoint */
static void winreg_unbind(struct dcesrv_connection *dc, const struct dcesrv_interface *di) 
{
}

static NTSTATUS winreg_bind(struct dcesrv_call_state *dc, const struct dcesrv_interface *di) 
{
	struct _privatedata *data;
	WERROR error;
	data = talloc_p(dc->conn, struct _privatedata);
	error = reg_open(&data->registry, "dir", "/tmp/reg", "");
	if(!W_ERROR_IS_OK(error)) return werror_to_ntstatus(error);
	dc->conn->private = data;
	return NT_STATUS_OK;
}

#define DCESRV_INTERFACE_WINREG_BIND winreg_bind
#define DCESRV_INTERFACE_WINREG_UNBIND winreg_unbind

#define func_winreg_OpenHive(k,n) static WERROR winreg_Open ## k (struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct winreg_Open ## k *r) \
{ \
	struct _privatedata *data = dce_call->conn->private; \
	struct registry_key *root; \
	struct dcesrv_handle *h; \
	WERROR error = reg_get_hive(data->registry, n, &root); \
	if(!W_ERROR_IS_OK(error)) return error; \
	\
	h = dcesrv_handle_new(dce_call->conn, HTYPE_REGKEY); \
	DCESRV_CHECK_HANDLE(h); \
	h->data = root; \
	r->out.handle = &h->wire_handle; \
	return WERR_OK; \
}

func_winreg_OpenHive(HKCR,"\\HKEY_CLASSES_ROOT")
func_winreg_OpenHive(HKCU,"\\HKEY_CURRENT_USER")
func_winreg_OpenHive(HKLM,"\\HKEY_LOCAL_MACHINE")
func_winreg_OpenHive(HKPD,"\\HKEY_PERFORMANCE_DATA")
func_winreg_OpenHive(HKU,"\\HKEY_USERS")
func_winreg_OpenHive(HKCC,"\\HKEY_CC")
func_winreg_OpenHive(HKDD,"\\HKEY_DD")
func_winreg_OpenHive(HKPT,"\\HKEY_PT")
func_winreg_OpenHive(HKPN,"\\HKEY_PN")

/* 
  winreg_CloseKey 
*/
static WERROR winreg_CloseKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_CloseKey *r)
{
	struct dcesrv_handle *h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);

	DCESRV_CHECK_HANDLE(h);

	dcesrv_handle_destroy(dce_call->conn, h);

	return WERR_OK;
}


/* 
  winreg_CreateKey 
*/
static WERROR winreg_CreateKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_CreateKey *r)
{
	struct dcesrv_handle *h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	WERROR error;
	struct registry_key *parent;

	DCESRV_CHECK_HANDLE(h);

	parent = h->data;
	error = reg_key_add_name_recursive(parent, r->in.key.name);
	if(W_ERROR_IS_OK(error)) {
		struct dcesrv_handle *newh = dcesrv_handle_new(dce_call->conn, HTYPE_REGKEY);
		error = reg_open_key(parent->hive->reg_ctx->mem_ctx, parent, r->in.key.name, (struct registry_key **)&newh->data);
		if(W_ERROR_IS_OK(error)) r->out.handle = &newh->wire_handle;
		else dcesrv_handle_destroy(dce_call->conn, newh);
	}

	return error;
}


/* 
  winreg_DeleteKey 
*/
static WERROR winreg_DeleteKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_DeleteKey *r)
{
	struct dcesrv_handle *h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	struct registry_key *parent, *key;
	WERROR result;

	DCESRV_CHECK_HANDLE(h);

	parent = h->data;
	result = reg_open_key(parent->hive->reg_ctx->mem_ctx, parent, r->in.key.name, &key);

	if (W_ERROR_IS_OK(result)) {
		return reg_key_del(key);
	}

	return result;
}


/* 
  winreg_DeleteValue 
*/
static WERROR winreg_DeleteValue(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_DeleteValue *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_EnumKey 
*/
static WERROR winreg_EnumKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_EnumKey *r)
{
	struct dcesrv_handle *h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	struct registry_key *key;

	DCESRV_CHECK_HANDLE(h);

	key = h->data;
	
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_EnumValue 
*/
static WERROR winreg_EnumValue(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_EnumValue *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_FlushKey 
*/
static WERROR winreg_FlushKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_FlushKey *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_GetKeySecurity 
*/
static WERROR winreg_GetKeySecurity(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_GetKeySecurity *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_LoadKey 
*/
static WERROR winreg_LoadKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_LoadKey *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_NotifyChangeKeyValue 
*/
static WERROR winreg_NotifyChangeKeyValue(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_NotifyChangeKeyValue *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_OpenKey 
*/
static WERROR winreg_OpenKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_OpenKey *r)
{
	struct dcesrv_handle *h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	struct registry_key *k, *subkey;
	WERROR result;

	DCESRV_CHECK_HANDLE(h);

	k = h->data;


	result = reg_open_key(k->hive->reg_ctx->mem_ctx, k, r->in.keyname.name, &subkey);
	if (W_ERROR_IS_OK(result)) {
		h->data = subkey; 
		r->out.handle = &h->wire_handle; 
	}
	
	return result;
}


/* 
  winreg_QueryInfoKey 
*/
static WERROR winreg_QueryInfoKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_QueryInfoKey *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_QueryValue 
*/
static WERROR winreg_QueryValue(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_QueryValue *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_ReplaceKey 
*/
static WERROR winreg_ReplaceKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_ReplaceKey *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_RestoreKey 
*/
static WERROR winreg_RestoreKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_RestoreKey *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_SaveKey 
*/
static WERROR winreg_SaveKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_SaveKey *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_SetKeySecurity 
*/
static WERROR winreg_SetKeySecurity(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_SetKeySecurity *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_SetValue 
*/
static WERROR winreg_SetValue(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_SetValue *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_UnLoadKey 
*/
static WERROR winreg_UnLoadKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_UnLoadKey *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_InitiateSystemShutdown 
*/
static WERROR winreg_InitiateSystemShutdown(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_InitiateSystemShutdown *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_AbortSystemShutdown 
*/
static WERROR winreg_AbortSystemShutdown(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_AbortSystemShutdown *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_GetVersion 
*/
static WERROR winreg_GetVersion(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_GetVersion *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_QueryMultipleValues 
*/
static WERROR winreg_QueryMultipleValues(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_QueryMultipleValues *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_InitiateSystemShutdownEx 
*/
static WERROR winreg_InitiateSystemShutdownEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_InitiateSystemShutdownEx *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_SaveKeyEx 
*/
static WERROR winreg_SaveKeyEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_SaveKeyEx *r)
{
	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_QueryMultipleValues2 
*/
static WERROR winreg_QueryMultipleValues2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_QueryMultipleValues2 *r)
{
	return WERR_NOT_SUPPORTED;
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_winreg_s.c"
