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
	REG_HANDLE *registry;
};


/* this function is called when the client disconnects the endpoint */
static void winreg_unbind(struct dcesrv_connection *dc, const struct dcesrv_interface *di) 
{
	struct _privatedata *data = dc->private;
	if (data) reg_free(data->registry);
}

static NTSTATUS winreg_bind(struct dcesrv_call_state *dc, const struct dcesrv_interface *di) 
{
	struct _privatedata *data;
	WERROR error;
	data = talloc(dc->conn->mem_ctx, sizeof(struct _privatedata));
	error = reg_open("dir", "/tmp/reg", "", &data->registry);
	if(!W_ERROR_IS_OK(error)) return werror_to_ntstatus(error);
	dc->conn->private = data;
	return NT_STATUS_OK;
}

#define DCESRV_INTERFACE_WINREG_BIND winreg_bind
#define DCESRV_INTERFACE_WINREG_UNBIND winreg_unbind

#define func_winreg_OpenHive(k,n) static NTSTATUS winreg_Open ## k (struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct winreg_Open ## k *r) \
{ \
	/*struct _privatedata *data = dce_call->conn->private;*/ \
	/*REG_KEY *root = reg_get_root(data->registry);*/ \
	REG_KEY *k /*= reg_open_key(root, n)*/; \
\
	if(!k) { \
		r->out.result = WERR_BADFILE; \
	} else { \
		struct dcesrv_handle *h = dcesrv_handle_new(dce_call->conn, HTYPE_REGKEY); \
		h->data = k; \
		r->out.handle = &h->wire_handle; \
	} \
\
	r->out.result = WERR_OK; \
\
	return NT_STATUS_OK; \
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
static NTSTATUS winreg_CloseKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_CloseKey *r)
{
	struct dcesrv_handle *h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	if(!h) {
		return NT_STATUS_INVALID_HANDLE;
	}

	reg_key_free((REG_KEY *)h->data);
	dcesrv_handle_destroy(dce_call->conn, h);

	return NT_STATUS_OK;
}


/* 
  winreg_CreateKey 
*/
static NTSTATUS winreg_CreateKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_CreateKey *r)
{
	struct dcesrv_handle *h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	WERROR error;
	REG_KEY *parent;
	if(!h) {
		return NT_STATUS_INVALID_HANDLE;
	}

	parent = h->data;
	error = reg_key_add_name_recursive(parent, r->in.key.name);
	if(W_ERROR_IS_OK(error)) {
		struct dcesrv_handle *newh = dcesrv_handle_new(dce_call->conn, HTYPE_REGKEY);
		error = reg_open_key(parent, r->in.key.name, (REG_KEY **)&newh->data);
		if(W_ERROR_IS_OK(error)) r->out.handle = &newh->wire_handle;
		else dcesrv_handle_destroy(dce_call->conn, newh);
	}

	r->out.result = error;

	return NT_STATUS_OK;
}


/* 
  winreg_DeleteKey 
*/
static NTSTATUS winreg_DeleteKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_DeleteKey *r)
{
	struct dcesrv_handle *h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	REG_KEY *parent, *key;
	if(!h) {
		return NT_STATUS_INVALID_HANDLE;
	}

	parent = h->data;
	r->out.result = reg_open_key(parent, r->in.key.name, &key);
	if(W_ERROR_IS_OK(r->out.result)) {
		r->out.result = reg_key_del(key);
	}
	return NT_STATUS_OK;
}


/* 
  winreg_DeleteValue 
*/
static NTSTATUS winreg_DeleteValue(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_DeleteValue *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_EnumKey 
*/
static NTSTATUS winreg_EnumKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_EnumKey *r)
{
	struct dcesrv_handle *h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	REG_KEY *key;
	if(!h) {
		return NT_STATUS_INVALID_HANDLE;
	}

	key = h->data;
	
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_EnumValue 
*/
static NTSTATUS winreg_EnumValue(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_EnumValue *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_FlushKey 
*/
static NTSTATUS winreg_FlushKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_FlushKey *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_GetKeySecurity 
*/
static NTSTATUS winreg_GetKeySecurity(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_GetKeySecurity *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_LoadKey 
*/
static NTSTATUS winreg_LoadKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_LoadKey *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_NotifyChangeKeyValue 
*/
static NTSTATUS winreg_NotifyChangeKeyValue(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_NotifyChangeKeyValue *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_OpenKey 
*/
static NTSTATUS winreg_OpenKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_OpenKey *r)
{
	struct dcesrv_handle *h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	REG_KEY *k, *subkey;
	if(!h) {
		return NT_STATUS_INVALID_HANDLE;
	}

	k = h->data;


	r->out.result = reg_open_key(k, r->in.keyname.name, &subkey);
	if(W_ERROR_IS_OK(r->out.result)) {
		h->data = subkey; 
		r->out.handle = &h->wire_handle; 
	}
	
	return NT_STATUS_OK;
}


/* 
  winreg_QueryInfoKey 
*/
static NTSTATUS winreg_QueryInfoKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_QueryInfoKey *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_QueryValue 
*/
static NTSTATUS winreg_QueryValue(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_QueryValue *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_ReplaceKey 
*/
static NTSTATUS winreg_ReplaceKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_ReplaceKey *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_RestoreKey 
*/
static NTSTATUS winreg_RestoreKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_RestoreKey *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_SaveKey 
*/
static NTSTATUS winreg_SaveKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_SaveKey *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_SetKeySecurity 
*/
static NTSTATUS winreg_SetKeySecurity(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_SetKeySecurity *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_SetValue 
*/
static NTSTATUS winreg_SetValue(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_SetValue *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_UnLoadKey 
*/
static NTSTATUS winreg_UnLoadKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_UnLoadKey *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_InitiateSystemShutdown 
*/
static NTSTATUS winreg_InitiateSystemShutdown(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_InitiateSystemShutdown *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_AbortSystemShutdown 
*/
static NTSTATUS winreg_AbortSystemShutdown(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_AbortSystemShutdown *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_GetVersion 
*/
static NTSTATUS winreg_GetVersion(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_GetVersion *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_QueryMultipleValues 
*/
static NTSTATUS winreg_QueryMultipleValues(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_QueryMultipleValues *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_InitiateSystemShutdownEx 
*/
static NTSTATUS winreg_InitiateSystemShutdownEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_InitiateSystemShutdownEx *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_SaveKeyEx 
*/
static NTSTATUS winreg_SaveKeyEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_SaveKeyEx *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_QueryMultipleValues2 
*/
static NTSTATUS winreg_QueryMultipleValues2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_QueryMultipleValues2 *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_winreg_s.c"
