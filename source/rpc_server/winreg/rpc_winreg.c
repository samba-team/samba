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

enum handle_types { HTYPE_REGKEY, HTYPE_REGVAL };

struct _privatedata {
	REG_HANDLE *registry;
};


/* this function is called when the client disconnects the endpoint */
static void winreg_unbind(struct dcesrv_connection *dc, const struct dcesrv_interface *di) 
{
	struct _privatedata *data = dc->private;
	reg_free(data->registry);
}

static NTSTATUS winreg_bind(struct dcesrv_call_state *dc, const struct dcesrv_interface *di) 
{
	struct _privatedata *data;
	data = talloc(dc->mem_ctx, sizeof(struct _privatedata));
	data->registry = reg_open("nt4", "/home/aurelia/jelmer/NTUSER.DAT", False);
	dc->conn->private = data;
	return NT_STATUS_OK;
}

#define DCESRV_INTERFACE_WINREG_BIND winreg_bind
#define DCESRV_INTERFACE_WINREG_UNBIND winreg_unbind

/* 
  winreg_OpenHKCR 
*/
static NTSTATUS winreg_OpenHKCR(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_OpenHKCR *r)
{
	
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_OpenHKCU 
*/
static NTSTATUS winreg_OpenHKCU(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_OpenHKCU *r)
{
	struct _privatedata *data = dce_call->conn->private;
	REG_KEY *k = reg_open_key(reg_get_root(data->registry), "\\HKEY_CURRENT_USER");

	if(!k) {
		r->out.result = WERR_BADFILE;
	} else {
		struct dcesrv_handle *h = dcesrv_handle_new(dce_call->conn, HTYPE_REGKEY);
		h->data = k;
		r->out.handle = &(h->wire_handle);
	}

	r->out.result = WERR_OK;

	return NT_STATUS_OK;
}


/* 
  winreg_OpenHKLM 
*/
static NTSTATUS winreg_OpenHKLM(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_OpenHKLM *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_OpenHKPD 
*/
static NTSTATUS winreg_OpenHKPD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_OpenHKPD *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_OpenHKU 
*/
static NTSTATUS winreg_OpenHKU(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_OpenHKU *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_CloseKey 
*/
static NTSTATUS winreg_CloseKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_CloseKey *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_CreateKey 
*/
static NTSTATUS winreg_CreateKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_CreateKey *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_DeleteKey 
*/
static NTSTATUS winreg_DeleteKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_DeleteKey *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
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
	if(!h) {
		return NT_STATUS_INVALID_HANDLE;
	}
	
	return NT_STATUS_NOT_IMPLEMENTED;
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
  winreg_OpenHKCC 
*/
static NTSTATUS winreg_OpenHKCC(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_OpenHKCC *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_OpenHKDD 
*/
static NTSTATUS winreg_OpenHKDD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_OpenHKDD *r)
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
  winreg_OpenHKPT 
*/
static NTSTATUS winreg_OpenHKPT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_OpenHKPT *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  winreg_OpenHKPN 
*/
static NTSTATUS winreg_OpenHKPN(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_OpenHKPN *r)
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
