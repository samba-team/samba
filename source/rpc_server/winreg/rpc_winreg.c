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
#include "librpc/gen_ndr/ndr_winreg.h"
#include "rpc_server/common/common.h"

enum handle_types { HTYPE_REGVAL, HTYPE_REGKEY };

static void winreg_destroy_hive(struct dcesrv_connection *c, struct dcesrv_handle *h)
{
	reg_close(((struct registry_key *)h->data)->hive->reg_ctx);
}

static WERROR winreg_openhive (struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, const char *hivename, struct policy_handle **outh)
{
	struct registry_context *ctx;
	struct dcesrv_handle *h; 
	WERROR error;
	const char *conf = lp_parm_string(-1, "registry", hivename);
	char *backend, *location;
	
	if (!conf) {
		return WERR_NOT_SUPPORTED;
	}

	backend = talloc_strdup(mem_ctx, conf);
	location = strchr(backend, ':');

	if (location) {
		*location = '\0';
		location++;
	}

	error = reg_open(&ctx, backend, location, NULL); 
	if(!W_ERROR_IS_OK(error)) return error; 
	
	h = dcesrv_handle_new(dce_call->conn, HTYPE_REGKEY); 
	h->data = ctx->hives[0]->root; 
	SMB_ASSERT(h->data);
	h->destroy = winreg_destroy_hive;
	*outh = &h->wire_handle; 
	return WERR_OK; 
}

#define func_winreg_OpenHive(k,n) static WERROR winreg_Open ## k (struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct winreg_Open ## k *r) \
{ \
	return winreg_openhive (dce_call, mem_ctx, n, &r->out.handle);\
}

func_winreg_OpenHive(HKCR,"HKEY_CLASSES_ROOT")
func_winreg_OpenHive(HKCU,"HKEY_CURRENT_USER")
func_winreg_OpenHive(HKLM,"HKEY_LOCAL_MACHINE")
func_winreg_OpenHive(HKPD,"HKEY_PERFORMANCE_DATA")
func_winreg_OpenHive(HKU,"HKEY_USERS")
func_winreg_OpenHive(HKCC,"HKEY_CC")
func_winreg_OpenHive(HKDD,"HKEY_DD")
func_winreg_OpenHive(HKPT,"HKEY_PT")
func_winreg_OpenHive(HKPN,"HKEY_PN")

/* 
  winreg_CloseKey 
*/
static WERROR winreg_CloseKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_CloseKey *r)
{
	struct dcesrv_handle *h; 

	h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
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
	struct dcesrv_handle *h, *newh;
	WERROR error;

	h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	DCESRV_CHECK_HANDLE(h);
	
	newh = dcesrv_handle_new(dce_call->conn, HTYPE_REGKEY);

	error = reg_key_add_name(newh, (struct registry_key *)h->data, r->in.key.name, 
							 r->in.access_mask, 
							 r->in.sec_desc?r->in.sec_desc->sd:NULL, 
							 (struct registry_key **)&newh->data);

	if(W_ERROR_IS_OK(error)) {
		r->out.handle = &newh->wire_handle;
	} else {
		dcesrv_handle_destroy(dce_call->conn, newh);
	}

	return error;
}


/* 
  winreg_DeleteKey 
*/
static WERROR winreg_DeleteKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_DeleteKey *r)
{
	struct dcesrv_handle *h;
	struct registry_key *key;
	WERROR result;

	h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	DCESRV_CHECK_HANDLE(h);

	result = reg_open_key(mem_ctx, (struct registry_key *)h->data, r->in.key.name, &key);

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
	struct dcesrv_handle *h;
	struct registry_value *value;

	h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGVAL);
	DCESRV_CHECK_HANDLE(h);

	value = h->data;
	
	/* FIXME */

	return WERR_NOT_SUPPORTED;
}


/* 
  winreg_EnumKey 
*/
static WERROR winreg_EnumKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_EnumKey *r)
{
	struct dcesrv_handle *h;
	struct registry_key *key;

	h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	DCESRV_CHECK_HANDLE(h);

	r->out.result = reg_key_get_subkey_by_index(mem_ctx, (struct registry_key *)h->data, r->in.enum_index, &key);

	if (W_ERROR_IS_OK(r->out.result)) {
		r->out.key_name_len = strlen(key->name);
		r->out.out_name = talloc_zero_p(mem_ctx, struct winreg_EnumKeyNameResponse);
		r->out.out_name->name = key->name;
		r->out.class = talloc_zero_p(mem_ctx, struct winreg_String);
		r->out.last_changed_time = talloc_zero_p(mem_ctx, struct winreg_Time);
	}
	
	return r->out.result;
}


/* 
  winreg_EnumValue 
*/
static WERROR winreg_EnumValue(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_EnumValue *r)
{
	struct dcesrv_handle *h;
	struct registry_key *key;
	struct registry_value *value;
	WERROR result;

	h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	DCESRV_CHECK_HANDLE(h);

	key = h->data;

	result = reg_key_get_value_by_index(mem_ctx, key, r->in.enum_index, &value);
	if (!W_ERROR_IS_OK(result)) {
		return result;
	}
	
	r->out.type = &value->data_type;
	r->out.name_out.name = value->name;
	r->out.value_out = talloc_p(mem_ctx, struct EnumValueOut);
	r->out.value_out->offset = 0;
	r->out.value_out->buffer = data_blob_talloc(mem_ctx, value->data_blk, value->data_len);
	r->out.value_len1 = r->in.value_len1;
	r->out.value_len2 = r->in.value_len2;
	

	return WERR_OK;
}


/* 
  winreg_FlushKey 
*/
static WERROR winreg_FlushKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_FlushKey *r)
{
	struct dcesrv_handle *h;

	h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	DCESRV_CHECK_HANDLE(h);

	return reg_key_flush(h->data);
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
	struct dcesrv_handle *h, *newh;
	WERROR result;

	h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	DCESRV_CHECK_HANDLE(h);

	newh = dcesrv_handle_new(dce_call->conn, HTYPE_REGKEY);

	result = reg_open_key(newh, (struct registry_key *)h->data, 
				r->in.keyname.name, (struct registry_key **)&newh->data);

	if (W_ERROR_IS_OK(result)) {
		r->out.handle = &newh->wire_handle; 
	} else {
		dcesrv_handle_destroy(dce_call->conn, newh);
	}
	
	return result;
}


/* 
  winreg_QueryInfoKey 
*/
static WERROR winreg_QueryInfoKey(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct winreg_QueryInfoKey *r)
{
	struct dcesrv_handle *h;
	struct registry_key *k;
	WERROR ret;

	h = dcesrv_handle_fetch(dce_call->conn, r->in.handle, HTYPE_REGKEY);
	DCESRV_CHECK_HANDLE(h);
	k = h->data;

	ret = reg_key_num_subkeys(k, &r->out.num_subkeys);
	if (!W_ERROR_IS_OK(ret)) { 
		return ret;
	}

	ret = reg_key_num_values(k, &r->out.num_values);
	if (!W_ERROR_IS_OK(ret)) { 
		return ret;
	}

	ret = reg_key_subkeysizes(k, &r->out.max_subkeysize, &r->out.max_subkeylen);
	if (!W_ERROR_IS_OK(ret)) { 
		return ret;
	}

	ret = reg_key_valuesizes(k, &r->out.max_valnamelen, &r->out.max_valbufsize);
	if (!W_ERROR_IS_OK(ret)) { 
		return ret;
	}

	r->out.secdescsize = 0; /* FIXME */
	ZERO_STRUCT(r->out.last_changed_time); /* FIXME */	if (!W_ERROR_IS_OK(ret)) { 
		return ret;
	}


	return WERR_OK;
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
	r->out.version = 5;
	return WERR_OK;
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
