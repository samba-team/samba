/*
   Samba Unix/Linux SMB implementation
   RPC backend for the registry library
   Copyright (C) 2003-2004 Jelmer Vernooij, jelmer@samba.org

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
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */
 
#include "includes.h"
#include "lib/registry/common/registry.h"

/**
 * This is the RPC backend for the registry library.
 */

static void init_winreg_String(struct winreg_String *name, const char *s)
{
    name->name = s;
    if (s) {
        name->name_len = 2 * (strlen_m(s) + 1);
        name->name_size = name->name_len;
    } else {
        name->name_len = 0;
        name->name_size = 0;
    }
}


#define openhive(u) static WERROR open_ ## u(struct dcerpc_pipe *p, REG_KEY *h, struct policy_handle *hnd) \
{ \
	struct winreg_Open ## u r; \
	struct winreg_OpenUnknown unknown; \
	NTSTATUS status; \
	\
	unknown.unknown0 = 0x84e0; \
	unknown.unknown1 = 0x0000; \
	r.in.unknown = &unknown; \
	r.in.access_required = SEC_RIGHTS_MAXIMUM_ALLOWED; \
	r.out.handle = hnd;\
	\
	status = dcerpc_winreg_Open ## u(p, h->mem_ctx, &r); \
	if (NT_STATUS_IS_ERR(status)) {\
		DEBUG(0,("Error executing open\n"));\
		return ntstatus_to_werror(status);\
	}\
\
	return r.out.result;\
}

openhive(HKLM)
openhive(HKCU)
openhive(HKPD)
openhive(HKU)
openhive(HKCR)

struct rpc_key_data {
	struct policy_handle pol;
	int num_subkeys;
	int num_values;
	int max_valnamelen;
	int max_valdatalen;
};

struct {
	const char *name;
	WERROR (*open) (struct dcerpc_pipe *p, REG_KEY *k, struct policy_handle *h);
} known_hives[] = {
{ "HKEY_LOCAL_MACHINE", open_HKLM },
{ "HKEY_CURRENT_USER", open_HKCU },
{ "HKEY_CLASSES_ROOT", open_HKCR },
{ "HKEY_PERFORMANCE_DATA", open_HKPD },
{ "HKEY_USERS", open_HKU },
{ NULL, NULL }
};

static WERROR rpc_query_key(REG_KEY *k);

static WERROR rpc_open_registry(REG_HANDLE *h, const char *location, const char *credentials)
{
	char *binding = strdup(location);
	NTSTATUS status;
	char *user, *pass;

	if(!credentials || !location) return WERR_INVALID_PARAM;

	user = talloc_strdup(h->mem_ctx, credentials);
	pass = strchr(user, '%');
	*pass = '\0'; pass++;

	status = dcerpc_pipe_connect((struct dcerpc_pipe **)&h->backend_data, binding, 
                    DCERPC_WINREG_UUID,
                    DCERPC_WINREG_VERSION,
                     lp_workgroup(),
                     user, pass);
	
	return ntstatus_to_werror(status);
}

static WERROR rpc_get_hive(REG_HANDLE *h, int n, REG_KEY **k)
{
	struct rpc_key_data *mykeydata;
	WERROR error;
	if(!known_hives[n].name) return WERR_NO_MORE_ITEMS;
	*k = reg_key_new_abs(known_hives[n].name, h, NULL);
	(*k)->backend_data = mykeydata = talloc_p((*k)->mem_ctx, struct rpc_key_data);
	mykeydata->num_values = -1;
	mykeydata->num_subkeys = -1;
	error = known_hives[n].open((struct dcerpc_pipe *)h->backend_data, *k, &mykeydata->pol);
	return error;
}

static WERROR rpc_close_registry(REG_HANDLE *h)
{
	dcerpc_pipe_close((struct dcerpc_pipe *)h->backend_data);
	return WERR_OK;
}

static WERROR rpc_key_put_rpc_data(REG_KEY *k, struct rpc_key_data **data)
{
    struct winreg_OpenKey r;
	int i;
	struct rpc_data *mydata = k->handle->backend_data;
	WERROR error;
	REG_KEY *hivekey;
	struct rpc_key_data *mykeydata;

	if(k->backend_data) { 
		*data = k->backend_data; 
		return WERR_OK;
	}

	k->backend_data = mykeydata = talloc_p(k->mem_ctx, struct rpc_key_data);
	*data = mykeydata;
	mykeydata->num_values = -1;
	mykeydata->num_subkeys = -1;

	/* Then, open the handle using the hive */

	memset(&r, 0, sizeof(struct winreg_OpenKey));
	error = rpc_get_hive(k->handle, k->hive, &hivekey);
	if(!W_ERROR_IS_OK(error))return error;
    r.in.handle = &(((struct rpc_key_data *)hivekey->backend_data)->pol);
    init_winreg_String(&r.in.keyname, reg_key_get_path(k));
    r.in.unknown = 0x00000000;
    r.in.access_mask = 0x02000000;
    r.out.handle = &mykeydata->pol;

    dcerpc_winreg_OpenKey((struct dcerpc_pipe *)k->handle->backend_data, k->mem_ctx, &r);

	return r.out.result;
}

static WERROR rpc_open_key(REG_HANDLE *h, int hive, const char *name, REG_KEY **key)
{
	struct rpc_key_data *mykeydata;
    struct winreg_OpenKey r;
	REG_KEY *hivekey;
	WERROR error;
	
	*key = reg_key_new_abs(name, h, NULL);

	(*key)->backend_data = mykeydata = talloc_p((*key)->mem_ctx, struct rpc_key_data);
	mykeydata->num_values = -1;
	mykeydata->num_subkeys = -1;

	/* Then, open the handle using the hive */

	memset(&r, 0, sizeof(struct winreg_OpenKey));
	error = rpc_get_hive(h, hive, &hivekey);
	if(!W_ERROR_IS_OK(error))return error;
    r.in.handle = &(((struct rpc_key_data *)hivekey->backend_data)->pol);
    init_winreg_String(&r.in.keyname, name);
    r.in.unknown = 0x00000000;
    r.in.access_mask = 0x02000000;
    r.out.handle = &mykeydata->pol;

    dcerpc_winreg_OpenKey((struct dcerpc_pipe *)(*key)->handle->backend_data, (*key)->mem_ctx, &r);

	return r.out.result;
}

static WERROR rpc_get_value_by_index(REG_KEY *parent, int n, REG_VAL **value)  
{
	struct winreg_EnumValue r;
	struct winreg_Uint8buf vb;
	struct winreg_EnumValueName vn;
	NTSTATUS status;
	struct rpc_key_data *mykeydata;
	uint32 type = 0x0, requested_len = 0, returned_len = 0;
	WERROR error;

	error = rpc_key_put_rpc_data(parent, &mykeydata);
	if(!W_ERROR_IS_OK(error)) return error;

	if(mykeydata->num_values == -1) {
		error = rpc_query_key(parent);
		if(!W_ERROR_IS_OK(error)) return error;
	}

	requested_len = mykeydata->max_valdatalen;

	r.in.handle = &mykeydata->pol;
	r.in.enum_index = n;
	r.in.type = r.out.type = &type;
	r.in.requested_len = r.out.requested_len = &requested_len;
	r.in.returned_len = r.out.returned_len = &returned_len;
	vn.max_len = mykeydata->max_valnamelen * 2;
	vn.len = 0;
	vn.buf = NULL;
	if(vn.max_len > 0) {
		vn.len = 0;
		vn.max_len = mykeydata->max_valnamelen*2;
		/* FIXME: we should not point a 'char *' to a const buffer!!! --metze*/
		vn.buf = "";
	}
	r.in.name = r.out.name = &vn;
	vb.max_len = mykeydata->max_valdatalen;
	vb.offset = 0x0;
	vb.len = 0x0;
	vb.buffer = talloc_array_p(parent->mem_ctx, uint8, mykeydata->max_valdatalen);
	r.in.value = r.out.value = &vb;

	status = dcerpc_winreg_EnumValue((struct dcerpc_pipe *)parent->handle->backend_data, parent->mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		DEBUG(0, ("Error in EnumValue: %s\n", nt_errstr(status)));
	}
	
	if(NT_STATUS_IS_OK(status) && W_ERROR_IS_OK(r.out.result)) {
		*value = reg_val_new(parent, NULL);
		(*value)->name = r.out.name->buf;
		(*value)->data_type = type;
		(*value)->data_len = r.out.value->len;
		(*value)->data_blk = r.out.value->buffer;
		exit(1);
		return WERR_OK;
	}
	
	return r.out.result;
}

static WERROR rpc_get_subkey_by_index(REG_KEY *parent, int n, REG_KEY **subkey) 
{
	struct winreg_EnumKey r;
	struct winreg_EnumKeyNameRequest keyname;
	struct winreg_String classname;
	struct winreg_Time tm;
	struct rpc_data *mydata = parent->handle->backend_data;
	struct rpc_key_data *mykeydata = parent->backend_data;
	WERROR error;
	NTSTATUS status;

	error = rpc_key_put_rpc_data(parent, &mykeydata);
	if(!W_ERROR_IS_OK(error)) return error;

	r.in.handle = &mykeydata->pol;
	keyname.unknown = 0x0000020a;
	init_winreg_String(&keyname.key_name, NULL);
	init_winreg_String(&classname, NULL);
	r.in.in_name = &keyname;
	r.in.class = &classname;
	tm.low = tm.high = 0x7fffffff;
	r.in.last_changed_time = &tm;

	r.in.enum_index = n;
	r.in.unknown = r.out.unknown = 0x0414;
	r.in.key_name_len = r.out.key_name_len = 0;
	status = dcerpc_winreg_EnumKey((struct dcerpc_pipe *)parent->handle->backend_data, parent->mem_ctx, &r);
	if(NT_STATUS_IS_OK(status) && W_ERROR_IS_OK(r.out.result)) {
		*subkey = reg_key_new_rel(r.out.out_name->name, parent, NULL);
	}

	return r.out.result;
}

static WERROR rpc_add_key(REG_KEY *parent, const char *name, uint32 access_mask, SEC_DESC *sec, REG_KEY **key)
{
	struct rpc_key_data *mykeydata;
	WERROR error;

	error = rpc_key_put_rpc_data(parent, &mykeydata);
	if(!W_ERROR_IS_OK(error)) return error;

	/* FIXME */
	return WERR_NOT_SUPPORTED;
}

static WERROR rpc_query_key(REG_KEY *k)
{
    NTSTATUS status;
	WERROR error;
    struct winreg_QueryInfoKey r;
    struct rpc_key_data *mykeydata;

	error = rpc_key_put_rpc_data(k, &mykeydata);
	if(!W_ERROR_IS_OK(error)) return error;

    init_winreg_String(&r.in.class, NULL);
    r.in.handle = &mykeydata->pol;
	
    status = dcerpc_winreg_QueryInfoKey((struct dcerpc_pipe *)k->handle->backend_data, k->mem_ctx, &r);

    if (!NT_STATUS_IS_OK(status)) {
        printf("QueryInfoKey failed - %s\n", nt_errstr(status));
        return ntstatus_to_werror(status);
    }
                                                                                                       
    if (W_ERROR_IS_OK(r.out.result)) {
		mykeydata->num_subkeys = r.out.num_subkeys;
		mykeydata->num_values = r.out.num_values;
		mykeydata->max_valnamelen = r.out.max_valnamelen;
		mykeydata->max_valdatalen = r.out.max_valbufsize;
	} 

	return r.out.result;
}

static WERROR rpc_del_key(REG_KEY *k)
{
	NTSTATUS status;
	struct rpc_key_data *mykeydata = k->backend_data;
	struct winreg_DeleteKey r;
	REG_KEY *parent;
	WERROR error;
	
	error = reg_key_get_parent(k, &parent);
	if(!W_ERROR_IS_OK(error)) return error;

	error = rpc_key_put_rpc_data(parent, &mykeydata);
	if(!W_ERROR_IS_OK(error)) return error;
	
    r.in.handle = &mykeydata->pol;
    init_winreg_String(&r.in.key, k->name);
 
    status = dcerpc_winreg_DeleteKey((struct dcerpc_pipe *)k->handle->backend_data, k->mem_ctx, &r);

	return r.out.result;
}

static void rpc_close_key(REG_KEY *k)
{
	reg_key_free(k);
}

static WERROR rpc_num_values(REG_KEY *key, int *count) {
	struct rpc_key_data *mykeydata = key->backend_data;
	WERROR error;
		
	error = rpc_key_put_rpc_data(key, &mykeydata);
	if(!W_ERROR_IS_OK(error)) return error;

	if(mykeydata->num_values == -1) {
		error = rpc_query_key(key);
		if(!W_ERROR_IS_OK(error)) return error;
	}
			
	*count = mykeydata->num_values;
	return WERR_OK;
}

static WERROR rpc_num_subkeys(REG_KEY *key, int *count) {
	struct rpc_key_data *mykeydata = key->backend_data;
	WERROR error;

	error = rpc_key_put_rpc_data(key, &mykeydata);
	if(!W_ERROR_IS_OK(error)) return error;
	
	if(mykeydata->num_subkeys == -1) {
		error = rpc_query_key(key);
		if(!W_ERROR_IS_OK(error)) return error;
	}
			
	*count = mykeydata->num_subkeys;
	return WERR_OK;
}

static struct registry_ops reg_backend_rpc = {
	.name = "rpc",
	.open_registry = rpc_open_registry,
	.close_registry = rpc_close_registry,
	.get_hive = rpc_get_hive,
	.open_key = rpc_open_key,
	.get_subkey_by_index = rpc_get_subkey_by_index,
	.get_value_by_index = rpc_get_value_by_index,
	.add_key = rpc_add_key,
	.del_key = rpc_del_key,
	.free_key_backend_data = rpc_close_key,
	.num_subkeys = rpc_num_subkeys,
	.num_values = rpc_num_values,
};

NTSTATUS registry_rpc_init(void)
{
	return register_backend("registry", &reg_backend_rpc);
}
