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
 *
 * This backend is a little special. The root key is 'virtual'. All 
 * of its subkeys are the hives available on the remote server.
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


#define openhive(u) static struct policy_handle *open_ ## u(struct dcerpc_pipe *p, REG_HANDLE *h) \
{ \
	struct winreg_Open ## u r; \
	struct winreg_OpenUnknown unknown; \
	struct policy_handle *hnd = malloc(sizeof(struct policy_handle)); \
	\
	unknown.unknown0 = 0x84e0; \
	unknown.unknown1 = 0x0000; \
	r.in.unknown = &unknown; \
	r.in.access_required = SEC_RIGHTS_MAXIMUM_ALLOWED; \
	r.out.handle = hnd;\
	\
	if (!NT_STATUS_IS_OK(dcerpc_winreg_Open ## u(p, h->mem_ctx, &r))) {\
		DEBUG(0,("Error executing open\n"));\
		return NULL;\
	}\
\
	return hnd;\
}

openhive(HKLM)
openhive(HKCU)
openhive(HKPD)
openhive(HKU)
openhive(HKCR)

struct rpc_data {
	struct dcerpc_pipe *pipe;
	struct policy_handle *hives[10];
};

struct rpc_key_data {
	struct policy_handle pol;
	int num_subkeys;
	int num_values;
	int max_valnamelen;
	int max_valdatalen;
};

struct {
	const char *name;
	struct policy_handle *(*open) (struct dcerpc_pipe *p, REG_HANDLE *h);
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
	struct rpc_data *mydata = talloc(h->mem_ctx, sizeof(struct rpc_data));
	char *binding = strdup(location);
	NTSTATUS status;
	char *user, *pass;

	if(!credentials || !location) return WERR_INVALID_PARAM;

	user = talloc_strdup(h->mem_ctx, credentials);
	pass = strchr(user, '%');
	*pass = '\0'; pass++;

	ZERO_STRUCTP(mydata);
	
	status = dcerpc_pipe_connect(&mydata->pipe, binding, 
                    DCERPC_WINREG_UUID,
                    DCERPC_WINREG_VERSION,
                     lp_workgroup(),
                     user, pass);

	h->backend_data = mydata;
	
	return ntstatus_to_werror(status);
}

static WERROR rpc_open_root(REG_HANDLE *h, REG_KEY **k)
{
	/* There's not really a 'root' key here */
	*k = reg_key_new_abs("\\", h, h->backend_data);
	return WERR_OK;
}

static WERROR rpc_close_registry(REG_HANDLE *h)
{
	dcerpc_pipe_close(((struct rpc_data *)h->backend_data)->pipe);
	return WERR_OK;
}

static WERROR rpc_key_put_rpc_data(REG_KEY *k, struct rpc_key_data **data)
{
	struct policy_handle *hive = NULL;
    struct winreg_OpenKey r;
	int i;
	struct rpc_data *mydata = k->handle->backend_data;
	struct rpc_key_data *mykeydata;
	char *realkeyname, *hivename;

	if(k->backend_data) { 
		*data = k->backend_data; 
		return WERR_OK;
	}

	k->backend_data = mykeydata = talloc_p(k->mem_ctx, struct rpc_key_data);
	*data = mykeydata;
	mykeydata->num_values = -1;
	mykeydata->num_subkeys = -1;

	/* First, ensure the handle to the hive is opened */
	realkeyname = strchr(k->path+1, '\\');
	if(realkeyname) hivename = strndup(k->path+1, realkeyname-k->path-1);
	else hivename = strdup(k->path+1);

	for(i = 0; known_hives[i].name; i++) {
		if(!strcmp(hivename, known_hives[i].name)) {
    		if(!mydata->hives[i]) mydata->hives[i] = known_hives[i].open(mydata->pipe, k->handle);
			hive = mydata->hives[i];
			break;
		}
	}
	
	if(!hive) {
		DEBUG(0, ("No such hive: %s\n", hivename));
		return WERR_FOOBAR;
	}

	if(realkeyname && realkeyname[0] == '\\')realkeyname++;

	if(!realkeyname || !(*realkeyname)) { 
		mykeydata->pol = *hive;
		return WERR_OK;
	}

	/* Then, open the handle using the hive */

	memset(&r, 0, sizeof(struct winreg_OpenKey));
    r.in.handle = hive;
    init_winreg_String(&r.in.keyname, realkeyname);
    r.in.unknown = 0x00000000;
    r.in.access_mask = 0x02000000;
    r.out.handle = &mykeydata->pol;

    dcerpc_winreg_OpenKey(mydata->pipe, k->mem_ctx, &r);

	return r.out.result;
}

static WERROR rpc_open_key(REG_HANDLE *h, const char *name, REG_KEY **key)
{
	struct rpc_key_data *mykeydata;
	*key = reg_key_new_abs(name, h, NULL);
	return rpc_key_put_rpc_data(*key, &mykeydata);
}

static WERROR rpc_get_value_by_index(REG_KEY *parent, int n, REG_VAL **value)  
{
	struct winreg_EnumValue r;
	struct winreg_Uint8buf vb;
	struct rpc_data *mydata = parent->handle->backend_data;
	struct winreg_EnumValueName vn;
	NTSTATUS status;
	struct rpc_key_data *mykeydata;
	uint32 type = 0x0, requested_len = 0, returned_len = 0;
	WERROR error;

	error = rpc_key_put_rpc_data(parent, &mykeydata);
	if(!W_ERROR_IS_OK(error)) return error;

	/* Root is a special case */
	if(parent->backend_data == parent->handle->backend_data) {
		return WERR_NO_MORE_ITEMS;
	}

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

	status = dcerpc_winreg_EnumValue(mydata->pipe, parent->mem_ctx, &r);
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

	/* If parent is the root key, list the hives */
	if(parent->backend_data == mydata) { 
		if(!known_hives[n].name) return WERR_NO_MORE_ITEMS;
		*subkey = reg_key_new_rel(known_hives[n].name, parent, NULL);
		return rpc_key_put_rpc_data(*subkey, &mykeydata);
	}

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
	status = dcerpc_winreg_EnumKey(mydata->pipe, parent->mem_ctx, &r);
	if(NT_STATUS_IS_OK(status) && W_ERROR_IS_OK(r.out.result)) {
		*subkey = reg_key_new_rel(r.out.out_name->name, parent, NULL);
	}

	return r.out.result;
}

static WERROR rpc_add_key(REG_KEY *parent, const char *name, uint32 access_mask, SEC_DESC *sec, REG_KEY **key)
{
	struct rpc_key_data *mykeydata;
	WERROR error = rpc_key_put_rpc_data(parent, &mykeydata);
	if(!W_ERROR_IS_OK(error)) return error;

	/* FIXME */
	return WERR_NOT_SUPPORTED;
}

static WERROR rpc_query_key(REG_KEY *k)
{
    NTSTATUS status;
    struct winreg_QueryInfoKey r;
    struct rpc_data *mydata = k->handle->backend_data;
    struct rpc_key_data *mykeydata;                                                                                                       
    r.in.handle = &mykeydata->pol;
    init_winreg_String(&r.in.class, NULL);
                                                                                                       
    status = dcerpc_winreg_QueryInfoKey(mydata->pipe, k->mem_ctx, &r);
                                                                                                       
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
	struct rpc_data *mydata = k->handle->backend_data;
	struct rpc_key_data *mykeydata;
	struct winreg_DeleteKey r;
	REG_KEY *parent;
	WERROR error;
	
	error = reg_key_get_parent(k, &parent);
	if(!W_ERROR_IS_OK(error)) return error;
	
	error = rpc_key_put_rpc_data(parent, &mykeydata);
	if(!W_ERROR_IS_OK(error)) return error;

    r.in.handle = &mykeydata->pol;
    init_winreg_String(&r.in.key, k->name);
 
    status = dcerpc_winreg_DeleteKey(mydata->pipe, k->mem_ctx, &r);

	return r.out.result;
}

static void rpc_close_key(REG_KEY *k)
{
	reg_key_free(k);
}

static WERROR rpc_num_values(REG_KEY *key, int *count) {
	struct rpc_key_data *mykeydata;
	WERROR error;
		
	/* Root is a special case */
	if(key->backend_data == key->handle->backend_data) {
		*count = 0;
		return WERR_OK;
	}
		
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
	struct rpc_key_data *mykeydata;
	WERROR error;
	
	/* Root is a special case */
	if(key->backend_data == key->handle->backend_data) {
		int i;
		for(i = 0; known_hives[i].name; i++);
		*count = i;
		return WERR_OK;
	}
	
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
	.open_root_key = rpc_open_root,
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
