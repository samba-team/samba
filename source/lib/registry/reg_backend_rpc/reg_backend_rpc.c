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


#define openhive(u) static WERROR open_ ## u(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct policy_handle *hnd) \
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
	status = dcerpc_winreg_Open ## u(p, mem_ctx, &r); \
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
	WERROR (*open) (struct dcerpc_pipe *p, TALLOC_CTX *, struct policy_handle *h);
} known_hives[] = {
{ "HKEY_LOCAL_MACHINE", open_HKLM },
{ "HKEY_CURRENT_USER", open_HKCU },
{ "HKEY_CLASSES_ROOT", open_HKCR },
{ "HKEY_PERFORMANCE_DATA", open_HKPD },
{ "HKEY_USERS", open_HKU },
{ NULL, NULL }
};

static WERROR rpc_query_key(struct registry_key *k);

WERROR rpc_list_hives (TALLOC_CTX *mem_ctx, const char *location, const char *credentials, char ***hives)
{
	int i = 0;
	*hives = talloc_p(mem_ctx, char *);
	for(i = 0; known_hives[i].name; i++) {
		*hives = talloc_realloc_p(*hives, char *, i+2);
		(*hives)[i] = talloc_strdup(mem_ctx, known_hives[i].name);
	}
	(*hives)[i] = NULL;
	return WERR_OK;
}

static WERROR rpc_open_hive(TALLOC_CTX *mem_ctx, struct registry_hive *h, struct registry_key **k)
{
	NTSTATUS status;
	char *user, *pass;
	struct rpc_key_data *mykeydata;
	struct dcerpc_pipe *p;
	int n;

	if(!h->credentials || !h->location) return WERR_INVALID_PARAM;

	user = talloc_strdup(mem_ctx, h->credentials);
	pass = strchr(user, '%');
	if(pass) 
	{
		*pass = '\0'; pass++;
	} else {
		pass = "";
	}

	status = dcerpc_pipe_connect(&p, h->location, 
                    DCERPC_WINREG_UUID,
                    DCERPC_WINREG_VERSION,
                     lp_workgroup(),
                     user, pass);

	h->backend_data = p;

	if(NT_STATUS_IS_ERR(status)) return ntstatus_to_werror(status);

	for(n = 0; known_hives[n].name; n++) 
	{
		if(!strcmp(known_hives[n].name, h->backend_hivename)) break;
	}
	
	if(!known_hives[n].name) return WERR_NO_MORE_ITEMS;
	
	*k = talloc_p(mem_ctx, struct registry_key);
	(*k)->backend_data = mykeydata = talloc_p(mem_ctx, struct rpc_key_data);
	mykeydata->num_values = -1;
	mykeydata->num_subkeys = -1;
	return known_hives[n].open((struct dcerpc_pipe *)h->backend_data, *k, &(mykeydata->pol));
}

static WERROR rpc_close_registry(struct registry_hive *h)
{
	dcerpc_pipe_close((struct dcerpc_pipe *)h->backend_data);
	return WERR_OK;
}

static WERROR rpc_key_put_rpc_data(TALLOC_CTX *mem_ctx, struct registry_key *k)
{
    struct winreg_OpenKey r;
	struct rpc_key_data *mykeydata;

	k->backend_data = mykeydata = talloc_p(mem_ctx, struct rpc_key_data);
	mykeydata->num_values = -1;
	mykeydata->num_subkeys = -1;

	/* Then, open the handle using the hive */

	memset(&r, 0, sizeof(struct winreg_OpenKey));
    r.in.handle = &(((struct rpc_key_data *)k->hive->root->backend_data)->pol);
    init_winreg_String(&r.in.keyname, k->path);
    r.in.unknown = 0x00000000;
    r.in.access_mask = 0x02000000;
    r.out.handle = &mykeydata->pol;

    dcerpc_winreg_OpenKey((struct dcerpc_pipe *)k->hive->backend_data, mem_ctx, &r);

	return r.out.result;
}

static WERROR rpc_open_key(TALLOC_CTX *mem_ctx, struct registry_hive *h, const char *name, struct registry_key **key)
{
	struct rpc_key_data *mykeydata;
    struct winreg_OpenKey r;

	*key = talloc_p(mem_ctx, struct registry_key);
	(*key)->name = talloc_strdup(mem_ctx, name);

	(*key)->backend_data = mykeydata = talloc_p(mem_ctx, struct rpc_key_data);
	mykeydata->num_values = -1;
	mykeydata->num_subkeys = -1;

	/* Then, open the handle using the hive */

	memset(&r, 0, sizeof(struct winreg_OpenKey));
    r.in.handle = &(((struct rpc_key_data *)h->root->backend_data)->pol);
    init_winreg_String(&r.in.keyname, name);
    r.in.unknown = 0x00000000;
    r.in.access_mask = 0x02000000;
    r.out.handle = &mykeydata->pol;

    dcerpc_winreg_OpenKey((struct dcerpc_pipe *)(h->backend_data), mem_ctx, &r);

	return r.out.result;
}

static WERROR rpc_get_value_by_index(TALLOC_CTX *mem_ctx, struct registry_key *parent, int n, struct registry_value **value)  
{
	struct rpc_key_data *mykeydata = parent->backend_data;
	uint32_t requested_len = 0;
	WERROR error;

	if(mykeydata->num_values == -1) {
		error = rpc_query_key(parent);
		if(!W_ERROR_IS_OK(error)) return error;
	}

	requested_len = mykeydata->max_valdatalen;

#if 0 /* EnumValue is not working yet ... */
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
	vb.buffer = talloc_array_p(mem_ctx, uint8, mykeydata->max_valdatalen);
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
#endif
	
	return WERR_NOT_SUPPORTED;
}

static WERROR rpc_get_subkey_by_index(TALLOC_CTX *mem_ctx, struct registry_key *parent, int n, struct registry_key **subkey) 
{
	struct winreg_EnumKey r;
	struct winreg_EnumKeyNameRequest keyname;
	struct winreg_String classname;
	struct winreg_Time tm;
	struct rpc_key_data *mykeydata = parent->backend_data;
	NTSTATUS status;

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
	status = dcerpc_winreg_EnumKey((struct dcerpc_pipe *)parent->hive->backend_data, mem_ctx, &r);
	if(NT_STATUS_IS_OK(status) && W_ERROR_IS_OK(r.out.result)) {
		if(parent->hive->root == parent)
			return rpc_open_key(mem_ctx, parent->hive, talloc_strdup(mem_ctx, r.out.out_name->name), subkey);
		return rpc_open_key(mem_ctx, parent->hive, talloc_asprintf(mem_ctx, "%s\\%s", parent->path, r.out.out_name->name), subkey);
	}

	return r.out.result;
}

static WERROR rpc_add_key(TALLOC_CTX *mem_ctx, struct registry_key *parent, const char *name, uint32_t access_mask, SEC_DESC *sec, struct registry_key **key)
{
	return WERR_NOT_SUPPORTED;
}

static WERROR rpc_query_key(struct registry_key *k)
{
    NTSTATUS status;
    struct winreg_QueryInfoKey r;
    struct rpc_key_data *mykeydata = k->backend_data;
	TALLOC_CTX *mem_ctx = talloc_init("query_key");

    init_winreg_String(&r.in.class, NULL);
    r.in.handle = &mykeydata->pol;
	
    status = dcerpc_winreg_QueryInfoKey((struct dcerpc_pipe *)(k->hive->backend_data), mem_ctx, &r);
	talloc_destroy(mem_ctx);

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

static WERROR rpc_del_key(struct registry_key *k)
{
	NTSTATUS status;
	struct rpc_key_data *mykeydata = k->backend_data;
	struct winreg_DeleteKey r;
	struct registry_key *parent;
	WERROR error;
	TALLOC_CTX *mem_ctx = talloc_init("del_key");
	
	error = reg_key_get_parent(mem_ctx, k, &parent);
	if(!W_ERROR_IS_OK(error)) { 
		talloc_destroy(mem_ctx); 
		return error; 
	}

	mykeydata = parent->backend_data;

    r.in.handle = &mykeydata->pol;
    init_winreg_String(&r.in.key, k->name);
 
    status = dcerpc_winreg_DeleteKey((struct dcerpc_pipe *)k->hive->backend_data, mem_ctx, &r);

	talloc_destroy(mem_ctx);

	return r.out.result;
}

static WERROR rpc_num_values(struct registry_key *key, int *count) {
	struct rpc_key_data *mykeydata = key->backend_data;
	WERROR error;
		
	if(mykeydata->num_values == -1) {
		error = rpc_query_key(key);
		if(!W_ERROR_IS_OK(error)) return error;
	}
			
	*count = mykeydata->num_values;
	return WERR_OK;
}

static WERROR rpc_num_subkeys(struct registry_key *key, int *count) {
	struct rpc_key_data *mykeydata = key->backend_data;
	WERROR error;

	if(mykeydata->num_subkeys == -1) {
		error = rpc_query_key(key);
		if(!W_ERROR_IS_OK(error)) return error;
	}
			
	*count = mykeydata->num_subkeys;
	return WERR_OK;
}

static struct registry_operations reg_backend_rpc = {
	.name = "rpc",
	.open_hive = rpc_open_hive,
	.open_key = rpc_open_key,
	.get_subkey_by_index = rpc_get_subkey_by_index,
	.get_value_by_index = rpc_get_value_by_index,
	.add_key = rpc_add_key,
	.del_key = rpc_del_key,
	.num_subkeys = rpc_num_subkeys,
	.num_values = rpc_num_values,
	.list_available_hives = rpc_list_hives,
};

NTSTATUS registry_rpc_init(void)
{
	return register_backend("registry", &reg_backend_rpc);
}
