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
#include "registry.h"
#include "librpc/gen_ndr/ndr_winreg.h"

static struct hive_operations reg_backend_rpc;

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
	r.in.access_required = SEC_FLAG_MAXIMUM_ALLOWED; \
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
openhive(HKDD)
openhive(HKCC)

struct rpc_key_data {
	struct policy_handle pol;
	int num_subkeys;
	int num_values;
	int max_valnamelen;
	int max_valdatalen;
};

struct {
	uint32 hkey;
	WERROR (*open) (struct dcerpc_pipe *p, TALLOC_CTX *, struct policy_handle *h);
} known_hives[] = {
{ HKEY_LOCAL_MACHINE, open_HKLM },
{ HKEY_CURRENT_USER, open_HKCU },
{ HKEY_CLASSES_ROOT, open_HKCR },
{ HKEY_PERFORMANCE_DATA, open_HKPD },
{ HKEY_USERS, open_HKU },
{ HKEY_DYN_DATA, open_HKDD },
{ HKEY_CURRENT_CONFIG, open_HKCC },
{ 0, NULL }
};

static WERROR rpc_query_key(struct registry_key *k);

static WERROR rpc_get_hive (struct registry_context *ctx, uint32 hkey_type, struct registry_key **k)
{
	int n;
	struct registry_hive *h;
	struct rpc_key_data *mykeydata;

	for(n = 0; known_hives[n].hkey; n++) 
	{
		if(known_hives[n].hkey == hkey_type) break;
	}
	
	if(!known_hives[n].open)  {
		DEBUG(1, ("No such hive %d\n", hkey_type));
		return WERR_NO_MORE_ITEMS;
	}

	h = talloc_p(ctx, struct registry_hive);
	h->functions = &reg_backend_rpc;
	h->location = NULL;
	h->backend_data = ctx->backend_data;
	h->reg_ctx = ctx;
	
	(*k) = h->root = talloc_p(h, struct registry_key);
	(*k)->hive = h;
	(*k)->backend_data = mykeydata = talloc_p(*k, struct rpc_key_data);
	mykeydata->num_values = -1;
	mykeydata->num_subkeys = -1;
	return known_hives[n].open((struct dcerpc_pipe *)ctx->backend_data, *k, &(mykeydata->pol));
}

static int rpc_close (void *_h)
{
	struct registry_context *h = _h;
	dcerpc_pipe_close(h->backend_data);
	return 0;
}

#if 0
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
#endif

static WERROR rpc_open_key(TALLOC_CTX *mem_ctx, struct registry_key *h, const char *name, struct registry_key **key)
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
    r.in.handle = &(((struct rpc_key_data *)h->backend_data)->pol);
    init_winreg_String(&r.in.keyname, name);
    r.in.unknown = 0x00000000;
    r.in.access_mask = 0x02000000;
    r.out.handle = &mykeydata->pol;

    dcerpc_winreg_OpenKey((struct dcerpc_pipe *)(h->hive->backend_data), mem_ctx, &r);

	return r.out.result;
}

static WERROR rpc_get_value_by_index(TALLOC_CTX *mem_ctx, struct registry_key *parent, int n, struct registry_value **value)  
{
	struct rpc_key_data *mykeydata = parent->backend_data;
	WERROR error;
	struct winreg_EnumValue r;
	uint32 type, len1, zero = 0;
	NTSTATUS status;
	uint8_t buf8;
	uint16_t buf16;
	
	if(mykeydata->num_values == -1) {
		error = rpc_query_key(parent);
		if(!W_ERROR_IS_OK(error)) return error;
	}

	len1 = mykeydata->max_valdatalen;
	
	r.in.handle = &mykeydata->pol;
	r.in.enum_index = n;
	r.in.name_in.length = 0;
	r.in.name_in.size = mykeydata->max_valnamelen * 2;
	r.in.name_in.name = &buf16;
	r.in.type = &type;
	r.in.value = &buf8;
	r.in.length = &zero;
	r.in.size = &len1;
	r.out.type = &type;

	
	status = dcerpc_winreg_EnumValue((struct dcerpc_pipe *)parent->hive->backend_data, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		DEBUG(0, ("Error in EnumValue: %s\n", nt_errstr(status)));
		return WERR_GENERAL_FAILURE;
	}
	
	if(NT_STATUS_IS_OK(status) && 
	   W_ERROR_IS_OK(r.out.result) && r.out.length) {
		*value = talloc_p(mem_ctx, struct registry_value);
		(*value)->parent = parent;
		(*value)->name = talloc_strdup(mem_ctx, r.out.name_out.name);
		(*value)->data_type = type;
		(*value)->data_len = *r.out.length;
		(*value)->data_blk = talloc_memdup(mem_ctx, r.out.value, *r.out.length);
		return WERR_OK;
	}
	
	return r.out.result;
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
			return rpc_open_key(mem_ctx, parent, talloc_strdup(mem_ctx, r.out.out_name->name), subkey);
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
        DEBUG(1, ("QueryInfoKey failed - %s\n", nt_errstr(status)));
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

static struct hive_operations reg_backend_rpc = {
	.name = "rpc",
	.open_key = rpc_open_key,
	.get_subkey_by_index = rpc_get_subkey_by_index,
	.get_value_by_index = rpc_get_value_by_index,
	.add_key = rpc_add_key,
	.del_key = rpc_del_key,
	.num_subkeys = rpc_num_subkeys,
	.num_values = rpc_num_values,
};

WERROR reg_open_remote (struct registry_context **ctx, const char *user, const char *pass, const char *location)
{
	NTSTATUS status;
	struct dcerpc_pipe *p;

	*ctx = talloc_p(NULL, struct registry_context);

	/* Default to local smbd if no connection is specified */
	if (!location) {
		location = talloc_strdup(ctx, "ncalrpc:");
	}

	status = dcerpc_pipe_connect(&p, location, 
				     DCERPC_WINREG_UUID,
				     DCERPC_WINREG_VERSION,
				     lp_workgroup(),
				     user, pass);
	(*ctx)->backend_data = p;

	if(NT_STATUS_IS_ERR(status)) {
		DEBUG(1, ("Unable to open '%s': %s\n", location, nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	(*ctx)->get_hive = rpc_get_hive;

	talloc_set_destructor(*ctx, rpc_close);

	return WERR_OK;
}

NTSTATUS registry_rpc_init(void)
{
	return registry_register(&reg_backend_rpc);
}
