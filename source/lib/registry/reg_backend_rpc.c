/*
   Samba Unix/Linux SMB implementation
   RPC backend for the registry library
   Copyright (C) 2003-2004 Jelmer Vernooij, jelmer@samba.org

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */
 
#include "includes.h"
#include "registry.h"
#include "librpc/gen_ndr/ndr_winreg_c.h"

static struct hive_operations reg_backend_rpc;

/**
 * This is the RPC backend for the registry library.
 */

static void init_winreg_String(struct winreg_String *name, const char *s)
{
	name->name = s;
}


#define openhive(u) static WERROR open_ ## u(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct policy_handle *hnd) \
{ \
	struct winreg_Open ## u r; \
	NTSTATUS status; \
	\
	r.in.system_name = NULL; \
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED; \
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

static struct {
	uint32_t hkey;
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

static WERROR rpc_query_key(const struct registry_key *k);

static WERROR rpc_get_predefined_key (struct registry_context *ctx, uint32_t hkey_type, struct registry_key **k)
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

	h = talloc(ctx, struct registry_hive);
	h->functions = &reg_backend_rpc;
	h->location = NULL;
	h->backend_data = ctx->backend_data;
	
	(*k) = h->root = talloc(h, struct registry_key);
	(*k)->hive = h;
	(*k)->backend_data = mykeydata = talloc(*k, struct rpc_key_data);
	mykeydata->num_values = -1;
	mykeydata->num_subkeys = -1;
	return known_hives[n].open((struct dcerpc_pipe *)ctx->backend_data, *k, &(mykeydata->pol));
}

#if 0
static WERROR rpc_key_put_rpc_data(TALLOC_CTX *mem_ctx, struct registry_key *k)
{
    struct winreg_OpenKey r;
	struct rpc_key_data *mykeydata;

	k->backend_data = mykeydata = talloc(mem_ctx, struct rpc_key_data);
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

static WERROR rpc_open_key(TALLOC_CTX *mem_ctx, const struct registry_key *h, const char *name, struct registry_key **key)
{
	struct rpc_key_data *mykeydata;
    struct winreg_OpenKey r;

	*key = talloc(mem_ctx, struct registry_key);
	(*key)->name = talloc_strdup(mem_ctx, name);

	(*key)->backend_data = mykeydata = talloc(mem_ctx, struct rpc_key_data);
	mykeydata->num_values = -1;
	mykeydata->num_subkeys = -1;

	/* Then, open the handle using the hive */

	memset(&r, 0, sizeof(struct winreg_OpenKey));
    r.in.parent_handle = &(((struct rpc_key_data *)h->backend_data)->pol);
    init_winreg_String(&r.in.keyname, name);
    r.in.unknown = 0x00000000;
    r.in.access_mask = 0x02000000;
    r.out.handle = &mykeydata->pol;

    dcerpc_winreg_OpenKey((struct dcerpc_pipe *)(h->hive->backend_data), mem_ctx, &r);

	return r.out.result;
}

static WERROR rpc_get_value_by_index(TALLOC_CTX *mem_ctx, const struct registry_key *parent, int n, struct registry_value **value)  
{
	struct rpc_key_data *mykeydata = parent->backend_data;
	WERROR error;
	struct winreg_EnumValue r;
	uint32_t len1, zero = 0;
	enum winreg_Type type;
	NTSTATUS status;
	struct winreg_StringBuf name;
	uint8_t u8;
	
	if(mykeydata->num_values == -1) {
		error = rpc_query_key(parent);
		if(!W_ERROR_IS_OK(error)) return error;
	}

	len1 = mykeydata->max_valdatalen;
	
	name.length = 0;
	name.size   = mykeydata->max_valnamelen * 2;
	name.name   = "";

	r.in.handle = &mykeydata->pol;
	r.in.enum_index = n;
	r.in.name = &name;
	r.in.type = &type;
	r.in.value = &u8;
	r.in.length = &zero;
	r.in.size = &len1;
	r.out.name = &name;
	
	status = dcerpc_winreg_EnumValue((struct dcerpc_pipe *)parent->hive->backend_data, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		DEBUG(0, ("Error in EnumValue: %s\n", nt_errstr(status)));
		return WERR_GENERAL_FAILURE;
	}
	
	if(NT_STATUS_IS_OK(status) && 
	   W_ERROR_IS_OK(r.out.result) && r.out.length) {
		*value = talloc(mem_ctx, struct registry_value);
		(*value)->name = talloc_strdup(mem_ctx, r.out.name->name);
		(*value)->data_type = type;
		(*value)->data = data_blob_talloc(mem_ctx, r.out.value, *r.out.length);
		return WERR_OK;
	}
	
	return r.out.result;
}

static WERROR rpc_get_subkey_by_index(TALLOC_CTX *mem_ctx, const struct registry_key *parent, int n, struct registry_key **subkey) 
{
	struct winreg_EnumKey r;
	struct rpc_key_data *mykeydata = parent->backend_data;
	NTSTATUS status;
	struct winreg_StringBuf namebuf, classbuf;
	NTTIME change_time = 0;

	namebuf.length = 0;
	namebuf.size   = 1024;
	namebuf.name   = NULL;
	classbuf.length = 0;
	classbuf.size   = 0;
	classbuf.name   = NULL;

	r.in.handle = &mykeydata->pol;
	r.in.enum_index = n;
	r.in.name = &namebuf;
	r.in.keyclass = &classbuf;
	r.in.last_changed_time = &change_time;
	r.out.name = &namebuf;

	status = dcerpc_winreg_EnumKey((struct dcerpc_pipe *)parent->hive->backend_data, mem_ctx, &r);
	if(NT_STATUS_IS_OK(status) && W_ERROR_IS_OK(r.out.result)) {
		char *name = talloc_strdup(mem_ctx, r.out.name->name);
		return rpc_open_key(mem_ctx, parent, name, subkey);
	}

	return r.out.result;
}

static WERROR rpc_add_key(TALLOC_CTX *mem_ctx, const struct registry_key *parent, const char *name, uint32_t access_mask, struct security_descriptor *sec, struct registry_key **key)
{
	NTSTATUS status;
	struct winreg_CreateKey r;

	init_winreg_String(&r.in.name, name);
	init_winreg_String(&r.in.keyclass, NULL);

	r.in.handle = parent->backend_data;
	r.out.new_handle = talloc(mem_ctx, struct policy_handle);	
	r.in.options = 0;
	r.in.access_mask = access_mask;
	r.in.secdesc = NULL;

	status = dcerpc_winreg_CreateKey((struct dcerpc_pipe *)(parent->hive->backend_data), mem_ctx, &r);

    if (!NT_STATUS_IS_OK(status)) {
        DEBUG(1, ("CreateKey failed - %s\n", nt_errstr(status)));
        return ntstatus_to_werror(status);
    }

	if (W_ERROR_IS_OK(r.out.result)) {
		*key = talloc(mem_ctx, struct registry_key);
		(*key)->name = talloc_strdup(*key, name);
		(*key)->backend_data = r.out.new_handle;
	}

	return r.out.result;
}

static WERROR rpc_query_key(const struct registry_key *k)
{
    NTSTATUS status;
    struct winreg_QueryInfoKey r;
    struct rpc_key_data *mykeydata = k->backend_data;
	TALLOC_CTX *mem_ctx = talloc_init("query_key");

	r.in.classname = talloc(mem_ctx, struct winreg_String);
    init_winreg_String(r.in.classname, NULL);
    r.in.handle = &mykeydata->pol;
	
    status = dcerpc_winreg_QueryInfoKey((struct dcerpc_pipe *)(k->hive->backend_data), mem_ctx, &r);
	talloc_free(mem_ctx);

    if (!NT_STATUS_IS_OK(status)) {
        DEBUG(1, ("QueryInfoKey failed - %s\n", nt_errstr(status)));
        return ntstatus_to_werror(status);
    }
                                                                                                       
    if (W_ERROR_IS_OK(r.out.result)) {
		mykeydata->num_subkeys = *r.out.num_subkeys;
		mykeydata->num_values = *r.out.num_values;
		mykeydata->max_valnamelen = *r.out.max_valnamelen;
		mykeydata->max_valdatalen = *r.out.max_valbufsize;
	} 

	return r.out.result;
}

static WERROR rpc_del_key(const struct registry_key *parent, const char *name)
{
	NTSTATUS status;
	struct rpc_key_data *mykeydata = parent->backend_data;
	struct winreg_DeleteKey r;
	TALLOC_CTX *mem_ctx = talloc_init("del_key");
	
    r.in.handle = &mykeydata->pol;
    init_winreg_String(&r.in.key, name);
 
    status = dcerpc_winreg_DeleteKey((struct dcerpc_pipe *)parent->hive->backend_data, mem_ctx, &r);

	talloc_free(mem_ctx);

	return r.out.result;
}

static WERROR rpc_num_values(const struct registry_key *key, uint32_t *count) 
{
	struct rpc_key_data *mykeydata = key->backend_data;
	WERROR error;
		
	if(mykeydata->num_values == -1) {
		error = rpc_query_key(key);
		if(!W_ERROR_IS_OK(error)) return error;
	}
			
	*count = mykeydata->num_values;
	return WERR_OK;
}

static WERROR rpc_num_subkeys(const struct registry_key *key, uint32_t *count) 
{
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

_PUBLIC_ WERROR reg_open_remote(struct registry_context **ctx, struct auth_session_info *session_info, struct cli_credentials *credentials, 
		       const char *location, struct event_context *ev)
{
	NTSTATUS status;
	struct dcerpc_pipe *p;

	*ctx = talloc(NULL, struct registry_context);

	/* Default to local smbd if no connection is specified */
	if (!location) {
		location = talloc_strdup(ctx, "ncalrpc:");
	}

	status = dcerpc_pipe_connect(*ctx /* TALLOC_CTX */, 
				     &p, location, 
					 &dcerpc_table_winreg,
				     credentials, ev);
	(*ctx)->backend_data = p;

	if(NT_STATUS_IS_ERR(status)) {
		DEBUG(1, ("Unable to open '%s': %s\n", location, nt_errstr(status)));
		talloc_free(*ctx);
		*ctx = NULL;
		return ntstatus_to_werror(status);
	}

	(*ctx)->get_predefined_key = rpc_get_predefined_key;

	return WERR_OK;
}

NTSTATUS registry_rpc_init(void)
{
	dcerpc_init();
	return registry_register(&reg_backend_rpc);
}
