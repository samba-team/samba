/*
   Samba Unix/Linux SMB implementation
   RPC backend for the registry library
   Copyright (C) 2003-2007 Jelmer Vernooij, jelmer@samba.org

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

struct rpc_key {
	struct registry_key key;
	struct policy_handle pol;
	struct dcerpc_pipe *pipe;

	uint32_t num_values;
	uint32_t num_subkeys;
	uint32_t max_valnamelen;
	uint32_t max_valdatalen;
};

struct rpc_registry_context {
	struct registry_context context;
	struct dcerpc_pipe *pipe;
};

static struct registry_operations reg_backend_rpc;

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

static struct {
	uint32_t hkey;
	WERROR (*open) (struct dcerpc_pipe *p, TALLOC_CTX *,
			struct policy_handle *h);
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

static WERROR rpc_get_predefined_key(struct registry_context *ctx,
				     uint32_t hkey_type,
				     struct registry_key **k)
{
	int n;
	struct rpc_key *mykeydata;
	struct rpc_registry_context *rctx = talloc_get_type(ctx, struct rpc_registry_context);

	*k = NULL;

	for(n = 0; known_hives[n].hkey; n++) {
		if(known_hives[n].hkey == hkey_type)
			break;
	}

	if (known_hives[n].open == NULL)  {
		DEBUG(1, ("No such hive %d\n", hkey_type));
		return WERR_NO_MORE_ITEMS;
	}

	mykeydata = talloc_zero(ctx, struct rpc_key);
	mykeydata->key.context = ctx;
	mykeydata->pipe = talloc_reference(mykeydata, rctx->pipe);
	mykeydata->num_values = -1;
	mykeydata->num_subkeys = -1;
	*k = (struct registry_key *)mykeydata;
	return known_hives[n].open(mykeydata->pipe, mykeydata, &(mykeydata->pol));
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

	dcerpc_winreg_OpenKey((struct dcerpc_pipe *)k->hive->backend_data,
			      mem_ctx, &r);

	return r.out.result;
}
#endif

static WERROR rpc_open_key(TALLOC_CTX *mem_ctx, struct registry_key *h,
			   const char *name, struct registry_key **key)
{
	struct rpc_key *parentkeydata = talloc_get_type(h, struct rpc_key),
						    *mykeydata;
	struct winreg_OpenKey r;
	NTSTATUS status;

	mykeydata = talloc(mem_ctx, struct rpc_key);

	mykeydata->key.context = parentkeydata->key.context;
	mykeydata->pipe = talloc_reference(mykeydata, parentkeydata->pipe);
	mykeydata->num_values = -1;
	mykeydata->num_subkeys = -1;
	*key = (struct registry_key *)mykeydata;

	/* Then, open the handle using the hive */
	ZERO_STRUCT(r);
	r.in.parent_handle = &parentkeydata->pol;
	init_winreg_String(&r.in.keyname, name);
	r.in.unknown = 0x00000000;
	r.in.access_mask = 0x02000000;
	r.out.handle = &mykeydata->pol;

	status = dcerpc_winreg_OpenKey(mykeydata->pipe, mem_ctx, &r);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(0,("Error executing openkey: %s\n", nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	return r.out.result;
}

static WERROR rpc_get_value_by_index(TALLOC_CTX *mem_ctx,
				     const struct registry_key *parent,
				     uint32_t n,
				     const char **value_name,
				     uint32_t *type,
				     DATA_BLOB *data)
{
	struct rpc_key *mykeydata = talloc_get_type(parent, struct rpc_key);
	WERROR error;
	struct winreg_EnumValue r;
	uint32_t in_type = 0;
	NTSTATUS status;
	struct winreg_StringBuf name;
	uint32_t zero = 0;

	ZERO_STRUCT(r);

	if (mykeydata->num_values == -1) {
		error = rpc_query_key(parent);
		if(!W_ERROR_IS_OK(error)) return error;
	}

	name.length = 0;
	name.size   = mykeydata->max_valnamelen * 2+1;
	name.name   = NULL;

	r.in.handle = &mykeydata->pol;
	r.in.enum_index = n;
	r.in.name = &name;
	r.in.type = &in_type;
	r.in.value = talloc_zero_array(mem_ctx, uint8_t, 0);
	r.in.length = &zero;
	r.in.size = &mykeydata->max_valdatalen;
	r.out.name = &name;

	status = dcerpc_winreg_EnumValue(mykeydata->pipe, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		DEBUG(0, ("Error in EnumValue: %s\n", nt_errstr(status)));
		return WERR_GENERAL_FAILURE;
	}

	if(NT_STATUS_IS_OK(status) &&
	   W_ERROR_IS_OK(r.out.result) && r.out.length) {
		*value_name = talloc_strdup(mem_ctx, r.out.name->name);
		*data = data_blob_talloc(mem_ctx, r.out.value, *r.out.length);
		return WERR_OK;
	}

	return r.out.result;
}

static WERROR rpc_get_subkey_by_index(TALLOC_CTX *mem_ctx,
				      const struct registry_key *parent,
				      uint32_t n,
				      const char **name,
				      const char **keyclass,
				      NTTIME *last_changed_time)
{
	struct winreg_EnumKey r;
	struct rpc_key *mykeydata = talloc_get_type(parent, struct rpc_key);
	NTSTATUS status;
	struct winreg_StringBuf namebuf, classbuf;
	NTTIME change_time = 0;

	ZERO_STRUCT(r);

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

	status = dcerpc_winreg_EnumKey(mykeydata->pipe, mem_ctx, &r);
	if (NT_STATUS_IS_OK(status) && W_ERROR_IS_OK(r.out.result)) {
		*name = talloc_strdup(mem_ctx, r.out.name->name);
		if (keyclass != NULL)
			*keyclass = talloc_strdup(mem_ctx, r.out.keyclass->name);
	}

	return r.out.result;
}

static WERROR rpc_add_key(TALLOC_CTX *mem_ctx,
			  struct registry_key *parent, const char *name,
			  const char *key_class,
			  struct security_descriptor *sec,
			  struct registry_key **key)
{
	NTSTATUS status;
	struct winreg_CreateKey r;
	struct rpc_key *parentkd = talloc_get_type(parent, struct rpc_key);
	struct rpc_key *rpck = talloc(mem_ctx, struct rpc_key);

	init_winreg_String(&r.in.name, name);
	init_winreg_String(&r.in.keyclass, NULL);

	r.in.handle = &parentkd->pol;
	r.out.new_handle = &rpck->pol;
	r.in.options = 0;
	r.in.access_mask = SEC_STD_ALL;
	r.in.secdesc = NULL;

	status = dcerpc_winreg_CreateKey(parentkd->pipe, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(rpck);
		DEBUG(1, ("CreateKey failed - %s\n", nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	if (W_ERROR_IS_OK(r.out.result)) {
		rpck->pipe = talloc_reference(rpck, parentkd->pipe);
		*key = (struct registry_key *)rpck;
	}

	return r.out.result;
}

static WERROR rpc_query_key(const struct registry_key *k)
{
	NTSTATUS status;
	struct winreg_QueryInfoKey r;
	struct rpc_key *mykeydata = talloc_get_type(k, struct rpc_key);
	TALLOC_CTX *mem_ctx = talloc_init("query_key");
	uint32_t max_subkeysize;
	uint32_t num_values;
	uint32_t secdescsize;
	NTTIME last_changed_time;

	ZERO_STRUCT(r.out);

	r.out.num_subkeys = &mykeydata->num_subkeys;
	r.out.max_subkeylen = &mykeydata->num_values;
	r.out.max_valnamelen = &mykeydata->max_valnamelen;
	r.out.max_valbufsize = &mykeydata->max_valdatalen;
	r.out.max_subkeysize = &max_subkeysize;
	r.out.num_values = &num_values;
	r.out.secdescsize = &secdescsize;
	r.out.last_changed_time = &last_changed_time;

	r.out.classname = r.in.classname = talloc_zero(mem_ctx, struct winreg_String);
	init_winreg_String(r.in.classname, NULL);
	r.in.handle = &mykeydata->pol;

	status = dcerpc_winreg_QueryInfoKey(mykeydata->pipe, mem_ctx, &r);
	talloc_free(mem_ctx);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("QueryInfoKey failed - %s\n", nt_errstr(status)));
		return ntstatus_to_werror(status);
	}

	if (W_ERROR_IS_OK(r.out.result)) {
	}

	return r.out.result;
}

static WERROR rpc_del_key(struct registry_key *parent, const char *name)
{
	NTSTATUS status;
	struct rpc_key *mykeydata = talloc_get_type(parent, struct rpc_key);
	struct winreg_DeleteKey r;
	TALLOC_CTX *mem_ctx = talloc_init("del_key");

	r.in.handle = &mykeydata->pol;
	init_winreg_String(&r.in.key, name);

	status = dcerpc_winreg_DeleteKey(mykeydata->pipe, mem_ctx, &r);

	talloc_free(mem_ctx);

	return r.out.result;
}

static WERROR rpc_get_info(TALLOC_CTX *mem_ctx, const struct registry_key *key,
						   const char **classname,
						   uint32_t *numsubkeys,
						   uint32_t *numvalue,
						   NTTIME *last_changed_time)
{
	struct rpc_key *mykeydata = talloc_get_type(key, struct rpc_key);
	WERROR error;

	if (mykeydata->num_values == -1) {
		error = rpc_query_key(key);
		if(!W_ERROR_IS_OK(error)) return error;
	}

	/* FIXME: *classname = talloc_strdup(mem_ctx, mykeydata->classname); */
	/* FIXME: *last_changed_time = mykeydata->last_changed_time */

	if (numvalue != NULL)
		*numvalue = mykeydata->num_values;

	if (numsubkeys != NULL)
		*numsubkeys = mykeydata->num_subkeys;

	return WERR_OK;
}

static struct registry_operations reg_backend_rpc = {
	.name = "rpc",
	.open_key = rpc_open_key,
	.get_predefined_key = rpc_get_predefined_key,
	.enum_key = rpc_get_subkey_by_index,
	.enum_value = rpc_get_value_by_index,
	.create_key = rpc_add_key,
	.delete_key = rpc_del_key,
	.get_key_info = rpc_get_info,
	.get_predefined_key = rpc_get_predefined_key,
};

_PUBLIC_ WERROR reg_open_remote(struct registry_context **ctx,
				struct auth_session_info *session_info,
				struct cli_credentials *credentials,
				struct loadparm_context *lp_ctx,
				const char *location, struct event_context *ev)
{
	NTSTATUS status;
	struct dcerpc_pipe *p;
	struct rpc_registry_context *rctx;

	dcerpc_init();

	rctx = talloc(NULL, struct rpc_registry_context);

	/* Default to local smbd if no connection is specified */
	if (!location) {
		location = talloc_strdup(rctx, "ncalrpc:");
	}

	status = dcerpc_pipe_connect(rctx /* TALLOC_CTX */,
				     &p, location,
					 &ndr_table_winreg,
				     credentials, ev, lp_ctx);
	rctx->pipe = p;

	if(NT_STATUS_IS_ERR(status)) {
		DEBUG(1, ("Unable to open '%s': %s\n", location,
			nt_errstr(status)));
		talloc_free(rctx);
		*ctx = NULL;
		return ntstatus_to_werror(status);
	}

	*ctx = (struct registry_context *)rctx;
	(*ctx)->ops = &reg_backend_rpc;

	return WERR_OK;
}
