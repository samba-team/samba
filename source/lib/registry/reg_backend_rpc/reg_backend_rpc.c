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
	NTSTATUS status; \
	struct winreg_Open ## u r; \
	struct winreg_OpenUnknown unknown; \
	struct policy_handle *hnd = malloc(sizeof(struct policy_handle)); \
	TALLOC_CTX *mem_ctx = talloc_init("openhive"); \
	\
	unknown.unknown0 = 0x84e0; \
	unknown.unknown1 = 0x0000; \
	r.in.unknown = &unknown; \
	r.in.access_required = SEC_RIGHTS_MAXIMUM_ALLOWED; \
	r.out.handle = hnd;\
	\
	if (!NT_STATUS_IS_OK(dcerpc_winreg_Open ## u(p, mem_ctx, &r))) {\
		printf("Error executing open\n");\
		return NULL;\
	}\
\
	talloc_destroy(mem_ctx);\
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

struct {
	char *name;
	struct policy_handle *(*open) (struct dcerpc_pipe *p, REG_HANDLE *h);
} known_hives[] = {
{ "HKEY_LOCAL_MACHINE", open_HKLM },
{ "HKEY_CURRENT_USER", open_HKCU },
{ "HKEY_CLASSES_ROOT", open_HKCR },
{ "HKEY_PERFORMANCE_DATA", open_HKPD },
{ "HKEY_USERS", open_HKU },
{ NULL, NULL }
};

static BOOL rpc_open_registry(REG_HANDLE *h, const char *location, BOOL try_full)
{
	BOOL res = True;
	struct rpc_data *mydata = malloc(sizeof(struct rpc_data));
	char *binding = strdup(location);
	NTSTATUS status;
	
	ZERO_STRUCTP(mydata);
	
	status = dcerpc_pipe_connect(&mydata->pipe, binding, 
                    DCERPC_WINREG_UUID,
                    DCERPC_WINREG_VERSION,
                     lp_workgroup(),
                     "jelwin", "dds");

	if(!NT_STATUS_IS_OK(status)) return False;

	h->backend_data = mydata;
	
	return True;
}

static REG_KEY *rpc_open_root(REG_HANDLE *h)
{
	/* There's not really a 'root' key here */
	return reg_key_new_abs("\\", h, h->backend_data);
}

static BOOL rpc_close_registry(REG_HANDLE *h)
{
	dcerpc_pipe_close(((struct rpc_data *)h->backend_data)->pipe);
	free(h->backend_data);
	return True;
}

static struct policy_handle *rpc_get_key_handle(REG_HANDLE *h, const char *path)
{
	char *hivename;
	int i = 0;
	struct rpc_data *mydata = h->backend_data;
	struct policy_handle *hive = NULL;
	char *end = strchr(path+1, '\\');
    NTSTATUS status;
    struct winreg_OpenKey r;
	struct policy_handle *key_handle = malloc(sizeof(struct policy_handle));
	TALLOC_CTX *mem_ctx;
 
	if(end) hivename = strndup(path+1, end-path-1);
	else hivename = strdup(path+1);

	for(i = 0; known_hives[i].name; i++) {
		if(!strcmp(hivename, known_hives[i].name)) {
    		if(!mydata->hives[i]) mydata->hives[i] = known_hives[i].open(mydata->pipe, h);
			hive = mydata->hives[i];
		}
	}
	
	if(!hive) {
		DEBUG(0, ("No such hive: %s\n", hivename));
		return NULL;
	}

	DEBUG(2, ("Opening %s, hive: %s\n", path, hivename));

	if(!end || !(*end) || !(*(end+1))) return hive;

	memset(&r, 0, sizeof(struct winreg_OpenKey));
    r.in.handle = hive;
    init_winreg_String(&r.in.keyname, end+1);
    r.in.unknown = 0x00000000;
    r.in.access_mask = 0x02000000;
    r.out.handle = key_handle;
                        
	mem_ctx = talloc_init("openkey");
    status = dcerpc_winreg_OpenKey(mydata->pipe, mem_ctx, &r);
	talloc_destroy(mem_ctx);
                                                                                                                               
    if (!NT_STATUS_IS_OK(status) || !W_ERROR_IS_OK(r.out.result)) {
        return NULL;
    }

	return key_handle;
}

static REG_KEY *rpc_open_key(REG_HANDLE *h, const char *name)
{
	return reg_key_new_abs(name, h, rpc_get_key_handle(h, name));
}

static BOOL rpc_fetch_subkeys(REG_KEY *parent, int *count, REG_KEY ***subkeys) 
{
	struct winreg_EnumKey r;
	struct winreg_EnumKeyNameRequest keyname;
	struct winreg_String classname;
	struct winreg_Time tm;
	struct rpc_data *mydata = parent->handle->backend_data;
	int i;
	REG_KEY **ar = malloc(sizeof(REG_KEY *));
	NTSTATUS status = NT_STATUS_OK;
	TALLOC_CTX *mem_ctx;

	/* List the hives */
	if(parent->backend_data == parent->handle->backend_data) { 
		REG_KEY **ar = malloc(sizeof(REG_KEY *));
		for(i = 0; known_hives[i].name; i++) {
			ar[i] = reg_key_new_rel(known_hives[i].name, parent, NULL);
			(*count)++;
			ar = realloc(ar, sizeof(REG_KEY *) * ((*count)+1));
		}

		*subkeys = ar;

		return True;
	}

	if(!parent->backend_data) parent->backend_data = rpc_get_key_handle(parent->handle, reg_key_get_path(parent));

	if(!parent->backend_data) return False;

	mem_ctx = talloc_init("enumkey");
	(*count) = 0;
	r.in.handle = parent->backend_data;
	keyname.unknown = 0x0000020a;
	init_winreg_String(&keyname.key_name, NULL);
	init_winreg_String(&classname, NULL);
	r.in.in_name = &keyname;
	r.in.class = &classname;
	tm.low = tm.high = 0x7fffffff;
	r.in.last_changed_time = &tm;
	r.out.result.v = 0;

	for(i = 0; NT_STATUS_IS_OK(status) && W_ERROR_IS_OK(r.out.result); i++) {
		r.in.enum_index = i;
		r.in.unknown = r.out.unknown = 0x0414;
		r.in.key_name_len = r.out.key_name_len = 0;
		status = dcerpc_winreg_EnumKey(mydata->pipe, mem_ctx, &r);
		if(NT_STATUS_IS_OK(status) && W_ERROR_IS_OK(r.out.result)) {
			ar[(*count)] = reg_key_new_rel(r.out.out_name->name, parent, NULL);
			(*count)++;
			ar = realloc(ar, ((*count)+1) * sizeof(REG_KEY *));
		}
	}

	*subkeys = ar;
	return True;
}

static BOOL rpc_fetch_values(REG_KEY *parent, int *count, REG_VAL ***values) 
{
	struct winreg_EnumValue r;
	struct winreg_EnumValueName name;
	struct winreg_Uint8buf value;
	struct winreg_Uint16buf buf;
	struct rpc_data *mydata = parent->handle->backend_data;
	TALLOC_CTX *mem_ctx;
	uint32 type, requested_len, returned_len;
	NTSTATUS status = NT_STATUS_OK;
	REG_VAL **ar = malloc(sizeof(REG_VAL *));

	(*count) = 0;

	if(!parent->backend_data) parent->backend_data = rpc_get_key_handle(parent->handle, reg_key_get_path(parent));

	if(!parent->backend_data) return False;

	r.in.handle = parent->backend_data;
	r.in.enum_index = 0;

	buf.max_len = 0x7fff;
	buf.offset = 0;
	buf.len = 0;
	buf.buffer = NULL;

	name.len = 0;
	name.max_len = buf.max_len *2;
	name.buf = &buf;

	r.in.name = r.out.name = &name;

	type = 0;
	r.in.type = r.out.type = &type;
	value.max_len = 0x7fff;
	value.offset = 0;
	value.len = 0;
	value.buffer = NULL;

	r.in.value = r.out.value = &value;

	requested_len = value.max_len;
	r.in.requested_len = &requested_len;
	returned_len = 0;
	r.in.returned_len = &returned_len;
	r.out.result.v = 0;

	mem_ctx = talloc_init("fetchvalues");
	while(1) {
		status = dcerpc_winreg_EnumValue(mydata->pipe, mem_ctx, &r);
		if(NT_STATUS_IS_OK(status) && W_ERROR_IS_OK(r.out.result)) {
			r.in.enum_index++;
			ar[(*count)] = reg_val_new(parent, NULL);
			ar[(*count)]->name = strdup((char *)name.buf);
			ar[(*count)]->data_type = *r.out.type;
			ar[(*count)]->data_len = value.len;
			ar[(*count)]->data_blk = malloc(value.len);
			memcpy(ar[(*count)]->data_blk, value.buffer, value.len);
			(*count)++;
			ar = realloc(ar, ((*count)+1) * sizeof(REG_VAL *));
		} else break;
	} 
	
	talloc_destroy(mem_ctx);

	return True;
}

static REG_OPS reg_backend_rpc = {
	.name = "rpc",
	.open_registry = rpc_open_registry,
	.close_registry = rpc_close_registry,
	.open_root_key = rpc_open_root,
	.open_key = rpc_open_key,
	.fetch_subkeys = rpc_fetch_subkeys,
	.fetch_values = rpc_fetch_values,
};

NTSTATUS reg_rpc_init(void)
{
	return register_backend("registry", &reg_backend_rpc);
}
