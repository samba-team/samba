/* 
   Unix SMB/CIFS implementation.
   test suite for winreg rpc operations

   Copyright (C) Tim Potter 2003
   
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

static void init_winreg_String(struct winreg_String *name, const char *s)
{
	name->name = s;
	name->name_len = 2*strlen_m(s);
	name->name_size = name->name_len;
}

static BOOL test_GetVersion(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			    struct policy_handle *handle)
{
	NTSTATUS status;
	struct winreg_GetVersion r;

	printf("\ntesting GetVersion\n");

	r.in.handle = handle;

	status = dcerpc_winreg_GetVersion(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("GetVersion failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_CloseKey(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			  struct policy_handle *handle)
{
	NTSTATUS status;
	struct winreg_CloseKey r;

	printf("\ntesting CloseKey\n");

	r.in.handle = r.out.handle = handle;

	status = dcerpc_winreg_CloseKey(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("CloseKey failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_FlushKey(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			  struct policy_handle *handle)
{
	NTSTATUS status;
	struct winreg_FlushKey r;

	printf("\ntesting FlushKey\n");

	r.in.handle = handle;

	status = dcerpc_winreg_FlushKey(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("FlushKey failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_OpenKey(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			 struct policy_handle *hive_handle,
			 char *keyname, struct policy_handle *key_handle)
{
	NTSTATUS status;
	struct winreg_OpenKey r;

	printf("\ntesting OpenKey\n");

	r.in.handle = hive_handle;
	init_winreg_String(&r.in.keyname, keyname);
	r.in.unknown = 0x00000000;
	r.in.access_mask = 0x02000000;
	r.out.handle = key_handle;

	status = dcerpc_winreg_OpenKey(p, mem_ctx, &r);

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("OpenKey failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_DeleteKey(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			   struct policy_handle *handle, char *key)
{
	NTSTATUS status;
	struct winreg_DeleteKey r;

	printf("\ntesting DeleteKey\n");

	r.in.handle = handle;
	init_winreg_String(&r.in.key, key);	

	status = dcerpc_winreg_DeleteKey(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("DeleteKey failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_QueryInfoKey(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			      struct policy_handle *handle, char *class)
{
	NTSTATUS status;
	struct winreg_QueryInfoKey r;

	printf("\ntesting QueryInfoKey\n");

	r.in.handle = handle;
	init_winreg_String(&r.in.class, class);
	
	status = dcerpc_winreg_QueryInfoKey(p, mem_ctx, &r);

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("QueryInfoKey failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	return True;
}

static BOOL test_EnumKey(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			 struct policy_handle *handle)
{
	NTSTATUS status;
	struct winreg_EnumKey r;
	struct winreg_EnumKeyNameRequest keyname;
	struct winreg_String classname;
	struct winreg_Time tm;

	printf("\ntesting EnumKey\n");

	r.in.handle = handle;
	r.in.key_index = 0;
	r.in.key_name_len = r.out.key_name_len = 0;
	r.in.unknown = r.out.unknown = 0x0414;
	keyname.unknown = 0x0000020a;
	init_winreg_String(&keyname.key_name, NULL);
	init_winreg_String(&classname, NULL);
	r.in.in_name = &keyname;
	r.in.class = &classname;
	tm.low = tm.high = 0x7fffffff;
	r.in.last_changed_time = &tm;

	do {
		status = dcerpc_winreg_EnumKey(p, mem_ctx, &r);
		r.in.key_index++;
	} while (W_ERROR_IS_OK(r.out.result));

	return True;
}

static BOOL test_EnumValue(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			   struct policy_handle *handle)
{
	NTSTATUS status;
	struct winreg_QueryInfoKey qik;
	struct winreg_EnumValue r;
	struct winreg_String name;
	uint32 type;
	uint32 value1, value2;


	printf("\ntesting EnumValue\n");

	qik.in.handle = handle;
	init_winreg_String(&qik.in.class, NULL);

	status = dcerpc_winreg_QueryInfoKey(p, mem_ctx, &qik);

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("QueryInfoKey failed - %s\n", win_errstr(r.out.result));
		return False;
	}

	r.in.handle = handle;
	r.in.val_index = 0;
	init_winreg_String(&name, "");
	r.in.name = &name;
	type = 0;
	r.in.type = r.out.type = &type;
	r.in.value = NULL;
	value1 = 0;
	value2 = 0;
	r.in.value1 = &value1;
	r.in.value2 = &value2;

	do {
		status = dcerpc_winreg_EnumValue(p, mem_ctx, &r);
		r.in.val_index++;
	} while (W_ERROR_IS_OK(r.out.result));

	return True;
}

static BOOL test_OpenHKLM(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			  struct policy_handle *handle)
{
	NTSTATUS status;
	struct winreg_OpenHKLM r;
	struct winreg_OpenUnknown unknown;
	BOOL ret = True;

	printf("\ntesting OpenHKLM\n");

	unknown.unknown0 = 0x84e0;
	unknown.unknown1 = 0x0000;
	r.in.unknown = &unknown;
	r.in.access_required = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.handle = handle;

	status = dcerpc_winreg_OpenHKLM(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenHKLM failed - %s\n", nt_errstr(status));
		return False;
	}

	return ret;
}

static BOOL test_OpenHKU(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *handle)
{
	NTSTATUS status;
	struct winreg_OpenHKU r;
	struct winreg_OpenUnknown unknown;
	BOOL ret = True;

	printf("\ntesting OpenHKU\n");

	unknown.unknown0 = 0x84e0;
	unknown.unknown1 = 0x0000;
	r.in.unknown = &unknown;
	r.in.access_required = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.handle = handle;

	status = dcerpc_winreg_OpenHKU(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenHKU failed - %s\n", nt_errstr(status));
		return False;
	}

	return ret;
}

static BOOL test_OpenHKCR(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			  struct policy_handle *handle)
{
	NTSTATUS status;
	struct winreg_OpenHKCR r;
	struct winreg_OpenUnknown unknown;
	BOOL ret = True;

	printf("\ntesting OpenHKCR\n");

	unknown.unknown0 = 0x84e0;
	unknown.unknown1 = 0x0000;
	r.in.unknown = &unknown;
	r.in.access_required = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.handle = handle;

	status = dcerpc_winreg_OpenHKCR(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenHKCR failed - %s\n", nt_errstr(status));
		return False;
	}

	return ret;
}

static BOOL test_OpenHKCU(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			  struct policy_handle *handle)
{
	NTSTATUS status;
	struct winreg_OpenHKCU r;
	struct winreg_OpenUnknown unknown;
	BOOL ret = True;

	printf("\ntesting OpenHKCU\n");

	unknown.unknown0 = 0x84e0;
	unknown.unknown1 = 0x0000;
	r.in.unknown = &unknown;
	r.in.access_required = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.handle = handle;

	status = dcerpc_winreg_OpenHKCU(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenHKCU failed - %s\n", nt_errstr(status));
		return False;
	}

	return ret;
}

typedef BOOL (*winreg_open_fn)(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			       struct policy_handle *handle);

BOOL torture_rpc_winreg(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	winreg_open_fn open_fns[] = { test_OpenHKLM };
	int i;

	mem_ctx = talloc_init("torture_rpc_winreg");

	status = torture_rpc_connection(&p, 
					DCERPC_WINREG_NAME, 
					DCERPC_WINREG_UUID, 
					DCERPC_WINREG_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}
	
	p->flags |= DCERPC_DEBUG_PRINT_BOTH;

	for (i = 0; i < ARRAY_SIZE(open_fns); i++) {
		struct policy_handle handle;

		if (!open_fns[i](p, mem_ctx, &handle))
			ret = False;

#if 0
		    if (!test_GetVersion(p, mem_ctx, &handle)) {
			    ret = False;
		    }
		    
		    if (!test_DeleteKey(p, mem_ctx, &handle, "spottyfoot")) {
			    ret = False;
		    }
#endif	    
		    if (!test_EnumKey(p, mem_ctx, &handle)) {
			    ret = False;
		    }
		    
		    if (!test_EnumValue(p, mem_ctx, &handle)) {
			    ret = False;
		    }

		    if (!test_CloseKey(p, mem_ctx, &handle)) {
			    ret = False;
		    }
	}

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
