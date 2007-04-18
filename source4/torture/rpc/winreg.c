/* 
   Unix SMB/CIFS implementation.
   test suite for winreg rpc operations

   Copyright (C) Tim Potter 2003
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
#include "torture/torture.h"
#include "librpc/gen_ndr/ndr_winreg_c.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "torture/rpc/rpc.h"

#define TEST_KEY_BASE "smbtorture test"
#define TEST_KEY1 TEST_KEY_BASE "\\spottyfoot"
#define TEST_KEY2 TEST_KEY_BASE "\\with a SD (#1)"

static void init_initshutdown_String(TALLOC_CTX *mem_ctx, struct initshutdown_String *name, const char *s)
{
	name->name = talloc(mem_ctx, struct initshutdown_String_sub);
	name->name->name = s;
}

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

static bool test_GetVersion(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			    struct policy_handle *handle)
{
	NTSTATUS status;
	struct winreg_GetVersion r;
	uint32_t v;
	printf("\ntesting GetVersion\n");

	ZERO_STRUCT(r);
	r.in.handle = handle;
	r.out.version = &v;

	status = dcerpc_winreg_GetVersion(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("GetVersion failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("GetVersion failed - %s\n", win_errstr(r.out.result));
		return false;
	}

	return true;
}

static bool test_NotifyChangeKeyValue(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
									  struct policy_handle *handle)
{
	struct winreg_NotifyChangeKeyValue r;
	NTSTATUS status;

	printf("\ntesting NotifyChangeKeyValue\n");

	r.in.handle = handle;
	r.in.watch_subtree = 1;
	r.in.notify_filter = 0;
	r.in.unknown = r.in.unknown2 = 0;
	init_winreg_String(&r.in.string1, NULL);
	init_winreg_String(&r.in.string2, NULL);

	status = dcerpc_winreg_NotifyChangeKeyValue(p, mem_ctx, &r);
	
	if (!NT_STATUS_IS_OK(status)) {
		printf("NotifyChangeKeyValue failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("NotifyChangeKeyValue failed - %s - not considering\n", win_errstr(r.out.result));
		return true;
	}

	return true;
}

static bool test_CreateKey(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			  struct policy_handle *handle, const char *name, 
			   const char *class)
{
	struct winreg_CreateKey r;
	struct policy_handle newhandle;
	NTSTATUS status;
	enum winreg_CreateAction action_taken = 0;

	printf("\ntesting CreateKey\n");

	r.in.handle = handle;
	r.out.new_handle = &newhandle;
	init_winreg_String(&r.in.name, name);	
	init_winreg_String(&r.in.keyclass, class);
	r.in.options = 0x0;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.in.action_taken = r.out.action_taken = &action_taken;
	r.in.secdesc = NULL;

	status = dcerpc_winreg_CreateKey(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateKey failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("CreateKey failed - %s\n", win_errstr(r.out.result));
		return false;
	}

	return true;
}


/*
  createkey testing with a SD
*/
static bool test_CreateKey_sd(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			      struct policy_handle *handle, const char *name, 
			      const char *class, struct policy_handle *newhandle)
{
	struct winreg_CreateKey r;
	NTSTATUS status;
	enum winreg_CreateAction action_taken = 0;
	struct security_descriptor *sd;
	DATA_BLOB sdblob;
	struct winreg_SecBuf secbuf;

	sd = security_descriptor_create(mem_ctx,
					NULL, NULL,
					SID_NT_AUTHENTICATED_USERS,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_GENERIC_ALL,
					SEC_ACE_FLAG_OBJECT_INHERIT,
					NULL);

	status = ndr_push_struct_blob(&sdblob, mem_ctx, sd, 
				      (ndr_push_flags_fn_t)ndr_push_security_descriptor);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to push security_descriptor ?!\n");
		return false;
	}

	secbuf.sd.data = sdblob.data;
	secbuf.sd.len = sdblob.length;
	secbuf.sd.size = sdblob.length;
	secbuf.length = sdblob.length-10;
	secbuf.inherit = 0;

	printf("\ntesting CreateKey with sd\n");

	r.in.handle = handle;
	r.out.new_handle = newhandle;
	init_winreg_String(&r.in.name, name);	
	init_winreg_String(&r.in.keyclass, class);
	r.in.options = 0x0;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.in.action_taken = r.out.action_taken = &action_taken;
	r.in.secdesc = &secbuf;

	status = dcerpc_winreg_CreateKey(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateKey with sd failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("CreateKey with sd failed - %s\n", win_errstr(r.out.result));
		return false;
	}

	return true;
}

static bool test_GetKeySecurity(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			  struct policy_handle *handle)
{
	NTSTATUS status;
	struct winreg_GetKeySecurity r;
	struct security_descriptor sd;
	DATA_BLOB sdblob;

	printf("\ntesting GetKeySecurity\n");

	ZERO_STRUCT(r);

	r.in.handle = handle;
	r.in.sd = r.out.sd = talloc_zero(mem_ctx, struct KeySecurityData);
	r.in.sd->size = 0x1000;
	r.in.sec_info = SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL;

	status = dcerpc_winreg_GetKeySecurity(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("GetKeySecurity failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("GetKeySecurity failed - %s\n", win_errstr(r.out.result));
		return false;
	}

	sdblob.data = r.out.sd->data;
	sdblob.length = r.out.sd->len;

	status = ndr_pull_struct_blob(&sdblob, mem_ctx, &sd, 
				      (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);
	if (!NT_STATUS_IS_OK(status)) {
		printf("pull_security_descriptor failed - %s\n", nt_errstr(status));
		return false;
	}
	if (p->conn->flags & DCERPC_DEBUG_PRINT_OUT) {
		NDR_PRINT_DEBUG(security_descriptor, &sd);
	}

	return true;
}

static bool test_CloseKey(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			  struct policy_handle *handle)
{
	NTSTATUS status;
	struct winreg_CloseKey r;

	printf("\ntesting CloseKey\n");

	r.in.handle = r.out.handle = handle;

	status = dcerpc_winreg_CloseKey(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("CloseKey failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("CloseKey failed - %s\n", win_errstr(r.out.result));
		return false;
	}

	return true;
}

static bool test_FlushKey(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			  struct policy_handle *handle)
{
	NTSTATUS status;
	struct winreg_FlushKey r;

	printf("\ntesting FlushKey\n");

	r.in.handle = handle;

	status = dcerpc_winreg_FlushKey(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("FlushKey failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("FlushKey failed - %s\n", win_errstr(r.out.result));
		return false;
	}

	return true;
}

static bool test_OpenKey(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			 struct policy_handle *hive_handle,
			 const char *keyname, struct policy_handle *key_handle)
{
	NTSTATUS status;
	struct winreg_OpenKey r;

	printf("\ntesting OpenKey\n");

	r.in.parent_handle = hive_handle;
	init_winreg_String(&r.in.keyname, keyname);
	r.in.unknown = 0x00000000;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = key_handle;

	status = dcerpc_winreg_OpenKey(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenKey failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("OpenKey failed - %s\n", win_errstr(r.out.result));

		return false;
	}

	return true;
}

static bool test_Cleanup(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			 struct policy_handle *handle, const char *key)
{
	struct winreg_DeleteKey r;

	r.in.handle = handle;

	init_winreg_String(&r.in.key, key);
	dcerpc_winreg_DeleteKey(p, mem_ctx, &r);

	return true;
}


static bool test_DeleteKey(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			   struct policy_handle *handle, const char *key)
{
	NTSTATUS status;
	struct winreg_DeleteKey r;

	printf("\ntesting DeleteKey\n");

	r.in.handle = handle;
	init_winreg_String(&r.in.key, key);	

	status = dcerpc_winreg_DeleteKey(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("DeleteKey failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("DeleteKey failed - %s\n", win_errstr(r.out.result));
		return false;
	}

	return true;
}

static bool test_QueryInfoKey(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			      struct policy_handle *handle, char *class)
{
	NTSTATUS status;
	struct winreg_QueryInfoKey r;
	uint32_t num_subkeys, max_subkeylen, max_subkeysize,
		num_values, max_valnamelen, max_valbufsize,
		secdescsize;
	NTTIME last_changed_time;

	printf("\ntesting QueryInfoKey\n");

	ZERO_STRUCT(r);
	r.in.handle = handle;
	r.out.num_subkeys = &num_subkeys;
	r.out.max_subkeylen = &max_subkeylen;
	r.out.max_subkeysize = &max_subkeysize;
	r.out.num_values = &num_values;
	r.out.max_valnamelen = &max_valnamelen;
	r.out.max_valbufsize = &max_valbufsize;
	r.out.secdescsize = &secdescsize;
	r.out.last_changed_time = &last_changed_time;

	r.out.classname = talloc(mem_ctx, struct winreg_String);
	
	r.in.classname = talloc(mem_ctx, struct winreg_String);
	init_winreg_String(r.in.classname, class);
	
	status = dcerpc_winreg_QueryInfoKey(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("QueryInfoKey failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("QueryInfoKey failed - %s\n", win_errstr(r.out.result));
		return false;
	}

	return true;
}

static bool test_key(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
		     struct policy_handle *handle, int depth);

static bool test_EnumKey(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			 struct policy_handle *handle, int depth)
{
	struct winreg_EnumKey r;
	struct winreg_StringBuf class, name;
	NTSTATUS status;
	NTTIME t = 0;

	printf("Testing EnumKey\n\n");

	class.name   = "";
	class.size   = 1024;

	r.in.handle = handle;
	r.in.enum_index = 0;
	r.in.name = &name;
	r.in.keyclass = &class;
	r.out.name = &name;
	r.in.last_changed_time = &t;

	do {
		name.name   = NULL;
		name.size   = 1024;

		status = dcerpc_winreg_EnumKey(p, mem_ctx, &r);

		if (NT_STATUS_IS_OK(status) && W_ERROR_IS_OK(r.out.result)) {
			struct policy_handle key_handle;

			printf("EnumKey: %d: %s\n", r.in.enum_index, r.out.name->name);

			if (!test_OpenKey(
				    p, mem_ctx, handle, r.out.name->name,
				    &key_handle)) {
			} else {
				test_key(p, mem_ctx, &key_handle, depth + 1);
			}
		}

		r.in.enum_index++;

	} while (NT_STATUS_IS_OK(status) && W_ERROR_IS_OK(r.out.result));

	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumKey failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result) && !W_ERROR_EQUAL(r.out.result, WERR_NO_MORE_ITEMS)) {
		printf("EnumKey failed - %s\n", win_errstr(r.out.result));
		return false;
	}



	return true;
}

static bool test_QueryMultipleValues(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct policy_handle *handle, const char *valuename)
{
	struct winreg_QueryMultipleValues r;
	NTSTATUS status;
	uint32_t bufsize=0;

	printf("Testing QueryMultipleValues\n");

	r.in.key_handle = handle;
	r.in.values = r.out.values = talloc_array(mem_ctx, struct QueryMultipleValue, 1);
	r.in.values[0].name = talloc(mem_ctx, struct winreg_String);
	r.in.values[0].name->name = valuename;
	r.in.values[0].offset = 0;
	r.in.values[0].length = 0;
	r.in.values[0].type = 0;

	r.in.num_values = 1;
	r.in.buffer_size = r.out.buffer_size = talloc(mem_ctx, uint32_t);
	*r.in.buffer_size = bufsize;
	do { 
		*r.in.buffer_size = bufsize;
		r.in.buffer = r.out.buffer = talloc_zero_array(mem_ctx, uint8_t, 
							       *r.in.buffer_size);

		status = dcerpc_winreg_QueryMultipleValues(p, mem_ctx, &r);
	
		if(NT_STATUS_IS_ERR(status)) {
			printf("QueryMultipleValues failed - %s\n", nt_errstr(status));
			return false;
		}
		talloc_free(r.in.buffer);
		bufsize += 0x20;
	} while (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA));

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("QueryMultipleValues failed - %s\n", win_errstr(r.out.result));
		return false;
	}

	return true;
}

static bool test_QueryValue(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, struct policy_handle *handle, const char *valuename)
{
	struct winreg_QueryValue r;
	NTSTATUS status;
	enum winreg_Type zero_type = 0;
	uint32_t offered = 0xfff;
	uint32_t zero = 0;

	printf("Testing QueryValue\n");

	r.in.handle = handle;
	r.in.data = NULL;
	r.in.value_name.name = valuename;
	r.in.type = &zero_type;
	r.in.size = &offered;
	r.in.length = &zero;

	status = dcerpc_winreg_QueryValue(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		printf("QueryValue failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("QueryValue failed - %s\n", win_errstr(r.out.result));
		return false;
	}

	return true;
}

static bool test_EnumValue(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			   struct policy_handle *handle, int max_valnamelen, int max_valbufsize)
{
	struct winreg_EnumValue r;
	enum winreg_Type type = 0;
	uint32_t size = max_valbufsize, zero = 0;
	bool ret = true;
	uint8_t buf8;
	struct winreg_StringBuf name;

	printf("testing EnumValue\n");

	name.name   = "";
	name.size   = 1024;

	r.in.handle = handle;
	r.in.enum_index = 0;
	r.in.name = &name;
	r.out.name = &name;
	r.in.type = &type;
	r.in.value = &buf8;
	r.in.length = &zero;
	r.in.size = &size;
	
	do {
		NTSTATUS status = dcerpc_winreg_EnumValue(p, mem_ctx, &r);
		if(NT_STATUS_IS_ERR(status)) {
			printf("EnumValue failed - %s\n", nt_errstr(status));
			return false;
		}

		if (W_ERROR_IS_OK(r.out.result)) {
			ret &= test_QueryValue(p, mem_ctx, handle, r.out.name->name);
			ret &= test_QueryMultipleValues(p, mem_ctx, handle, r.out.name->name);
		}

		r.in.enum_index++;
	} while (W_ERROR_IS_OK(r.out.result));

	if(!W_ERROR_EQUAL(r.out.result, WERR_NO_MORE_ITEMS)) {
		printf("EnumValue failed - %s\n", win_errstr(r.out.result));
		return false;
	}

	return ret;
}

static bool test_InitiateSystemShutdown(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			const char *msg, uint32_t timeout)
{
	struct winreg_InitiateSystemShutdown r;
	NTSTATUS status;
	uint16_t hostname = 0x0;
	
	r.in.hostname = &hostname;
	r.in.message = talloc(mem_ctx, struct initshutdown_String);
	init_initshutdown_String(mem_ctx, r.in.message, msg);
	r.in.force_apps = 1;
	r.in.timeout = timeout;
	r.in.reboot = 1;

	status = dcerpc_winreg_InitiateSystemShutdown(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("InitiateSystemShutdown failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("InitiateSystemShutdown failed - %s\n", win_errstr(r.out.result));
		return false;
	}

	return true;
}

static bool test_InitiateSystemShutdownEx(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			const char *msg, uint32_t timeout)
{
	struct winreg_InitiateSystemShutdownEx r;
	NTSTATUS status;
	uint16_t hostname = 0x0;
	
	r.in.hostname = &hostname;
	r.in.message = talloc(mem_ctx, struct initshutdown_String);
	init_initshutdown_String(mem_ctx, r.in.message, msg);
	r.in.force_apps = 1;
	r.in.timeout = timeout;
	r.in.reboot = 1;
	r.in.reason = 0;

	status = dcerpc_winreg_InitiateSystemShutdownEx(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("InitiateSystemShutdownEx failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("InitiateSystemShutdownEx failed - %s\n", win_errstr(r.out.result));
		return false;
	}

	return true;
}

static bool test_AbortSystemShutdown(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct winreg_AbortSystemShutdown r;
	NTSTATUS status;
	uint16_t server = 0x0;

	r.in.server = &server;
	
	status = dcerpc_winreg_AbortSystemShutdown(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("AbortSystemShutdown failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("AbortSystemShutdown failed - %s\n", win_errstr(r.out.result));
		return false;
	}

	return true;
}

#define MAX_DEPTH 2		/* Only go this far down the tree */

static bool test_key(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
		     struct policy_handle *handle, int depth)
{
	if (depth == MAX_DEPTH)
		return true;

	if (!test_QueryInfoKey(p, mem_ctx, handle, NULL)) {
	}

	if (!test_NotifyChangeKeyValue(p, mem_ctx, handle)) {
	}
	
	if (!test_GetKeySecurity(p, mem_ctx, handle)) {
	}

	if (!test_EnumKey(p, mem_ctx, handle, depth)) {
	}

	if (!test_EnumValue(p, mem_ctx, handle, 0xFF, 0xFFFF)) {
	}

	test_CloseKey(p, mem_ctx, handle);

	return true;
}

typedef NTSTATUS (*winreg_open_fn)(struct dcerpc_pipe *, TALLOC_CTX *, void *);

static bool test_Open(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
		      const char *name, winreg_open_fn open_fn)
{
	struct policy_handle handle, newhandle;
	bool ret = true, created = false, created2 = false, deleted = false;
	struct winreg_OpenHKLM r;
	NTSTATUS status;

	printf("Testing %s\n", name);

	r.in.system_name = 0;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = &handle;
	
	status = open_fn(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	test_Cleanup(p, mem_ctx, &handle, TEST_KEY1);
	test_Cleanup(p, mem_ctx, &handle, TEST_KEY2);
	test_Cleanup(p, mem_ctx, &handle, TEST_KEY_BASE);

	if (!test_CreateKey(p, mem_ctx, &handle, TEST_KEY1, NULL)) {
		printf("CreateKey failed - not considering a failure\n");
	} else {
		created = true;
	}

	if (created && !test_FlushKey(p, mem_ctx, &handle)) {
		printf("FlushKey failed\n");
		ret = false;
	}

	if (created && !test_OpenKey(p, mem_ctx, &handle, TEST_KEY1, &newhandle)) {
		printf("CreateKey failed (OpenKey after Create didn't work)\n");
		ret = false;
	}

	if (created && !test_DeleteKey(p, mem_ctx, &handle, TEST_KEY1)) {
		printf("DeleteKey failed\n");
		ret = false;
	} else {
		deleted = true;
	}

	if (created && !test_FlushKey(p, mem_ctx, &handle)) {
		printf("FlushKey failed\n");
		ret = false;
	}

	if (created && deleted && 
	    test_OpenKey(p, mem_ctx, &handle, TEST_KEY1, &newhandle)) {
		printf("DeleteKey failed (OpenKey after Delete didn't work)\n");
		ret = false;
	}

	if (!test_GetVersion(p, mem_ctx, &handle)) {
		printf("GetVersion failed\n");
		ret = false;
	}

	if (created && test_CreateKey_sd(p, mem_ctx, &handle, TEST_KEY2, 
					  NULL, &newhandle)) {
		created2 = true;
	}

	if (created2 && !test_GetKeySecurity(p, mem_ctx, &newhandle)) {
		printf("GetKeySecurity failed\n");
		ret = false;
	}

	if (created2 && !test_CloseKey(p, mem_ctx, &newhandle)) {
		printf("CloseKey failed\n");
		ret = false;
	}

	if (created && !test_DeleteKey(p, mem_ctx, &handle, TEST_KEY2)) {
		printf("DeleteKey failed\n");
		ret = false;
	}

	/* The HKCR hive has a very large fanout */

	if (open_fn == (void *)dcerpc_winreg_OpenHKCR) {
		if(!test_key(p, mem_ctx, &handle, MAX_DEPTH - 1)) {
			ret = false;
		}
	}

	if(!test_key(p, mem_ctx, &handle, 0)) {
		ret = false;
	}

	test_Cleanup(p, mem_ctx, &handle, TEST_KEY_BASE);

	return ret;
}

bool torture_rpc_winreg(struct torture_context *torture)
{
        NTSTATUS status;
	struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	bool ret = true;
	struct {
		const char *name;
		winreg_open_fn fn;
	} open_fns[] = {{"OpenHKLM", (winreg_open_fn)dcerpc_winreg_OpenHKLM },
			{"OpenHKU",  (winreg_open_fn)dcerpc_winreg_OpenHKU },
			{"OpenHKCR", (winreg_open_fn)dcerpc_winreg_OpenHKCR },
			{"OpenHKCU", (winreg_open_fn)dcerpc_winreg_OpenHKCU }};
	int i;
	mem_ctx = talloc_init("torture_rpc_winreg");

	status = torture_rpc_connection(mem_ctx, &p, &dcerpc_table_winreg);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return false;
	}

	if (!torture_setting_bool(torture, "dangerous", false)) {
		printf("winreg_InitiateShutdown disabled - enable dangerous tests to use\n");
	} else {
		ret &= test_InitiateSystemShutdown(p, mem_ctx, "spottyfood", 30);
		ret &= test_AbortSystemShutdown(p, mem_ctx);
		ret &= test_InitiateSystemShutdownEx(p, mem_ctx, "spottyfood", 30);
		ret &= test_AbortSystemShutdown(p, mem_ctx);
	}

	for (i = 0; i < ARRAY_SIZE(open_fns); i++) {
		ret &= test_Open(p, mem_ctx, open_fns[i].name, open_fns[i].fn);
	}

	talloc_free(mem_ctx);

	return ret;
}
