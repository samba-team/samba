/* 
   Unix SMB/CIFS implementation.
   test suite for winreg rpc operations

   Copyright (C) Tim Potter 2003
   Copyright (C) Jelmer Vernooij 2004-2007
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
#define TEST_KEY3 TEST_KEY_BASE "\\with a subkey"
#define TEST_SUBKEY TEST_KEY3 "\\subkey"

static void init_initshutdown_String(TALLOC_CTX *mem_ctx, 
									 struct initshutdown_String *name, 
									 const char *s)
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

static bool test_GetVersion(struct dcerpc_pipe *p, 
				struct torture_context *tctx,
			    struct policy_handle *handle)
{
	struct winreg_GetVersion r;
	uint32_t v;

	ZERO_STRUCT(r);
	r.in.handle = handle;
	r.out.version = &v;

	torture_assert_ntstatus_ok(tctx, dcerpc_winreg_GetVersion(p, tctx, &r),
							   "GetVersion failed");

	torture_assert_werr_ok(tctx, r.out.result, "GetVersion failed");

	return true;
}

static bool test_NotifyChangeKeyValue(struct dcerpc_pipe *p, 
									  struct torture_context *tctx, 
									  struct policy_handle *handle)
{
	struct winreg_NotifyChangeKeyValue r;

	r.in.handle = handle;
	r.in.watch_subtree = 1;
	r.in.notify_filter = 0;
	r.in.unknown = r.in.unknown2 = 0;
	init_winreg_String(&r.in.string1, NULL);
	init_winreg_String(&r.in.string2, NULL);

	torture_assert_ntstatus_ok(tctx, 
							   dcerpc_winreg_NotifyChangeKeyValue(p, tctx, &r),
							   "NotifyChangeKeyValue failed");

	if (!W_ERROR_IS_OK(r.out.result)) {
		torture_comment(tctx, 
						"NotifyChangeKeyValue failed - %s - not considering\n", win_errstr(r.out.result));
		return true;
	}

	return true;
}

static bool test_CreateKey(struct dcerpc_pipe *p, struct torture_context *tctx,
			  struct policy_handle *handle, const char *name, 
			   const char *class)
{
	struct winreg_CreateKey r;
	struct policy_handle newhandle;
	enum winreg_CreateAction action_taken = 0;

	r.in.handle = handle;
	r.out.new_handle = &newhandle;
	init_winreg_String(&r.in.name, name);	
	init_winreg_String(&r.in.keyclass, class);
	r.in.options = 0x0;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.in.action_taken = r.out.action_taken = &action_taken;
	r.in.secdesc = NULL;

	torture_assert_ntstatus_ok(tctx, dcerpc_winreg_CreateKey(p, tctx, &r),
		"CreateKey failed");

	torture_assert_werr_ok(tctx,  r.out.result, "CreateKey failed");

	return true;
}


/*
  createkey testing with a SD
*/
static bool test_CreateKey_sd(struct dcerpc_pipe *p, 
							  struct torture_context *tctx,
			      struct policy_handle *handle, const char *name, 
			      const char *class, struct policy_handle *newhandle)
{
	struct winreg_CreateKey r;
	enum winreg_CreateAction action_taken = 0;
	struct security_descriptor *sd;
	DATA_BLOB sdblob;
	struct winreg_SecBuf secbuf;

	sd = security_descriptor_create(tctx,
					NULL, NULL,
					SID_NT_AUTHENTICATED_USERS,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_GENERIC_ALL,
					SEC_ACE_FLAG_OBJECT_INHERIT,
					NULL);

	torture_assert_ntstatus_ok(tctx, 
		ndr_push_struct_blob(&sdblob, tctx, sd, 
				      (ndr_push_flags_fn_t)ndr_push_security_descriptor),
				"Failed to push security_descriptor ?!\n");

	secbuf.sd.data = sdblob.data;
	secbuf.sd.len = sdblob.length;
	secbuf.sd.size = sdblob.length;
	secbuf.length = sdblob.length-10;
	secbuf.inherit = 0;

	r.in.handle = handle;
	r.out.new_handle = newhandle;
	init_winreg_String(&r.in.name, name);	
	init_winreg_String(&r.in.keyclass, class);
	r.in.options = 0x0;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.in.action_taken = r.out.action_taken = &action_taken;
	r.in.secdesc = &secbuf;

	torture_assert_ntstatus_ok(tctx, dcerpc_winreg_CreateKey(p, tctx, &r),
		"CreateKey with sd failed");

	torture_assert_werr_ok(tctx, r.out.result, "CreateKey with sd failed");

	return true;
}

static bool test_GetKeySecurity(struct dcerpc_pipe *p, 
								struct torture_context *tctx,
			  struct policy_handle *handle)
{
	struct winreg_GetKeySecurity r;
	struct security_descriptor sd;
	DATA_BLOB sdblob;

	ZERO_STRUCT(r);

	r.in.handle = handle;
	r.in.sd = r.out.sd = talloc_zero(tctx, struct KeySecurityData);
	r.in.sd->size = 0x1000;
	r.in.sec_info = SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL;

	torture_assert_ntstatus_ok(tctx, dcerpc_winreg_GetKeySecurity(p, tctx, &r),
		"GetKeySecurity failed");

	torture_assert_werr_ok(tctx, r.out.result, "GetKeySecurity failed");

	sdblob.data = r.out.sd->data;
	sdblob.length = r.out.sd->len;

	torture_assert_ntstatus_ok(tctx, 
		ndr_pull_struct_blob(&sdblob, tctx, &sd, 
				      (ndr_pull_flags_fn_t)ndr_pull_security_descriptor),
			"pull_security_descriptor failed");

	if (p->conn->flags & DCERPC_DEBUG_PRINT_OUT) {
		NDR_PRINT_DEBUG(security_descriptor, &sd);
	}

	return true;
}

static bool test_CloseKey(struct dcerpc_pipe *p, struct torture_context *tctx, 
			  struct policy_handle *handle)
{
	struct winreg_CloseKey r;

	r.in.handle = r.out.handle = handle;

	torture_assert_ntstatus_ok(tctx, dcerpc_winreg_CloseKey(p, tctx, &r),
							   "CloseKey failed");

	torture_assert_werr_ok(tctx, r.out.result, "CloseKey failed");

	return true;
}

static bool test_FlushKey(struct dcerpc_pipe *p, struct torture_context *tctx, 
			  struct policy_handle *handle)
{
	struct winreg_FlushKey r;

	r.in.handle = handle;

	torture_assert_ntstatus_ok(tctx, dcerpc_winreg_FlushKey(p, tctx, &r),
			"FlushKey failed");

	torture_assert_werr_ok(tctx, r.out.result, "FlushKey failed");

	return true;
}

static bool test_OpenKey(struct dcerpc_pipe *p, struct torture_context *tctx,
			 struct policy_handle *hive_handle,
			 const char *keyname, struct policy_handle *key_handle)
{
	struct winreg_OpenKey r;

	r.in.parent_handle = hive_handle;
	init_winreg_String(&r.in.keyname, keyname);
	r.in.unknown = 0x00000000;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = key_handle;

	torture_assert_ntstatus_ok(tctx, dcerpc_winreg_OpenKey(p, tctx, &r),
				"OpenKey failed");

	torture_assert_werr_ok(tctx, r.out.result, "OpenKey failed");

	return true;
}

static bool test_Cleanup(struct dcerpc_pipe *p, struct torture_context *tctx,
			 struct policy_handle *handle, const char *key)
{
	struct winreg_DeleteKey r;

	r.in.handle = handle;

	init_winreg_String(&r.in.key, key);
	dcerpc_winreg_DeleteKey(p, tctx, &r);

	return true;
}


static bool test_DeleteKey(struct dcerpc_pipe *p, struct torture_context *tctx,
			   struct policy_handle *handle, const char *key)
{
	NTSTATUS status;
	struct winreg_DeleteKey r;

	r.in.handle = handle;
	init_winreg_String(&r.in.key, key);	

	status = dcerpc_winreg_DeleteKey(p, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "DeleteKey failed");
	torture_assert_werr_ok(tctx, r.out.result, "DeleteKey failed");

	return true;
}

/* DeleteKey on a key with subkey(s) should
 * return WERR_ACCESS_DENIED. */
static bool test_DeleteKeyWithSubkey(struct dcerpc_pipe *p, 
				     struct torture_context *tctx,
				     struct policy_handle *handle, const char *key)
{
	struct winreg_DeleteKey r;

	r.in.handle = handle;
	init_winreg_String(&r.in.key, key);

	torture_assert_ntstatus_ok(tctx, dcerpc_winreg_DeleteKey(p, tctx, &r),
							   "DeleteKeyWithSubkey failed");

	torture_assert_werr_equal(tctx, r.out.result, WERR_ACCESS_DENIED, 
			"DeleteKeyWithSubkey failed");

	return true;
}

static bool test_QueryInfoKey(struct dcerpc_pipe *p, 
							  struct torture_context *tctx,
			      struct policy_handle *handle, char *class)
{
	struct winreg_QueryInfoKey r;
	uint32_t num_subkeys, max_subkeylen, max_subkeysize,
		num_values, max_valnamelen, max_valbufsize,
		secdescsize;
	NTTIME last_changed_time;

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

	r.out.classname = talloc(tctx, struct winreg_String);
	
	r.in.classname = talloc(tctx, struct winreg_String);
	init_winreg_String(r.in.classname, class);
	
	torture_assert_ntstatus_ok(tctx, 
		dcerpc_winreg_QueryInfoKey(p, tctx, &r),
		"QueryInfoKey failed");

	torture_assert_werr_ok(tctx, r.out.result, "QueryInfoKey failed");

	return true;
}

static bool test_key(struct dcerpc_pipe *p, struct torture_context *tctx,
		     struct policy_handle *handle, int depth);

static bool test_EnumKey(struct dcerpc_pipe *p, struct torture_context *tctx,
			 struct policy_handle *handle, int depth)
{
	struct winreg_EnumKey r;
	struct winreg_StringBuf class, name;
	NTSTATUS status;
	NTTIME t = 0;

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

		status = dcerpc_winreg_EnumKey(p, tctx, &r);

		if (NT_STATUS_IS_OK(status) && W_ERROR_IS_OK(r.out.result)) {
			struct policy_handle key_handle;

			torture_comment(tctx, "EnumKey: %d: %s\n", r.in.enum_index, 
							r.out.name->name);

			if (!test_OpenKey(
				    p, tctx, handle, r.out.name->name,
				    &key_handle)) {
			} else {
				test_key(p, tctx, &key_handle, depth + 1);
			}
		}

		r.in.enum_index++;

	} while (NT_STATUS_IS_OK(status) && W_ERROR_IS_OK(r.out.result));

	torture_assert_ntstatus_ok(tctx, status, "EnumKey failed");

	if (!W_ERROR_IS_OK(r.out.result) && 
		!W_ERROR_EQUAL(r.out.result, WERR_NO_MORE_ITEMS)) {
		torture_fail(tctx, "EnumKey failed");
	}

	return true;
}

static bool test_QueryMultipleValues(struct dcerpc_pipe *p, 
									 struct torture_context *tctx, 
									 struct policy_handle *handle, 
									 const char *valuename)
{
	struct winreg_QueryMultipleValues r;
	NTSTATUS status;
	uint32_t bufsize=0;

	r.in.key_handle = handle;
	r.in.values = r.out.values = talloc_array(tctx, struct QueryMultipleValue, 1);
	r.in.values[0].name = talloc(tctx, struct winreg_String);
	r.in.values[0].name->name = valuename;
	r.in.values[0].offset = 0;
	r.in.values[0].length = 0;
	r.in.values[0].type = 0;

	r.in.num_values = 1;
	r.in.buffer_size = r.out.buffer_size = talloc(tctx, uint32_t);
	*r.in.buffer_size = bufsize;
	do { 
		*r.in.buffer_size = bufsize;
		r.in.buffer = r.out.buffer = talloc_zero_array(tctx, uint8_t, 
							       *r.in.buffer_size);

		status = dcerpc_winreg_QueryMultipleValues(p, tctx, &r);
	
		if(NT_STATUS_IS_ERR(status))
			torture_fail(tctx, "QueryMultipleValues failed");

		talloc_free(r.in.buffer);
		bufsize += 0x20;
	} while (W_ERROR_EQUAL(r.out.result, WERR_MORE_DATA));

	torture_assert_werr_ok(tctx, r.out.result, "QueryMultipleValues failed");

	return true;
}

static bool test_QueryValue(struct dcerpc_pipe *p, 
							struct torture_context *tctx, 
							struct policy_handle *handle, 
							const char *valuename)
{
	struct winreg_QueryValue r;
	NTSTATUS status;
	enum winreg_Type zero_type = 0;
	uint32_t offered = 0xfff;
	uint32_t zero = 0;

	r.in.handle = handle;
	r.in.data = NULL;
	r.in.value_name.name = valuename;
	r.in.type = &zero_type;
	r.in.size = &offered;
	r.in.length = &zero;

	status = dcerpc_winreg_QueryValue(p, tctx, &r);
	if (NT_STATUS_IS_ERR(status)) {
		torture_fail(tctx, "QueryValue failed");
	}

	torture_assert_werr_ok(tctx, r.out.result, "QueryValue failed");

	return true;
}

static bool test_EnumValue(struct dcerpc_pipe *p, struct torture_context *tctx,
			   struct policy_handle *handle, int max_valnamelen, int max_valbufsize)
{
	struct winreg_EnumValue r;
	enum winreg_Type type = 0;
	uint32_t size = max_valbufsize, zero = 0;
	bool ret = true;
	uint8_t buf8;
	struct winreg_StringBuf name;

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
		torture_assert_ntstatus_ok(tctx, dcerpc_winreg_EnumValue(p, tctx, &r),
								   "EnumValue failed");

		if (W_ERROR_IS_OK(r.out.result)) {
			ret &= test_QueryValue(p, tctx, handle, r.out.name->name);
			ret &= test_QueryMultipleValues(p, tctx, handle, r.out.name->name);
		}

		r.in.enum_index++;
	} while (W_ERROR_IS_OK(r.out.result));

	torture_assert_werr_equal(tctx, r.out.result, WERR_NO_MORE_ITEMS,
		"EnumValue failed");

	return ret;
}

static bool test_AbortSystemShutdown(struct dcerpc_pipe *p, 
									 struct torture_context *tctx)
{
	struct winreg_AbortSystemShutdown r;
	uint16_t server = 0x0;

	r.in.server = &server;
	
	torture_assert_ntstatus_ok(tctx, 
							   dcerpc_winreg_AbortSystemShutdown(p, tctx, &r),
							   "AbortSystemShutdown failed");

	torture_assert_werr_ok(tctx, r.out.result, "AbortSystemShutdown failed");

	return true;
}

static bool test_InitiateSystemShutdown(struct torture_context *tctx,
										struct dcerpc_pipe *p)
{
	struct winreg_InitiateSystemShutdown r;
	uint16_t hostname = 0x0;

	if (!torture_setting_bool(tctx, "dangerous", false))
		torture_skip(tctx, 
		   "winreg_InitiateShutdown disabled - enable dangerous tests to use");

	r.in.hostname = &hostname;
	r.in.message = talloc(tctx, struct initshutdown_String);
	init_initshutdown_String(tctx, r.in.message, "spottyfood");
	r.in.force_apps = 1;
	r.in.timeout = 30;
	r.in.reboot = 1;

	torture_assert_ntstatus_ok(tctx, 
							dcerpc_winreg_InitiateSystemShutdown(p, tctx, &r),
							"InitiateSystemShutdown failed");

	torture_assert_werr_ok(tctx, r.out.result, "InitiateSystemShutdown failed");

	return test_AbortSystemShutdown(p, tctx);
}


static bool test_InitiateSystemShutdownEx(struct torture_context *tctx,
										  struct dcerpc_pipe *p)
{
	struct winreg_InitiateSystemShutdownEx r;
	uint16_t hostname = 0x0;

	if (!torture_setting_bool(tctx, "dangerous", false))
		torture_skip(tctx, 
		   "winreg_InitiateShutdownEx disabled - enable dangerous tests to use");
	
	r.in.hostname = &hostname;
	r.in.message = talloc(tctx, struct initshutdown_String);
	init_initshutdown_String(tctx, r.in.message, "spottyfood");
	r.in.force_apps = 1;
	r.in.timeout = 30;
	r.in.reboot = 1;
	r.in.reason = 0;

	torture_assert_ntstatus_ok(tctx, 
		dcerpc_winreg_InitiateSystemShutdownEx(p, tctx, &r),
		"InitiateSystemShutdownEx failed");

	torture_assert_werr_ok(tctx, r.out.result, 
						   "InitiateSystemShutdownEx failed");

	return test_AbortSystemShutdown(p, tctx);
}
#define MAX_DEPTH 2		/* Only go this far down the tree */

static bool test_key(struct dcerpc_pipe *p, struct torture_context *tctx, 
		     struct policy_handle *handle, int depth)
{
	if (depth == MAX_DEPTH)
		return true;

	if (!test_QueryInfoKey(p, tctx, handle, NULL)) {
	}

	if (!test_NotifyChangeKeyValue(p, tctx, handle)) {
	}
	
	if (!test_GetKeySecurity(p, tctx, handle)) {
	}

	if (!test_EnumKey(p, tctx, handle, depth)) {
	}

	if (!test_EnumValue(p, tctx, handle, 0xFF, 0xFFFF)) {
	}

	test_CloseKey(p, tctx, handle);

	return true;
}

typedef NTSTATUS (*winreg_open_fn)(struct dcerpc_pipe *, TALLOC_CTX *, void *);

static bool test_Open(struct torture_context *tctx, struct dcerpc_pipe *p, 
		      void *userdata)
{
	struct policy_handle handle, newhandle;
	bool ret = true, created = false, created2 = false, deleted = false;
	bool created3 = false, created_subkey = false;
	struct winreg_OpenHKLM r;

	winreg_open_fn open_fn = userdata;

	r.in.system_name = 0;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = &handle;
	
	torture_assert_ntstatus_ok(tctx, open_fn(p, tctx, &r), 
							   "open");

	test_Cleanup(p, tctx, &handle, TEST_KEY1);
	test_Cleanup(p, tctx, &handle, TEST_KEY2);
	test_Cleanup(p, tctx, &handle, TEST_SUBKEY);
	test_Cleanup(p, tctx, &handle, TEST_KEY3);
	test_Cleanup(p, tctx, &handle, TEST_KEY_BASE);

	if (!test_CreateKey(p, tctx, &handle, TEST_KEY1, NULL)) {
		torture_comment(tctx, "CreateKey failed - not considering a failure\n");
	} else {
		created = true;
	}

	if (created && !test_FlushKey(p, tctx, &handle)) {
		torture_comment(tctx, "FlushKey failed\n");
		ret = false;
	}

	if (created && !test_OpenKey(p, tctx, &handle, TEST_KEY1, &newhandle))
		torture_fail(tctx, 
					 "CreateKey failed (OpenKey after Create didn't work)\n");

	if (created && !test_DeleteKey(p, tctx, &handle, TEST_KEY1)) {
		torture_comment(tctx, "DeleteKey failed\n");
		ret = false;
	} else {
		deleted = true;
	}

	if (created && !test_FlushKey(p, tctx, &handle)) {
		torture_comment(tctx, "FlushKey failed\n");
		ret = false;
	}

	if (created && deleted && 
	    test_OpenKey(p, tctx, &handle, TEST_KEY1, &newhandle)) {
		torture_comment(tctx, 
						"DeleteKey failed (OpenKey after Delete worked)\n");
		ret = false;
	}

	if (!test_GetVersion(p, tctx, &handle)) {
		torture_comment(tctx, "GetVersion failed\n");
		ret = false;
	}

	if (created && test_CreateKey_sd(p, tctx, &handle, TEST_KEY2, 
					  NULL, &newhandle)) {
		created2 = true;
	}

	if (created2 && !test_GetKeySecurity(p, tctx, &newhandle)) {
		printf("GetKeySecurity failed\n");
		ret = false;
	}

	if (created2 && !test_CloseKey(p, tctx, &newhandle)) {
		printf("CloseKey failed\n");
		ret = false;
	}

	if (created && !test_DeleteKey(p, tctx, &handle, TEST_KEY2)) {
		printf("DeleteKey failed\n");
		ret = false;
	}

	if (created && test_CreateKey(p, tctx, &handle, TEST_KEY3, NULL)) {
		created3 = true;
	}

	if (created3 && 
	    test_CreateKey(p, tctx, &handle, TEST_SUBKEY, NULL)) 
	{
		created_subkey = true;
	}

	if (created_subkey && 
	    !test_DeleteKeyWithSubkey(p, tctx, &handle, TEST_KEY3)) 
	{
		printf("DeleteKeyWithSubkey failed "
		       "(DeleteKey didn't return ACCESS_DENIED)\n");
		ret = false;
	}

	if (created_subkey && 
	    !test_DeleteKey(p, tctx, &handle, TEST_SUBKEY))
	{
		printf("DeleteKey failed\n");
		ret = false;
	}

	if (created3 &&
	    !test_DeleteKey(p, tctx, &handle, TEST_KEY3))
	{
		printf("DeleteKey failed\n");
		ret = false;
	}

	/* The HKCR hive has a very large fanout */
	if (open_fn == (void *)dcerpc_winreg_OpenHKCR) {
		if(!test_key(p, tctx, &handle, MAX_DEPTH - 1)) {
			ret = false;
		}
	}

	if(!test_key(p, tctx, &handle, 0)) {
		ret = false;
	}

	test_Cleanup(p, tctx, &handle, TEST_KEY_BASE);

	return ret;
}

struct torture_suite *torture_rpc_winreg(TALLOC_CTX *mem_ctx)
{
	struct {
		const char *name;
		winreg_open_fn fn;
	} open_fns[] = {{"OpenHKLM", (winreg_open_fn)dcerpc_winreg_OpenHKLM },
			{"OpenHKU",  (winreg_open_fn)dcerpc_winreg_OpenHKU },
			{"OpenHKCR", (winreg_open_fn)dcerpc_winreg_OpenHKCR },
			{"OpenHKCU", (winreg_open_fn)dcerpc_winreg_OpenHKCU }};
	int i;
	struct torture_rpc_tcase *tcase;
	struct torture_suite *suite = torture_suite_create(mem_ctx, "WINREG");

	tcase = torture_suite_add_rpc_iface_tcase(suite, "winreg", 
											  &ndr_table_winreg);

	torture_rpc_tcase_add_test(tcase, "InitiateSystemShutdown", 
							   test_InitiateSystemShutdown);

	torture_rpc_tcase_add_test(tcase, "InitiateSystemShutdownEx", 
							   test_InitiateSystemShutdownEx);

	for (i = 0; i < ARRAY_SIZE(open_fns); i++) {
		torture_rpc_tcase_add_test_ex(tcase, open_fns[i].name, test_Open, 
									  open_fns[i].fn);
	}

	return suite;
}
