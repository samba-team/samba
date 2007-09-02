/* 
   Unix SMB/CIFS implementation.
   test suite for lsa rpc operations

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   
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
#include "librpc/gen_ndr/ndr_lsa_c.h"

#include "libcli/auth/libcli_auth.h"
#include "torture/rpc/rpc.h"
#include "lib/cmdline/popt_common.h"

static void init_lsa_String(struct lsa_String *name, const char *s)
{
	name->string = s;
}

static bool test_CreateSecret_basic(struct dcerpc_pipe *p, 
				    struct torture_context *tctx,
				    struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_CreateSecret r;
	struct lsa_SetSecret r3;
	struct lsa_QuerySecret r4;
	struct policy_handle sec_handle;
	struct lsa_Delete d;
	struct lsa_DATA_BUF buf1;
	struct lsa_DATA_BUF_PTR bufp1;
	DATA_BLOB enc_key;
	DATA_BLOB session_key;
	NTTIME old_mtime, new_mtime;
	DATA_BLOB blob1, blob2;
	const char *secret1 = "abcdef12345699qwerty";
	char *secret2;
	char *secname;

	secname = talloc_asprintf(tctx, "torturesecret-%u", (uint_t)random());

	torture_comment(tctx, "Testing CreateSecret of %s\n", secname);
		
	init_lsa_String(&r.in.name, secname);
	
	r.in.handle = handle;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.sec_handle = &sec_handle;
	
	status = dcerpc_lsa_CreateSecret(p, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "CreateSecret failed");
	
	status = dcerpc_fetch_session_key(p, &session_key);
	torture_assert_ntstatus_ok(tctx, status, "dcerpc_fetch_session_key failed");
	
	enc_key = sess_encrypt_string(secret1, &session_key);
	
	r3.in.sec_handle = &sec_handle;
	r3.in.new_val = &buf1;
	r3.in.old_val = NULL;
	r3.in.new_val->data = enc_key.data;
	r3.in.new_val->length = enc_key.length;
	r3.in.new_val->size = enc_key.length;
	
	torture_comment(tctx, "Testing SetSecret\n");
	
	status = dcerpc_lsa_SetSecret(p, tctx, &r3);
	torture_assert_ntstatus_ok(tctx, status, "SetSecret failed");
		
	r3.in.sec_handle = &sec_handle;
	r3.in.new_val = &buf1;
	r3.in.old_val = NULL;
	r3.in.new_val->data = enc_key.data;
	r3.in.new_val->length = enc_key.length;
	r3.in.new_val->size = enc_key.length;
	
	/* break the encrypted data */
	enc_key.data[0]++;
	
	torture_comment(tctx, "Testing SetSecret with broken key\n");
	
	status = dcerpc_lsa_SetSecret(p, tctx, &r3);
	torture_assert_ntstatus_equal(tctx, status, NT_STATUS_UNKNOWN_REVISION, 
		"SetSecret should have failed UNKNOWN_REVISION");
	
	data_blob_free(&enc_key);
	
	ZERO_STRUCT(new_mtime);
	ZERO_STRUCT(old_mtime);
	
	/* fetch the secret back again */
	r4.in.sec_handle = &sec_handle;
	r4.in.new_val = &bufp1;
	r4.in.new_mtime = &new_mtime;
	r4.in.old_val = NULL;
	r4.in.old_mtime = NULL;
	
	bufp1.buf = NULL;
	
	torture_comment(tctx, "Testing QuerySecret\n");
	status = dcerpc_lsa_QuerySecret(p, tctx, &r4);
	torture_assert_ntstatus_ok(tctx, status, "QuerySecret failed");
	if (r4.out.new_val == NULL || r4.out.new_val->buf == NULL)
		torture_fail(tctx, "No secret buffer returned");
	blob1.data = r4.out.new_val->buf->data;
	blob1.length = r4.out.new_val->buf->size;
	
	blob2 = data_blob_talloc(tctx, NULL, blob1.length);
	
	secret2 = sess_decrypt_string(tctx, &blob1, &session_key);
	
	torture_assert_str_equal(tctx, secret1, secret2, "Returned secret invalid");

	d.in.handle = &sec_handle;
	status = dcerpc_lsa_Delete(p, tctx, &d);
	torture_assert_ntstatus_ok(tctx, status, "delete should have returned OKINVALID_HANDLE");
	return true;
}

struct secret_settings {
	uint32_t bindoptions;
};

static bool test_secrets(struct torture_context *torture, const void *_data)
{
        struct dcerpc_pipe *p;
	struct policy_handle *handle;
	struct dcerpc_binding *binding;
	const struct secret_settings *settings = _data;

	torture_assert_ntstatus_ok(torture, torture_rpc_binding(torture, &binding), 
				   "Getting bindoptions");

	binding->flags |= settings->bindoptions;

	torture_assert_ntstatus_ok(torture, 
				   dcerpc_pipe_connect_b(torture, &p, binding, &ndr_table_lsarpc, cmdline_credentials, NULL),
				   "connect");

	if (!test_lsa_OpenPolicy2(p, torture, &handle)) {
		return false;
	}

	torture_assert(torture, handle, "OpenPolicy2 failed.  This test cannot run against this server");
	
	if (!test_CreateSecret_basic(p, torture, handle)) {
		return false;
	}

	return true;
}

/* TEST session key correctness by pushing and pulling secrets */

struct torture_suite *torture_rpc_lsa_secrets(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "SECRETS");
	struct secret_settings *settings;

	settings = talloc_zero(suite, struct secret_settings);
	settings->bindoptions = DCERPC_PUSH_BIGENDIAN;

	torture_suite_add_simple_tcase(suite, "bigendian", test_secrets, settings);

	settings = talloc_zero(suite, struct secret_settings);
	settings->bindoptions = DCERPC_SEAL;

	torture_suite_add_simple_tcase(suite, "seal", test_secrets, settings);

	settings = talloc_zero(suite, struct secret_settings);
	settings->bindoptions = 0;

	torture_suite_add_simple_tcase(suite, "none", test_secrets, settings);

	return suite;
}
