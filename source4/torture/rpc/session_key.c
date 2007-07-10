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

static void init_lsa_String(struct lsa_String *name, const char *s)
{
	name->string = s;
}

static BOOL test_CreateSecret_basic(struct dcerpc_pipe *p, 
				    TALLOC_CTX *mem_ctx, 
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
	BOOL ret = True;
	DATA_BLOB session_key;
	NTTIME old_mtime, new_mtime;
	DATA_BLOB blob1, blob2;
	const char *secret1 = "abcdef12345699qwerty";
	char *secret2;
	char *secname;

	secname = talloc_asprintf(mem_ctx, "torturesecret-%u", (uint_t)random());

	printf("Testing CreateSecret of %s\n", secname);
		
	init_lsa_String(&r.in.name, secname);
	
	r.in.handle = handle;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.sec_handle = &sec_handle;
	
	status = dcerpc_lsa_CreateSecret(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateSecret failed - %s\n", nt_errstr(status));
		return False;
	}
	
	status = dcerpc_fetch_session_key(p, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("dcerpc_fetch_session_key failed - %s\n", nt_errstr(status));
		ret = False;
	}
	
	enc_key = sess_encrypt_string(secret1, &session_key);
	
	r3.in.sec_handle = &sec_handle;
	r3.in.new_val = &buf1;
	r3.in.old_val = NULL;
	r3.in.new_val->data = enc_key.data;
	r3.in.new_val->length = enc_key.length;
	r3.in.new_val->size = enc_key.length;
	
	printf("Testing SetSecret\n");
	
	status = dcerpc_lsa_SetSecret(p, mem_ctx, &r3);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetSecret failed - %s\n", nt_errstr(status));
		ret = False;
	}
		
	r3.in.sec_handle = &sec_handle;
	r3.in.new_val = &buf1;
	r3.in.old_val = NULL;
	r3.in.new_val->data = enc_key.data;
	r3.in.new_val->length = enc_key.length;
	r3.in.new_val->size = enc_key.length;
	
	/* break the encrypted data */
	enc_key.data[0]++;
	
	printf("Testing SetSecret with broken key\n");
	
	status = dcerpc_lsa_SetSecret(p, mem_ctx, &r3);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_UNKNOWN_REVISION)) {
		printf("SetSecret should have failed UNKNOWN_REVISION - %s\n", nt_errstr(status));
		ret = False;
	}
	
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
	
	printf("Testing QuerySecret\n");
	status = dcerpc_lsa_QuerySecret(p, mem_ctx, &r4);
	if (!NT_STATUS_IS_OK(status)) {
		printf("QuerySecret failed - %s\n", nt_errstr(status));
		ret = False;
	} else {
		if (r4.out.new_val == NULL || r4.out.new_val->buf == NULL) {
			printf("No secret buffer returned\n");
			ret = False;
		} else {
			blob1.data = r4.out.new_val->buf->data;
			blob1.length = r4.out.new_val->buf->size;
			
			blob2 = data_blob_talloc(mem_ctx, NULL, blob1.length);
			
			secret2 = sess_decrypt_string(mem_ctx, &blob1, &session_key);
			
			if (strcmp(secret1, secret2) != 0) {
				printf("Returned secret '%s' doesn't match '%s'\n", 
				       secret2, secret1);
				ret = False;
			}
		}
	}

	d.in.handle = &sec_handle;
	status = dcerpc_lsa_Delete(p, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		printf("delete should have returned OKINVALID_HANDLE - %s\n", nt_errstr(status));
		ret = False;
	}
	return ret;
}


/* TEST session key correctness by pushing and pulling secrets */

BOOL torture_rpc_lsa_secrets(struct torture_context *torture) 
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct policy_handle *handle;

	mem_ctx = talloc_init("torture_rpc_lsa_secrets");

	status = torture_rpc_connection(mem_ctx, 
					&p, 
					&dcerpc_table_lsarpc);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return False;
	}

	if (test_lsa_OpenPolicy2(p, mem_ctx, &handle)) {
		if (!handle) {
			printf("OpenPolicy2 failed.  This test cannot run against this server\n");
			ret = False;
		} else if (!test_CreateSecret_basic(p, mem_ctx, handle)) {
			ret = False;
		}
	} else {
		return False;
	}

	talloc_free(mem_ctx);

	return ret;
}
