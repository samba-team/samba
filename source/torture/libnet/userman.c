/* 
   Unix SMB/CIFS implementation.
   Test suite for libnet calls.

   Copyright (C) Rafal Szczesniak 2005
   
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
#include "libnet/userman.h"
#include "libnet/libnet.h"

#define TEST_USERNAME  "libnetusermantest"


static BOOL test_opendomain(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			    struct policy_handle *handle, struct lsa_String *domname)
{
	NTSTATUS status;
	struct policy_handle h, domain_handle;
	struct samr_Connect r1;
	struct samr_LookupDomain r2;
	struct samr_OpenDomain r3;
	
	printf("connecting\n");
	
	r1.in.system_name = 0;
	r1.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r1.out.connect_handle = &h;
	
	status = dcerpc_samr_Connect(p, mem_ctx, &r1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect failed - %s\n", nt_errstr(status));
		return False;
	}
	
	r2.in.connect_handle = &h;
	r2.in.domain_name = domname;

	printf("domain lookup on %s\n", domname->string);

	status = dcerpc_samr_LookupDomain(p, mem_ctx, &r2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupDomain failed - %s\n", nt_errstr(status));
		return False;
	}

	r3.in.connect_handle = &h;
	r3.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r3.in.sid = r2.out.sid;
	r3.out.domain_handle = &domain_handle;

	printf("opening domain\n");

	status = dcerpc_samr_OpenDomain(p, mem_ctx, &r3);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenDomain failed - %s\n", nt_errstr(status));
		return False;
	} else {
		*handle = domain_handle;
	}

	return True;
}


static BOOL test_useradd(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *domain_handle,
			 const char *name)
{
	NTSTATUS status;
	BOOL ret = True;
	struct libnet_rpc_useradd user;
	
	user.in.domain_handle = *domain_handle;
	user.in.username      = name;

	printf("Testing libnet_rpc_useradd\n");

	status = libnet_rpc_useradd(p, mem_ctx, &user);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to call sync rpc_composite_userinfo - %s\n", nt_errstr(status));
		return False;
	}
	
	return ret;
}


static void msg_handler(struct monitor_msg *m)
{
	struct msg_rpc_create_user *msg_create;

	switch (m->type) {
	case rpc_create_user:
		msg_create = (struct msg_rpc_create_user*)m->data;
		printf("monitor_msg: user created (rid=%d)\n", msg_create->rid);
		break;
	}
}


static BOOL test_useradd_async(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			       struct policy_handle *handle, const char* username)
{
	NTSTATUS status;
	struct composite_context *c;
	struct libnet_rpc_useradd user;

	user.in.domain_handle = *handle;
	user.in.username      = username;
	
	printf("Testing async libnet_rpc_useradd\n");
	
	c = libnet_rpc_useradd_send(p, &user, msg_handler);
	if (!c) {
		printf("Failed to call async libnet_rpc_useradd\n");
		return False;
	}

	status = libnet_rpc_useradd_recv(c, mem_ctx, &user);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Calling async libnet_rpc_useradd failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;

}


static BOOL test_cleanup(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *domain_handle, const char *username)
{
	NTSTATUS status;
	struct samr_LookupNames r1;
	struct samr_OpenUser r2;
	struct samr_DeleteUser r3;
	struct lsa_String names[2];
	uint32_t rid;
	struct policy_handle user_handle;

	names[0].string = username;

	r1.in.domain_handle  = domain_handle;
	r1.in.num_names      = 1;
	r1.in.names          = names;
	
	printf("user account lookup '%s'\n", username);

	status = dcerpc_samr_LookupNames(p, mem_ctx, &r1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupNames failed - %s\n", nt_errstr(status));
		return False;
	}

	rid = r1.out.rids.ids[0];
	
	r2.in.domain_handle  = domain_handle;
	r2.in.access_mask    = SEC_FLAG_MAXIMUM_ALLOWED;
	r2.in.rid            = rid;
	r2.out.user_handle   = &user_handle;

	printf("opening user account\n");

	status = dcerpc_samr_OpenUser(p, mem_ctx, &r2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenUser failed - %s\n", nt_errstr(status));
		return False;
	}

	r3.in.user_handle  = &user_handle;
	r3.out.user_handle = &user_handle;

	printf("deleting user account\n");
	
	status = dcerpc_samr_DeleteUser(p, mem_ctx, &r3);
	if (!NT_STATUS_IS_OK(status)) {
		printf("DeleteUser failed - %s\n", nt_errstr(status));
		return False;
	}
	
	return True;
}


static BOOL test_createuser(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
 			    struct policy_handle *handle, const char* user)
{
	NTSTATUS status;
	struct policy_handle user_handle;
	struct lsa_String username;
	struct samr_CreateUser r1;
	struct samr_Close r2;
	uint32_t user_rid;

	username.string = user;
	
	r1.in.domain_handle = handle;
	r1.in.account_name = &username;
	r1.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r1.out.user_handle = &user_handle;
	r1.out.rid = &user_rid;

	printf("creating user '%s'\n", username.string);
	
	status = dcerpc_samr_CreateUser(p, mem_ctx, &r1);
	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateUser failed - %s\n", nt_errstr(status));

		if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
			printf("User (%s) already exists - attempting to delete and recreate account again\n", user);
			if (!test_cleanup(p, mem_ctx, handle, TEST_USERNAME)) {
				return False;
			}

			printf("creating user account\n");
			
			status = dcerpc_samr_CreateUser(p, mem_ctx, &r1);
			if (!NT_STATUS_IS_OK(status)) {
				printf("CreateUser failed - %s\n", nt_errstr(status));
				return False;
			}
			return True;
		}		
		return False;
	}

	r2.in.handle = &user_handle;
	r2.out.handle = &user_handle;
	
	printf("closing user '%s'\n", username.string);

	status = dcerpc_samr_Close(p, mem_ctx, &r2);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Close failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_userdel(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *handle, const char *username)
{
	NTSTATUS status;
	struct libnet_rpc_userdel user;
	
	user.in.domain_handle = *handle;
	user.in.username = username;
	
	status = libnet_rpc_userdel(p, mem_ctx, &user);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to call sync libnet_rpc_userdel - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_usermod(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *handle, const char *username,
			 struct usermod_change *change)
{
	NTSTATUS status;
	struct libnet_rpc_usermod user;
	
	user.in.domain_handle = *handle;
	user.in.username = username;
	user.in.change = *change;

	printf("modifying user\n");

	status = libnet_rpc_usermod(p, mem_ctx, &user);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to call sync libnet_rpc_usermod - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


BOOL torture_useradd(void)
{
	NTSTATUS status;
	const char *binding;
	struct dcerpc_pipe *p;
	struct policy_handle h;
	struct lsa_String domain_name;
	const char *name = TEST_USERNAME;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("test_useradd");
	binding = lp_parm_string(-1, "torture", "binding");

	status = torture_rpc_connection(mem_ctx, 
					&p,
					&dcerpc_table_samr);
	
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	domain_name.string = lp_workgroup();
	if (!test_opendomain(p, mem_ctx, &h, &domain_name)) {
		ret = False;
		goto done;
	}

	if (!test_useradd(p, mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}

	if (!test_cleanup(p, mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}

	if (!test_opendomain(p, mem_ctx, &h, &domain_name)) {
		ret = False;
		goto done;
	}

	if (!test_useradd_async(p, mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}

	if (!test_cleanup(p, mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}

done:
	talloc_free(mem_ctx);
	return ret;
}


BOOL torture_userdel(void)
{
	NTSTATUS status;
	const char *binding;
	struct dcerpc_pipe *p;
	struct policy_handle h;
	struct lsa_String domain_name;
	const char *name = TEST_USERNAME;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("test_userdel");
	binding = lp_parm_string(-1, "torture", "binding");

	status = torture_rpc_connection(mem_ctx, 
					&p,
					&dcerpc_table_samr);
	
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	domain_name.string = lp_workgroup();
	if (!test_opendomain(p, mem_ctx, &h, &domain_name)) {
		ret = False;
		goto done;
	}

	if (!test_createuser(p, mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}
	
       	if (!test_userdel(p, mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}
	
done:
	talloc_free(mem_ctx);
	return ret;
}


BOOL torture_usermod(void)
{
	NTSTATUS status;
	const char *binding;
	struct dcerpc_pipe *p;
	struct policy_handle h;
	struct lsa_String domain_name;
	const char *name = TEST_USERNAME;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	int i;

	struct timeval expiry = { 12345, 67890 };
	struct timeval allow  = { 67890, 12345 };
	struct timeval force  = { 33333, 55444 };

	struct usermod_change changes[] = {
		{ USERMOD_FIELD_ACCOUNT_NAME,   "changed", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0 },
		{ USERMOD_FIELD_FULL_NAME,      NULL, "Testing full account name", NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0 },
		{ USERMOD_FIELD_DESCRIPTION,    NULL, NULL, "Description of tested account", NULL, NULL, NULL, NULL, NULL, NULL, 0 },
		{ USERMOD_FIELD_COMMENT,        NULL, NULL, NULL, "Comment for the tested account", NULL, NULL, NULL, NULL, NULL, 0 },
		{ USERMOD_FIELD_LOGON_SCRIPT,   NULL, NULL, NULL, NULL, "test_logon.cmd", NULL, NULL, NULL, NULL, 0 },
		{ USERMOD_FIELD_PROFILE_PATH,   NULL, NULL, NULL, NULL, NULL, "\\\\TESTSRV\\profiles\\test", NULL, NULL, NULL, 0 },
		{ USERMOD_FIELD_ACCT_EXPIRY,    NULL, NULL, NULL, NULL, NULL, NULL, &expiry, NULL, NULL, 0 },
		{ USERMOD_FIELD_ALLOW_PASS_CHG, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &allow, NULL, 0 },
		{ USERMOD_FIELD_FORCE_PASS_CHG, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &force, ACB_NORMAL }
	};
	
	mem_ctx = talloc_init("test_userdel");
	binding = lp_parm_string(-1, "torture", "binding");

	status = torture_rpc_connection(mem_ctx, 
					&p,
					&dcerpc_table_samr);
	
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	domain_name.string = lp_workgroup();

	if (!test_opendomain(p, mem_ctx, &h, &domain_name)) {
		ret = False;
		goto done;
	}

	if (!test_createuser(p, mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}

	for (i = 0; i < (sizeof(changes)/sizeof(struct usermod_change)); i++) {
		if (!test_usermod(p, mem_ctx, &h, name, &changes[i])) {
			ret = False;
			goto done;
		}

		if (changes[i].fields & USERMOD_FIELD_ACCOUNT_NAME) {
			name = talloc_strdup(mem_ctx, changes[i].account_name);
		}
	}

	if (!test_cleanup(p, mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}

done:
	talloc_free(mem_ctx);
	return ret;
}
