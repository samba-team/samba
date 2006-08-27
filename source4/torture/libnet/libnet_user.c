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
#include "system/time.h"
#include "lib/cmdline/popt_common.h"
#include "libnet/libnet.h"
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "torture/torture.h"
#include "torture/rpc/rpc.h"


#define TEST_USERNAME        "libnetusertest"

static BOOL test_cleanup(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *domain_handle, const char *username)
{
	NTSTATUS status;
	struct samr_LookupNames r1;
	struct samr_OpenUser r2;
	struct samr_DeleteUser r3;
	struct samr_Close r4;
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

	r4.in.handle = domain_handle;
	r4.out.handle = domain_handle;

	status = dcerpc_samr_Close(p, mem_ctx, &r4);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Close failed - %s\n", nt_errstr(status));
		return False;
	}
	
	return True;
}


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


BOOL torture_createuser(struct torture_context *torture)
{
	NTSTATUS status;
	const char *binding;
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	struct libnet_CreateUser req;

	mem_ctx = talloc_init("test_createuser");
	binding = lp_parm_string(-1, "torture", "binding");

	ctx = libnet_context_init(NULL);
	ctx->cred = cmdline_credentials;

	req.in.user_name = TEST_USERNAME;
	req.in.domain_name = lp_workgroup();
	req.out.error_string = NULL;

	status = libnet_CreateUser(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		printf("libnet_CreateUser call failed: %s\n", nt_errstr(status));
		return False;
	}

	if (!test_cleanup(ctx->samr.pipe, mem_ctx, &ctx->samr.handle, TEST_USERNAME)) {
		printf("cleanup failed\n");
		return False;
	}

	return True;
}


BOOL torture_deleteuser(struct torture_context *torture)
{
	NTSTATUS status;
	const char *binding;
	struct dcerpc_pipe *p;
	TALLOC_CTX *prep_mem_ctx, *mem_ctx;
	struct policy_handle h;
	struct lsa_String domain_name;
	const char *name = TEST_USERNAME;
	struct libnet_context *ctx;
	struct libnet_DeleteUser req;
	BOOL ret = True;

	prep_mem_ctx = talloc_init("prepare test_deleteuser");
	binding = lp_parm_string(-1, "torture", "binding");

	ctx = libnet_context_init(NULL);
	ctx->cred = cmdline_credentials;

	req.in.user_name = TEST_USERNAME;
	req.in.domain_name = lp_workgroup();

	status = torture_rpc_connection(prep_mem_ctx,
					&p,
					&dcerpc_table_samr);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	domain_name.string = lp_workgroup();
	if (!test_opendomain(p, prep_mem_ctx, &h, &domain_name)) {
		ret = False;
		goto done;
	}

	if (!test_createuser(p, prep_mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}

	mem_ctx = talloc_init("test_deleteuser");

	status = libnet_DeleteUser(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		printf("libnet_DeleteUser call failed: %s\n", nt_errstr(status));
		return False;
	}

done:
	talloc_free(prep_mem_ctx);
	talloc_free(mem_ctx);
	return ret;
}


/*
  Generate testing set of random changes
*/

#define TEST_CHG_ACCOUNTNAME   "newlibnetusertest%02d"
#define TEST_CHG_DESCRIPTION   "Sample description %ld"
#define TEST_CHG_FULLNAME      "First%04x Last%04x"
#define TEST_CHG_COMMENT       "Comment[%04lu%04lu]"
#define TEST_CHG_PROFILEPATH   "\\\\srv%04ld\\profile%02u\\prof"

#define continue_if_field_set(field) \
	if (field != 0) { \
		i--; \
		continue; \
	}

static void set_test_changes(TALLOC_CTX *mem_ctx, struct libnet_ModifyUser *r, int num_changes)
{
	enum fields { account_name = 0, full_name, description, home_directory, home_drive,
		      comment, logon_script, profile_path, acct_expiry, allow_password_change,
		      force_password_change, last_logon, last_logoff, last_password_change };
	const int num_fields = 14;
	const char* logon_scripts[] = { "start_login.cmd", "login.bat", "start.cmd" };
	const char* home_dirs[] = { "\\\\srv\\home", "\\\\homesrv\\home\\user", "\\\\pdcsrv\\domain" };
	const char* home_drives[] = { "H:", "z:", "I:", "J:", "n:" };
	const char *homedir, *homedrive, *logonscript;
	struct timeval now;
	int i, randval;

	srandom((unsigned)time(NULL));

	printf("Fields to change: [");

	for (i = 0; i < num_changes && i < num_fields; i++) {
		const char *fldname;
		randval = random() % num_fields;

		/* get one in case we hit time field this time */
		gettimeofday(&now, NULL);
		
		switch (randval) {
		case account_name:
			continue_if_field_set(r->in.account_name);
			r->in.account_name = talloc_asprintf(mem_ctx, TEST_CHG_ACCOUNTNAME,
							     (int)random());
			fldname = "account_name";
			break;

		case full_name:
			continue_if_field_set(r->in.full_name);
			r->in.full_name = talloc_asprintf(mem_ctx, TEST_CHG_FULLNAME,
							  (unsigned int)random(), (unsigned int)random());
			fldname = "full_name";
			break;

		case description:
			continue_if_field_set(r->in.description);
			r->in.description = talloc_asprintf(mem_ctx, TEST_CHG_DESCRIPTION,
							    (long)random());
			fldname = "description";
			break;

		case home_directory:
			continue_if_field_set(r->in.home_directory);
			homedir = home_dirs[random() % (sizeof(home_dirs)/sizeof(char*))];
			r->in.home_directory = talloc_strdup(mem_ctx, homedir);
			fldname = "home_dir";
			break;

		case home_drive:
			continue_if_field_set(r->in.home_drive);
			homedrive = home_drives[random() % (sizeof(home_drives)/sizeof(char*))];
			r->in.home_drive = talloc_strdup(mem_ctx, homedrive);
			fldname = "home_drive";
			break;

		case comment:
			continue_if_field_set(r->in.comment);
			r->in.comment = talloc_asprintf(mem_ctx, TEST_CHG_COMMENT,
							(unsigned long)random(), (unsigned long)random());
			fldname = "comment";
			break;

		case logon_script:
			continue_if_field_set(r->in.logon_script);
			logonscript = logon_scripts[random() % (sizeof(logon_scripts)/sizeof(char*))];
			r->in.logon_script = talloc_strdup(mem_ctx, logonscript);
			fldname = "logon_script";
			break;
			
		case profile_path:
			continue_if_field_set(r->in.profile_path);
			r->in.profile_path = talloc_asprintf(mem_ctx, TEST_CHG_PROFILEPATH,
							     (unsigned long)random(), (unsigned int)random());
			fldname = "profile_path";
			break;

		case acct_expiry:
			continue_if_field_set(r->in.acct_expiry);
			now = timeval_add(&now, (random() % (31*24*60*60)), 0);
			r->in.acct_expiry = talloc_memdup(mem_ctx, &now, sizeof(now));
			fldname = "acct_expiry";
			break;

		case allow_password_change:
			continue_if_field_set(r->in.allow_password_change);
			now = timeval_add(&now, (random() % (31*24*60*60)), 0);
			r->in.allow_password_change = talloc_memdup(mem_ctx, &now, sizeof(now));
			fldname = "allow_password_change";
			break;

		case force_password_change:
			continue_if_field_set(r->in.force_password_change);
			now = timeval_add(&now, (random() % (31*24*60*60)), 0);
			r->in.force_password_change = talloc_memdup(mem_ctx, &now, sizeof(now));
			fldname = "force_password_change";
			break;

		case last_logon:
			continue_if_field_set(r->in.last_logon);
			now = timeval_add(&now, (random() % (31*24*60*60)), 0);
			r->in.last_logon = talloc_memdup(mem_ctx, &now, sizeof(now));
			fldname = "last_logon";
			break;

		case last_logoff:
			continue_if_field_set(r->in.last_logoff);
			now = timeval_add(&now, (random() % (31*24*60*60)), 0);
			r->in.last_logoff = talloc_memdup(mem_ctx, &now, sizeof(now));
			fldname = "last_logoff";
			break;

		case last_password_change:
			continue_if_field_set(r->in.last_password_change);
			now = timeval_add(&now, (random() % (31*24*60*60)), 0);
			r->in.last_password_change = talloc_memdup(mem_ctx, &now, sizeof(now));
			fldname = "last_password_change";
			break;
		}
		
		printf(((i < num_changes - 1) ? "%s," : "%s"), fldname);
	}

	printf("]\n");
}


BOOL torture_modifyuser(struct torture_context *torture)
{
	NTSTATUS status;
	const char *binding;
	struct dcerpc_binding *bind;
	struct dcerpc_pipe *p;
	TALLOC_CTX *prep_mem_ctx, *mem_ctx;
	struct policy_handle h;
	struct lsa_String domain_name;
	const char *name = TEST_USERNAME;
	struct libnet_context *ctx;
	struct libnet_ModifyUser req;
	BOOL ret = True;

	prep_mem_ctx = talloc_init("prepare test_deleteuser");
	binding = lp_parm_string(-1, "torture", "binding");

	ctx = libnet_context_init(NULL);
	ctx->cred = cmdline_credentials;

	status = torture_rpc_connection(prep_mem_ctx,
					&p,
					&dcerpc_table_samr);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	domain_name.string = lp_workgroup();
	if (!test_opendomain(p, prep_mem_ctx, &h, &domain_name)) {
		ret = False;
		goto done;
	}

	if (!test_createuser(p, prep_mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}

	mem_ctx = talloc_init("test_modifyuser");

	status = dcerpc_parse_binding(mem_ctx, binding, &bind);
	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
		goto done;
	}

	ZERO_STRUCT(req);
	req.in.domain_name = lp_workgroup();
	req.in.user_name = TEST_USERNAME;
	
	printf("Testing change of a single field\n");
	set_test_changes(mem_ctx, &req, 1);
	
	req.in.account_name = "newlibnetuser";

	status = libnet_ModifyUser(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		printf("libnet_ModifyUser call failed: %s\n", nt_errstr(status));
		return False;
	}

	if (!test_cleanup(ctx->samr.pipe, mem_ctx, &ctx->samr.handle, TEST_USERNAME)) {
		printf("cleanup failed\n");
		return False;
	}

done:
	talloc_free(prep_mem_ctx);
	talloc_free(mem_ctx);
	return ret;
}


BOOL torture_userinfo_api(struct torture_context *torture)
{
	const char *name = TEST_USERNAME;
	const char *binding;
	BOOL ret = True;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx, *prep_mem_ctx;
	struct libnet_context *ctx;
	struct dcerpc_pipe *p;
	struct policy_handle h;
	struct lsa_String domain_name;
	struct libnet_UserInfo req;

	prep_mem_ctx = talloc_init("torture user info");
	binding = lp_parm_string(-1, "torture", "binding");

	ctx = libnet_context_init(NULL);
	ctx->cred = cmdline_credentials;

	status = torture_rpc_connection(prep_mem_ctx,
					&p,
					&dcerpc_table_samr);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	domain_name.string = lp_workgroup();
	if (!test_opendomain(p, prep_mem_ctx, &h, &domain_name)) {
		ret = False;
		goto done;
	}

	if (!test_createuser(p, prep_mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}

	ZERO_STRUCT(req);
	
	req.in.domain_name = domain_name.string;
	req.in.user_name   = name;

	status = libnet_UserInfo(ctx, mem_ctx, &req);
	if (!NT_STATUS_IS_OK(status)) {
		printf("libnet_UserInfo call failed: %s\n", nt_errstr(status));
		ret = False;
	}

	if (!test_cleanup(ctx->samr.pipe, mem_ctx, &ctx->samr.handle, TEST_USERNAME)) {
		printf("cleanup failed\n");
		ret = False;
		goto done;
	}

done:
	talloc_free(ctx);
	talloc_free(mem_ctx);
	return ret;
}
