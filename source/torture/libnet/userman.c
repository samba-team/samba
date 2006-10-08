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
#include "torture/rpc/rpc.h"
#include "torture/libnet/usertest.h"
#include "libnet/libnet.h"
#include "librpc/gen_ndr/ndr_samr_c.h"


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


static BOOL test_usermod(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *handle, int num_changes,
			 struct libnet_rpc_usermod *mod, char **username)
{
	const char* logon_scripts[] = { "start_login.cmd", "login.bat", "start.cmd" };
	const char* home_dirs[] = { "\\\\srv\\home", "\\\\homesrv\\home\\user", "\\\\pdcsrv\\domain" };
	const char* home_drives[] = { "H:", "z:", "I:", "J:", "n:" };
	const char *homedir, *homedrive, *logonscript;
	const uint32_t flags[] = { (ACB_DISABLED | ACB_NORMAL),
				   (ACB_NORMAL | ACB_PWNOEXP),
				   (ACB_NORMAL | ACB_PW_EXPIRED) };

	NTSTATUS status;
	struct timeval now;
	enum test_fields testfld;
	int i;

	ZERO_STRUCT(*mod);
	srandom((unsigned)time(NULL));

	mod->in.username = talloc_strdup(mem_ctx, *username);
	mod->in.domain_handle = *handle;

	printf("modifying user (%d simultaneous change(s))\n", num_changes);

	printf("fields to change: [");

	for (i = 0; i < num_changes && i < FIELDS_NUM - 1; i++) {
		const char *fldname;

		testfld = (random() % (FIELDS_NUM - 1)) + 1;

		gettimeofday(&now, NULL);

		switch (testfld) {
		case account_name:
			continue_if_field_set(mod->in.change.account_name);
			mod->in.change.account_name = talloc_asprintf(mem_ctx, TEST_CHG_ACCOUNTNAME,
								      (int)(random()/100));
			mod->in.change.fields |= USERMOD_FIELD_ACCOUNT_NAME;
			fldname = "account_name";
			*username = talloc_strdup(mem_ctx, mod->in.change.account_name);
			break;

		case full_name:
			continue_if_field_set(mod->in.change.full_name);
			mod->in.change.full_name = talloc_asprintf(mem_ctx, TEST_CHG_FULLNAME,
								  (int)random(), (int)random());
			mod->in.change.fields |= USERMOD_FIELD_FULL_NAME;
			fldname = "full_name";
			break;

		case description:
			continue_if_field_set(mod->in.change.description);
			mod->in.change.description = talloc_asprintf(mem_ctx, TEST_CHG_DESCRIPTION,
								    random());
			mod->in.change.fields |= USERMOD_FIELD_DESCRIPTION;
			fldname = "description";
			break;
			
		case home_directory:
			continue_if_field_set(mod->in.change.home_directory);
			homedir = home_dirs[random() % (sizeof(home_dirs)/sizeof(char*))];
			mod->in.change.home_directory = talloc_strdup(mem_ctx, homedir);
			mod->in.change.fields |= USERMOD_FIELD_HOME_DIRECTORY;
			fldname = "home directory";
			break;

		case home_drive:
			continue_if_field_set(mod->in.change.home_drive);
			homedrive = home_drives[random() % (sizeof(home_drives)/sizeof(char*))];
			mod->in.change.home_drive = talloc_strdup(mem_ctx, homedrive);
			mod->in.change.fields |= USERMOD_FIELD_HOME_DRIVE;
			fldname = "home drive";
			break;

		case comment:
			continue_if_field_set(mod->in.change.comment);
			mod->in.change.comment = talloc_asprintf(mem_ctx, TEST_CHG_COMMENT,
								random(), random());
			mod->in.change.fields |= USERMOD_FIELD_COMMENT;
			fldname = "comment";
			break;

		case logon_script:
			continue_if_field_set(mod->in.change.logon_script);
			logonscript = logon_scripts[random() % (sizeof(logon_scripts)/sizeof(char*))];
			mod->in.change.logon_script = talloc_strdup(mem_ctx, logonscript);
			mod->in.change.fields |= USERMOD_FIELD_LOGON_SCRIPT;
			fldname = "logon script";
			break;

		case profile_path:
			continue_if_field_set(mod->in.change.profile_path);
			mod->in.change.profile_path = talloc_asprintf(mem_ctx, TEST_CHG_PROFILEPATH,
								     (long int)random(), (unsigned int)random());
			mod->in.change.fields |= USERMOD_FIELD_PROFILE_PATH;
			fldname = "profile path";
			break;

		case acct_expiry:
			continue_if_field_set(mod->in.change.acct_expiry);
			now = timeval_add(&now, (random() % (31*24*60*60)), 0);
			mod->in.change.acct_expiry = talloc_memdup(mem_ctx, &now, sizeof(now));
			mod->in.change.fields |= USERMOD_FIELD_ACCT_EXPIRY;
			fldname = "acct_expiry";
			break;

		case acct_flags:
			continue_if_field_set(mod->in.change.acct_flags);
			mod->in.change.acct_flags = flags[random() % (sizeof(flags)/sizeof(uint32_t))];
			mod->in.change.fields |= USERMOD_FIELD_ACCT_EXPIRY;
			fldname = "acct_flags";
			break;

		default:
			fldname = talloc_asprintf(mem_ctx, "unknown_field (%d)", testfld);
			break;
		}

		printf(((i < num_changes - 1) ? "%s," : "%s"), fldname);
	}
	printf("]\n");

	status = libnet_rpc_usermod(p, mem_ctx, mod);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to call sync libnet_rpc_usermd - %s\n", nt_errstr(status));
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


#define CMP_LSA_STRING_FLD(fld, flags) \
	if ((mod->in.change.fields & flags) && \
	    !strequal(i->fld.string, mod->in.change.fld)) { \
		printf("'%s' field does not match\n", #fld); \
		printf("received: '%s'\n", i->fld.string); \
		printf("expected: '%s'\n", mod->in.change.fld); \
		return False; \
	}


#define CMP_TIME_FLD(fld, flags) \
	if (mod->in.change.fields & flags) { \
		nttime_to_timeval(&t, i->fld); \
		if (timeval_compare(&t, mod->in.change.fld)) { \
			printf("'%s' field does not match\n", #fld); \
			printf("received: '%s (+%ld us)'\n", timestring(mem_ctx, t.tv_sec), t.tv_usec); \
			printf("expected: '%s (+%ld us)'\n", timestring(mem_ctx, mod->in.change.fld->tv_sec), mod->in.change.fld->tv_usec); \
			return False; \
		} \
	}

#define CMP_NUM_FLD(fld, flags) \
	if ((mod->in.change.fields & flags) && \
	    (i->fld != mod->in.change.fld)) { \
		printf("'%s' field does not match\n", #fld); \
		printf("received: '%04x'\n", i->fld); \
		printf("expected: '%04x'\n", mod->in.change.fld); \
		return False; \
	}


static BOOL test_compare(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
			 struct policy_handle *handle, struct libnet_rpc_usermod *mod,
			 const char *username)
{
	NTSTATUS status;
	struct libnet_rpc_userinfo info;
	struct samr_UserInfo21 *i;
	struct timeval t;

	ZERO_STRUCT(info);

	info.in.username = username;
	info.in.domain_handle = *handle;
	info.in.level = 21;             /* the most rich infolevel available */

	status = libnet_rpc_userinfo(p, mem_ctx, &info);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to call sync libnet_rpc_userinfo - %s\n", nt_errstr(status));
		return False;
	}

	i = &info.out.info.info21;

	CMP_LSA_STRING_FLD(account_name, USERMOD_FIELD_ACCOUNT_NAME);
	CMP_LSA_STRING_FLD(full_name, USERMOD_FIELD_FULL_NAME);
	CMP_LSA_STRING_FLD(description, USERMOD_FIELD_DESCRIPTION);
	CMP_LSA_STRING_FLD(comment, USERMOD_FIELD_COMMENT);
	CMP_LSA_STRING_FLD(logon_script, USERMOD_FIELD_LOGON_SCRIPT);
	CMP_LSA_STRING_FLD(profile_path, USERMOD_FIELD_PROFILE_PATH);
	CMP_LSA_STRING_FLD(home_directory, USERMOD_FIELD_HOME_DIRECTORY);
	CMP_LSA_STRING_FLD(home_drive, USERMOD_FIELD_HOME_DRIVE);
	CMP_TIME_FLD(acct_expiry, USERMOD_FIELD_ACCT_EXPIRY);
	CMP_NUM_FLD(acct_flags, USERMOD_FIELD_ACCT_FLAGS)

	return True;
}


BOOL torture_useradd(struct torture_context *torture)
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


BOOL torture_userdel(struct torture_context *torture)
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


BOOL torture_usermod(struct torture_context *torture)
{
	NTSTATUS status;
	const char *binding;
	struct dcerpc_pipe *p;
	struct policy_handle h;
	struct lsa_String domain_name;
	int i;
	char *name;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("test_userdel");
	binding = lp_parm_string(-1, "torture", "binding");

	status = torture_rpc_connection(mem_ctx, 
					&p,
					&dcerpc_table_samr);
	
	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
		goto done;
	}

	domain_name.string = lp_workgroup();
	name = talloc_strdup(mem_ctx, TEST_USERNAME);

	if (!test_opendomain(p, mem_ctx, &h, &domain_name)) {
		ret = False;
		goto done;
	}

	if (!test_createuser(p, mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}
	
	for (i = 1; i < FIELDS_NUM; i++) {
		struct libnet_rpc_usermod m;

		if (!test_usermod(p, mem_ctx, &h, i, &m, &name)) {
			ret = False;
			goto cleanup;
		}

		if (!test_compare(p, mem_ctx, &h, &m, name)) {
			ret = False;
			goto cleanup;
		}
	}
	
cleanup:	
	if (!test_cleanup(p, mem_ctx, &h, name)) {
		ret = False;
		goto done;
	}

done:
	talloc_free(mem_ctx);
	return ret;
}
