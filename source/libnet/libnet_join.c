/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Stefan Metzmacher	2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
 
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
#include "libnet/libnet.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "lib/crypto/crypto.h"

/*
 * do a domain join using DCERPC/SAMR calls
 * 1. connect to the SAMR pipe of users domain PDC (maybe a standalone server or workstation)
 *    is it correct to contact the the pdc of the domain of the user who's password should be set?
 * 2. do a samr_Connect to get a policy handle
 * 3. do a samr_LookupDomain to get the domain sid
 * 4. do a samr_OpenDomain to get a domain handle
 * 5. do a samr_CreateAccount to try and get a new account 
 * 
 * If that fails, do:
 * 5.1. do a samr_LookupNames to get the users rid
 * 5.2. do a samr_OpenUser to get a user handle
 * 
 * 6. call libnet_SetPassword_samr_handle to set the password
 *
 * 7. do a samrSetUserInfo to set the account flags
 */
static NTSTATUS libnet_JoinDomain_samr(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_JoinDomain *r)
{
	NTSTATUS status;
	union libnet_rpc_connect c;
	struct samr_Connect sc;
	struct policy_handle p_handle;
	struct samr_LookupDomain ld;
	struct samr_String d_name;
	struct samr_OpenDomain od;
	struct policy_handle d_handle;
	struct samr_LookupNames ln;
	struct samr_OpenUser ou;
	struct samr_CreateUser2 cu;
	struct policy_handle u_handle;
	struct samr_SetUserInfo sui;
	union samr_UserInfo u_info;
	union libnet_SetPassword r2;
	struct samr_GetUserPwInfo pwp;
	struct samr_String samr_account_name;

	uint32 rid, access_granted;
	int policy_min_pw_len = 0;

	/* prepare connect to the SAMR pipe of users domain PDC */
	c.pdc.level			= LIBNET_RPC_CONNECT_PDC;
	c.pdc.in.domain_name		= r->samr.in.domain_name;
	c.pdc.in.dcerpc_iface_name	= DCERPC_SAMR_NAME;
	c.pdc.in.dcerpc_iface_uuid	= DCERPC_SAMR_UUID;
	c.pdc.in.dcerpc_iface_version	= DCERPC_SAMR_VERSION;

	/* 1. connect to the SAMR pipe of users domain PDC (maybe a standalone server or workstation) */
	status = libnet_rpc_connect(ctx, mem_ctx, &c);
	if (!NT_STATUS_IS_OK(status)) {
		r->samr.out.error_string = talloc_asprintf(mem_ctx,
						"Connection to SAMR pipe of PDC of domain '%s' failed: %s\n",
						r->samr.in.domain_name, nt_errstr(status));
		return status;
	}

	/* prepare samr_Connect */
	ZERO_STRUCT(p_handle);
	sc.in.system_name = NULL;
	sc.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	sc.out.connect_handle = &p_handle;

	/* 2. do a samr_Connect to get a policy handle */
	status = dcerpc_samr_Connect(c.pdc.out.dcerpc_pipe, mem_ctx, &sc);
	if (!NT_STATUS_IS_OK(status)) {
		r->samr.out.error_string = talloc_asprintf(mem_ctx,
						"samr_Connect failed: %s\n",
						nt_errstr(status));
		goto disconnect;
	}

	/* check result of samr_Connect */
	if (!NT_STATUS_IS_OK(sc.out.result)) {
		r->samr.out.error_string = talloc_asprintf(mem_ctx,
						"samr_Connect failed: %s\n", 
						nt_errstr(sc.out.result));
		status = sc.out.result;
		goto disconnect;
	}

	/* prepare samr_LookupDomain */
	d_name.string = r->samr.in.domain_name;
	ld.in.connect_handle = &p_handle;
	ld.in.domain = &d_name;

	/* 3. do a samr_LookupDomain to get the domain sid */
	status = dcerpc_samr_LookupDomain(c.pdc.out.dcerpc_pipe, mem_ctx, &ld);
	if (!NT_STATUS_IS_OK(status)) {
		r->samr.out.error_string = talloc_asprintf(mem_ctx,
						"samr_LookupDomain for [%s] failed: %s\n",
						r->samr.in.domain_name, nt_errstr(status));
		goto disconnect;
	}

	/* check result of samr_LookupDomain */
	if (!NT_STATUS_IS_OK(ld.out.result)) {
		r->samr.out.error_string = talloc_asprintf(mem_ctx,
						"samr_LookupDomain for [%s] failed: %s\n",
						r->samr.in.domain_name, nt_errstr(ld.out.result));
		status = ld.out.result;
		goto disconnect;
	}

	/* prepare samr_OpenDomain */
	ZERO_STRUCT(d_handle);
	od.in.connect_handle = &p_handle;
	od.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	od.in.sid = ld.out.sid;
	od.out.domain_handle = &d_handle;

	/* 4. do a samr_OpenDomain to get a domain handle */
	status = dcerpc_samr_OpenDomain(c.pdc.out.dcerpc_pipe, mem_ctx, &od);
	if (!NT_STATUS_IS_OK(status)) {
		r->samr.out.error_string = talloc_asprintf(mem_ctx,
						"samr_OpenDomain for [%s] failed: %s\n",
						r->samr.in.domain_name, nt_errstr(status));
		goto disconnect;
	}

	/* prepare samr_CreateUser2 */
	ZERO_STRUCT(u_handle);
	cu.in.domain_handle  = &d_handle;
	cu.in.access_mask     = SEC_FLAG_MAXIMUM_ALLOWED;
	samr_account_name.string = r->samr.in.account_name;
	cu.in.account_name    = &samr_account_name;
	cu.in.acct_flags      = r->samr.in.acct_type;
	cu.out.user_handle    = &u_handle;
	cu.out.rid            = &rid;
	cu.out.access_granted = &access_granted;

	/* 4. do a samr_CreateUser2 to get an account handle, or an error */
	status = dcerpc_samr_CreateUser2(c.pdc.out.dcerpc_pipe, mem_ctx, &cu);
	if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
			r->samr.out.error_string = talloc_asprintf(mem_ctx,
								   "samr_CreateUser2 for [%s] failed: %s\n",
								   r->samr.in.domain_name, nt_errstr(status));
			goto disconnect;

	} else if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
		/* prepare samr_LookupNames */
		ln.in.domain_handle = &d_handle;
		ln.in.num_names = 1;
		ln.in.names = talloc_array_p(mem_ctx, struct samr_String, 1);
		if (!ln.in.names) {
			r->samr.out.error_string = "Out of Memory";
			return NT_STATUS_NO_MEMORY;
		}
		ln.in.names[0].string = r->samr.in.account_name;
		
		/* 5. do a samr_LookupNames to get the users rid */
		status = dcerpc_samr_LookupNames(c.pdc.out.dcerpc_pipe, mem_ctx, &ln);
		if (!NT_STATUS_IS_OK(status)) {
			r->samr.out.error_string = talloc_asprintf(mem_ctx,
								   "samr_LookupNames for [%s] failed: %s\n",
						r->samr.in.account_name, nt_errstr(status));
			goto disconnect;
		}
		
		
		/* check if we got one RID for the user */
		if (ln.out.rids.count != 1) {
			r->samr.out.error_string = talloc_asprintf(mem_ctx,
								   "samr_LookupNames for [%s] returns %d RIDs\n",
								   r->samr.in.account_name, ln.out.rids.count);
			status = NT_STATUS_INVALID_PARAMETER;
			goto disconnect;	
		}
		
		/* prepare samr_OpenUser */
		ZERO_STRUCT(u_handle);
		ou.in.domain_handle = &d_handle;
		ou.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		ou.in.rid = ln.out.rids.ids[0];
		ou.out.user_handle = &u_handle;
		
		/* 6. do a samr_OpenUser to get a user handle */
		status = dcerpc_samr_OpenUser(c.pdc.out.dcerpc_pipe, mem_ctx, &ou);
		if (!NT_STATUS_IS_OK(status)) {
			r->samr.out.error_string = talloc_asprintf(mem_ctx,
								   "samr_OpenUser for [%s] failed: %s\n",
								   r->samr.in.account_name, nt_errstr(status));
			goto disconnect;
		}
	}

	pwp.in.user_handle = &u_handle;

	status = dcerpc_samr_GetUserPwInfo(c.pdc.out.dcerpc_pipe, mem_ctx, &pwp);
	if (NT_STATUS_IS_OK(status)) {
		policy_min_pw_len = pwp.out.info.min_password_length;
	}

	r->samr.out.join_password = generate_random_str(mem_ctx, MAX(8, policy_min_pw_len));

	r2.samr_handle.level		= LIBNET_SET_PASSWORD_SAMR_HANDLE;
	r2.samr_handle.in.account_name	= r->samr.in.account_name;
	r2.samr_handle.in.newpassword	= r->samr.out.join_password;
	r2.samr_handle.in.user_handle   = &u_handle;
	r2.samr_handle.in.dcerpc_pipe   = c.pdc.out.dcerpc_pipe;

	status = libnet_SetPassword(ctx, mem_ctx, &r2);

	r->samr.out.error_string = r2.samr_handle.out.error_string;

	if (!NT_STATUS_IS_OK(status)) {
		goto disconnect;
	}

	/* prepare samr_SetUserInfo level 23 */
	ZERO_STRUCT(u_info);
	u_info.info16.acct_flags = r->samr.in.acct_type;

	sui.in.user_handle = &u_handle;
	sui.in.info = &u_info;
	sui.in.level = 16;
	
	dcerpc_samr_SetUserInfo(c.pdc.out.dcerpc_pipe, mem_ctx, &sui);

disconnect:
	/* close connection */
	dcerpc_pipe_close(c.pdc.out.dcerpc_pipe);

	return status;
}

static NTSTATUS libnet_JoinDomain_generic(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_JoinDomain *r)
{
	NTSTATUS status;
	union libnet_JoinDomain r2;

	r2.samr.level		= LIBNET_JOIN_DOMAIN_SAMR;
	r2.samr.in.account_name	= r->generic.in.account_name;
	r2.samr.in.domain_name	= r->generic.in.domain_name;
	r2.samr.in.acct_type	= r->generic.in.acct_type;

	status = libnet_JoinDomain(ctx, mem_ctx, &r2);

	r->generic.out.error_string = r2.samr.out.error_string;

	return status;
}

NTSTATUS libnet_JoinDomain(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_JoinDomain *r)
{
	switch (r->generic.level) {
		case LIBNET_JOIN_DOMAIN_GENERIC:
			return libnet_JoinDomain_generic(ctx, mem_ctx, r);
		case LIBNET_JOIN_DOMAIN_SAMR:
			return libnet_JoinDomain_samr(ctx, mem_ctx, r);
	}

	return NT_STATUS_INVALID_LEVEL;
}
