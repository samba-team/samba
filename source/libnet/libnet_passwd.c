/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Stefan Metzmacher	2004
   
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

/*
 * do a password change using DCERPC/SAMR calls
 * 1. connect to the SAMR pipe of users domain PDC (maybe a standalone server or workstation)
 * 2. try samr_ChangePassword3
 */
static NTSTATUS libnet_ChangePassword_rpc(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_ChangePassword *r)
{
        NTSTATUS status;
	union libnet_rpc_connect c;
#if 0
	struct policy_handle user_handle;
	struct samr_Password hash1, hash2, hash3, hash4, hash5, hash6;
	struct samr_ChangePasswordUser pw;
#endif
	struct samr_OemChangePasswordUser2 oe2;
	struct samr_ChangePasswordUser2 pw2;
	struct samr_ChangePasswordUser3 pw3;
	struct samr_Name server, account;
	struct samr_AsciiName a_server, a_account;
	struct samr_CryptPassword nt_pass, lm_pass;
	struct samr_Password nt_verifier, lm_verifier;
	uint8_t old_nt_hash[16], new_nt_hash[16];
	uint8_t old_lm_hash[16], new_lm_hash[16];

	/* prepare connect to the SAMR pipe of the */
	c.pdc.level			= LIBNET_RPC_CONNECT_PDC;
	c.pdc.in.domain_name		= r->rpc.in.domain_name;
	c.pdc.in.dcerpc_iface_name	= DCERPC_SAMR_NAME;
	c.pdc.in.dcerpc_iface_uuid	= DCERPC_SAMR_UUID;
	c.pdc.in.dcerpc_iface_version	= DCERPC_SAMR_VERSION;

	/* do connect to the SAMR pipe of the */
	status = libnet_rpc_connect(ctx, mem_ctx, &c);
	if (!NT_STATUS_IS_OK(status)) {
		r->rpc.out.error_string = talloc_asprintf(mem_ctx,
						"Connection to SAMR pipe of PDC of domain '%s' failed: %s\n",
						r->rpc.in.domain_name, nt_errstr(status));
		return status;
	}

	/* prepare password change for account */
	server.name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(c.pdc.out.dcerpc_pipe));
	account.name = r->rpc.in.account_name;

	E_md4hash(r->rpc.in.oldpassword, old_nt_hash);
	E_md4hash(r->rpc.in.newpassword, new_nt_hash);

	E_deshash(r->rpc.in.oldpassword, old_lm_hash);
	E_deshash(r->rpc.in.newpassword, new_lm_hash);

	encode_pw_buffer(lm_pass.data, r->rpc.in.newpassword, STR_UNICODE);
	arcfour_crypt(lm_pass.data, old_nt_hash, 516);
	E_old_pw_hash(new_lm_hash, old_lm_hash, lm_verifier.hash);

	encode_pw_buffer(nt_pass.data,  r->rpc.in.newpassword, STR_UNICODE);
	arcfour_crypt(nt_pass.data, old_nt_hash, 516);
	E_old_pw_hash(new_nt_hash, old_nt_hash, nt_verifier.hash);

	pw3.in.server = &server;
	pw3.in.account = &account;
	pw3.in.nt_password = &nt_pass;
	pw3.in.nt_verifier = &nt_verifier;
	pw3.in.lm_change = 1;
	pw3.in.lm_password = &lm_pass;
	pw3.in.lm_verifier = &lm_verifier;
	pw3.in.password3 = NULL;

	/* do password change for account */
	status = dcerpc_samr_ChangePasswordUser3(c.pdc.out.dcerpc_pipe, mem_ctx, &pw3);
	if (!NT_STATUS_IS_OK(status)) {
		r->rpc.out.error_string = talloc_asprintf(mem_ctx,
						"samr_ChangePasswordUser3 failed: %s\n",
						nt_errstr(status));
		goto ChangePasswordUser2;
	}

	/* check result of password change */
	if (!NT_STATUS_IS_OK(pw3.out.result)) {
		r->rpc.out.error_string = talloc_asprintf(mem_ctx,
						"samr_ChangePasswordUser3 for '%s\\%s' failed: %s\n",
						r->rpc.in.domain_name, r->rpc.in.account_name, 
						nt_errstr(pw3.out.result));
						/* TODO: give the reason of the reject */
		if (NT_STATUS_EQUAL(status, NT_STATUS_PASSWORD_RESTRICTION)) {
			goto disconnect;
		}
		goto ChangePasswordUser2;
	}

	goto disconnect;

ChangePasswordUser2:

	encode_pw_buffer(lm_pass.data, r->rpc.in.newpassword, STR_ASCII|STR_TERMINATE);
	arcfour_crypt(lm_pass.data, old_lm_hash, 516);
	E_old_pw_hash(new_lm_hash, old_lm_hash, lm_verifier.hash);

	encode_pw_buffer(nt_pass.data, r->rpc.in.newpassword, STR_UNICODE);
	arcfour_crypt(nt_pass.data, old_nt_hash, 516);
	E_old_pw_hash(new_nt_hash, old_nt_hash, nt_verifier.hash);

	pw2.in.server = &server;
	pw2.in.account = &account;
	pw2.in.nt_password = &nt_pass;
	pw2.in.nt_verifier = &nt_verifier;
	pw2.in.lm_change = 1;
	pw2.in.lm_password = &lm_pass;
	pw2.in.lm_verifier = &lm_verifier;

	status = dcerpc_samr_ChangePasswordUser2(c.pdc.out.dcerpc_pipe, mem_ctx, &pw2);
	if (!NT_STATUS_IS_OK(status)) {
		r->rpc.out.error_string = talloc_asprintf(mem_ctx,
						"samr_ChangePasswordUser2 failed: %s\n",
						nt_errstr(status));
		goto OemChangePasswordUser2;
	}

	/* check result of password change */
	if (!NT_STATUS_IS_OK(pw2.out.result)) {
		r->rpc.out.error_string = talloc_asprintf(mem_ctx,
						"samr_ChangePasswordUser2 for '%s\\%s' failed: %s\n",
						r->rpc.in.domain_name, r->rpc.in.account_name, 
						nt_errstr(pw2.out.result));
		goto OemChangePasswordUser2;
	}

	goto disconnect;

OemChangePasswordUser2:

	a_server.name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(c.pdc.out.dcerpc_pipe));
	a_account.name = r->rpc.in.account_name;

	encode_pw_buffer(lm_pass.data, r->rpc.in.newpassword, STR_ASCII);
	arcfour_crypt(lm_pass.data, old_lm_hash, 516);
	E_old_pw_hash(new_lm_hash, old_lm_hash, lm_verifier.hash);

	oe2.in.server = &a_server;
	oe2.in.account = &a_account;
	oe2.in.password = &lm_pass;
	oe2.in.hash = &lm_verifier;

	status = dcerpc_samr_OemChangePasswordUser2(c.pdc.out.dcerpc_pipe, mem_ctx, &oe2);
	if (!NT_STATUS_IS_OK(status)) {
		r->rpc.out.error_string = talloc_asprintf(mem_ctx,
						"samr_OemChangePasswordUser2 failed: %s\n",
						nt_errstr(status));
		goto ChangePasswordUser;
	}

	/* check result of password change */
	if (!NT_STATUS_IS_OK(oe2.out.result)) {
		r->rpc.out.error_string = talloc_asprintf(mem_ctx,
						"samr_OemChangePasswordUser2 for '%s\\%s' failed: %s\n",
						r->rpc.in.domain_name, r->rpc.in.account_name, 
						nt_errstr(oe2.out.result));
		goto ChangePasswordUser;
	}

	goto disconnect;

ChangePasswordUser:
#if 0
	E_old_pw_hash(new_lm_hash, old_lm_hash, hash1.hash);
	E_old_pw_hash(old_lm_hash, new_lm_hash, hash2.hash);
	E_old_pw_hash(new_nt_hash, old_nt_hash, hash3.hash);
	E_old_pw_hash(old_nt_hash, new_nt_hash, hash4.hash);
	E_old_pw_hash(old_lm_hash, new_nt_hash, hash5.hash);
	E_old_pw_hash(old_nt_hash, new_lm_hash, hash6.hash);

	/* TODO: ask for a user_handle */
	pw.in.handle = &user_handle;
	pw.in.lm_present = 1;
	pw.in.old_lm_crypted = &hash1;
	pw.in.new_lm_crypted = &hash2;
	pw.in.nt_present = 1;
	pw.in.old_nt_crypted = &hash3;
	pw.in.new_nt_crypted = &hash4;
	pw.in.cross1_present = 1;
	pw.in.nt_cross = &hash5;
	pw.in.cross2_present = 1;
	pw.in.lm_cross = &hash6;

	status = dcerpc_samr_ChangePasswordUser(c.pdc.out.dcerpc_pipe, mem_ctx, &pw);
	if (!NT_STATUS_IS_OK(status)) {
		r->rpc.out.error_string = talloc_asprintf(mem_ctx,
						"samr_ChangePasswordUser failed: %s\n",
						nt_errstr(status));
		goto disconnect;
	}

	/* check result of password change */
	if (!NT_STATUS_IS_OK(pw.out.result)) {
		r->rpc.out.error_string = talloc_asprintf(mem_ctx,
						"samr_ChangePasswordUser for '%s\\%s' failed: %s\n",
						r->rpc.in.domain_name, r->rpc.in.account_name, 
						nt_errstr(pw.out.result));
		goto disconnect;
	}
#endif
disconnect:
	/* close connection */
	dcerpc_pipe_close(c.pdc.out.dcerpc_pipe);

	return status;
}

static NTSTATUS libnet_ChangePassword_generic(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_ChangePassword *r)
{
	NTSTATUS status;
	union libnet_ChangePassword r2;

	r2.rpc.level		= LIBNET_CHANGE_PASSWORD_RPC;
	r2.rpc.in.account_name	= r->generic.in.account_name;
	r2.rpc.in.domain_name	= r->generic.in.domain_name;
	r2.rpc.in.oldpassword	= r->generic.in.oldpassword;
	r2.rpc.in.newpassword	= r->generic.in.newpassword;

	status = libnet_ChangePassword(ctx, mem_ctx, &r2);

	r->generic.out.error_string = r2.rpc.out.error_string;

	return status;
}

NTSTATUS libnet_ChangePassword(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_ChangePassword *r)
{
	switch (r->generic.level) {
		case LIBNET_CHANGE_PASSWORD_GENERIC:
			return libnet_ChangePassword_generic(ctx, mem_ctx, r);
		case LIBNET_CHANGE_PASSWORD_RPC:
			return libnet_ChangePassword_rpc(ctx, mem_ctx, r);
		case LIBNET_CHANGE_PASSWORD_KRB5:
			return NT_STATUS_NOT_IMPLEMENTED;
		case LIBNET_CHANGE_PASSWORD_LDAP:
			return NT_STATUS_NOT_IMPLEMENTED;
		case LIBNET_CHANGE_PASSWORD_RAP:
			return NT_STATUS_NOT_IMPLEMENTED;
	}

	return NT_STATUS_INVALID_LEVEL;
}

/*
 * set a password with DCERPC/SAMR calls
 */
static NTSTATUS libnet_SetPassword_rpc(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_SetPassword *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS libnet_SetPassword_generic(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_SetPassword *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS libnet_SetPassword(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_SetPassword *r)
{
	switch (r->generic.level) {
		case LIBNET_SET_PASSWORD_GENERIC:
			return libnet_SetPassword_generic(ctx, mem_ctx, r);
		case LIBNET_SET_PASSWORD_RPC:
			return libnet_SetPassword_rpc(ctx, mem_ctx, r);
		case LIBNET_SET_PASSWORD_KRB5:
			return NT_STATUS_NOT_IMPLEMENTED;
		case LIBNET_SET_PASSWORD_LDAP:
			return NT_STATUS_NOT_IMPLEMENTED;
		case LIBNET_SET_PASSWORD_RAP:
			return NT_STATUS_NOT_IMPLEMENTED;
	}

	return NT_STATUS_INVALID_LEVEL;
}
