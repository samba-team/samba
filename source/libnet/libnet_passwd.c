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

/*
 * 1. connect to the SAMR pipe of *our* PDC
 * 2. try samr_ChangePassword3
 */
static NTSTATUS libnet_ChangePassword_rpc(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct net_ChangePassword *r)
{
        NTSTATUS status;
        struct dcerpc_pipe *p = NULL;
	struct samr_ChangePasswordUser3 pw3;
	struct samr_Name server, account;
	struct samr_CryptPassword nt_pass, lm_pass;
	struct samr_Password nt_verifier, lm_verifier;
	uint8_t old_nt_hash[16], new_nt_hash[16];
	uint8_t old_lm_hash[16], new_lm_hash[16];

	/* connect to the SAMR pipe of the */
	status = libnet_rpc_connect_pdc(ctx, mem_ctx,
					r->rpc.in.domain_name,
					DCERPC_SAMR_NAME,
					DCERPC_SAMR_UUID,
					DCERPC_SAMR_VERSION,
					&p);
	if (!NT_STATUS_IS_OK(status)) {
		r->rpc.out.error_string = talloc_asprintf(mem_ctx,
						"Connection to SAMR pipe of PDC of domain '%s' failed\n",
						r->rpc.in.domain_name);
		return status;
	}

	server.name = talloc_asprintf(mem_ctx, "\\\\%s", dcerpc_server_name(p));
	init_samr_Name(&account, r->rpc.in.account_name);

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

	status = dcerpc_samr_ChangePassword3(p, mem_ctx, &pw3);
	if (!NT_STATUS_IS_OK(status)) {
		r->rpc.out.error_string = talloc_asprintf(mem_ctx,
						"ChangePassword3 failed: %s\n",nt_errstr(status);
		return status;
	}

	if (!NT_STATUS_IS_OK(r->rpc.out.result)) {
		r->rpc.out.error_string = talloc_asprintf(mem_ctx,
						"ChangePassword3 for '%s\\%s' failed: %s\n",
						r->rpc.in.domain_name, r->rpc.in.account_name, 
						nt_errstr(status));
						/* TODO: give the reason of the reject */
		return status;
	
	}

	dcerpc_diconnect(&p);

	return NT_STATUS_OK;
}

static NTSTATUS libnet_ChangePassword_generic(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct net_ChangePassword *r)
{
	return NT_STATUS_NOT_IMPLEMTED;
}

NTSTATUS libnet_ChangePassword(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct net_ChangePassword *r)
{
	switch (r->generic.level) {
		case LIBNET_CHANGE_PASSWORD_GENERIC:
			return libnet_ChangePassword_generic(ctx, mem_ctx, r);
		case LIBNET_CHANGE_PASSWORD_RPC:
			return libnet_ChangePassword_rpc(ctx, mem_ctx, r);
		case LIBNET_CHANGE_PASSWORD_ADS:
			return NT_STATUS_NOT_IMPLEMTED;
		case LIBNET_CHANGE_PASSWORD_RAP:
			return NT_STATUS_NOT_IMPLEMTED;
	}

	return NT_STATUS_INVALID_LEVEL;
}
