/* 
   Unix SMB/CIFS implementation.
   RPC pipe client
   Copyright (C) Tim Potter                        2000-2001,
   Copyright (C) Andrew Tridgell              1992-1997,2000,
   Copyright (C) Rafal Szczesniak                       2002.
   Copyright (C) Jeremy Allison                         2005.
   
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

/* Enumerate domain groups */

NTSTATUS rpccli_samr_enum_als_groups(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx, 
				     POLICY_HND *pol, uint32 *start_idx, 
				     uint32 size, struct acct_info **dom_aliases,
				     uint32 *num_dom_aliases)
{
	prs_struct qbuf, rbuf;
	SAMR_Q_ENUM_DOM_ALIASES q;
	SAMR_R_ENUM_DOM_ALIASES r;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 name_idx, i;

	DEBUG(10,("cli_samr_enum_als_groups starting at index %u\n", (unsigned int)*start_idx));

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Marshall data and send request */

	init_samr_q_enum_dom_aliases(&q, pol, *start_idx, size);

	CLI_DO_RPC(cli, mem_ctx, PI_SAMR, SAMR_ENUM_DOM_ALIASES,
		q, r,
		qbuf, rbuf,
		samr_io_q_enum_dom_aliases,
		samr_io_r_enum_dom_aliases,
		NT_STATUS_UNSUCCESSFUL); 

	/* Return output parameters */

	result = r.status;

	if (!NT_STATUS_IS_OK(result) &&
	    NT_STATUS_V(result) != NT_STATUS_V(STATUS_MORE_ENTRIES)) {
		goto done;
	}

	*num_dom_aliases = r.num_entries2;

	if (*num_dom_aliases == 0)
		goto done;

	if (!((*dom_aliases) = TALLOC_ARRAY(mem_ctx, struct acct_info, *num_dom_aliases))) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	memset(*dom_aliases, 0, sizeof(struct acct_info) * *num_dom_aliases);

	name_idx = 0;

	for (i = 0; i < *num_dom_aliases; i++) {

		(*dom_aliases)[i].rid = r.sam[i].rid;

		if (r.sam[i].hdr_name.buffer) {
			unistr2_to_ascii((*dom_aliases)[i].acct_name,
					 &r.uni_grp_name[name_idx],
					 sizeof((*dom_aliases)[i].acct_name));
			name_idx++;
		}

		*start_idx = r.next_idx;
	}

 done:
	return result;
}

/* User change password */

NTSTATUS rpccli_samr_chgpasswd_user(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx,
				    const char *username,
				    const char *newpassword,
				    const char *oldpassword)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	struct samr_CryptPassword new_nt_password;
	struct samr_CryptPassword new_lm_password;
	struct samr_Password old_nt_hash_enc;
	struct samr_Password old_lanman_hash_enc;

	uchar old_nt_hash[16];
	uchar old_lanman_hash[16];
	uchar new_nt_hash[16];
	uchar new_lanman_hash[16];
	struct lsa_String server, account;
	char *srv_name_slash = NULL;

	DEBUG(10,("rpccli_samr_chgpasswd_user\n"));

	init_lsa_String(&server, srv_name_slash);
	init_lsa_String(&account, username);

	srv_name_slash = talloc_asprintf(mem_ctx, "\\\\%s", cli->cli->desthost);
	if (!srv_name_slash) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Calculate the MD4 hash (NT compatible) of the password */
	E_md4hash(oldpassword, old_nt_hash);
	E_md4hash(newpassword, new_nt_hash);

	if (lp_client_lanman_auth() &&
	    E_deshash(newpassword, new_lanman_hash) &&
	    E_deshash(oldpassword, old_lanman_hash)) {
		/* E_deshash returns false for 'long' passwords (> 14
		   DOS chars).  This allows us to match Win2k, which
		   does not store a LM hash for these passwords (which
		   would reduce the effective password length to 14) */

		encode_pw_buffer(new_lm_password.data, newpassword, STR_UNICODE);

		SamOEMhash(new_lm_password.data, old_nt_hash, 516);
		E_old_pw_hash(new_nt_hash, old_lanman_hash, old_lanman_hash_enc.hash);
	} else {
		ZERO_STRUCT(new_lm_password);
		ZERO_STRUCT(old_lanman_hash_enc);
	}

	encode_pw_buffer(new_nt_password.data, newpassword, STR_UNICODE);

	SamOEMhash(new_nt_password.data, old_nt_hash, 516);
	E_old_pw_hash(new_nt_hash, old_nt_hash, old_nt_hash_enc.hash);

	result = rpccli_samr_ChangePasswordUser2(cli, mem_ctx,
						 &server,
						 &account,
						 &new_nt_password,
						 &old_nt_hash_enc,
						 true,
						 &new_lm_password,
						 &old_lanman_hash_enc);

	return result;
}

/* User change password given blobs */

NTSTATUS rpccli_samr_chng_pswd_auth_crap(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx,
					 const char *username,
					 DATA_BLOB new_nt_password_blob,
					 DATA_BLOB old_nt_hash_enc_blob,
					 DATA_BLOB new_lm_password_blob,
					 DATA_BLOB old_lm_hash_enc_blob)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	struct samr_CryptPassword new_nt_password;
	struct samr_CryptPassword new_lm_password;
	struct samr_Password old_nt_hash_enc;
	struct samr_Password old_lm_hash_enc;
	struct lsa_String server, account;
	char *srv_name_slash = NULL;

	DEBUG(10,("rpccli_samr_chng_pswd_auth_crap\n"));

	srv_name_slash = talloc_asprintf(mem_ctx, "\\\\%s", cli->cli->desthost);
	if (!srv_name_slash) {
		return NT_STATUS_NO_MEMORY;
	}

	init_lsa_String(&server, srv_name_slash);
	init_lsa_String(&account, username);

	memcpy(&new_nt_password.data, new_nt_password_blob.data, 516);
	memcpy(&new_lm_password.data, new_lm_password_blob.data, 516);
	memcpy(&old_nt_hash_enc.hash, old_nt_hash_enc_blob.data, 16);
	memcpy(&old_lm_hash_enc.hash, old_lm_hash_enc_blob.data, 16);

	result = rpccli_samr_ChangePasswordUser2(cli, mem_ctx,
						 &server,
						 &account,
						 &new_nt_password,
						 &old_nt_hash_enc,
						 true,
						 &new_lm_password,
						 &old_lm_hash_enc);
	return result;
}


/* change password 3 */

NTSTATUS rpccli_samr_chgpasswd3(struct rpc_pipe_client *cli,
				TALLOC_CTX *mem_ctx,
				const char *username,
				const char *newpassword,
				const char *oldpassword,
				struct samr_DomInfo1 **dominfo1,
				struct samr_ChangeReject **reject)
{
	NTSTATUS status;

	struct samr_CryptPassword new_nt_password;
	struct samr_CryptPassword new_lm_password;
	struct samr_Password old_nt_hash_enc;
	struct samr_Password old_lanman_hash_enc;

	uchar old_nt_hash[16];
	uchar old_lanman_hash[16];
	uchar new_nt_hash[16];
	uchar new_lanman_hash[16];

	struct lsa_String server, account;
	char *srv_name_slash = NULL;

	DEBUG(10,("rpccli_samr_chgpasswd_user3\n"));

	srv_name_slash = talloc_asprintf(mem_ctx, "\\\\%s", cli->cli->desthost);
	if (!srv_name_slash) {
		return NT_STATUS_NO_MEMORY;
	}

	init_lsa_String(&server, srv_name_slash);
	init_lsa_String(&account, username);

	/* Calculate the MD4 hash (NT compatible) of the password */
	E_md4hash(oldpassword, old_nt_hash);
	E_md4hash(newpassword, new_nt_hash);

	if (lp_client_lanman_auth() &&
	    E_deshash(newpassword, new_lanman_hash) &&
	    E_deshash(oldpassword, old_lanman_hash)) {
		/* E_deshash returns false for 'long' passwords (> 14
		   DOS chars).  This allows us to match Win2k, which
		   does not store a LM hash for these passwords (which
		   would reduce the effective password length to 14) */

		encode_pw_buffer(new_lm_password.data, newpassword, STR_UNICODE);

		SamOEMhash(new_lm_password.data, old_nt_hash, 516);
		E_old_pw_hash(new_nt_hash, old_lanman_hash, old_lanman_hash_enc.hash);
	} else {
		ZERO_STRUCT(new_lm_password);
		ZERO_STRUCT(old_lanman_hash_enc);
	}

	encode_pw_buffer(new_nt_password.data, newpassword, STR_UNICODE);

	SamOEMhash(new_nt_password.data, old_nt_hash, 516);
	E_old_pw_hash(new_nt_hash, old_nt_hash, old_nt_hash_enc.hash);

	status = rpccli_samr_ChangePasswordUser3(cli, mem_ctx,
						 &server,
						 &account,
						 &new_nt_password,
						 &old_nt_hash_enc,
						 true,
						 &new_lm_password,
						 &old_lanman_hash_enc,
						 NULL,
						 dominfo1,
						 reject);
	return status;
}

/* This function returns the bizzare set of (max_entries, max_size) required
   for the QueryDisplayInfo RPC to actually work against a domain controller
   with large (10k and higher) numbers of users.  These values were 
   obtained by inspection using ethereal and NT4 running User Manager. */

void get_query_dispinfo_params(int loop_count, uint32 *max_entries,
			       uint32 *max_size)
{
	switch(loop_count) {
	case 0:
		*max_entries = 512;
		*max_size = 16383;
		break;
	case 1:
		*max_entries = 1024;
		*max_size = 32766;
		break;
	case 2:
		*max_entries = 2048;
		*max_size = 65532;
		break;
	case 3:
		*max_entries = 4096;
		*max_size = 131064;
		break;
	default:              /* loop_count >= 4 */
		*max_entries = 4096;
		*max_size = 131071;
		break;
	}
}
