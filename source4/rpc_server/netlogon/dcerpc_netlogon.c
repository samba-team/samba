/* 
   Unix SMB/CIFS implementation.

   endpoint server for the netlogon pipe

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004
   Copyright (C) Stefan Metzmacher <metze@samba.org>  2005
   
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
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "lib/ldb/include/ldb.h"
#include "auth/auth.h"
#include "auth/auth_sam.h"
#include "dsdb/samdb/samdb.h"
#include "rpc_server/samr/proto.h"
#include "db_wrap.h"
#include "libcli/auth/libcli_auth.h"
#include "auth/gensec/schannel_state.h"
#include "libcli/security/security.h"

struct server_pipe_state {
	struct netr_Credential client_challenge;
	struct netr_Credential server_challenge;
};


static NTSTATUS netr_ServerReqChallenge(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct netr_ServerReqChallenge *r)
{
	struct server_pipe_state *pipe_state = dce_call->context->private;

	ZERO_STRUCTP(r->out.credentials);

	/* destroyed on pipe shutdown */

	if (pipe_state) {
		talloc_free(pipe_state);
		dce_call->context->private = NULL;
	}
	
	pipe_state = talloc(dce_call->context, struct server_pipe_state);
	NT_STATUS_HAVE_NO_MEMORY(pipe_state);

	pipe_state->client_challenge = *r->in.credentials;

	generate_random_buffer(pipe_state->server_challenge.data, 
			       sizeof(pipe_state->server_challenge.data));

	*r->out.credentials = pipe_state->server_challenge;

	dce_call->context->private = pipe_state;

	return NT_STATUS_OK;
}

static NTSTATUS netr_ServerAuthenticate3(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					 struct netr_ServerAuthenticate3 *r)
{
	struct server_pipe_state *pipe_state = dce_call->context->private;
	struct creds_CredentialState *creds;
	void *sam_ctx;
	struct samr_Password *mach_pwd;
	uint16_t acct_flags;
	int num_records;
	struct ldb_message **msgs;
	NTSTATUS nt_status;
	const char *attrs[] = {"ntPwdHash", "userAccountControl", 
			       "objectSid", NULL};

	ZERO_STRUCTP(r->out.credentials);
	*r->out.rid = 0;
	*r->out.negotiate_flags = *r->in.negotiate_flags;

	if (!pipe_state) {
		DEBUG(1, ("No challenge requested by client, cannot authenticate\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	sam_ctx = samdb_connect(mem_ctx, system_session(mem_ctx));
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}
	/* pull the user attributes */
	num_records = gendb_search(sam_ctx, mem_ctx, NULL, &msgs, attrs,
				   "(&(sAMAccountName=%s)(objectclass=user))", 
				   r->in.account_name);

	if (num_records == 0) {
		DEBUG(3,("Couldn't find user [%s] in samdb.\n", 
			 r->in.account_name));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (num_records > 1) {
		DEBUG(0,("Found %d records matching user [%s]\n", num_records, r->in.account_name));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	acct_flags = samdb_result_acct_flags(msgs[0], 
					     "userAccountControl");

	if (acct_flags & ACB_DISABLED) {
		DEBUG(1, ("Account [%s] is disabled\n", r->in.account_name));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (r->in.secure_channel_type == SEC_CHAN_WKSTA) {
		if (!(acct_flags & ACB_WSTRUST)) {
			DEBUG(1, ("Client asked for a workstation secure channel, but is not a workstation (member server) acb flags: 0x%x\n", acct_flags));
			return NT_STATUS_ACCESS_DENIED;
		}
	} else if (r->in.secure_channel_type == SEC_CHAN_DOMAIN) {
		if (!(acct_flags & ACB_DOMTRUST)) {
			DEBUG(1, ("Client asked for a trusted domain secure channel, but is not a trusted domain: acb flags: 0x%x\n", acct_flags));
			return NT_STATUS_ACCESS_DENIED;
		}
	} else if (r->in.secure_channel_type == SEC_CHAN_BDC) {
		if (!(acct_flags & ACB_SVRTRUST)) {
			DEBUG(1, ("Client asked for a server secure channel, but is not a server (domain controller): acb flags: 0x%x\n", acct_flags));
			return NT_STATUS_ACCESS_DENIED;
		}
	} else {
		DEBUG(1, ("Client asked for an invalid secure channel type: %d\n", 
			  r->in.secure_channel_type));
		return NT_STATUS_ACCESS_DENIED;
	}

	*r->out.rid = samdb_result_rid_from_sid(mem_ctx, msgs[0], 
						"objectSid", 0);

	mach_pwd = samdb_result_hash(mem_ctx, msgs[0], "ntPwdHash");
	if (mach_pwd == NULL) {
		return NT_STATUS_ACCESS_DENIED;
	}

	creds = talloc(mem_ctx, struct creds_CredentialState);
	NT_STATUS_HAVE_NO_MEMORY(creds);

	creds_server_init(creds, &pipe_state->client_challenge, 
			  &pipe_state->server_challenge, mach_pwd,
			  r->out.credentials,
			  *r->in.negotiate_flags);
	
	if (!creds_server_check(creds, r->in.credentials)) {
		talloc_free(creds);
		return NT_STATUS_ACCESS_DENIED;
	}

	creds->account_name = talloc_steal(creds, r->in.account_name);
	
	creds->computer_name = talloc_steal(creds, r->in.computer_name);
	creds->domain = talloc_strdup(creds, lp_workgroup());

	creds->secure_channel_type = r->in.secure_channel_type;

	creds->sid = samdb_result_dom_sid(creds, msgs[0], "objectSid");


	/* remember this session key state */
	nt_status = schannel_store_session_key(mem_ctx, creds);

	return nt_status;
}
						 
static NTSTATUS netr_ServerAuthenticate(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct netr_ServerAuthenticate *r)
{
	struct netr_ServerAuthenticate3 r3;
	uint32_t rid = 0;
	/* TODO: 
	 * negotiate_flags is used as an [in] parameter
	 * so it need to be initialised.
	 *
	 * (I think ... = 0; seems wrong here --metze)
	 */
	uint32_t negotiate_flags = 0;  

	r3.in.server_name = r->in.server_name;
	r3.in.account_name = r->in.account_name;
	r3.in.secure_channel_type = r->in.secure_channel_type;
	r3.in.computer_name = r->in.computer_name;
	r3.in.credentials = r->in.credentials;
	r3.out.credentials = r->out.credentials;
	r3.in.negotiate_flags = &negotiate_flags;
	r3.out.negotiate_flags = &negotiate_flags;
	r3.out.rid = &rid;
	
	return netr_ServerAuthenticate3(dce_call, mem_ctx, &r3);
}

static NTSTATUS netr_ServerAuthenticate2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					 struct netr_ServerAuthenticate2 *r)
{
	struct netr_ServerAuthenticate3 r3;
	uint32_t rid = 0;

	r3.in.server_name = r->in.server_name;
	r3.in.account_name = r->in.account_name;
	r3.in.secure_channel_type = r->in.secure_channel_type;
	r3.in.computer_name = r->in.computer_name;
	r3.in.credentials = r->in.credentials;
	r3.out.credentials = r->out.credentials;
	r3.in.negotiate_flags = r->in.negotiate_flags;
	r3.out.negotiate_flags = r->out.negotiate_flags;
	r3.out.rid = &rid;
	
	return netr_ServerAuthenticate3(dce_call, mem_ctx, &r3);
}

/*
  Validate an incoming authenticator against the credentials for the remote machine.

  The credentials are (re)read and from the schannel database, and
  written back after the caclulations are performed.

  The creds_out parameter (if not NULL) returns the credentials, if
  the caller needs some of that information.

*/
static NTSTATUS netr_creds_server_step_check(const char *computer_name,
					     TALLOC_CTX *mem_ctx, 
					     struct netr_Authenticator *received_authenticator,
					     struct netr_Authenticator *return_authenticator,
					     struct creds_CredentialState **creds_out) 
{
	struct creds_CredentialState *creds;
	NTSTATUS nt_status;
	struct ldb_context *ldb;
	int ret;

	ldb = schannel_db_connect(mem_ctx);
	if (!ldb) {
		return NT_STATUS_ACCESS_DENIED;
	}

	ret = ldb_transaction_start(ldb);
	if (ret != 0) {
		talloc_free(ldb);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* Because this is a shared structure (even across
	 * disconnects) we must update the database every time we
	 * update the structure */ 
	
	nt_status = schannel_fetch_session_key_ldb(ldb, ldb, computer_name, lp_workgroup(),
						   &creds);
	if (NT_STATUS_IS_OK(nt_status)) {
		nt_status = creds_server_step_check(creds, 
						    received_authenticator, 
						    return_authenticator);
	}
	if (NT_STATUS_IS_OK(nt_status)) {
		nt_status = schannel_store_session_key_ldb(ldb, ldb, creds);
	}

	if (NT_STATUS_IS_OK(nt_status)) {
		ldb_transaction_commit(ldb);
		if (creds_out) {
			*creds_out = creds;
			talloc_steal(mem_ctx, creds);
		}
	} else {
		ldb_transaction_cancel(ldb);
	}
	talloc_free(ldb);
	return nt_status;
}

/* 
  Change the machine account password for the currently connected
  client.  Supplies only the NT#.
*/

static NTSTATUS netr_ServerPasswordSet(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				       struct netr_ServerPasswordSet *r)
{
	struct creds_CredentialState *creds;
	struct ldb_context *sam_ctx;
	NTSTATUS nt_status;

	nt_status = netr_creds_server_step_check(r->in.computer_name, mem_ctx, 
						 &r->in.credential, &r->out.return_authenticator,
						 &creds);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	sam_ctx = samdb_connect(mem_ctx, system_session(mem_ctx));
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	creds_des_decrypt(creds, &r->in.new_password);

	/* Using the sid for the account as the key, set the password */
	nt_status = samdb_set_password_sid(sam_ctx, mem_ctx, 
					   creds->sid,
					   NULL, /* Don't have plaintext */
					   NULL, &r->in.new_password,
					   False, /* This is not considered a password change */
					   False, /* don't restrict this password change (match w2k3) */
					   NULL, NULL);
	return nt_status;
}

/* 
  Change the machine account password for the currently connected
  client.  Supplies new plaintext.
*/
static NTSTATUS netr_ServerPasswordSet2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				       struct netr_ServerPasswordSet2 *r)
{
	struct creds_CredentialState *creds;
	struct ldb_context *sam_ctx;
	NTSTATUS nt_status;
	char new_pass[512];
	uint32_t new_pass_len;
	BOOL ret;

	struct samr_CryptPassword password_buf;

	nt_status = netr_creds_server_step_check(r->in.computer_name, mem_ctx, 
						 &r->in.credential, &r->out.return_authenticator,
						 &creds);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	sam_ctx = samdb_connect(mem_ctx, system_session(mem_ctx));
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	memcpy(password_buf.data, r->in.new_password.data, 512);
	SIVAL(password_buf.data,512,r->in.new_password.length);
	creds_arcfour_crypt(creds, password_buf.data, 516);

	ret = decode_pw_buffer(password_buf.data, new_pass, sizeof(new_pass),
			       &new_pass_len, STR_UNICODE);
	if (!ret) {
		DEBUG(3,("netr_ServerPasswordSet2: failed to decode password buffer\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	/* Using the sid for the account as the key, set the password */
	nt_status = samdb_set_password_sid(sam_ctx, mem_ctx,
					   creds->sid,
					   new_pass, /* we have plaintext */
					   NULL, NULL,
					   False, /* This is not considered a password change */
					   False, /* don't restrict this password change (match w2k3) */
					   NULL, NULL);
	return nt_status;
}


/* 
  netr_LogonUasLogon 
*/
static WERROR netr_LogonUasLogon(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct netr_LogonUasLogon *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_LogonUasLogoff 
*/
static WERROR netr_LogonUasLogoff(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_LogonUasLogoff *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_LogonSamLogon_base

  This version of the function allows other wrappers to say 'do not check the credentials'

  We can't do the traditional 'wrapping' format completly, as this function must only run under schannel
*/
static NTSTATUS netr_LogonSamLogon_base(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct netr_LogonSamLogonEx *r, struct creds_CredentialState *creds)
{
	struct auth_context *auth_context;
	struct auth_usersupplied_info *user_info;
	struct auth_serversupplied_info *server_info;
	NTSTATUS nt_status;
	static const char zeros[16];
	struct netr_SamBaseInfo *sam;
	struct netr_SamInfo2 *sam2;
	struct netr_SamInfo3 *sam3;
	struct netr_SamInfo6 *sam6;
	
	user_info = talloc(mem_ctx, struct auth_usersupplied_info);
	NT_STATUS_HAVE_NO_MEMORY(user_info);

	user_info->flags = 0;
	user_info->mapped_state = False;
	user_info->remote_host = NULL;

	switch (r->in.logon_level) {
	case 1:
	case 3:
	case 5:
		if (creds->negotiate_flags & NETLOGON_NEG_ARCFOUR) {
			creds_arcfour_crypt(creds, 
					    r->in.logon.password->lmpassword.hash, 
					    sizeof(r->in.logon.password->lmpassword.hash));
			creds_arcfour_crypt(creds, 
					    r->in.logon.password->ntpassword.hash, 
					    sizeof(r->in.logon.password->ntpassword.hash));
		} else {
			creds_des_decrypt(creds, &r->in.logon.password->lmpassword);
			creds_des_decrypt(creds, &r->in.logon.password->ntpassword);
		}

		/* TODO: we need to deny anonymous access here */
		nt_status = auth_context_create(mem_ctx, lp_auth_methods(),
						dce_call->event_ctx, dce_call->msg_ctx,
						&auth_context);
		NT_STATUS_NOT_OK_RETURN(nt_status);

		user_info->logon_parameters = r->in.logon.password->identity_info.parameter_control;
		user_info->client.account_name = r->in.logon.password->identity_info.account_name.string;
		user_info->client.domain_name = r->in.logon.password->identity_info.domain_name.string;
		user_info->workstation_name = r->in.logon.password->identity_info.workstation.string;
		
		user_info->flags |= USER_INFO_INTERACTIVE_LOGON;
		user_info->password_state = AUTH_PASSWORD_HASH;

		user_info->password.hash.lanman = talloc(user_info, struct samr_Password);
		NT_STATUS_HAVE_NO_MEMORY(user_info->password.hash.lanman);
		*user_info->password.hash.lanman = r->in.logon.password->lmpassword;

		user_info->password.hash.nt = talloc(user_info, struct samr_Password);
		NT_STATUS_HAVE_NO_MEMORY(user_info->password.hash.nt);
		*user_info->password.hash.nt = r->in.logon.password->ntpassword;

		break;
	case 2:
	case 6:

		/* TODO: we need to deny anonymous access here */
		nt_status = auth_context_create(mem_ctx, lp_auth_methods(),
						dce_call->event_ctx, dce_call->msg_ctx,
						&auth_context);
		NT_STATUS_NOT_OK_RETURN(nt_status);

		nt_status = auth_context_set_challenge(auth_context, r->in.logon.network->challenge, "netr_LogonSamLogonWithFlags");
		NT_STATUS_NOT_OK_RETURN(nt_status);

		user_info->logon_parameters = r->in.logon.network->identity_info.parameter_control;
		user_info->client.account_name = r->in.logon.network->identity_info.account_name.string;
		user_info->client.domain_name = r->in.logon.network->identity_info.domain_name.string;
		user_info->workstation_name = r->in.logon.network->identity_info.workstation.string;
		
		user_info->password_state = AUTH_PASSWORD_RESPONSE;
		user_info->password.response.lanman = data_blob_talloc(mem_ctx, r->in.logon.network->lm.data, r->in.logon.network->lm.length);
		user_info->password.response.nt = data_blob_talloc(mem_ctx, r->in.logon.network->nt.data, r->in.logon.network->nt.length);
	
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	nt_status = auth_check_password(auth_context, mem_ctx, user_info, &server_info);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	nt_status = auth_convert_server_info_sambaseinfo(mem_ctx, server_info, &sam);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	/* Don't crypt an all-zero key, it would give away the NETLOGON pipe session key */
	/* It appears that level 6 is not individually encrypted */
	if ((r->in.validation_level != 6) &&
	    memcmp(sam->key.key, zeros, sizeof(sam->key.key)) != 0) {
		/* This key is sent unencrypted without the ARCFOUR flag set */
		if (creds->negotiate_flags & NETLOGON_NEG_ARCFOUR) {
			creds_arcfour_crypt(creds, 
					    sam->key.key, 
					    sizeof(sam->key.key));
		}
	}

	/* Don't crypt an all-zero key, it would give away the NETLOGON pipe session key */
	/* It appears that level 6 is not individually encrypted */
	if ((r->in.validation_level != 6) &&
	    memcmp(sam->LMSessKey.key, zeros, sizeof(sam->LMSessKey.key)) != 0) {
		if (creds->negotiate_flags & NETLOGON_NEG_ARCFOUR) {
			creds_arcfour_crypt(creds, 
					    sam->LMSessKey.key, 
					    sizeof(sam->LMSessKey.key));
		} else {
			creds_des_encrypt_LMKey(creds, 
						&sam->LMSessKey);
		}
	}

	switch (r->in.validation_level) {
	case 2:
		sam2 = talloc_zero(mem_ctx, struct netr_SamInfo2);
		NT_STATUS_HAVE_NO_MEMORY(sam2);
		sam2->base = *sam;
		r->out.validation.sam2 = sam2;
		break;

	case 3:
		sam3 = talloc_zero(mem_ctx, struct netr_SamInfo3);
		NT_STATUS_HAVE_NO_MEMORY(sam3);
		sam3->base = *sam;
		r->out.validation.sam3 = sam3;
		break;

	case 6:
		sam6 = talloc_zero(mem_ctx, struct netr_SamInfo6);
		NT_STATUS_HAVE_NO_MEMORY(sam6);
		sam6->base = *sam;
		sam6->forest.string = lp_realm();
		sam6->principle.string = talloc_asprintf(mem_ctx, "%s@%s", 
							 sam->account_name.string, sam6->forest.string);
		NT_STATUS_HAVE_NO_MEMORY(sam6->principle.string);
		r->out.validation.sam6 = sam6;
		break;

	default:
		break;
	}

	r->out.authoritative = 1;

	/* TODO: Describe and deal with these flags */
	r->out.flags = 0;

	return NT_STATUS_OK;
}

static NTSTATUS netr_LogonSamLogonEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct netr_LogonSamLogonEx *r) 
{
	NTSTATUS nt_status;
	struct creds_CredentialState *creds;
	nt_status = schannel_fetch_session_key(mem_ctx, r->in.computer_name, lp_workgroup(), &creds);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	if (!dce_call->conn->auth_state.auth_info ||
	    dce_call->conn->auth_state.auth_info->auth_type != DCERPC_AUTH_TYPE_SCHANNEL) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	return netr_LogonSamLogon_base(dce_call, mem_ctx, r, creds);
}

/* 
  netr_LogonSamLogonWithFlags

*/
static NTSTATUS netr_LogonSamLogonWithFlags(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					    struct netr_LogonSamLogonWithFlags *r)
{
	NTSTATUS nt_status;
	struct creds_CredentialState *creds;
	struct netr_LogonSamLogonEx r2;

	struct netr_Authenticator *return_authenticator;

	return_authenticator = talloc(mem_ctx, struct netr_Authenticator);
	NT_STATUS_HAVE_NO_MEMORY(return_authenticator);

	nt_status = netr_creds_server_step_check(r->in.computer_name, mem_ctx, 
						 r->in.credential, return_authenticator,
						 &creds);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	ZERO_STRUCT(r2);

	r2.in.server_name	= r->in.server_name;
	r2.in.computer_name	= r->in.computer_name;
	r2.in.logon_level	= r->in.logon_level;
	r2.in.logon		= r->in.logon;
	r2.in.validation_level	= r->in.validation_level;
	r2.in.flags		= r->in.flags;

	nt_status = netr_LogonSamLogon_base(dce_call, mem_ctx, &r2, creds);

	r->out.return_authenticator	= return_authenticator;
	r->out.validation		= r2.out.validation;
	r->out.authoritative		= r2.out.authoritative;
	r->out.flags			= r2.out.flags;

	return nt_status;
}

/* 
  netr_LogonSamLogon
*/
static NTSTATUS netr_LogonSamLogon(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   struct netr_LogonSamLogon *r)
{
	struct netr_LogonSamLogonWithFlags r2;
	NTSTATUS status;

	ZERO_STRUCT(r2);

	r2.in.server_name = r->in.server_name;
	r2.in.computer_name = r->in.computer_name;
	r2.in.credential  = r->in.credential;
	r2.in.return_authenticator = r->in.return_authenticator;
	r2.in.logon_level = r->in.logon_level;
	r2.in.logon = r->in.logon;
	r2.in.validation_level = r->in.validation_level;
	r2.in.flags = 0;

	status = netr_LogonSamLogonWithFlags(dce_call, mem_ctx, &r2);

	r->out.return_authenticator = r2.out.return_authenticator;
	r->out.validation = r2.out.validation;
	r->out.authoritative = r2.out.authoritative;

	return status;
}


/* 
  netr_LogonSamLogoff 
*/
static NTSTATUS netr_LogonSamLogoff(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_LogonSamLogoff *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}



/* 
  netr_DatabaseDeltas 
*/
static NTSTATUS netr_DatabaseDeltas(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DatabaseDeltas *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_DatabaseSync 
*/
static NTSTATUS netr_DatabaseSync(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DatabaseSync *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_AccountDeltas 
*/
static NTSTATUS netr_AccountDeltas(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_AccountDeltas *r)
{
	/* w2k3 returns "NOT IMPLEMENTED" for this call */
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  netr_AccountSync 
*/
static NTSTATUS netr_AccountSync(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_AccountSync *r)
{
	/* w2k3 returns "NOT IMPLEMENTED" for this call */
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* 
  netr_GetDcName 
*/
static NTSTATUS netr_GetDcName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_GetDcName *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_LogonControl 
*/
static WERROR netr_LogonControl(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_LogonControl *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_GetAnyDCName 
*/
static WERROR netr_GetAnyDCName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_GetAnyDCName *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_LogonControl2 
*/
static WERROR netr_LogonControl2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_LogonControl2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_DatabaseSync2 
*/
static NTSTATUS netr_DatabaseSync2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DatabaseSync2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_DatabaseRedo 
*/
static NTSTATUS netr_DatabaseRedo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DatabaseRedo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_LogonControl2Ex 
*/
static WERROR netr_LogonControl2Ex(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_LogonControl2Ex *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_NETRENUMERATETRUSTEDDOMAINS 
*/
static WERROR netr_NETRENUMERATETRUSTEDDOMAINS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRENUMERATETRUSTEDDOMAINS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_NETRLOGONDUMMYROUTINE1 
*/
static WERROR netr_NETRLOGONDUMMYROUTINE1(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRLOGONDUMMYROUTINE1 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_NETRLOGONSETSERVICEBITS 
*/
static WERROR netr_NETRLOGONSETSERVICEBITS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRLOGONSETSERVICEBITS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_NETRLOGONGETTRUSTRID 
*/
static WERROR netr_NETRLOGONGETTRUSTRID(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRLOGONGETTRUSTRID *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_NETRLOGONCOMPUTESERVERDIGEST 
*/
static WERROR netr_NETRLOGONCOMPUTESERVERDIGEST(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRLOGONCOMPUTESERVERDIGEST *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_NETRLOGONCOMPUTECLIENTDIGEST 
*/
static WERROR netr_NETRLOGONCOMPUTECLIENTDIGEST(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRLOGONCOMPUTECLIENTDIGEST *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}



/* 
  netr_DsRGetSiteName
*/
static WERROR netr_DsRGetSiteName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct netr_DsRGetSiteName *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  fill in a netr_DomainTrustInfo from a ldb search result
*/
static NTSTATUS fill_domain_trust_info(TALLOC_CTX *mem_ctx,
				       struct ldb_message *res,
				       struct ldb_message *ref_res,
				       struct netr_DomainTrustInfo *info, 
				       BOOL is_local)
{
	ZERO_STRUCTP(info);

	if (is_local) {
		info->domainname.string = samdb_result_string(ref_res, "nETBIOSName", NULL);
		info->fulldomainname.string = samdb_result_string(ref_res, "dnsRoot", NULL);
		info->forest.string = NULL;
		info->guid = samdb_result_guid(res, "objectGUID");
		info->sid = samdb_result_dom_sid(mem_ctx, res, "objectSid");
	} else {
		info->domainname.string = samdb_result_string(res, "flatName", NULL);
		info->fulldomainname.string = samdb_result_string(res, "trustPartner", NULL);
		info->forest.string = NULL;
		info->guid = samdb_result_guid(res, "objectGUID");
		info->sid = samdb_result_dom_sid(mem_ctx, res, "securityIdentifier");
	}

	return NT_STATUS_OK;
}

/* 
  netr_LogonGetDomainInfo
  this is called as part of the ADS domain logon procedure.
*/
static NTSTATUS netr_LogonGetDomainInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct netr_LogonGetDomainInfo *r)
{
	const char * const attrs[] = { "objectSid", 
				       "objectGUID", "flatName", "securityIdentifier",
				       "trustPartner", NULL };
	const char * const ref_attrs[] = { "nETBIOSName", "dnsRoot", NULL };
	struct ldb_context *sam_ctx;
	struct ldb_message **res1, **res2, **ref_res;
	struct netr_DomainInfo1 *info1;
	int ret, ret1, ret2, i;
	NTSTATUS status;
	struct ldb_dn *partitions_basedn;

	const char *local_domain;

	status = netr_creds_server_step_check(r->in.computer_name, mem_ctx, 
					      r->in.credential, 
					      r->out.return_authenticator,
					      NULL);
	NT_STATUS_NOT_OK_RETURN(status);

	sam_ctx = samdb_connect(mem_ctx, dce_call->conn->auth_state.session_info);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	partitions_basedn = samdb_partitions_dn(sam_ctx, mem_ctx);

	/* we need to do two searches. The first will pull our primary
	   domain and the second will pull any trusted domains. Our
	   primary domain is also a "trusted" domain, so we need to
	   put the primary domain into the lists of returned trusts as
	   well */
	ret1 = gendb_search_dn(sam_ctx, mem_ctx, samdb_base_dn(sam_ctx), &res1, attrs);
	if (ret1 != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* try and find the domain */
	ret = gendb_search(sam_ctx, mem_ctx, partitions_basedn, 
			   &ref_res, ref_attrs, 
			   "(&(objectClass=crossRef)(ncName=%s))", 
			   ldb_dn_linearize(mem_ctx, res1[0]->dn));
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	local_domain = samdb_result_string(ref_res[0], "nETBIOSName", NULL);

	ret2 = gendb_search(sam_ctx, mem_ctx, NULL, &res2, attrs, "(objectClass=trustedDomain)");
	if (ret2 == -1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	info1 = talloc(mem_ctx, struct netr_DomainInfo1);
	NT_STATUS_HAVE_NO_MEMORY(info1);

	ZERO_STRUCTP(info1);

	info1->num_trusts = ret2 + 1;
	info1->trusts = talloc_array(mem_ctx, struct netr_DomainTrustInfo, 
				       info1->num_trusts);
	NT_STATUS_HAVE_NO_MEMORY(info1->trusts);

	status = fill_domain_trust_info(mem_ctx, res1[0], ref_res[0], &info1->domaininfo, True);
	NT_STATUS_NOT_OK_RETURN(status);

	for (i=0;i<ret2;i++) {
		status = fill_domain_trust_info(mem_ctx, res2[i], NULL, &info1->trusts[i], False);
		NT_STATUS_NOT_OK_RETURN(status);
	}

	status = fill_domain_trust_info(mem_ctx, res1[0], ref_res[0], &info1->trusts[i], True);
	NT_STATUS_NOT_OK_RETURN(status);

	r->out.info.info1 = info1;

	return NT_STATUS_OK;
}



/* 
  netr_NETRSERVERPASSWORDGET 
*/
static WERROR netr_NETRSERVERPASSWORDGET(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRSERVERPASSWORDGET *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_NETRLOGONSENDTOSAM 
*/
static WERROR netr_NETRLOGONSENDTOSAM(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRLOGONSENDTOSAM *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_DSRADDRESSTOSITENAMESW 
*/
static WERROR netr_DSRADDRESSTOSITENAMESW(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DSRADDRESSTOSITENAMESW *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_DsRGetDCNameEx2
*/
static WERROR netr_DsRGetDCNameEx2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   struct netr_DsRGetDCNameEx2 *r)
{
	const char * const attrs[] = { "dnsDomain", "objectGUID", NULL };
	void *sam_ctx;
	struct ldb_message **res;
	int ret;

	ZERO_STRUCT(r->out);

	sam_ctx = samdb_connect(mem_ctx, dce_call->conn->auth_state.session_info);
	if (sam_ctx == NULL) {
		return WERR_DS_SERVICE_UNAVAILABLE;
	}

	ret = gendb_search(sam_ctx, mem_ctx, NULL, &res, attrs,
				"(&(objectClass=domainDNS)(dnsDomain=%s))",
				r->in.domain_name);
	if (ret != 1) {
		return WERR_NO_SUCH_DOMAIN;
	}

	r->out.info = talloc(mem_ctx, struct netr_DsRGetDCNameInfo);
	W_ERROR_HAVE_NO_MEMORY(r->out.info);

	/* TODO: - return real IP address
	 *       - check all r->in.* parameters (server_unc is ignored by w2k3!)
	 */
	r->out.info->dc_unc		= talloc_asprintf(mem_ctx, "\\\\%s.%s", lp_netbios_name(),lp_realm());
	W_ERROR_HAVE_NO_MEMORY(r->out.info->dc_unc);
	r->out.info->dc_address		= talloc_strdup(mem_ctx, "\\\\0.0.0.0");
	W_ERROR_HAVE_NO_MEMORY(r->out.info->dc_address);
	r->out.info->dc_address_type	= 1;
	r->out.info->domain_guid	= samdb_result_guid(res[0], "objectGUID");
	r->out.info->domain_name	= samdb_result_string(res[0], "dnsDomain", NULL);
	r->out.info->forest_name	= samdb_result_string(res[0], "dnsDomain", NULL);
	r->out.info->dc_flags		= 0xE00001FD;
	r->out.info->dc_site_name	= talloc_strdup(mem_ctx, "Default-First-Site-Name");
	W_ERROR_HAVE_NO_MEMORY(r->out.info->dc_site_name);
	r->out.info->client_site_name	= talloc_strdup(mem_ctx, "Default-First-Site-Name");
	W_ERROR_HAVE_NO_MEMORY(r->out.info->client_site_name);

	return WERR_OK;
}

/* 
  netr_DsRGetDCNameEx
*/
static WERROR netr_DsRGetDCNameEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct netr_DsRGetDCNameEx *r)
{
	struct netr_DsRGetDCNameEx2 r2;
	WERROR werr;

	ZERO_STRUCT(r2);

	r2.in.server_unc = r->in.server_unc;
	r2.in.client_account = NULL;
	r2.in.mask = 0;
	r2.in.domain_guid = r->in.domain_guid;
	r2.in.domain_name = r->in.domain_name;
	r2.in.site_name = r->in.site_name;
	r2.in.flags = r->in.flags;
	r2.out.info = NULL;

	werr = netr_DsRGetDCNameEx2(dce_call, mem_ctx, &r2);
	
	r->out.info = r2.out.info;
	
	return werr;
}

/* 
  netr_DsRGetDCName
*/
static WERROR netr_DsRGetDCName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct netr_DsRGetDCName *r)
{
	struct netr_DsRGetDCNameEx2 r2;
	WERROR werr;

	ZERO_STRUCT(r2);

	r2.in.server_unc = r->in.server_unc;
	r2.in.client_account = NULL;
	r2.in.mask = 0;
	r2.in.domain_name = r->in.domain_name;
	r2.in.domain_guid = r->in.domain_guid;
	
	r2.in.site_name = NULL; /* should fill in from site GUID */
	r2.in.flags = r->in.flags;
	r2.out.info = NULL;

	werr = netr_DsRGetDCNameEx2(dce_call, mem_ctx, &r2);
	
	r->out.info = r2.out.info;
	
	return werr;
}

/* 
  netr_NETRLOGONGETTIMESERVICEPARENTDOMAIN 
*/
static WERROR netr_NETRLOGONGETTIMESERVICEPARENTDOMAIN(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRLOGONGETTIMESERVICEPARENTDOMAIN *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_NETRENUMERATETRUSTEDDOMAINSEX 
*/
static WERROR netr_NETRENUMERATETRUSTEDDOMAINSEX(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRENUMERATETRUSTEDDOMAINSEX *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_DSRADDRESSTOSITENAMESEXW 
*/
static WERROR netr_DSRADDRESSTOSITENAMESEXW(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DSRADDRESSTOSITENAMESEXW *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_DSRGETDCSITECOVERAGEW 
*/
static WERROR netr_DSRGETDCSITECOVERAGEW(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DSRGETDCSITECOVERAGEW *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_DsrEnumerateDomainTrusts 
*/
static WERROR netr_DsrEnumerateDomainTrusts(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					      struct netr_DsrEnumerateDomainTrusts *r)
{
	struct netr_DomainTrust *trusts;
	void *sam_ctx;
	int ret;
	struct ldb_message **dom_res, **ref_res;
	const char * const dom_attrs[] = { "objectSid", "objectGUID", NULL };
	const char * const ref_attrs[] = { "nETBIOSName", "dnsRoot", NULL };
	struct ldb_dn *partitions_basedn;

	ZERO_STRUCT(r->out);

	sam_ctx = samdb_connect(mem_ctx, dce_call->conn->auth_state.session_info);
	if (sam_ctx == NULL) {
		return WERR_GENERAL_FAILURE;
	}

	partitions_basedn = samdb_partitions_dn(sam_ctx, mem_ctx);

	ret = gendb_search_dn(sam_ctx, mem_ctx, NULL, &dom_res, dom_attrs);
	if (ret == -1) {
		return WERR_GENERAL_FAILURE;		
	}
	if (ret != 1) {
		return WERR_GENERAL_FAILURE;
	}

	ret = gendb_search(sam_ctx, mem_ctx, partitions_basedn, &ref_res, ref_attrs,
			   "(&(objectClass=crossRef)(ncName=%s))",
			   ldb_dn_linearize(mem_ctx, dom_res[0]->dn));
	if (ret == -1) {
		return WERR_GENERAL_FAILURE;
	}
	if (ret != 1) {
		return WERR_GENERAL_FAILURE;
	}

	trusts = talloc_array(mem_ctx, struct netr_DomainTrust, ret);
	W_ERROR_HAVE_NO_MEMORY(trusts);
	
	r->out.count = 1;
	r->out.trusts = trusts;

	/* TODO: add filtering by trust_flags, and correct trust_type
	   and attributes */
	trusts[0].netbios_name = samdb_result_string(ref_res[0], "nETBIOSName", NULL);
	trusts[0].dns_name     = samdb_result_string(ref_res[0], "dnsRoot", NULL);
	trusts[0].trust_flags = 
		NETR_TRUST_FLAG_TREEROOT | 
		NETR_TRUST_FLAG_IN_FOREST | 
		NETR_TRUST_FLAG_PRIMARY;
	trusts[0].parent_index = 0;
	trusts[0].trust_type = 2;
	trusts[0].trust_attributes = 0;
	trusts[0].sid  = samdb_result_dom_sid(mem_ctx, dom_res[0], "objectSid");
	trusts[0].guid = samdb_result_guid(dom_res[0], "objectGUID");

	return WERR_OK;
}


/* 
  netr_DSRDEREGISTERDNSHOSTRECORDS 
*/
static WERROR netr_DSRDEREGISTERDNSHOSTRECORDS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DSRDEREGISTERDNSHOSTRECORDS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_NETRSERVERTRUSTPASSWORDSGET 
*/
static WERROR netr_NETRSERVERTRUSTPASSWORDSGET(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRSERVERTRUSTPASSWORDSGET *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_DSRGETFORESTTRUSTINFORMATION 
*/
static WERROR netr_DSRGETFORESTTRUSTINFORMATION(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DSRGETFORESTTRUSTINFORMATION *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_NETRGETFORESTTRUSTINFORMATION 
*/
static WERROR netr_NETRGETFORESTTRUSTINFORMATION(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRGETFORESTTRUSTINFORMATION *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_NETRSERVERGETTRUSTINFO 
*/
static WERROR netr_NETRSERVERGETTRUSTINFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRSERVERGETTRUSTINFO *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_netlogon_s.c"
