/* 
   Unix SMB/CIFS implementation.

   endpoint server for the netlogon pipe

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004
   
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
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "librpc/gen_ndr/ndr_dcom.h"
#include "auth/auth.h"
#include "lib/ldb/include/ldb.h"

struct server_pipe_state {
	struct netr_Credential client_challenge;
	struct netr_Credential server_challenge;
	BOOL authenticated;
	char *account_name;
	char *computer_name;  /* for logging only */
	uint32_t acct_flags;
	uint16_t sec_chan_type;
	struct creds_CredentialState *creds;
};


/*
  a client has connected to the netlogon server using schannel, so we need
  to re-establish the credentials state
*/
static NTSTATUS netlogon_schannel_setup(struct dcesrv_call_state *dce_call) 
{
	struct server_pipe_state *state;
	NTSTATUS status;

	state = talloc_p(dce_call->conn, struct server_pipe_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ZERO_STRUCTP(state);
	state->authenticated = True;
	
	if (dce_call->conn->auth_state.session_info == NULL) {
		talloc_free(state);
		smb_panic("No session info provided by schannel level setup!");
		return NT_STATUS_NO_USER_SESSION_KEY;
	}
	
	status = dcerpc_schannel_creds(dce_call->conn->auth_state.gensec_security, 
				       state, 
				       &state->creds);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("getting schannel credentials failed with %s\n", nt_errstr(status)));
		talloc_free(state);
		return status;
	}
	
	dce_call->conn->private = state;

	return NT_STATUS_OK;
}

/*
  a hook for bind on the netlogon pipe
*/
static NTSTATUS netlogon_bind(struct dcesrv_call_state *dce_call, const struct dcesrv_interface *di) 
{
	dce_call->conn->private = NULL;

	/* if this is a schannel bind then we need to reconstruct the pipe state */
	if (dce_call->conn->auth_state.auth_info &&
	    dce_call->conn->auth_state.auth_info->auth_type == DCERPC_AUTH_TYPE_SCHANNEL) {
		NTSTATUS status;

		DEBUG(5, ("schannel bind on netlogon\n"));

		status = netlogon_schannel_setup(dce_call);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("schannel bind on netlogon failed with %s\n", nt_errstr(status)));
			return status;
		}
	}

	return NT_STATUS_OK;
}

/* this function is called when the client disconnects the endpoint */
static void netlogon_unbind(struct dcesrv_connection *conn, const struct dcesrv_interface *di) 
{
	struct server_pipe_state *pipe_state = conn->private;

	if (pipe_state) {
		talloc_free(pipe_state);
	}

	conn->private = NULL;
}

#define DCESRV_INTERFACE_NETLOGON_BIND netlogon_bind
#define DCESRV_INTERFACE_NETLOGON_UNBIND netlogon_unbind

static NTSTATUS netr_ServerReqChallenge(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct netr_ServerReqChallenge *r)
{
	struct server_pipe_state *pipe_state = dce_call->conn->private;

	ZERO_STRUCTP(r->out.credentials);

	/* destroyed on pipe shutdown */

	if (pipe_state) {
		talloc_free(pipe_state);
		dce_call->conn->private = NULL;
	}
	
	pipe_state = talloc_p(dce_call->conn, struct server_pipe_state);
	if (!pipe_state) {
		return NT_STATUS_NO_MEMORY;
	}

	pipe_state->authenticated = False;
	pipe_state->creds = NULL;
	pipe_state->account_name = NULL;
	pipe_state->computer_name = NULL;

	pipe_state->client_challenge = *r->in.credentials;

	generate_random_buffer(pipe_state->server_challenge.data, 
			       sizeof(pipe_state->server_challenge.data));

	*r->out.credentials = pipe_state->server_challenge;

	dce_call->conn->private = pipe_state;

	return NT_STATUS_OK;
}

static NTSTATUS netr_ServerAuthenticate3(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					 struct netr_ServerAuthenticate3 *r)
{
	struct server_pipe_state *pipe_state = dce_call->conn->private;
	void *sam_ctx;
	struct samr_Password *mach_pwd;
	uint16_t acct_flags;
	int num_records;
	struct ldb_message **msgs;
	NTSTATUS nt_status;
	const char *attrs[] = {"unicodePwd", "lmPwdHash", "ntPwdHash", "userAccountControl", 
			       "objectSid", NULL};

	ZERO_STRUCTP(r->out.credentials);
	*r->out.rid = 0;
	*r->out.negotiate_flags = *r->in.negotiate_flags;

	if (!pipe_state) {
		DEBUG(1, ("No challenge requested by client, cannot authenticate\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	sam_ctx = samdb_connect(mem_ctx);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}
	/* pull the user attributes */
	num_records = samdb_search(sam_ctx, mem_ctx, NULL, &msgs, attrs,
				   "(&(sAMAccountName=%s)(objectclass=user))", 
				   r->in.account_name);

	if (num_records == 0) {
		DEBUG(3,("Couldn't find user [%s] in samdb.\n", 
			 r->in.account_name));
		return NT_STATUS_NO_SUCH_USER;
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

	pipe_state->acct_flags = acct_flags;
	pipe_state->sec_chan_type = r->in.secure_channel_type;

	*r->out.rid = samdb_result_rid_from_sid(mem_ctx, msgs[0], "objectSid", 0);

	nt_status = samdb_result_passwords(mem_ctx, msgs[0], NULL, &mach_pwd);
	if (!NT_STATUS_IS_OK(nt_status) || mach_pwd == NULL) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!pipe_state->creds) {
		pipe_state->creds = talloc_p(pipe_state, struct creds_CredentialState);
		if (!pipe_state->creds) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	creds_server_init(pipe_state->creds, &pipe_state->client_challenge, 
			  &pipe_state->server_challenge, mach_pwd,
			  r->out.credentials,
			  *r->in.negotiate_flags);
	
	if (!creds_server_check(pipe_state->creds, r->in.credentials)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	pipe_state->authenticated = True;

	if (pipe_state->account_name) {
		/* We don't want a memory leak on this long-lived talloc context */
		talloc_free(pipe_state->account_name);
	}

	pipe_state->account_name = talloc_strdup(pipe_state, r->in.account_name);
	
	if (pipe_state->computer_name) {
		/* We don't want a memory leak on this long-lived talloc context */
		talloc_free(pipe_state->account_name);
	}

	pipe_state->computer_name = talloc_strdup(pipe_state, r->in.computer_name);

	/* remember this session key state */
	nt_status = schannel_store_session_key(mem_ctx, pipe_state->computer_name, pipe_state->creds);

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
	uint32 negotiate_flags = 0;  

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
	uint32 rid = 0;

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


static BOOL netr_creds_server_step_check(struct server_pipe_state *pipe_state,
					 struct netr_Authenticator *received_authenticator,
					 struct netr_Authenticator *return_authenticator) 
{
	if (!pipe_state->authenticated) {
		return False;
	}
	return creds_server_step_check(pipe_state->creds, 
				       received_authenticator, 
				       return_authenticator);
}


static NTSTATUS netr_ServerPasswordSet(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				       struct netr_ServerPasswordSet *r)
{
	struct server_pipe_state *pipe_state = dce_call->conn->private;

	void *sam_ctx;
	int num_records;
	int num_records_domain;
	int ret;
	struct ldb_message **msgs;
	struct ldb_message **msgs_domain;
	NTSTATUS nt_status;
	struct ldb_message mod, *msg_set_pw = &mod;
	const char *domain_dn;
	const char *domain_sid;

	const char *attrs[] = {"objectSid", NULL };

	const char **domain_attrs = attrs;
	ZERO_STRUCT(mod);

	if (!pipe_state) {
		DEBUG(1, ("No challenge requested by client, cannot authenticate\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!netr_creds_server_step_check(pipe_state, &r->in.credential, &r->out.return_authenticator)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	sam_ctx = samdb_connect(mem_ctx);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}
	/* pull the user attributes */
	num_records = samdb_search(sam_ctx, mem_ctx, NULL, &msgs, attrs,
				   "(&(sAMAccountName=%s)(objectclass=user))", 
				   pipe_state->account_name);

	if (num_records == 0) {
		DEBUG(3,("Couldn't find user [%s] in samdb.\n", 
			 pipe_state->account_name));
		return NT_STATUS_NO_SUCH_USER;
	}

	if (num_records > 1) {
		DEBUG(0,("Found %d records matching user [%s]\n", num_records, 
			 pipe_state->account_name));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	domain_sid = samdb_result_sid_prefix(mem_ctx, msgs[0], "objectSid");
	if (!domain_sid) {
		DEBUG(0,("no objectSid in user record\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* find the domain's DN */
	num_records_domain = samdb_search(sam_ctx, mem_ctx, NULL, 
					  &msgs_domain, domain_attrs,
					  "(&(objectSid=%s)(objectclass=domain))", 
					  domain_sid);

	if (num_records_domain == 0) {
		DEBUG(3,("check_sam_security: Couldn't find domain [%s] in passdb file.\n", 
			 domain_sid));
		return NT_STATUS_NO_SUCH_USER;
	}

	if (num_records_domain > 1) {
		DEBUG(0,("Found %d records matching domain [%s]\n", 
			 num_records_domain, domain_sid));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	domain_dn = msgs_domain[0]->dn;
	
	mod.dn = talloc_strdup(mem_ctx, msgs[0]->dn);
	if (!mod.dn) {
		return NT_STATUS_NO_MEMORY;
	}
	
	creds_des_decrypt(pipe_state->creds, &r->in.new_password);

	/* set the password - samdb needs to know both the domain and user DNs,
	   so the domain password policy can be used */
	nt_status = samdb_set_password(sam_ctx, mem_ctx,
				       msgs[0]->dn, domain_dn,
				       msg_set_pw, 
				       NULL, /* Don't have plaintext */
				       NULL, &r->in.new_password,
				       False /* This is not considered a password change */,
				       NULL);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	ret = samdb_replace(sam_ctx, mem_ctx, msg_set_pw);
	if (ret != 0) {
		/* we really need samdb.c to return NTSTATUS */
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
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
  netr_LogonSamLogonWithFlags

*/
static NTSTATUS netr_LogonSamLogonWithFlags(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					    struct netr_LogonSamLogonWithFlags *r)
{
	struct server_pipe_state *pipe_state = dce_call->conn->private;

	struct auth_context *auth_context;
	struct auth_usersupplied_info *user_info;
	struct auth_serversupplied_info *server_info;
	NTSTATUS nt_status;
	const uint8_t *chal;
	static const char zeros[16];
	struct netr_SamBaseInfo *sam;
	struct netr_SamInfo2 *sam2;
	struct netr_SamInfo3 *sam3;
	struct netr_SamInfo6 *sam6;
	
	if (!pipe_state) {
		DEBUG(1, ("No challenge requested by client, cannot authenticate\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	r->out.return_authenticator = talloc_p(mem_ctx, struct netr_Authenticator);
	if (!r->out.return_authenticator) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!netr_creds_server_step_check(pipe_state, r->in.credential, r->out.return_authenticator)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	switch (r->in.logon_level) {
	case 1:
	case 3:
	case 5:
		creds_arcfour_crypt(pipe_state->creds, 
				    r->in.logon.password->lmpassword.hash, 
				    sizeof(r->in.logon.password->lmpassword.hash));
		creds_arcfour_crypt(pipe_state->creds, 
				    r->in.logon.password->ntpassword.hash, 
				    sizeof(r->in.logon.password->ntpassword.hash));

		nt_status = make_auth_context_subsystem(pipe_state, &auth_context);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		chal = auth_context->get_ntlm_challenge(auth_context);
		nt_status = make_user_info_netlogon_interactive(auth_context, 
								&user_info,
								r->in.logon.password->identity_info.account_name.string,
								r->in.logon.password->identity_info.domain_name.string,
								r->in.logon.password->identity_info.workstation.string,
								chal,
								&r->in.logon.password->lmpassword,
								&r->in.logon.password->ntpassword);
		break;
		
	case 2:
	case 6:
		nt_status = make_auth_context_fixed(pipe_state,
						    &auth_context, r->in.logon.network->challenge);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		nt_status = make_user_info_netlogon_network(auth_context,
							    &user_info,
							    r->in.logon.network->identity_info.account_name.string,
							    r->in.logon.network->identity_info.domain_name.string,
							    r->in.logon.network->identity_info.workstation.string,
							    r->in.logon.network->lm.data, r->in.logon.network->lm.length,
							    r->in.logon.network->nt.data, r->in.logon.network->nt.length);
		break;
	default:
		free_auth_context(&auth_context);
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	nt_status = auth_context->check_ntlm_password(auth_context,
						      user_info, 
						      mem_ctx,
						      &server_info);

	/* keep the auth_context for the life of this call */
	talloc_steal(dce_call, auth_context);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	sam = talloc_p(mem_ctx, struct netr_SamBaseInfo);

	ZERO_STRUCTP(sam);
	
	sam->last_logon = server_info->last_logon;
	sam->last_logoff = server_info->last_logoff;
	sam->acct_expiry = server_info->acct_expiry;
	sam->last_password_change = server_info->last_password_change;
	sam->allow_password_change = server_info->allow_password_change;
	sam->force_password_change = server_info->force_password_change;
	
	sam->account_name.string = talloc_strdup(mem_ctx, server_info->account_name);
	sam->full_name.string = talloc_strdup(mem_ctx, server_info->full_name);
	sam->logon_script.string = talloc_strdup(mem_ctx, server_info->logon_script);
	sam->profile_path.string = talloc_strdup(mem_ctx, server_info->profile_path);
	sam->home_directory.string = talloc_strdup(mem_ctx, server_info->home_directory);
	sam->home_drive.string = talloc_strdup(mem_ctx, server_info->home_drive);
	
	sam->logon_count = server_info->logon_count;
	sam->bad_password_count = sam->bad_password_count;
	sam->rid = server_info->user_sid->sub_auths[server_info->user_sid->num_auths-1];
	sam->primary_gid = server_info->primary_group_sid->sub_auths[server_info->primary_group_sid->num_auths-1];
	sam->group_count = 0;
	sam->groupids = NULL;
	sam->user_flags = 0; /* TODO: w2k3 uses 0x120 - what is this? */
	sam->acct_flags = server_info->acct_flags;	
	sam->logon_server.string = lp_netbios_name();
	
	sam->domain.string = talloc_strdup(mem_ctx, server_info->domain);
	
	sam->domain_sid = dom_sid_dup(mem_ctx, server_info->user_sid);
	sam->domain_sid->num_auths--;

	if (server_info->user_session_key.length == sizeof(sam->key.key)) {
		memcpy(sam->key.key, server_info->user_session_key.data, sizeof(sam->key.key));
	} else {
		ZERO_STRUCT(sam->key.key);
	}
	
	/* Don't crypt an all-zero key, it would give away the NETLOGON pipe session key */
	/* It appears that level 6 is not individually encrypted */
	if ((r->in.validation_level != 6) 
	    && memcmp(sam->key.key, zeros,  
		      sizeof(sam->key.key)) != 0) {
		creds_arcfour_crypt(pipe_state->creds, 
				    sam->key.key, 
				    sizeof(sam->key.key));
	}
	
	if (server_info->lm_session_key.length == sizeof(sam->LMSessKey.key)) {
		memcpy(sam->LMSessKey.key, server_info->lm_session_key.data, 
		       sizeof(sam->LMSessKey.key));
	} else {
		ZERO_STRUCT(sam->LMSessKey.key);
	}
	
	/* Don't crypt an all-zero key, it would give away the NETLOGON pipe session key */
	/* It appears that level 6 is not individually encrypted */
	if ((r->in.validation_level != 6) 
	    && memcmp(sam->LMSessKey.key, zeros,  
		      sizeof(sam->LMSessKey.key)) != 0) {
		creds_arcfour_crypt(pipe_state->creds, 
				    sam->LMSessKey.key, 
				    sizeof(sam->LMSessKey.key));
	}

	switch (r->in.validation_level) {
	case 2:
		sam2 = talloc_p(mem_ctx, struct netr_SamInfo2);
		ZERO_STRUCTP(sam2);
		sam2->base = *sam;
		r->out.validation.sam2 = sam2;
		break;

	case 3:
		sam3 = talloc_p(mem_ctx, struct netr_SamInfo3);
		ZERO_STRUCTP(sam3);
		sam3->base = *sam;
		r->out.validation.sam3 = sam3;
		break;

	case 6:
		sam6 = talloc_p(mem_ctx, struct netr_SamInfo6);
		ZERO_STRUCTP(sam6);
		sam6->base = *sam;
		sam6->forest.string = lp_realm();
		sam6->principle.string = talloc_asprintf(mem_ctx, "%s@%s", 
							 sam->account_name.string, sam6->forest.string);
		r->out.validation.sam6 = sam6;
		break;

	default:
		break;
	}

	r->out.authoritative = 1;

	return NT_STATUS_OK;
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
	r2.in.workstation = r->in.workstation;
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
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_AccountSync 
*/
static NTSTATUS netr_AccountSync(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_AccountSync *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
  netr_DSRGETDCNAME 
*/
static WERROR netr_DSRGETDCNAME(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DSRGETDCNAME *r)
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
  netr_DSRGETDCNAMEX 
*/
static WERROR netr_DSRGETDCNAMEX(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DSRGETDCNAMEX *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  netr_DSRGETSITENAME 
*/
static WERROR netr_DSRGETSITENAME(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DSRGETSITENAME *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  fill in a netr_DomainTrustInfo from a ldb search result
*/
static NTSTATUS fill_domain_trust_info(TALLOC_CTX *mem_ctx, struct ldb_message *res,
				       struct netr_DomainTrustInfo *info)
{
	ZERO_STRUCTP(info);
	
	info->domainname.string = samdb_result_string(res, "flatName", NULL);
	if (info->domainname.string == NULL) {
		info->domainname.string = samdb_result_string(res, "name", NULL);
		info->fulldomainname.string = samdb_result_string(res, "dnsDomain", NULL);
	} else {
		info->fulldomainname.string = samdb_result_string(res, "name", NULL);
	}

	/* TODO: we need proper forest support */
	info->forest.string = info->fulldomainname.string;

	info->guid = samdb_result_guid(res, "objectGUID");
	info->sid = samdb_result_dom_sid(mem_ctx, res, "objectSid");

	return NT_STATUS_OK;
}

/* 
  netr_LogonGetDomainInfo
  this is called as part of the ADS domain logon procedure.
*/
static NTSTATUS netr_LogonGetDomainInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct netr_LogonGetDomainInfo *r)
{
	struct server_pipe_state *pipe_state = dce_call->conn->private;
	const char * const attrs[] = { "name", "dnsDomain", "objectSid", 
				       "objectGUID", "flatName", NULL };
	void *sam_ctx;
	struct ldb_message **res1, **res2;
	struct netr_DomainInfo1 *info1;
	int ret1, ret2, i;
	NTSTATUS status;

	if (!pipe_state) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!netr_creds_server_step_check(pipe_state, 
					  r->in.credential, r->out.credential)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	sam_ctx = samdb_connect(mem_ctx);
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	/* we need to do two searches. The first will pull our primary
	   domain and the second will pull any trusted domains. Our
	   primary domain is also a "trusted" domain, so we need to
	   put the primary domain into the lists of returned trusts as
	   well */
	ret1 = samdb_search(sam_ctx, mem_ctx, NULL, &res1, attrs, "(objectClass=domainDNS)");
	if (ret1 != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	ret2 = samdb_search(sam_ctx, mem_ctx, NULL, &res2, attrs, "(objectClass=trustedDomain)");
	if (ret2 == -1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	info1 = talloc_p(mem_ctx, struct netr_DomainInfo1);
	if (info1 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(info1);

	info1->num_trusts = ret2 + 1;
	info1->trusts = talloc_array_p(mem_ctx, struct netr_DomainTrustInfo, 
				       info1->num_trusts);
	if (info1->trusts == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = fill_domain_trust_info(mem_ctx, res1[0], &info1->domaininfo);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = fill_domain_trust_info(mem_ctx, res1[0], &info1->trusts[0]);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	for (i=0;i<ret2;i++) {
		status = fill_domain_trust_info(mem_ctx, res2[i], &info1->trusts[i+1]);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	r->out.info.info1 = info1;

	return NT_STATUS_OK;
}


/* 
  netr_NETRSERVERPASSWORDSET2 
*/
static WERROR netr_NETRSERVERPASSWORDSET2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRSERVERPASSWORDSET2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
  netr_DrsGetDCNameEx2
*/
static WERROR netr_DrsGetDCNameEx2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DrsGetDCNameEx2 *r)
{
	const char * const attrs[] = { "dnsDomain", "objectGUID", NULL };
	void *sam_ctx;
	struct ldb_message **res;
	int ret;

	ZERO_STRUCT(r->out);

	sam_ctx = samdb_connect(mem_ctx);
	if (sam_ctx == NULL) {
		return WERR_DS_SERVICE_UNAVAILABLE;
	}

	ret = samdb_search(sam_ctx, mem_ctx, NULL, &res, attrs,
				"(&(objectClass=domainDNS)(dnsDomain=%s))",
				r->in.domain_name);
	if (ret != 1) {
		return WERR_NO_SUCH_DOMAIN;
	}

	r->out.info = talloc_p(mem_ctx, struct netr_DrsGetDCNameEx2Info);
	if (!r->out.info) {
		return WERR_NOMEM;
	}

	/* TODO: - return real IP address
	 *       - check all r->in.* parameters (server_unc is ignored by w2k3!)
	 */
	r->out.info->dc_unc		= talloc_asprintf(mem_ctx, "\\\\%s.%s", lp_netbios_name(),lp_realm());
	r->out.info->dc_address	= talloc_strdup(mem_ctx, "\\\\0.0.0.0");
	r->out.info->dc_address_type	= 1;
	r->out.info->domain_guid	= samdb_result_guid(res[0], "objectGUID");
	r->out.info->domain_name	= samdb_result_string(res[0], "dnsDomain", NULL);
	r->out.info->forest_name	= samdb_result_string(res[0], "dnsDomain", NULL);
	r->out.info->dc_flags		= 0xE00001FD;
	r->out.info->dc_site_name	= talloc_strdup(mem_ctx, "Default-First-Site-Name");
	r->out.info->client_site_name	= talloc_strdup(mem_ctx, "Default-First-Site-Name");

	return WERR_OK;
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
  netr_LogonSamLogonEx
*/
static NTSTATUS netr_LogonSamLogonEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_LogonSamLogonEx *r)
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
	int ret, i;
	struct ldb_message **res;
	const char * const attrs[] = { "name", "dnsDomain", "objectSid", "objectGUID", NULL };

	ZERO_STRUCT(r->out);

	sam_ctx = samdb_connect(mem_ctx);
	if (sam_ctx == NULL) {
		return WERR_GENERAL_FAILURE;
	}

	ret = samdb_search(sam_ctx, mem_ctx, NULL, &res, attrs, "(objectClass=domainDNS)");
	if (ret == -1) {
		return WERR_GENERAL_FAILURE;		
	}

	if (ret == 0) {
		return WERR_OK;
	}

	trusts = talloc_array_p(mem_ctx, struct netr_DomainTrust, ret);
	if (trusts == NULL) {
		return WERR_NOMEM;
	}
	
	r->out.count = ret;
	r->out.trusts = trusts;

	/* TODO: add filtering by trust_flags, and correct trust_type
	   and attributes */
	for (i=0;i<ret;i++) {
		trusts[i].netbios_name = samdb_result_string(res[i], "name", NULL);
		trusts[i].dns_name     = samdb_result_string(res[i], "dnsDomain", NULL);
		trusts[i].trust_flags = 
			NETR_TRUST_FLAG_TREEROOT | 
			NETR_TRUST_FLAG_IN_FOREST | 
			NETR_TRUST_FLAG_PRIMARY;
		trusts[i].parent_index = 0;
		trusts[i].trust_type = 2;
		trusts[i].trust_attributes = 0;
		trusts[i].sid  = samdb_result_dom_sid(mem_ctx, res[i], "objectSid");
		trusts[i].guid = samdb_result_guid(res[i], "objectGUID");
	}
	

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
