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
#include "rpc_server/common/common.h"

struct server_pipe_state {
	TALLOC_CTX *mem_ctx;
	struct netr_Credential client_challenge;
	struct netr_Credential server_challenge;
	BOOL authenticated;
	char *account_name;
	char *computer_name;  /* for logging only */
	uint32_t acct_flags;
	uint16_t sec_chan_type;
	struct creds_CredentialState *creds;
};

static NTSTATUS netlogon_bind(struct dcesrv_call_state *dce_call, const struct dcesrv_interface *di) 
{
	dce_call->conn->private = NULL;

	return NT_STATUS_OK;
}

/* this function is called when the client disconnects the endpoint */
static void netlogon_unbind(struct dcesrv_connection *conn, const struct dcesrv_interface *di) 
{
	struct server_pipe_state *pipe_state = conn->private;

	if (pipe_state)
		talloc_destroy(pipe_state->mem_ctx);
	
	conn->private = NULL;
}

#define DCESRV_INTERFACE_NETLOGON_BIND netlogon_bind
#define DCESRV_INTERFACE_NETLOGON_UNBIND netlogon_unbind

/* 
  netr_ServerReqChallenge 

	NTSTATUS netr_ServerReqChallenge(
		[in]         unistr *server_name,
		[in]         unistr computer_name,
		[in,out,ref] netr_Credential *credentials
		);

*/
static NTSTATUS netr_ServerReqChallenge(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct netr_ServerReqChallenge *r)
{
	struct server_pipe_state *pipe_state = dce_call->conn->private;
	TALLOC_CTX *pipe_mem_ctx;

	ZERO_STRUCTP(r->out.credentials);

	/* destroyed on pipe shutdown */

	if (pipe_state) {
		talloc_destroy(pipe_state->mem_ctx);
		dce_call->conn->private = NULL;
	}
	
	pipe_mem_ctx = talloc_init("internal netlogon pipe state for %s", 
				   r->in.computer_name);
	
	if (!pipe_mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	pipe_state = talloc_p(pipe_mem_ctx, struct server_pipe_state);
	if (!pipe_state) {
		talloc_destroy(pipe_mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	pipe_state->mem_ctx = pipe_mem_ctx;
	pipe_state->authenticated = False;
	pipe_state->creds = NULL;
	pipe_state->account_name = NULL;
	pipe_state->computer_name = NULL;

	pipe_state->client_challenge = *r->in.credentials;

	generate_random_buffer(pipe_state->server_challenge.data, 
			       sizeof(pipe_state->server_challenge.data),
			       False);

	*r->out.credentials = pipe_state->server_challenge;

	dce_call->conn->private = pipe_state;

	return NT_STATUS_OK;
}


/* 
  netr_ServerAuthenticate 

	 secure channel types:
 
	const int SEC_CHAN_WKSTA   = 2;
	const int SEC_CHAN_DOMAIN  = 4;
	const int SEC_CHAN_BDC     = 6;

	NTSTATUS netr_ServerAuthenticate3(
		[in]         unistr *server_name,
		[in]         unistr username,
		[in]         uint16 secure_channel_type,
		[in]         unistr computer_name,
		[in,out,ref] netr_Credential *credentials
		[in,out,ref] uint32 *negotiate_flags,
		[out,ref]    uint32 *rid
		);
*/
static NTSTATUS netr_ServerAuthenticate3(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					 struct netr_ServerAuthenticate3 *r)
{
	struct server_pipe_state *pipe_state = dce_call->conn->private;
	void *sam_ctx;
	uint8_t *mach_pwd;
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
		DEBUG(1, ("No challange requested by client, cannot authenticate\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	sam_ctx = samdb_connect();
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}
	/* pull the user attributes */
	num_records = samdb_search(sam_ctx, mem_ctx, NULL, &msgs, attrs,
				   "(&(sAMAccountName=%s)(objectclass=user))", 
				   r->in.username);

	if (num_records == 0) {
		DEBUG(3,("Couldn't find user [%s] in samdb.\n", 
			 r->in.username));
		samdb_close(sam_ctx);
		return NT_STATUS_NO_SUCH_USER;
	}

	if (num_records > 1) {
		DEBUG(1,("Found %d records matching user [%s]\n", num_records, r->in.username));
		samdb_close(sam_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	acct_flags = samdb_result_acct_flags(msgs[0], 
					     "userAccountControl");

	if (acct_flags & ACB_DISABLED) {
		DEBUG(1, ("Account [%s] is disabled\n", r->in.username));
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
	if (!NT_STATUS_IS_OK(nt_status)) {
		samdb_close(sam_ctx);
		return NT_STATUS_ACCESS_DENIED;
	}

	samdb_close(sam_ctx);

	if (!pipe_state->creds) {
		pipe_state->creds = talloc_p(pipe_state->mem_ctx, struct creds_CredentialState);
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
		talloc_free(pipe_state->mem_ctx, pipe_state->account_name);
	}

	pipe_state->account_name = talloc_strdup(pipe_state->mem_ctx, r->in.username);
	
	if (pipe_state->computer_name) {
		/* We don't want a memory leak on this long-lived talloc context */
		talloc_free(pipe_state->mem_ctx, pipe_state->account_name);
	}

	pipe_state->computer_name = talloc_strdup(pipe_state->mem_ctx, r->in.computer_name);

	return NT_STATUS_OK;
}
						 

static NTSTATUS netr_ServerAuthenticate(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct netr_ServerAuthenticate *r)
{
	struct netr_ServerAuthenticate3 r3;
	uint32 negotiate_flags, rid;

	r3.in.server_name = r->in.server_name;
	r3.in.username = r->in.username;
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
	uint32 rid;

	r3.in.server_name = r->in.server_name;
	r3.in.username = r->in.username;
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

/* 
 netr_ServerPasswordSet 

 	NTSTATUS netr_ServerPasswordSet(
		[in]  unistr *server_name,
		[in]  unistr username,
		[in]  uint16 secure_channel_type,
		[in]  unistr computer_name,
		[in]  netr_Authenticator credential,
		[in]  netr_Password new_password,
		[out] netr_Authenticator return_authenticator
		);

*/
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
	struct samr_Hash newNtHash;
	struct ldb_message mod, *msg_set_pw = &mod;
	const char *domain_dn;
	const char *domain_sid;

	const char *attrs[] = {"objectSid", NULL };

	const char **domain_attrs = attrs;
	ZERO_STRUCT(mod);

	if (!netr_creds_server_step_check(pipe_state, &r->in.credential, &r->out.return_authenticator)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!pipe_state) {
		DEBUG(1, ("No challange requested by client, cannot authenticate\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	sam_ctx = samdb_connect();
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
		samdb_close(sam_ctx);
		return NT_STATUS_NO_SUCH_USER;
	}

	if (num_records > 1) {
		DEBUG(1,("Found %d records matching user [%s]\n", num_records, 
			 pipe_state->account_name));
		samdb_close(sam_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	domain_sid = samdb_result_sid_prefix(mem_ctx, msgs[0], "objectSid");
	if (!domain_sid) {
		samdb_close(sam_ctx);
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
		samdb_close(sam_ctx);
		return NT_STATUS_NO_SUCH_USER;
	}

	if (num_records_domain > 1) {
		DEBUG(1,("Found %d records matching domain [%s]\n", 
			 num_records_domain, domain_sid));
		samdb_close(sam_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	domain_dn = msgs_domain[0]->dn;
	
	mod.dn = talloc_strdup(mem_ctx, msgs[0]->dn);
	if (!mod.dn) {
		samdb_close(sam_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	
	creds_des_decrypt(pipe_state->creds, &r->in.new_password);

	memcpy(newNtHash.hash, r->in.new_password.data, sizeof(newNtHash.hash));

	/* set the password - samdb needs to know both the domain and user DNs,
	   so the domain password policy can be used */
	nt_status = samdb_set_password(sam_ctx, mem_ctx,
				       msgs[0]->dn, domain_dn,
				       msg_set_pw, 
				       NULL, /* Don't have plaintext */
				       NULL, &newNtHash,
				       False /* This is not considered a password change */,
				       NULL);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		samdb_close(sam_ctx);
		return nt_status;
	}

	ret = samdb_replace(sam_ctx, mem_ctx, msg_set_pw);
	if (ret != 0) {
		/* we really need samdb.c to return NTSTATUS */

		samdb_close(sam_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	samdb_close(sam_ctx);
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
  netr_LogonSamLogon 



*/
static NTSTATUS netr_LogonSamLogon(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_LogonSamLogon *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
  netr_NETRLOGONGETDOMAININFO 
*/
static WERROR netr_NETRLOGONGETDOMAININFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRLOGONGETDOMAININFO *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
  netr_DSRGETDCNAMEEX2 
*/
static WERROR netr_DSRGETDCNAMEEX2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_DSRGETDCNAMEEX2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
  netr_NETRLOGONSAMLOGONEX 
*/
static WERROR netr_NETRLOGONSAMLOGONEX(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRLOGONSAMLOGONEX *r)
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

	sam_ctx = samdb_connect();
	if (sam_ctx == NULL) {
		return WERR_GENERAL_FAILURE;
	}

	ret = samdb_search(sam_ctx, mem_ctx, NULL, &res, attrs, "(objectClass=domainDNS)");
	if (ret == -1) {
		samdb_close(sam_ctx);
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
  netr_NETRLOGONSAMLOGONWITHFLAGS 
*/
static WERROR netr_NETRLOGONSAMLOGONWITHFLAGS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct netr_NETRLOGONSAMLOGONWITHFLAGS *r)
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
