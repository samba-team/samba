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
	uint32 acct_flags;
	uint16 sec_chan_type;
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
		[in]        unistr *server_name,
		[in]        unistr computer_name,
		[in][out]   netr_Credential credentials
		);

*/
static NTSTATUS netr_ServerReqChallenge(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct netr_ServerReqChallenge *r)
{
	struct server_pipe_state *pipe_state = dce_call->conn->private;
	TALLOC_CTX *pipe_mem_ctx;

	ZERO_STRUCT(r->out.credentials);

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

	pipe_state->client_challenge = r->in.credentials;

	generate_random_buffer(pipe_state->server_challenge.data, 
			       sizeof(pipe_state->server_challenge.data),
			       False);

	r->out.credentials = pipe_state->server_challenge;

	dce_call->conn->private = pipe_state;

	return NT_STATUS_OK;
}


/* 
  netr_ServerAuthenticate 

	 secure channel types:
 
	const int SEC_CHAN_WKSTA   = 2;
	const int SEC_CHAN_DOMAIN  = 4;
	const int SEC_CHAN_BDC     = 6;

	NTSTATUS netr_ServerAuthenticate(
		[in]        unistr *server_name,
		[in]        unistr username,
		[in]        uint16 secure_channel_type,
		[in]        unistr computer_name,
		[in,out]    netr_Credential credentials
		);


*/

static NTSTATUS netr_ServerAuthenticateInternals(struct server_pipe_state *pipe_state,
						 TALLOC_CTX *mem_ctx,
						 const char *account_name, 
						 const char *computer_name, 
						 uint16 secure_channel_type,
						 uint32 in_flags,
						 const struct netr_Credential *client_credentials,
						 struct netr_Credential *server_credentials,
						 uint32 *out_flags) 
{
	void *sam_ctx;
	uint8 *mach_pwd;
	uint16 acct_flags;
	int num_records;
	struct ldb_message **msgs;
	NTSTATUS nt_status;

	const char *attrs[] = {"unicodePwd", "lmPwdHash", "ntPwdHash", 
			       "userAccountControl", NULL 
	};

	ZERO_STRUCTP(server_credentials);
	if (out_flags) {
		*out_flags = 0;
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
				   account_name);

	if (num_records == 0) {
		DEBUG(3,("Couldn't find user [%s] in passdb file.\n", 
			 account_name));
		samdb_close(sam_ctx);
		return NT_STATUS_NO_SUCH_USER;
	}

	if (num_records > 1) {
		DEBUG(1,("Found %d records matching user [%s]\n", num_records, account_name));
		samdb_close(sam_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	acct_flags = samdb_result_acct_flags(msgs[0], 
					     "userAccountControl");

	if (acct_flags & ACB_DISABLED) {
		DEBUG(1, ("Account [%s] is disabled\n", account_name));
		return NT_STATUS_ACCESS_DENIED;
	}

	if (secure_channel_type == SEC_CHAN_WKSTA) {
		if (!(acct_flags & ACB_WSTRUST)) {
			DEBUG(1, ("Client asked for a workstation secure channel, but is not a workstation (member server) acb flags: 0x%x\n", acct_flags));
			return NT_STATUS_ACCESS_DENIED;
		}
	} else if (secure_channel_type == SEC_CHAN_DOMAIN) {
		if (!(acct_flags & ACB_DOMTRUST)) {
			DEBUG(1, ("Client asked for a trusted domain secure channel, but is not a trusted domain: acb flags: 0x%x\n", acct_flags));
			return NT_STATUS_ACCESS_DENIED;
		}
	} else if (secure_channel_type == SEC_CHAN_BDC) {
		if (!(acct_flags & ACB_SVRTRUST)) {
			DEBUG(1, ("Client asked for a server secure channel, but is not a server (domain controller): acb flags: 0x%x\n", acct_flags));
			return NT_STATUS_ACCESS_DENIED;
		}
	} else {
		DEBUG(1, ("Client asked for an invalid secure channel type: %d\n", secure_channel_type));
		return NT_STATUS_ACCESS_DENIED;
	}

	pipe_state->acct_flags = acct_flags;
	pipe_state->sec_chan_type = secure_channel_type;

	if (!NT_STATUS_IS_OK(nt_status = samdb_result_passwords(mem_ctx, msgs[0], 
								NULL, &mach_pwd))) {
		samdb_close(sam_ctx);
		return NT_STATUS_ACCESS_DENIED;
	}

	samdb_close(sam_ctx);

	if (!pipe_state->creds) {
		pipe_state->creds = talloc_p(mem_ctx, struct creds_CredentialState);
		if (!pipe_state->creds) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	creds_server_init(pipe_state->creds, &pipe_state->client_challenge, 
			  &pipe_state->server_challenge, mach_pwd,
			  server_credentials);

	if (!creds_server_check(pipe_state->creds, client_credentials)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	pipe_state->authenticated = True;

	if (pipe_state->account_name) {
		/* We don't want a memory leak on this long-lived talloc context */
		talloc_free(pipe_state->mem_ctx, pipe_state->account_name);
	}

	pipe_state->account_name = talloc_strdup(pipe_state->mem_ctx, account_name);
	
	if (pipe_state->computer_name) {
		/* We don't want a memory leak on this long-lived talloc context */
		talloc_free(pipe_state->mem_ctx, pipe_state->account_name);
	}

	pipe_state->computer_name = talloc_strdup(pipe_state->mem_ctx, computer_name);
	
	if (out_flags) {
		*out_flags = NETLOGON_NEG_AUTH2_FLAGS;
	}

	return NT_STATUS_OK;
}
						 

static NTSTATUS netr_ServerAuthenticate(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct netr_ServerAuthenticate *r)
{
	struct server_pipe_state *pipe_state = dce_call->conn->private;
	
	return netr_ServerAuthenticateInternals(pipe_state,
						mem_ctx,
						r->in.username,
						r->in.computer_name,
						r->in.secure_channel_type,
						0,
						&r->in.credentials,
						&r->out.credentials,
						NULL); 
}

static NTSTATUS netr_ServerAuthenticate2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct netr_ServerAuthenticate2 *r)
{
	struct server_pipe_state *pipe_state = dce_call->conn->private;
	
	return netr_ServerAuthenticateInternals(pipe_state,
						mem_ctx,
						r->in.username,
						r->in.computer_name,
						r->in.secure_channel_type,
						*r->in.negotiate_flags,
						&r->in.credentials,
						&r->out.credentials,
						r->out.negotiate_flags); 
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

	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
	

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


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_netlogon_s.c"
