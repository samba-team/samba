/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   handle NLTMSSP, server side

   Copyright (C) Andrew Tridgell      2001
   Copyright (C) Andrew Bartlett 2001-2003

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

/**
 * Print out the NTLMSSP flags for debugging 
 * @param neg_flags The flags from the packet
 */

void debug_ntlmssp_flags(uint32 neg_flags)
{
	DEBUG(3,("Got NTLMSSP neg_flags=0x%08x\n", neg_flags));
	
	if (neg_flags & NTLMSSP_NEGOTIATE_UNICODE) 
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_UNICODE\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_OEM) 
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_OEM\n"));
	if (neg_flags & NTLMSSP_REQUEST_TARGET) 
		DEBUGADD(4, ("  NTLMSSP_REQUEST_TARGET\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_SIGN) 
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_SIGN\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_SEAL) 
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_SEAL\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_LM_KEY) 
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_LM_KEY\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_NETWARE) 
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_NETWARE\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_NTLM) 
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_NTLM\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED) 
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED) 
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_THIS_IS_LOCAL_CALL) 
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_THIS_IS_LOCAL_CALL\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN) 
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_ALWAYS_SIGN\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_NTLM2) 
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_NTLM2\n"));
	if (neg_flags & NTLMSSP_CHAL_TARGET_INFO) 
		DEBUGADD(4, ("  NTLMSSP_CHAL_TARGET_INFO\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_128) 
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_128\n"));
	if (neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) 
		DEBUGADD(4, ("  NTLMSSP_NEGOTIATE_KEY_EXCH\n"));
}

/**
 * Default challenge generation code.
 *
 */
   
static const uint8 *get_challenge(struct ntlmssp_state *ntlmssp_state)
{
	static uchar chal[8];
	generate_random_buffer(chal, sizeof(chal), False);

	return chal;
}

/**
 * Determine correct target name flags for reply, given server role 
 * and negoitated falgs
 * 
 * @param ntlmssp_state NTLMSSP State
 * @param neg_flags The flags from the packet
 * @param chal_flags The flags to be set in the reply packet
 * @return The 'target name' string.
 */

static const char *ntlmssp_target_name(struct ntlmssp_state *ntlmssp_state,
				       uint32 neg_flags, uint32 *chal_flags) 
{
	if (neg_flags & NTLMSSP_REQUEST_TARGET) {
		*chal_flags |= NTLMSSP_CHAL_TARGET_INFO;
		*chal_flags |= NTLMSSP_REQUEST_TARGET;
		if (ntlmssp_state->server_role == ROLE_STANDALONE) {
			*chal_flags |= NTLMSSP_TARGET_TYPE_SERVER;
			return ntlmssp_state->get_global_myname();
		} else {
			*chal_flags |= NTLMSSP_TARGET_TYPE_DOMAIN;
			return ntlmssp_state->get_domain();
		};
	} else {
		return "";
	}
}

/**
 * Next state function for the Negotiate packet
 * 
 * @param ntlmssp_state NTLMSSP State
 * @param request The request, as a DATA_BLOB
 * @param request The reply, as an allocated DATA_BLOB, caller to free.
 * @return Errors or MORE_PROCESSING_REQUIRED if a reply is sent. 
 */

static NTSTATUS ntlmssp_server_negotiate(struct ntlmssp_state *ntlmssp_state,
					 const DATA_BLOB request, DATA_BLOB *reply) 
{
	DATA_BLOB struct_blob;
	fstring dnsname, dnsdomname;
	uint32 ntlmssp_command, neg_flags, chal_flags;
	char *cliname=NULL, *domname=NULL;
	const uint8 *cryptkey;
	const char *target_name;

	/* parse the NTLMSSP packet */
#if 0
	file_save("ntlmssp_negotiate.dat", request.data, request.length);
#endif

	if (!msrpc_parse(&request, "CddAA",
			 "NTLMSSP",
			 &ntlmssp_command,
			 &neg_flags,
			 &cliname,
			 &domname)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	SAFE_FREE(cliname);
	SAFE_FREE(domname);
  
	debug_ntlmssp_flags(neg_flags);

	cryptkey = ntlmssp_state->get_challenge(ntlmssp_state);

	data_blob_free(&ntlmssp_state->chal);
	ntlmssp_state->chal = data_blob(cryptkey, 8);

	/* Give them the challenge. For now, ignore neg_flags and just
	   return the flags we want. Obviously this is not correct */
	
	chal_flags = 
		NTLMSSP_NEGOTIATE_128 | 
		NTLMSSP_NEGOTIATE_NTLM;
	
	if (neg_flags & NTLMSSP_NEGOTIATE_UNICODE) {
		chal_flags |= NTLMSSP_NEGOTIATE_UNICODE;
		ntlmssp_state->unicode = True;
	} else {
		chal_flags |= NTLMSSP_NEGOTIATE_OEM;
	}

	target_name = ntlmssp_target_name(ntlmssp_state, 
					  neg_flags, &chal_flags); 

	/* This should be a 'netbios domain -> DNS domain' mapping */
	dnsdomname[0] = '\0';
	get_mydomname(dnsdomname);
	strlower(dnsdomname);
	
	dnsname[0] = '\0';
	get_myfullname(dnsname);
	strlower(dnsname);
	
	if (chal_flags & NTLMSSP_CHAL_TARGET_INFO) 
	{
		const char *target_name_dns = "";
		if (chal_flags |= NTLMSSP_TARGET_TYPE_DOMAIN) {
			target_name_dns = dnsdomname;
		} else if (chal_flags |= NTLMSSP_TARGET_TYPE_SERVER) {
			target_name_dns = dnsname;
		}

		/* the numbers here are the string type flags */
		msrpc_gen(&struct_blob, "aaaaa",
			  ntlmssp_state->unicode, NTLMSSP_NAME_TYPE_DOMAIN, target_name,
			  ntlmssp_state->unicode, NTLMSSP_NAME_TYPE_SERVER, ntlmssp_state->get_global_myname(),
			  ntlmssp_state->unicode, NTLMSSP_NAME_TYPE_DOMAIN_DNS, target_name_dns,
			  ntlmssp_state->unicode, NTLMSSP_NAME_TYPE_SERVER_DNS, dnsdomname,
			  ntlmssp_state->unicode, 0, "");
	} else {
		struct_blob = data_blob(NULL, 0);
	}

	{
		const char *gen_string;
		if (ntlmssp_state->unicode) {
			gen_string = "CdUdbddB";
		} else {
			gen_string = "CdAdbddB";
		}
		
		msrpc_gen(reply, gen_string,
			  "NTLMSSP", 
			  NTLMSSP_CHALLENGE,
			  target_name,
			  chal_flags,
			  cryptkey, 8,
			  0, 0,
			  struct_blob.data, struct_blob.length);
	}
		
	data_blob_free(&struct_blob);

	ntlmssp_state->expected_state = NTLMSSP_AUTH;

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

/**
 * Next state function for the Authenticate packet
 * 
 * @param ntlmssp_state NTLMSSP State
 * @param request The request, as a DATA_BLOB
 * @param request The reply, as an allocated DATA_BLOB, caller to free.
 * @return Errors or NT_STATUS_OK. 
 */

static NTSTATUS ntlmssp_server_auth(struct ntlmssp_state *ntlmssp_state,
				    const DATA_BLOB request, DATA_BLOB *reply) 
{
	DATA_BLOB sess_key;
	uint32 ntlmssp_command, neg_flags;
	NTSTATUS nt_status;

	const char *parse_string;

	/* parse the NTLMSSP packet */
#if 0
	file_save("ntlmssp_auth.dat", request.data, request.length);
#endif

	if (ntlmssp_state->unicode) {
		parse_string = "CdBBUUUBd";
	} else {
		parse_string = "CdBBAAABd";
	}

	data_blob_free(&ntlmssp_state->lm_resp);
	data_blob_free(&ntlmssp_state->nt_resp);

	SAFE_FREE(ntlmssp_state->user);
	SAFE_FREE(ntlmssp_state->domain);
	SAFE_FREE(ntlmssp_state->workstation);

	/* now the NTLMSSP encoded auth hashes */
	if (!msrpc_parse(&request, parse_string,
			 "NTLMSSP", 
			 &ntlmssp_command, 
			 &ntlmssp_state->lm_resp,
			 &ntlmssp_state->nt_resp,
			 &ntlmssp_state->domain, 
			 &ntlmssp_state->user, 
			 &ntlmssp_state->workstation,
			 &sess_key,
			 &neg_flags)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	data_blob_free(&sess_key);
	
	DEBUG(3,("Got user=[%s] domain=[%s] workstation=[%s] len1=%d len2=%d\n",
		 ntlmssp_state->user, ntlmssp_state->domain, ntlmssp_state->workstation, ntlmssp_state->lm_resp.length, ntlmssp_state->nt_resp.length));

#if 0
	file_save("nthash1.dat",  &ntlmssp_state->nt_resp.data,  &ntlmssp_state->nt_resp.length);
	file_save("lmhash1.dat",  &ntlmssp_state->lm_resp.data,  &ntlmssp_state->lm_resp.length);
#endif

	nt_status = ntlmssp_state->check_password(ntlmssp_state);
	
	*reply = data_blob(NULL, 0);

	return nt_status;
}

/**
 * Create an NTLMSSP state machine
 * 
 * @param ntlmssp_state NTLMSSP State, allocated by this funciton
 */

NTSTATUS ntlmssp_server_start(NTLMSSP_STATE **ntlmssp_state)
{
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("NTLMSSP context");
	
	*ntlmssp_state = talloc_zero(mem_ctx, sizeof(**ntlmssp_state));
	if (!*ntlmssp_state) {
		DEBUG(0,("ntlmssp_server_start: talloc failed!\n"));
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	(*ntlmssp_state)->mem_ctx = mem_ctx;
	(*ntlmssp_state)->get_challenge = get_challenge;

	(*ntlmssp_state)->get_global_myname = global_myname;
	(*ntlmssp_state)->get_domain = lp_workgroup;
	(*ntlmssp_state)->server_role = ROLE_DOMAIN_MEMBER; /* a good default */

	(*ntlmssp_state)->expected_state = NTLMSSP_NEGOTIATE;

	return NT_STATUS_OK;
}

/**
 * End an NTLMSSP state machine
 * 
 * @param ntlmssp_state NTLMSSP State, free()ed by this funciton
 */

NTSTATUS ntlmssp_server_end(NTLMSSP_STATE **ntlmssp_state)
{
	TALLOC_CTX *mem_ctx = (*ntlmssp_state)->mem_ctx;

	data_blob_free(&(*ntlmssp_state)->chal);
	data_blob_free(&(*ntlmssp_state)->lm_resp);
	data_blob_free(&(*ntlmssp_state)->nt_resp);

	SAFE_FREE((*ntlmssp_state)->user);
	SAFE_FREE((*ntlmssp_state)->domain);
	SAFE_FREE((*ntlmssp_state)->workstation);

	talloc_destroy(mem_ctx);
	*ntlmssp_state = NULL;
	return NT_STATUS_OK;
}

/**
 * Next state function for the NTLMSSP state machine
 * 
 * @param ntlmssp_state NTLMSSP State
 * @param request The request, as a DATA_BLOB
 * @param request The reply, as an allocated DATA_BLOB, caller to free.
 * @return Errors, NT_STATUS_MORE_PROCESSING_REQUIRED or NT_STATUS_OK. 
 */

NTSTATUS ntlmssp_server_update(NTLMSSP_STATE *ntlmssp_state, 
			       const DATA_BLOB request, DATA_BLOB *reply) 
{
	uint32 ntlmssp_command;
	*reply = data_blob(NULL, 0);

	if (!msrpc_parse(&request, "Cd",
			 "NTLMSSP",
			 &ntlmssp_command)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (ntlmssp_command != ntlmssp_state->expected_state) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (ntlmssp_command == NTLMSSP_NEGOTIATE) {
		return ntlmssp_server_negotiate(ntlmssp_state, request, reply);
	} else if (ntlmssp_command == NTLMSSP_AUTH) {
		return ntlmssp_server_auth(ntlmssp_state, request, reply);
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}
}

/*********************************************************************
 Client side NTLMSSP
*********************************************************************/

/**
 * Next state function for the Initial packet
 * 
 * @param ntlmssp_state NTLMSSP State
 * @param request The request, as a DATA_BLOB.  reply.data must be NULL
 * @param request The reply, as an allocated DATA_BLOB, caller to free.
 * @return Errors or NT_STATUS_OK. 
 */

static NTSTATUS ntlmssp_client_initial(struct ntlmssp_client_state *ntlmssp_state, 
				  DATA_BLOB reply, DATA_BLOB *next_request) 
{
	if (ntlmssp_state->unicode) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_UNICODE;
	}
	
	/* generate the ntlmssp negotiate packet */
	msrpc_gen(next_request, "CddAA",
		  "NTLMSSP",
		  NTLMSSP_NEGOTIATE,
		  ntlmssp_state->neg_flags,
		  ntlmssp_state->get_domain(), 
		  ntlmssp_state->get_global_myname());

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

/**
 * Next state function for the Challenge Packet.  Generate an auth packet.
 * 
 * @param ntlmssp_state NTLMSSP State
 * @param request The request, as a DATA_BLOB.  reply.data must be NULL
 * @param request The reply, as an allocated DATA_BLOB, caller to free.
 * @return Errors or NT_STATUS_OK. 
 */

static NTSTATUS ntlmssp_client_challenge(struct ntlmssp_client_state *ntlmssp_state, 
					 const DATA_BLOB reply, DATA_BLOB *next_request) 
{
	uint32 chal_flags, ntlmssp_command, unkn1, unkn2;
	DATA_BLOB server_domain_blob;
	DATA_BLOB challenge_blob;
	DATA_BLOB struct_blob;
	char *server_domain;
	const char *chal_parse_string;
	const char *auth_gen_string;
	DATA_BLOB lm_response = data_blob(NULL, 0);
	DATA_BLOB nt_response = data_blob(NULL, 0);
	DATA_BLOB session_key = data_blob(NULL, 0);
	uint8 datagram_sess_key[16];

	ZERO_STRUCT(datagram_sess_key);

	if (!msrpc_parse(&reply, "CdBd",
			 "NTLMSSP",
			 &ntlmssp_command, 
			 &server_domain_blob,
			 &chal_flags)) {
		DEBUG(0, ("Failed to parse the NTLMSSP Challenge\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	data_blob_free(&server_domain_blob);

	if (chal_flags & NTLMSSP_NEGOTIATE_UNICODE) {
		chal_parse_string = "CdUdbddB";
		auth_gen_string = "CdBBUUUBd";
		ntlmssp_state->unicode = True;
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_UNICODE;
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_OEM;
	} else if (chal_flags & NTLMSSP_NEGOTIATE_OEM) {
		chal_parse_string = "CdAdbddB";
		auth_gen_string = "CdBBAAABd";
		ntlmssp_state->unicode = False;
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_UNICODE;
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_OEM;
	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!msrpc_parse(&reply, chal_parse_string,
			 "NTLMSSP",
			 &ntlmssp_command, 
			 &server_domain,
			 &chal_flags,
			 &challenge_blob, 8,
			 &unkn1, &unkn2,
			 &struct_blob)) {
		DEBUG(0, ("Failed to parse the NTLMSSP Challenge\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	SAFE_FREE(server_domain);
	data_blob_free(&struct_blob);
	
	if (challenge_blob.length != 8) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (ntlmssp_state->use_ntlmv2) {

		/* TODO: if the remote server is standalone, then we should replace 'domain'
		   with the server name as supplied above */
		
		if (!SMBNTLMv2encrypt(ntlmssp_state->user, 
				      ntlmssp_state->domain, 
				      ntlmssp_state->password, challenge_blob, 
				      &lm_response, &nt_response, &session_key)) {
			data_blob_free(&challenge_blob);
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		uchar nt_hash[16];
		E_md4hash(ntlmssp_state->password, nt_hash);
		
		/* non encrypted password supplied. Ignore ntpass. */
		if (lp_client_lanman_auth()) {
			lm_response = data_blob(NULL, 24);
			SMBencrypt(ntlmssp_state->password,challenge_blob.data,
				   lm_response.data);
		}
		
		nt_response = data_blob(NULL, 24);
		SMBNTencrypt(ntlmssp_state->password,challenge_blob.data,
			     nt_response.data);
		session_key = data_blob(NULL, 16);
		SMBsesskeygen_ntv1(nt_hash, NULL, session_key.data);
	}
	
	data_blob_free(&challenge_blob);

	/* this generates the actual auth packet */
	if (!msrpc_gen(next_request, auth_gen_string, 
		       "NTLMSSP", 
		       NTLMSSP_AUTH, 
		       lm_response.data, lm_response.length,
		       nt_response.data, nt_response.length,
		       ntlmssp_state->domain, 
		       ntlmssp_state->user, 
		       ntlmssp_state->get_global_myname(), 
		       datagram_sess_key, 0,
		       ntlmssp_state->neg_flags)) {
		
		data_blob_free(&lm_response);
		data_blob_free(&nt_response);
		data_blob_free(&session_key);
		return NT_STATUS_NO_MEMORY;
	}

	data_blob_free(&lm_response);
	data_blob_free(&nt_response);

	ntlmssp_state->session_key = session_key;

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS ntlmssp_client_start(NTLMSSP_CLIENT_STATE **ntlmssp_state)
{
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("NTLMSSP Client context");
	
	*ntlmssp_state = talloc_zero(mem_ctx, sizeof(**ntlmssp_state));
	if (!*ntlmssp_state) {
		DEBUG(0,("ntlmssp_server_start: talloc failed!\n"));
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	(*ntlmssp_state)->mem_ctx = mem_ctx;

	(*ntlmssp_state)->get_global_myname = global_myname;
	(*ntlmssp_state)->get_domain = lp_workgroup;

	(*ntlmssp_state)->unicode = True;

	(*ntlmssp_state)->neg_flags = 
	       	NTLMSSP_NEGOTIATE_128 | 
		NTLMSSP_NEGOTIATE_NTLM |
		NTLMSSP_REQUEST_TARGET;

	return NT_STATUS_OK;
}

NTSTATUS ntlmssp_client_end(NTLMSSP_CLIENT_STATE **ntlmssp_state)
{
	TALLOC_CTX *mem_ctx = (*ntlmssp_state)->mem_ctx;

	data_blob_free(&(*ntlmssp_state)->session_key);
	talloc_destroy(mem_ctx);
	*ntlmssp_state = NULL;
	return NT_STATUS_OK;
}

NTSTATUS ntlmssp_client_update(NTLMSSP_CLIENT_STATE *ntlmssp_state, 
			       DATA_BLOB reply, DATA_BLOB *next_request) 
{
	uint32 ntlmssp_command;
	*next_request = data_blob(NULL, 0);

	if (!reply.length) {
		return ntlmssp_client_initial(ntlmssp_state, reply, next_request);
	} 		

	if (!msrpc_parse(&reply, "Cd",
			 "NTLMSSP",
			 &ntlmssp_command)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (ntlmssp_command == NTLMSSP_CHALLENGE) {
		return ntlmssp_client_challenge(ntlmssp_state, reply, next_request);
	}
	return NT_STATUS_INVALID_PARAMETER;
}

NTSTATUS ntlmssp_set_username(NTLMSSP_CLIENT_STATE *ntlmssp_state, const char *user) 
{
	ntlmssp_state->user = talloc_strdup(ntlmssp_state->mem_ctx, user);
	if (!ntlmssp_state->user) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

NTSTATUS ntlmssp_set_password(NTLMSSP_CLIENT_STATE *ntlmssp_state, const char *password) 
{
	ntlmssp_state->password = talloc_strdup(ntlmssp_state->mem_ctx, password);
	if (!ntlmssp_state->password) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

NTSTATUS ntlmssp_set_domain(NTLMSSP_CLIENT_STATE *ntlmssp_state, const char *domain) 
{
	ntlmssp_state->domain = talloc_strdup(ntlmssp_state->mem_ctx, domain);
	if (!ntlmssp_state->domain) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}
