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

static NTSTATUS ntlmssp_server_negotiate(struct ntlmssp_state *ntlmssp_state,
					 DATA_BLOB request, DATA_BLOB *reply) 
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

static NTSTATUS ntlmssp_server_auth(struct ntlmssp_state *ntlmssp_state,
				    DATA_BLOB request, DATA_BLOB *reply) 
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

	ZERO_STRUCTP(*ntlmssp_state);

	(*ntlmssp_state)->mem_ctx = mem_ctx;
	(*ntlmssp_state)->get_challenge = get_challenge;

	(*ntlmssp_state)->get_global_myname = global_myname;
	(*ntlmssp_state)->get_domain = lp_workgroup;
	(*ntlmssp_state)->server_role = ROLE_DOMAIN_MEMBER; /* a good default */

	(*ntlmssp_state)->expected_state = NTLMSSP_NEGOTIATE;

	return NT_STATUS_OK;
}

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

NTSTATUS ntlmssp_server_update(NTLMSSP_STATE *ntlmssp_state, 
			       DATA_BLOB request, DATA_BLOB *reply) 
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

