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

static NTSTATUS ntlmssp_client_initial(struct ntlmssp_state *ntlmssp_state, 
				       TALLOC_CTX *out_mem_ctx, 
				       DATA_BLOB in, DATA_BLOB *out);
static NTSTATUS ntlmssp_server_negotiate(struct ntlmssp_state *ntlmssp_state,
					 TALLOC_CTX *out_mem_ctx, 
					 const DATA_BLOB in, DATA_BLOB *out);
static NTSTATUS ntlmssp_client_challenge(struct ntlmssp_state *ntlmssp_state, 
					 TALLOC_CTX *out_mem_ctx, 
					 const DATA_BLOB in, DATA_BLOB *out);
static NTSTATUS ntlmssp_server_auth(struct ntlmssp_state *ntlmssp_state,
				    TALLOC_CTX *out_mem_ctx, 
				    const DATA_BLOB in, DATA_BLOB *out);

/**
 * Callbacks for NTLMSSP - for both client and server operating modes
 * 
 */

static const struct ntlmssp_callbacks {
	enum ntlmssp_role role;
	enum ntlmssp_message_type ntlmssp_command;
	NTSTATUS (*fn)(struct ntlmssp_state *ntlmssp_state, 
		       TALLOC_CTX *out_mem_ctx, 
		       DATA_BLOB in, DATA_BLOB *out);
} ntlmssp_callbacks[] = {
	{NTLMSSP_CLIENT, NTLMSSP_INITIAL, ntlmssp_client_initial},
	{NTLMSSP_SERVER, NTLMSSP_NEGOTIATE, ntlmssp_server_negotiate},
	{NTLMSSP_CLIENT, NTLMSSP_CHALLENGE, ntlmssp_client_challenge},
	{NTLMSSP_SERVER, NTLMSSP_AUTH, ntlmssp_server_auth},
	{NTLMSSP_CLIENT, NTLMSSP_UNKNOWN, NULL},
	{NTLMSSP_SERVER, NTLMSSP_UNKNOWN, NULL}
};


/**
 * Print out the NTLMSSP flags for debugging 
 * @param neg_flags The flags from the packet
 */

void debug_ntlmssp_flags(uint32_t neg_flags)
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
   
static const uint8_t *get_challenge(const struct ntlmssp_state *ntlmssp_state)
{
	static uint8_t chal[8];
	generate_random_buffer(chal, sizeof(chal));

	return chal;
}

/**
 * Default 'we can set the challenge to anything we like' implementation
 *
 */
   
static BOOL may_set_challenge(const struct ntlmssp_state *ntlmssp_state)
{
	return True;
}

/**
 * Default 'we can set the challenge to anything we like' implementation
 *
 * Does not actually do anything, as the value is always in the structure anyway.
 *
 */
   
static NTSTATUS set_challenge(struct ntlmssp_state *ntlmssp_state, DATA_BLOB *challenge)
{
	SMB_ASSERT(challenge->length == 8);
	return NT_STATUS_OK;
}

/** 
 * Set a username on an NTLMSSP context - ensures it is talloc()ed 
 *
 */

NTSTATUS ntlmssp_set_username(struct ntlmssp_state *ntlmssp_state, const char *user) 
{
	ntlmssp_state->user = talloc_strdup(ntlmssp_state->mem_ctx, user);
	if (!ntlmssp_state->user) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

/** 
 * Set a password on an NTLMSSP context - ensures it is talloc()ed 
 *
 */
NTSTATUS ntlmssp_set_password(struct ntlmssp_state *ntlmssp_state, const char *password) 
{
	if (!password) {
		ntlmssp_state->password = NULL;
	} else {
		ntlmssp_state->password = talloc_strdup(ntlmssp_state->mem_ctx, password);
		if (!ntlmssp_state->password) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	return NT_STATUS_OK;
}

/** 
 * Set a domain on an NTLMSSP context - ensures it is talloc()ed 
 *
 */
NTSTATUS ntlmssp_set_domain(struct ntlmssp_state *ntlmssp_state, const char *domain) 
{
	ntlmssp_state->domain = talloc_strdup(ntlmssp_state->mem_ctx, domain);
	if (!ntlmssp_state->domain) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

/** 
 * Set a workstation on an NTLMSSP context - ensures it is talloc()ed 
 *
 */
NTSTATUS ntlmssp_set_workstation(struct ntlmssp_state *ntlmssp_state, const char *workstation) 
{
	ntlmssp_state->workstation = talloc_strdup(ntlmssp_state->mem_ctx, workstation);
	if (!ntlmssp_state->domain) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

/**
 *  Store a DATA_BLOB containing an NTLMSSP response, for use later.
 *  This copies the data blob
 */

NTSTATUS ntlmssp_store_response(struct ntlmssp_state *ntlmssp_state,
				DATA_BLOB response) 
{
	ntlmssp_state->stored_response = data_blob_talloc(ntlmssp_state->mem_ctx, 
							  response.data, response.length);
	return NT_STATUS_OK;
}

/**
 * Next state function for the NTLMSSP state machine
 * 
 * @param ntlmssp_state NTLMSSP State
 * @param out_mem_ctx The TALLOC_CTX for *out to be allocated on
 * @param in The request, as a DATA_BLOB
 * @param out The reply, as an talloc()ed DATA_BLOB, on *out_mem_ctx
 * @return Error, MORE_PROCESSING_REQUIRED if a reply is sent, 
 *                or NT_STATUS_OK if the user is authenticated. 
 */

NTSTATUS ntlmssp_update(struct ntlmssp_state *ntlmssp_state, 
			TALLOC_CTX *out_mem_ctx, 
			const DATA_BLOB in, DATA_BLOB *out) 
{
	DATA_BLOB input;
	uint32_t ntlmssp_command;
	int i;

	*out = data_blob(NULL, 0);

	if (ntlmssp_state->expected_state == NTLMSSP_DONE) {
		return NT_STATUS_OK;
	}

	if (!out_mem_ctx) {
		/* if the caller doesn't want to manage/own the memory, 
		   we can put it on our context */
		out_mem_ctx = ntlmssp_state->mem_ctx;
	}

	if (!in.length && ntlmssp_state->stored_response.length) {
		input = ntlmssp_state->stored_response;
		
		/* we only want to read the stored response once - overwrite it */
		ntlmssp_state->stored_response = data_blob(NULL, 0);
	} else {
		input = in;
	}

	if (!input.length) {
		switch (ntlmssp_state->role) {
		case NTLMSSP_CLIENT:
			ntlmssp_command = NTLMSSP_INITIAL;
			break;
		case NTLMSSP_SERVER:
			/* 'datagram' mode - no neg packet */
			ntlmssp_command = NTLMSSP_NEGOTIATE;
			break;
		}
	} else {
		if (!msrpc_parse(ntlmssp_state->mem_ctx, 
				 &input, "Cd",
				 "NTLMSSP",
				 &ntlmssp_command)) {
			DEBUG(1, ("Failed to parse NTLMSSP packet, could not extract NTLMSSP command\n"));
			dump_data(2, (const char *)input.data, input.length);
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	if (ntlmssp_command != ntlmssp_state->expected_state) {
		DEBUG(1, ("got NTLMSSP command %u, expected %u\n", ntlmssp_command, ntlmssp_state->expected_state));
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (i=0; ntlmssp_callbacks[i].fn; i++) {
		if (ntlmssp_callbacks[i].role == ntlmssp_state->role 
		    && ntlmssp_callbacks[i].ntlmssp_command == ntlmssp_command 
		    && ntlmssp_callbacks[i].fn) {
			return ntlmssp_callbacks[i].fn(ntlmssp_state, out_mem_ctx, input, out);
		}
	}

	DEBUG(1, ("failed to find NTLMSSP callback for NTLMSSP mode %u, command %u\n", 
		  ntlmssp_state->role, ntlmssp_command)); 

	return NT_STATUS_INVALID_PARAMETER;
}

/**
 * Return the NTLMSSP master session key
 * 
 * @param ntlmssp_state NTLMSSP State
 */

NTSTATUS ntlmssp_session_key(struct ntlmssp_state *ntlmssp_state,
			     DATA_BLOB *session_key)
{
	if (!ntlmssp_state->session_key.data) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}
	*session_key = ntlmssp_state->session_key;

	return NT_STATUS_OK;
}

/**
 * End an NTLMSSP state machine
 * 
 * @param ntlmssp_state NTLMSSP State, free()ed by this function
 */

void ntlmssp_end(struct ntlmssp_state **ntlmssp_state)
{
	TALLOC_CTX *mem_ctx = (*ntlmssp_state)->mem_ctx;

	(*ntlmssp_state)->ref_count--;

	if ((*ntlmssp_state)->ref_count == 0) {
		talloc_destroy(mem_ctx);
	}

	*ntlmssp_state = NULL;
	return;
}

/**
 * Determine correct target name flags for reply, given server role 
 * and negotiated flags
 * 
 * @param ntlmssp_state NTLMSSP State
 * @param neg_flags The flags from the packet
 * @param chal_flags The flags to be set in the reply packet
 * @return The 'target name' string.
 */

static const char *ntlmssp_target_name(struct ntlmssp_state *ntlmssp_state,
				       uint32_t neg_flags, uint32_t *chal_flags) 
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

static void ntlmssp_handle_neg_flags(struct ntlmssp_state *ntlmssp_state,
				      uint32_t neg_flags, BOOL allow_lm) {
	if (neg_flags & NTLMSSP_NEGOTIATE_UNICODE) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_UNICODE;
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_OEM;
		ntlmssp_state->unicode = True;
	} else {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_UNICODE;
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_OEM;
		ntlmssp_state->unicode = False;
	}

	if ((neg_flags & NTLMSSP_NEGOTIATE_LM_KEY) && allow_lm && !ntlmssp_state->use_ntlmv2) {
		/* other end forcing us to use LM */
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_LM_KEY;
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_NTLM2;
	} else {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	}

	if (neg_flags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
	}

	if (!(neg_flags & NTLMSSP_NEGOTIATE_NTLM2)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_NTLM2;
	}

	if (!(neg_flags & NTLMSSP_NEGOTIATE_128)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_128;
		if (neg_flags & NTLMSSP_NEGOTIATE_56) {
			ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_56;
		}
	}

	if (!(neg_flags & NTLMSSP_NEGOTIATE_56)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_56;
	}

	if (!(neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_KEY_EXCH;
	}

	if ((neg_flags & NTLMSSP_REQUEST_TARGET)) {
		ntlmssp_state->neg_flags |= NTLMSSP_REQUEST_TARGET;
	}
	
}

/**
   Weaken NTLMSSP keys to cope with down-level clients and servers.

   We probably should have some parameters to control this, but as
   it only occours for LM_KEY connections, and this is controlled
   by the client lanman auth/lanman auth parameters, it isn't too bad.
*/

static void ntlmssp_weaken_keys(struct ntlmssp_state *ntlmssp_state) {
	/* Key weakening not performed on the master key for NTLM2
	   and does not occour for NTLM1.  Therefore we only need
	   to do this for the LM_KEY.  
	*/

	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_LM_KEY) {
		if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_128) {
			
		} else if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_56) {
			ntlmssp_state->session_key.data[7] = 0xa0;
		} else { /* forty bits */
			ntlmssp_state->session_key.data[5] = 0xe5;
			ntlmssp_state->session_key.data[6] = 0x38;
			ntlmssp_state->session_key.data[7] = 0xb0;
		}
		ntlmssp_state->session_key.length = 8;
	}
}

/**
 * Next state function for the Negotiate packet
 * 
 * @param ntlmssp_state NTLMSSP State
 * @param out_mem_ctx The TALLOC_CTX for *out to be allocated on
 * @param in The request, as a DATA_BLOB
 * @param out The reply, as an talloc()ed DATA_BLOB, on *out_mem_ctx
 * @return Errors or MORE_PROCESSING_REQUIRED if a reply is sent. 
 */

static NTSTATUS ntlmssp_server_negotiate(struct ntlmssp_state *ntlmssp_state,
					 TALLOC_CTX *out_mem_ctx, 
					 const DATA_BLOB in, DATA_BLOB *out) 
{
	DATA_BLOB struct_blob;
	fstring dnsname, dnsdomname;
	uint32_t neg_flags = 0;
	uint32_t ntlmssp_command, chal_flags;
	char *cliname=NULL, *domname=NULL;
	const uint8_t *cryptkey;
	const char *target_name;

	/* parse the NTLMSSP packet */
#if 0
	file_save("ntlmssp_negotiate.dat", request.data, request.length);
#endif

	if (in.length) {
		if (!msrpc_parse(ntlmssp_state->mem_ctx, 
				 &in, "CddAA",
				 "NTLMSSP",
				 &ntlmssp_command,
				 &neg_flags,
				 &cliname,
				 &domname)) {
			DEBUG(1, ("ntlmssp_server_negotiate: failed to parse NTLMSSP:\n"));
			dump_data(2, (const char *)in.data, in.length);
			return NT_STATUS_INVALID_PARAMETER;
		}
		
		debug_ntlmssp_flags(neg_flags);
	}
	
	ntlmssp_handle_neg_flags(ntlmssp_state, neg_flags, ntlmssp_state->allow_lm_key);

	/* Ask our caller what challenge they would like in the packet */
	cryptkey = ntlmssp_state->get_challenge(ntlmssp_state);

	/* Check if we may set the challenge */
	if (!ntlmssp_state->may_set_challenge(ntlmssp_state)) {
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_NTLM2;
	}

	/* The flags we send back are not just the negotiated flags,
	 * they are also 'what is in this packet'.  Therfore, we
	 * operate on 'chal_flags' from here on 
	 */

	chal_flags = ntlmssp_state->neg_flags;

	/* get the right name to fill in as 'target' */
	target_name = ntlmssp_target_name(ntlmssp_state, 
					  neg_flags, &chal_flags); 
	if (target_name == NULL) 
		return NT_STATUS_INVALID_PARAMETER;

	ntlmssp_state->chal = data_blob_talloc(ntlmssp_state->mem_ctx, cryptkey, 8);
	ntlmssp_state->internal_chal = data_blob_talloc(ntlmssp_state->mem_ctx, cryptkey, 8);

	/* This should be a 'netbios domain -> DNS domain' mapping */
	dnsdomname[0] = '\0';
	get_mydomname(dnsdomname);
	strlower_m(dnsdomname);
	
	dnsname[0] = '\0';
	get_myfullname(dnsname);
	
	/* This creates the 'blob' of names that appears at the end of the packet */
	if (chal_flags & NTLMSSP_CHAL_TARGET_INFO) 
	{
		const char *target_name_dns = "";
		if (chal_flags |= NTLMSSP_TARGET_TYPE_DOMAIN) {
			target_name_dns = dnsdomname;
		} else if (chal_flags |= NTLMSSP_TARGET_TYPE_SERVER) {
			target_name_dns = dnsname;
		}

		msrpc_gen(out_mem_ctx, 
			  &struct_blob, "aaaaa",
			  NTLMSSP_NAME_TYPE_DOMAIN, target_name,
			  NTLMSSP_NAME_TYPE_SERVER, ntlmssp_state->get_global_myname(),
			  NTLMSSP_NAME_TYPE_DOMAIN_DNS, dnsdomname,
			  NTLMSSP_NAME_TYPE_SERVER_DNS, dnsname,
			  0, "");
	} else {
		struct_blob = data_blob(NULL, 0);
	}

	{
		/* Marshel the packet in the right format, be it unicode or ASCII */
		const char *gen_string;
		if (ntlmssp_state->unicode) {
			gen_string = "CdUdbddB";
		} else {
			gen_string = "CdAdbddB";
		}
		
		msrpc_gen(out_mem_ctx, 
			  out, gen_string,
			  "NTLMSSP", 
			  NTLMSSP_CHALLENGE,
			  target_name,
			  chal_flags,
			  cryptkey, 8,
			  0, 0,
			  struct_blob.data, struct_blob.length);
	}
		
	ntlmssp_state->expected_state = NTLMSSP_AUTH;

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

/**
 * Next state function for the Authenticate packet
 * 
 * @param ntlmssp_state NTLMSSP State
 * @param request The request, as a DATA_BLOB
 * @return Errors or NT_STATUS_OK. 
 */

static NTSTATUS ntlmssp_server_preauth(struct ntlmssp_state *ntlmssp_state,
				       const DATA_BLOB request) 
{
	uint32_t ntlmssp_command, auth_flags;
	NTSTATUS nt_status;

	uint8_t session_nonce_hash[16];

	const char *parse_string;
	char *domain = NULL;
	char *user = NULL;
	char *workstation = NULL;

#if 0
	file_save("ntlmssp_auth.dat", request.data, request.length);
#endif

	if (ntlmssp_state->unicode) {
		parse_string = "CdBBUUUBd";
	} else {
		parse_string = "CdBBAAABd";
	}

	/* zero these out */
	data_blob_free(&ntlmssp_state->lm_resp);
	data_blob_free(&ntlmssp_state->nt_resp);

	ntlmssp_state->user = NULL;
	ntlmssp_state->domain = NULL;
	ntlmssp_state->workstation = NULL;

	/* now the NTLMSSP encoded auth hashes */
	if (!msrpc_parse(ntlmssp_state->mem_ctx, 
			 &request, parse_string,
			 "NTLMSSP", 
			 &ntlmssp_command, 
			 &ntlmssp_state->lm_resp,
			 &ntlmssp_state->nt_resp,
			 &domain, 
			 &user, 
			 &workstation,
			 &ntlmssp_state->encrypted_session_key,
			 &auth_flags)) {
		DEBUG(10, ("ntlmssp_server_auth: failed to parse NTLMSSP (nonfatal):\n"));
		dump_data(10, (const char *)request.data, request.length);

		/* zero this out */
		data_blob_free(&ntlmssp_state->encrypted_session_key);
		auth_flags = 0;
		
		/* Try again with a shorter string (Win9X truncates this packet) */
		if (ntlmssp_state->unicode) {
			parse_string = "CdBBUUU";
		} else {
			parse_string = "CdBBAAA";
		}

		/* now the NTLMSSP encoded auth hashes */
		if (!msrpc_parse(ntlmssp_state->mem_ctx, 
				 &request, parse_string,
				 "NTLMSSP", 
				 &ntlmssp_command, 
				 &ntlmssp_state->lm_resp,
				 &ntlmssp_state->nt_resp,
				 &domain, 
				 &user, 
				 &workstation)) {
			DEBUG(1, ("ntlmssp_server_auth: failed to parse NTLMSSP:\n"));
			dump_data(2, (const char *)request.data, request.length);

			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	if (auth_flags)
		ntlmssp_handle_neg_flags(ntlmssp_state, auth_flags, ntlmssp_state->allow_lm_key);

	if (!NT_STATUS_IS_OK(nt_status = ntlmssp_set_domain(ntlmssp_state, domain))) {
		/* zero this out */
		data_blob_free(&ntlmssp_state->encrypted_session_key);
		return nt_status;
	}

	if (!NT_STATUS_IS_OK(nt_status = ntlmssp_set_username(ntlmssp_state, user))) {
		/* zero this out */
		data_blob_free(&ntlmssp_state->encrypted_session_key);
		return nt_status;
	}

	if (!NT_STATUS_IS_OK(nt_status = ntlmssp_set_workstation(ntlmssp_state, workstation))) {
		/* zero this out */
		data_blob_free(&ntlmssp_state->encrypted_session_key);
		return nt_status;
	}

	DEBUG(3,("Got user=[%s] domain=[%s] workstation=[%s] len1=%lu len2=%lu\n",
		 ntlmssp_state->user, ntlmssp_state->domain, ntlmssp_state->workstation, (unsigned long)ntlmssp_state->lm_resp.length, (unsigned long)ntlmssp_state->nt_resp.length));

#if 0
	file_save("nthash1.dat",  &ntlmssp_state->nt_resp.data,  &ntlmssp_state->nt_resp.length);
	file_save("lmhash1.dat",  &ntlmssp_state->lm_resp.data,  &ntlmssp_state->lm_resp.length);
#endif

	/* NTLM2 uses a 'challenge' that is made of up both the server challenge, and a 
	   client challenge 
	
	   However, the NTLM2 flag may still be set for the real NTLMv2 logins, be careful.
	*/
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		if (ntlmssp_state->nt_resp.length == 24 && ntlmssp_state->lm_resp.length == 24) {
			struct MD5Context md5_session_nonce_ctx;
			SMB_ASSERT(ntlmssp_state->internal_chal.data 
				   && ntlmssp_state->internal_chal.length == 8);
			
			ntlmssp_state->doing_ntlm2 = True;

			memcpy(ntlmssp_state->session_nonce, ntlmssp_state->internal_chal.data, 8);
			memcpy(&ntlmssp_state->session_nonce[8], ntlmssp_state->lm_resp.data, 8);
			
			MD5Init(&md5_session_nonce_ctx);
			MD5Update(&md5_session_nonce_ctx, ntlmssp_state->session_nonce, 16);
			MD5Final(session_nonce_hash, &md5_session_nonce_ctx);
			
			ntlmssp_state->chal = data_blob_talloc(ntlmssp_state->mem_ctx, 
							       session_nonce_hash, 8);

			/* LM response is no longer useful, zero it out */
			data_blob_free(&ntlmssp_state->lm_resp);

			/* We changed the effective challenge - set it */
			if (!NT_STATUS_IS_OK(nt_status = 
					     ntlmssp_state->set_challenge(ntlmssp_state, 
									  &ntlmssp_state->chal))) {
				/* zero this out */
				data_blob_free(&ntlmssp_state->encrypted_session_key);
				return nt_status;
			}

			/* LM Key is incompatible... */
			ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
		}
	}
	return NT_STATUS_OK;
}

/**
 * Next state function for the Authenticate packet 
 * (after authentication - figures out the session keys etc)
 * 
 * @param ntlmssp_state NTLMSSP State
 * @return Errors or NT_STATUS_OK. 
 */

static NTSTATUS ntlmssp_server_postauth(struct ntlmssp_state *ntlmssp_state,
					DATA_BLOB *user_session_key, 
					DATA_BLOB *lm_session_key) 
{
	NTSTATUS nt_status;
	DATA_BLOB session_key = data_blob(NULL, 0);

	if (user_session_key)
		dump_data_pw("USER session key:\n", user_session_key->data, user_session_key->length);

	if (lm_session_key) 
		dump_data_pw("LM first-8:\n", lm_session_key->data, lm_session_key->length);

	/* Handle the different session key derivation for NTLM2 */
	if (ntlmssp_state->doing_ntlm2) {
		if (user_session_key && user_session_key->data && user_session_key->length == 16) {
			session_key = data_blob_talloc(ntlmssp_state->mem_ctx, NULL, 16);
			hmac_md5(user_session_key->data, ntlmssp_state->session_nonce, 
				 sizeof(ntlmssp_state->session_nonce), session_key.data);
			DEBUG(10,("ntlmssp_server_auth: Created NTLM2 session key.\n"));
			dump_data_pw("NTLM2 session key:\n", session_key.data, session_key.length);
			
		} else {
			DEBUG(10,("ntlmssp_server_auth: Failed to create NTLM2 session key.\n"));
			session_key = data_blob(NULL, 0);
		}
	} else if ((ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_LM_KEY) 
		/* Ensure we can never get here on NTLMv2 */
		&& (ntlmssp_state->nt_resp.length == 0 || ntlmssp_state->nt_resp.length == 24)) {

		if (lm_session_key && lm_session_key->data && lm_session_key->length >= 8) {
			if (ntlmssp_state->lm_resp.data && ntlmssp_state->lm_resp.length == 24) {
				session_key = data_blob_talloc(ntlmssp_state->mem_ctx, NULL, 16);
				SMBsesskeygen_lm_sess_key(lm_session_key->data, ntlmssp_state->lm_resp.data, 
							  session_key.data);
				DEBUG(10,("ntlmssp_server_auth: Created NTLM session key.\n"));
				dump_data_pw("LM session key:\n", session_key.data, session_key.length);
  			} else {
				
				/* When there is no LM response, just use zeros */
 				static const uint8_t zeros[24];
 				session_key = data_blob_talloc(ntlmssp_state->mem_ctx, NULL, 16);
 				SMBsesskeygen_lm_sess_key(zeros, zeros, 
 							  session_key.data);
 				DEBUG(10,("ntlmssp_server_auth: Created NTLM session key.\n"));
 				dump_data_pw("LM session key:\n", session_key.data, session_key.length);
			}
		} else {
 			/* LM Key not selected */
 			ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;

			DEBUG(10,("ntlmssp_server_auth: Failed to create NTLM session key.\n"));
			session_key = data_blob(NULL, 0);
		}

	} else if (user_session_key && user_session_key->data) {
		session_key = *user_session_key;
		DEBUG(10,("ntlmssp_server_auth: Using unmodified nt session key.\n"));
		dump_data_pw("unmodified session key:\n", session_key.data, session_key.length);

		/* LM Key not selected */
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;

	} else if (lm_session_key && lm_session_key->data) {
		/* Very weird to have LM key, but no user session key, but anyway.. */
		session_key = *lm_session_key;
		DEBUG(10,("ntlmssp_server_auth: Using unmodified lm session key.\n"));
		dump_data_pw("unmodified session key:\n", session_key.data, session_key.length);

		/* LM Key not selected */
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;

	} else {
		DEBUG(10,("ntlmssp_server_auth: Failed to create unmodified session key.\n"));
		session_key = data_blob(NULL, 0);

		/* LM Key not selected */
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	}

	/* With KEY_EXCH, the client supplies the proposed session key, 
	   but encrypts it with the long-term key */
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
		if (!ntlmssp_state->encrypted_session_key.data 
		    || ntlmssp_state->encrypted_session_key.length != 16) {
			data_blob_free(&ntlmssp_state->encrypted_session_key);
			DEBUG(1, ("Client-supplied KEY_EXCH session key was of invalid length (%u)!\n", 
				  ntlmssp_state->encrypted_session_key.length));
			return NT_STATUS_INVALID_PARAMETER;
		} else if (!session_key.data || session_key.length != 16) {
			DEBUG(5, ("server session key is invalid (len == %u), cannot do KEY_EXCH!\n", 
				  session_key.length));
			ntlmssp_state->session_key = session_key;
		} else {
			dump_data_pw("KEY_EXCH session key (enc):\n", 
				     ntlmssp_state->encrypted_session_key.data, 
				     ntlmssp_state->encrypted_session_key.length);
			arcfour_crypt(ntlmssp_state->encrypted_session_key.data, 
				      session_key.data, 
				      ntlmssp_state->encrypted_session_key.length);
			ntlmssp_state->session_key = data_blob_talloc(ntlmssp_state->mem_ctx, 
								      ntlmssp_state->encrypted_session_key.data, 
								      ntlmssp_state->encrypted_session_key.length);
			dump_data_pw("KEY_EXCH session key:\n", ntlmssp_state->encrypted_session_key.data, 
				     ntlmssp_state->encrypted_session_key.length);
		}
	} else {
		ntlmssp_state->session_key = session_key;
	}

 	/* The server might need us to use a partial-strength session key */
 	ntlmssp_weaken_keys(ntlmssp_state);

	nt_status = ntlmssp_sign_init(ntlmssp_state);

	data_blob_free(&ntlmssp_state->encrypted_session_key);
	
	/* allow arbitarily many authentications, but watch that this will cause a 
	   memory leak, until the ntlmssp_state is shutdown 
	*/

	if (ntlmssp_state->server_multiple_authentications) {
		ntlmssp_state->expected_state = NTLMSSP_AUTH;
	} else {
		ntlmssp_state->expected_state = NTLMSSP_DONE;
	}

	return nt_status;
}


/**
 * Next state function for the Authenticate packet
 * 
 * @param ntlmssp_state NTLMSSP State
 * @param in The packet in from the NTLMSSP partner, as a DATA_BLOB
 * @param out The reply, as an allocated DATA_BLOB, caller to free.
 * @return Errors, NT_STATUS_MORE_PROCESSING_REQUIRED or NT_STATUS_OK. 
 */

static NTSTATUS ntlmssp_server_auth(struct ntlmssp_state *ntlmssp_state,
				    TALLOC_CTX *out_mem_ctx, 
				    const DATA_BLOB in, DATA_BLOB *out) 
{
	DATA_BLOB user_session_key = data_blob(NULL, 0);
	DATA_BLOB lm_session_key = data_blob(NULL, 0);
	NTSTATUS nt_status;

	/* zero the outbound NTLMSSP packet */
	*out = data_blob_talloc(out_mem_ctx, NULL, 0);

	if (!NT_STATUS_IS_OK(nt_status = ntlmssp_server_preauth(ntlmssp_state, in))) {
		return nt_status;
	}

	/*
	 * Note we don't check here for NTLMv2 auth settings. If NTLMv2 auth
	 * is required (by "ntlm auth = no" and "lm auth = no" being set in the
	 * smb.conf file) and no NTLMv2 response was sent then the password check
	 * will fail here. JRA.
	 */

	/* Finally, actually ask if the password is OK */

	if (!NT_STATUS_IS_OK(nt_status = ntlmssp_state->check_password(ntlmssp_state, 
								       &user_session_key, &lm_session_key))) {
		return nt_status;
	}
	
	if (ntlmssp_state->server_use_session_keys) {
		return ntlmssp_server_postauth(ntlmssp_state, &user_session_key, &lm_session_key);
	} else {
		ntlmssp_state->session_key = data_blob(NULL, 0);
		return NT_STATUS_OK;
	}
}

/**
 * Create an NTLMSSP state machine
 * 
 * @param ntlmssp_state NTLMSSP State, allocated by this function
 */

NTSTATUS ntlmssp_server_start(struct ntlmssp_state **ntlmssp_state)
{
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("NTLMSSP context");
	
	*ntlmssp_state = talloc_zero(mem_ctx, sizeof(**ntlmssp_state));
	if (!*ntlmssp_state) {
		DEBUG(0,("ntlmssp_server_start: talloc failed!\n"));
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	(*ntlmssp_state)->role = NTLMSSP_SERVER;

	(*ntlmssp_state)->mem_ctx = mem_ctx;
	(*ntlmssp_state)->get_challenge = get_challenge;
	(*ntlmssp_state)->set_challenge = set_challenge;
	(*ntlmssp_state)->may_set_challenge = may_set_challenge;

	(*ntlmssp_state)->get_global_myname = lp_netbios_name;
	(*ntlmssp_state)->get_domain = lp_workgroup;
	(*ntlmssp_state)->server_role = ROLE_DOMAIN_MEMBER; /* a good default */

	(*ntlmssp_state)->expected_state = NTLMSSP_NEGOTIATE;

	(*ntlmssp_state)->allow_lm_key = (lp_lanman_auth() 
					  && lp_parm_bool(-1, "ntlmssp_server", "allow_lm_key", False));

	(*ntlmssp_state)->server_use_session_keys = True;
	(*ntlmssp_state)->server_multiple_authentications = False;
	
	(*ntlmssp_state)->ref_count = 1;

	(*ntlmssp_state)->neg_flags = 
		NTLMSSP_NEGOTIATE_128 |
		NTLMSSP_NEGOTIATE_NTLM |
/*		NTLMSSP_NEGOTIATE_NTLM2 | */
		NTLMSSP_NEGOTIATE_KEY_EXCH |
		NTLMSSP_NEGOTIATE_SIGN |
		NTLMSSP_NEGOTIATE_SEAL;

	return NT_STATUS_OK;
}

/*********************************************************************
 Client side NTLMSSP
*********************************************************************/

/**
 * Next state function for the Initial packet
 * 
 * @param ntlmssp_state NTLMSSP State
 * @param out_mem_ctx The DATA_BLOB *out will be allocated on this context
 * @param in The request, as a DATA_BLOB.  reply.data must be NULL
 * @param out The reply, as an talloc()ed DATA_BLOB, on out_mem_ctx
 * @return Errors or NT_STATUS_OK. 
 */

static NTSTATUS ntlmssp_client_initial(struct ntlmssp_state *ntlmssp_state, 
				       TALLOC_CTX *out_mem_ctx, 
				       DATA_BLOB in, DATA_BLOB *out) 
{
	if (ntlmssp_state->unicode) {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_UNICODE;
	} else {
		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_OEM;
	}
	
	if (ntlmssp_state->use_ntlmv2) {
/*		ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_NTLM2;*/
	}

	/* generate the ntlmssp negotiate packet */
	msrpc_gen(out_mem_ctx, 
		  out, "CddAA",
		  "NTLMSSP",
		  NTLMSSP_NEGOTIATE,
		  ntlmssp_state->neg_flags,
		  ntlmssp_state->get_domain(), 
		  ntlmssp_state->get_global_myname());

	ntlmssp_state->expected_state = NTLMSSP_CHALLENGE;

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

static NTSTATUS ntlmssp_client_challenge(struct ntlmssp_state *ntlmssp_state, 
					 TALLOC_CTX *out_mem_ctx,
					 const DATA_BLOB in, DATA_BLOB *out) 
{
	uint32_t chal_flags, ntlmssp_command, unkn1, unkn2;
	DATA_BLOB server_domain_blob;
	DATA_BLOB challenge_blob;
	DATA_BLOB struct_blob = data_blob(NULL, 0);
	char *server_domain;
	const char *chal_parse_string;
	const char *auth_gen_string;
	uint8_t lm_hash[16];
	DATA_BLOB lm_response = data_blob(NULL, 0);
	DATA_BLOB nt_response = data_blob(NULL, 0);
	DATA_BLOB session_key = data_blob(NULL, 0);
	DATA_BLOB lm_session_key = data_blob(NULL, 0);
	DATA_BLOB encrypted_session_key = data_blob(NULL, 0);
	NTSTATUS nt_status;

	if (!msrpc_parse(ntlmssp_state->mem_ctx, 
			 &in, "CdBd",
			 "NTLMSSP",
			 &ntlmssp_command, 
			 &server_domain_blob,
			 &chal_flags)) {
		DEBUG(1, ("Failed to parse the NTLMSSP Challenge: (#1)\n"));
		dump_data(2, (const char *)in.data, in.length);

		return NT_STATUS_INVALID_PARAMETER;
	}
	
	data_blob_free(&server_domain_blob);

	DEBUG(3, ("Got challenge flags:\n"));
	debug_ntlmssp_flags(chal_flags);

	ntlmssp_handle_neg_flags(ntlmssp_state, chal_flags, ntlmssp_state->allow_lm_key);

	if (ntlmssp_state->unicode) {
		if (chal_flags & NTLMSSP_CHAL_TARGET_INFO) {
			chal_parse_string = "CdUdbddB";
		} else {
			chal_parse_string = "CdUdbdd";
		}
		auth_gen_string = "CdBBUUUBd";
	} else {
		if (chal_flags & NTLMSSP_CHAL_TARGET_INFO) {
			chal_parse_string = "CdAdbddB";
		} else {
			chal_parse_string = "CdAdbdd";
		}

		auth_gen_string = "CdBBAAABd";
	}

	DEBUG(3, ("NTLMSSP: Set final flags:\n"));
	debug_ntlmssp_flags(ntlmssp_state->neg_flags);

	if (!msrpc_parse(ntlmssp_state->mem_ctx, 
			 &in, chal_parse_string,
			 "NTLMSSP",
			 &ntlmssp_command, 
			 &server_domain,
			 &chal_flags,
			 &challenge_blob, 8,
			 &unkn1, &unkn2,
			 &struct_blob)) {
		DEBUG(1, ("Failed to parse the NTLMSSP Challenge: (#2)\n"));
		dump_data(2, (const char *)in.data, in.length);
		return NT_STATUS_INVALID_PARAMETER;
	}

	ntlmssp_state->server_domain = server_domain;

	if (challenge_blob.length != 8) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!ntlmssp_state->password) {
		static const uint8_t zeros[16];
		/* do nothing - blobs are zero length */

		/* session key is all zeros */
		session_key = data_blob_talloc(ntlmssp_state->mem_ctx, zeros, 16);
		lm_session_key = data_blob_talloc(ntlmssp_state->mem_ctx, zeros, 16);

		/* not doing NLTM2 without a password */
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_NTLM2;
	} else if (ntlmssp_state->use_ntlmv2) {

		if (!struct_blob.length) {
			/* be lazy, match win2k - we can't do NTLMv2 without it */
			DEBUG(1, ("Server did not provide 'target information', required for NTLMv2\n"));
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* TODO: if the remote server is standalone, then we should replace 'domain'
		   with the server name as supplied above */
		
		if (!SMBNTLMv2encrypt(ntlmssp_state->user, 
				      ntlmssp_state->domain, 
				      ntlmssp_state->password, &challenge_blob, 
				      &struct_blob, 
				      &lm_response, &nt_response, &session_key)) {
			data_blob_free(&challenge_blob);
			data_blob_free(&struct_blob);
			return NT_STATUS_NO_MEMORY;
		}

		/* LM Key is incompatible... */
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;

	} else if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_NTLM2) {
		struct MD5Context md5_session_nonce_ctx;
		uint8_t nt_hash[16];
		uint8_t session_nonce[16];
		uint8_t session_nonce_hash[16];
		uint8_t user_session_key[16];
		E_md4hash(ntlmssp_state->password, nt_hash);
		
		lm_response = data_blob_talloc(ntlmssp_state->mem_ctx, NULL, 24);
		generate_random_buffer(lm_response.data, 8);
		memset(lm_response.data+8, 0, 16);

		memcpy(session_nonce, challenge_blob.data, 8);
		memcpy(&session_nonce[8], lm_response.data, 8);
	
		MD5Init(&md5_session_nonce_ctx);
		MD5Update(&md5_session_nonce_ctx, challenge_blob.data, 8);
		MD5Update(&md5_session_nonce_ctx, lm_response.data, 8);
		MD5Final(session_nonce_hash, &md5_session_nonce_ctx);

		DEBUG(5, ("NTLMSSP challenge set by NTLM2\n"));
		DEBUG(5, ("challenge is: \n"));
		dump_data(5, (const char *)session_nonce_hash, 8);
		
		nt_response = data_blob_talloc(ntlmssp_state->mem_ctx, NULL, 24);
		SMBNTencrypt(ntlmssp_state->password,
			     session_nonce_hash,
			     nt_response.data);

		session_key = data_blob_talloc(ntlmssp_state->mem_ctx, NULL, 16);

		SMBsesskeygen_ntv1(nt_hash, user_session_key);
		hmac_md5(user_session_key, session_nonce, sizeof(session_nonce), session_key.data);
		dump_data_pw("NTLM2 session key:\n", session_key.data, session_key.length);

		/* LM Key is incompatible... */
		ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
	} else {
		uint8_t nt_hash[16];

		if (ntlmssp_state->use_nt_response) {
			nt_response = data_blob_talloc(ntlmssp_state->mem_ctx, NULL, 24);
			SMBNTencrypt(ntlmssp_state->password,challenge_blob.data,
				     nt_response.data);
			E_md4hash(ntlmssp_state->password, nt_hash);
			session_key = data_blob_talloc(ntlmssp_state->mem_ctx, NULL, 16);
			SMBsesskeygen_ntv1(nt_hash, session_key.data);
			dump_data_pw("NT session key:\n", session_key.data, session_key.length);
		}

		/* lanman auth is insecure, it may be disabled */
		if (lp_client_lanman_auth()) {
			lm_response = data_blob_talloc(ntlmssp_state->mem_ctx, NULL, 24);
			if (!SMBencrypt(ntlmssp_state->password,challenge_blob.data,
					lm_response.data)) {
				/* If the LM password was too long (and therefore the LM hash being
				   of the first 14 chars only), don't send it */
				data_blob_free(&lm_response);

				/* LM Key is incompatible with 'long' passwords */
				ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
			} else {
				E_deshash(ntlmssp_state->password, lm_hash);
				lm_session_key = data_blob_talloc(ntlmssp_state->mem_ctx, NULL, 16);
				memcpy(lm_session_key.data, lm_hash, 8);
				memset(&lm_session_key.data[8], '\0', 8);

				if (!ntlmssp_state->use_nt_response) {
					session_key = lm_session_key;
				}
			}
		} else {
			/* LM Key is incompatible... */
			ntlmssp_state->neg_flags &= ~NTLMSSP_NEGOTIATE_LM_KEY;
		}
	}
	
	if ((ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_LM_KEY) 
	    && lp_client_lanman_auth() && lm_session_key.length == 16) {
		DATA_BLOB new_session_key = data_blob_talloc(ntlmssp_state->mem_ctx, NULL, 16);
		if (lm_response.length == 24) {
			SMBsesskeygen_lm_sess_key(lm_session_key.data, lm_response.data, 
						  new_session_key.data);
		} else {
			static const uint8_t zeros[24];
			SMBsesskeygen_lm_sess_key(lm_session_key.data, zeros,
						  new_session_key.data);
		}
		new_session_key.length = 16;
		session_key = new_session_key;
		dump_data_pw("LM session key\n", session_key.data, session_key.length);
	}


	/* Key exchange encryptes a new client-generated session key with
	   the password-derived key */
	if (ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCH) {
		/* Make up a new session key */
		uint8_t client_session_key[16];
		generate_random_buffer(client_session_key, sizeof(client_session_key));

		/* Encrypt the new session key with the old one */
		encrypted_session_key = data_blob_talloc(ntlmssp_state->mem_ctx, 
							 client_session_key, sizeof(client_session_key));
		dump_data_pw("KEY_EXCH session key:\n", encrypted_session_key.data, encrypted_session_key.length);
		arcfour_crypt(encrypted_session_key.data, session_key.data, encrypted_session_key.length);
		dump_data_pw("KEY_EXCH session key (enc):\n", encrypted_session_key.data, encrypted_session_key.length);

		/* Mark the new session key as the 'real' session key */
		session_key = data_blob_talloc(ntlmssp_state->mem_ctx, client_session_key, sizeof(client_session_key));
	}

	/* this generates the actual auth packet */
	if (!msrpc_gen(out_mem_ctx, 
		       out, auth_gen_string, 
		       "NTLMSSP", 
		       NTLMSSP_AUTH, 
		       lm_response.data, lm_response.length,
		       nt_response.data, nt_response.length,
		       ntlmssp_state->domain, 
		       ntlmssp_state->user, 
		       ntlmssp_state->get_global_myname(), 
		       encrypted_session_key.data, encrypted_session_key.length,
		       ntlmssp_state->neg_flags)) {
		
		return NT_STATUS_NO_MEMORY;
	}

	ntlmssp_state->session_key = session_key;

	/* The client might be using 56 or 40 bit weakened keys */
	ntlmssp_weaken_keys(ntlmssp_state);

	ntlmssp_state->chal = challenge_blob;
	ntlmssp_state->lm_resp = lm_response;
	ntlmssp_state->nt_resp = nt_response;

	ntlmssp_state->expected_state = NTLMSSP_DONE;

	if (!NT_STATUS_IS_OK(nt_status = ntlmssp_sign_init(ntlmssp_state))) {
		DEBUG(1, ("Could not setup NTLMSSP signing/sealing system (error was: %s)\n", 
			  nt_errstr(nt_status)));
		return nt_status;
	}

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS ntlmssp_client_start(struct ntlmssp_state **ntlmssp_state)
{
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("NTLMSSP Client context");
	
	*ntlmssp_state = talloc_zero(mem_ctx, sizeof(**ntlmssp_state));
	if (!*ntlmssp_state) {
		DEBUG(0,("ntlmssp_client_start: talloc failed!\n"));
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	(*ntlmssp_state)->role = NTLMSSP_CLIENT;

	(*ntlmssp_state)->mem_ctx = mem_ctx;

	(*ntlmssp_state)->get_global_myname = lp_netbios_name;
	(*ntlmssp_state)->get_domain = lp_workgroup;

	(*ntlmssp_state)->unicode = lp_parm_bool(-1, "ntlmssp_client", "unicode", True);

	(*ntlmssp_state)->use_nt_response = lp_parm_bool(-1, "ntlmssp_client", "send_nt_reponse", True);

	(*ntlmssp_state)->allow_lm_key = (lp_lanman_auth() 
					  && lp_parm_bool(-1, "ntlmssp_client", "allow_lm_key", False));

	(*ntlmssp_state)->use_ntlmv2 = lp_client_ntlmv2_auth();

	(*ntlmssp_state)->expected_state = NTLMSSP_INITIAL;

	(*ntlmssp_state)->ref_count = 1;

	(*ntlmssp_state)->neg_flags = 
		NTLMSSP_NEGOTIATE_128 |
		NTLMSSP_NEGOTIATE_NTLM |
/*		NTLMSSP_NEGOTIATE_NTLM2 |*/
		NTLMSSP_NEGOTIATE_KEY_EXCH |
		/*
		 * We need to set this to allow a later SetPassword
		 * via the SAMR pipe to succeed. Strange.... We could
		 * also add  NTLMSSP_NEGOTIATE_SEAL here. JRA.
		 * 
		 * Without this, Windows will not create the master key
		 * that it thinks is only used for NTLMSSP signing and 
		 * sealing.  (It is actually pulled out and used directly) 
		 */
		NTLMSSP_NEGOTIATE_SIGN |
		NTLMSSP_REQUEST_TARGET;

	return NT_STATUS_OK;
}

