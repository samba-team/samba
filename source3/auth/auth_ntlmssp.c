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

NTSTATUS ntlmssp_server_start(NTLMSSP_STATE **ntlmssp_state)
{
	NTSTATUS nt_status;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("NTLMSSP context");
	
	*ntlmssp_state = talloc_zero(mem_ctx, sizeof(**ntlmssp_state));
	if (!*ntlmssp_state) {
		DEBUG(0,("ntlmssp_start: talloc failed!\n"));
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(*ntlmssp_state);

	(*ntlmssp_state)->mem_ctx = mem_ctx;

	if (!NT_STATUS_IS_OK(nt_status = make_auth_context_subsystem(&(*ntlmssp_state)->auth_context))) {
		return nt_status;
	}
	return NT_STATUS_OK;
}

NTSTATUS ntlmssp_server_end(NTLMSSP_STATE **ntlmssp_state)
{
	TALLOC_CTX *mem_ctx = (*ntlmssp_state)->mem_ctx;
	if ((*ntlmssp_state)->auth_context) {
		((*ntlmssp_state)->auth_context->free)(&(*ntlmssp_state)->auth_context);
	}
	if ((*ntlmssp_state)->server_info) {
		free_server_info(&(*ntlmssp_state)->server_info);
	}

	talloc_destroy(mem_ctx);
	return NT_STATUS_OK;
}

NTSTATUS ntlmssp_server_update(NTLMSSP_STATE *ntlmssp_state, 
			       DATA_BLOB request, DATA_BLOB *reply) 
{
	uint32 ntlmssp_command;
		
	if (!msrpc_parse(&request, "Cd",
			 "NTLMSSP",
			 &ntlmssp_command)) {
		return NT_STATUS_LOGON_FAILURE;
	}

	if (ntlmssp_command == NTLMSSP_NEGOTIATE) {
		return ntlmssp_negotiate(ntlmssp_state, request, reply);
	} else if (ntlmssp_command == NTLMSSP_AUTH) {
		return ntlmssp_auth(ntlmssp_state, request, reply);
	} else {
		return NT_STATUS_LOGON_FAILURE;
	}
}

static const char *ntlmssp_target_name(uint32 neg_flags, uint32 *chal_flags) 
{
	if (neg_flags & NTLMSSP_REQUEST_TARGET) {
		if (lp_server_role() == ROLE_STANDALONE) {
			*chal_flags |= NTLMSSP_TARGET_TYPE_SERVER;
			return global_myname();
		} else {
			*chal_flags |= NTLMSSP_TARGET_TYPE_DOMAIN;
			return lp_workgroup();
		};
	} else {
		return "";
	}
}

NTSTATUS ntlmssp_negotiate(NTLMSSP_STATE *ntlmssp_state, 
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
		return NT_STATUS_LOGON_FAILURE;
	}

	SAFE_FREE(cliname);
	SAFE_FREE(domname);
  
	debug_ntlmssp_flags(neg_flags);

	cryptkey = ntlmssp_state->auth_context->get_ntlm_challenge(ntlmssp_state->auth_context);

	/* Give them the challenge. For now, ignore neg_flags and just
	   return the flags we want. Obviously this is not correct */
	
	chal_flags = 
		NTLMSSP_NEGOTIATE_128 | 
		NTLMSSP_NEGOTIATE_NTLM |
		NTLMSSP_CHAL_TARGET_INFO;
	
	if (neg_flags & NTLMSSP_NEGOTIATE_UNICODE) {
		chal_flags |= NTLMSSP_NEGOTIATE_UNICODE;
		ntlmssp_state->unicode = True;
	} else {
		chal_flags |= NTLMSSP_NEGOTIATE_OEM;
	}

	target_name = ntlmssp_target_name(neg_flags, &chal_flags); 

	dnsdomname[0] = '\0';
	get_mydomname(dnsdomname);
	strlower(dnsdomname);
	
	dnsname[0] = '\0';
	get_myfullname(dnsname);
	strlower(dnsname);
	
	/* the numbers here are the string type flags */
	msrpc_gen(&struct_blob, "aaaaa",
		  ntlmssp_state->unicode, NTLMSSP_NAME_TYPE_DOMAIN, lp_workgroup(),
		  ntlmssp_state->unicode, NTLMSSP_NAME_TYPE_SERVER, global_myname(),
		  ntlmssp_state->unicode, NTLMSSP_NAME_TYPE_DOMAIN_DNS, dnsname,
		  ntlmssp_state->unicode, NTLMSSP_NAME_TYPE_SERVER_DNS, dnsdomname,
		  ntlmssp_state->unicode, 0, "");

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

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS ntlmssp_auth(NTLMSSP_STATE *ntlmssp_state, 
		      DATA_BLOB request, DATA_BLOB *reply) 
{
	char *workgroup = NULL, *user = NULL, *machine = NULL;
	DATA_BLOB lmhash, nthash, sess_key;
	DATA_BLOB plaintext_password = data_blob(NULL, 0);
	uint32 ntlmssp_command, neg_flags;
	NTSTATUS nt_status;
	uint32 auth_flags = AUTH_FLAG_NONE;
	auth_usersupplied_info *user_info = NULL;

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

	/* now the NTLMSSP encoded auth hashes */
	if (!msrpc_parse(&request, parse_string,
			 "NTLMSSP", 
			 &ntlmssp_command, 
			 &lmhash,
			 &nthash,
			 &workgroup, 
			 &user, 
			 &machine,
			 &sess_key,
			 &neg_flags)) {
		return NT_STATUS_LOGON_FAILURE;
	}

	data_blob_free(&sess_key);
	
	DEBUG(3,("Got user=[%s] workgroup=[%s] machine=[%s] len1=%d len2=%d\n",
		 user, workgroup, machine, lmhash.length, nthash.length));

	/* the client has given us its machine name (which we otherwise would not get on port 445).
	   we need to possibly reload smb.conf if smb.conf includes depend on the machine name */

	set_remote_machine_name(machine);

	/* setup the string used by %U */
	sub_set_smb_name(user);

	reload_services(True);

#if 0
	file_save("nthash1.dat", nthash.data, nthash.length);
	file_save("lmhash1.dat", lmhash.data, lmhash.length);
#endif

	if (lmhash.length) {
		auth_flags |= AUTH_FLAG_LM_RESP;
	}

	if (nthash.length == 24) {
		auth_flags |= AUTH_FLAG_NTLM_RESP;
	} else if (nthash.length > 24) {
		auth_flags |= AUTH_FLAG_NTLMv2_RESP;
	};

	

	nt_status = make_user_info_map(&user_info, user, workgroup, machine, 
	                               lmhash, nthash, plaintext_password, 
	                               auth_flags, True);

	ntlmssp_state->orig_user = talloc_strdup(ntlmssp_state->mem_ctx, user);
	ntlmssp_state->orig_domain = talloc_strdup(ntlmssp_state->mem_ctx, workgroup);

	SAFE_FREE(user);
	SAFE_FREE(workgroup);
	SAFE_FREE(machine);

	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	nt_status = ntlmssp_state->auth_context->check_ntlm_password(ntlmssp_state->auth_context, user_info, &ntlmssp_state->server_info); 
			
	(ntlmssp_state->auth_context->free)(&ntlmssp_state->auth_context);

	free_user_info(&user_info);
	
	data_blob_free(&lmhash);
	
	data_blob_free(&nthash);

	*reply = data_blob(NULL, 0);

	return nt_status;
}
