/*
   Unix SMB/CIFS implementation.

   Winbind daemon - pam auth funcions

   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Tim Potter 2001
   Copyright (C) Andrew Bartlett 2001-2002
   
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
#include "winbindd.h"
#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND


static NTSTATUS append_info3_as_ndr(TALLOC_CTX *mem_ctx, 
				    struct winbindd_cli_state *state, 
				    NET_USER_INFO_3 *info3) 
{
	prs_struct ps;
	uint32 size;
	if (!prs_init(&ps, 256 /* Random, non-zero number */, mem_ctx, MARSHALL)) {
		return NT_STATUS_NO_MEMORY;
	}
	if (!net_io_user_info3("", info3, &ps, 1, 3, False)) {
		prs_mem_free(&ps);
		return NT_STATUS_UNSUCCESSFUL;
	}

	size = prs_data_size(&ps);
	state->response.extra_data = SMB_MALLOC(size);
	if (!state->response.extra_data) {
		prs_mem_free(&ps);
		return NT_STATUS_NO_MEMORY;
	}
	memset( state->response.extra_data, '\0', size );
	prs_copy_all_data_out(state->response.extra_data, &ps);
	state->response.length += size;
	prs_mem_free(&ps);
	return NT_STATUS_OK;
}

static NTSTATUS check_info3_in_group(TALLOC_CTX *mem_ctx, 
				     NET_USER_INFO_3 *info3,
				     const char *group_sid) 
{
	DOM_SID require_membership_of_sid;
	DOM_SID *all_sids;
	size_t num_all_sids = (2 + info3->num_groups2 + info3->num_other_sids);
	size_t i, j = 0;

	/* Parse the 'required group' SID */
	
	if (!group_sid || !group_sid[0]) {
		/* NO sid supplied, all users may access */
		return NT_STATUS_OK;
	}
	
	if (!string_to_sid(&require_membership_of_sid, group_sid)) {
		DEBUG(0, ("check_info3_in_group: could not parse %s as a SID!", 
			  group_sid));

		return NT_STATUS_INVALID_PARAMETER;
	}

	all_sids = TALLOC_ARRAY(mem_ctx, DOM_SID, num_all_sids);
	if (!all_sids)
		return NT_STATUS_NO_MEMORY;

	/* and create (by appending rids) the 'domain' sids */
	
	sid_copy(&all_sids[0], &(info3->dom_sid.sid));
	
	if (!sid_append_rid(&all_sids[0], info3->user_rid)) {
		DEBUG(3,("could not append user's primary RID 0x%x\n",
			 info3->user_rid));			
		
		return NT_STATUS_INVALID_PARAMETER;
	}
	j++;

	sid_copy(&all_sids[1], &(info3->dom_sid.sid));
		
	if (!sid_append_rid(&all_sids[1], info3->group_rid)) {
		DEBUG(3,("could not append additional group rid 0x%x\n",
			 info3->group_rid));			
		
		return NT_STATUS_INVALID_PARAMETER;
	}
	j++;	

	for (i = 0; i < info3->num_groups2; i++) {
	
		sid_copy(&all_sids[j], &(info3->dom_sid.sid));
		
		if (!sid_append_rid(&all_sids[j], info3->gids[i].g_rid)) {
			DEBUG(3,("could not append additional group rid 0x%x\n",
				info3->gids[i].g_rid));			
				
			return NT_STATUS_INVALID_PARAMETER;
		}
		j++;
	}

	/* Copy 'other' sids.  We need to do sid filtering here to
 	   prevent possible elevation of privileges.  See:

           http://www.microsoft.com/windows2000/techinfo/administration/security/sidfilter.asp
         */

	for (i = 0; i < info3->num_other_sids; i++) {
		sid_copy(&all_sids[info3->num_groups2 + i + 2],
			 &info3->other_sids[i].sid);
		j++;
	}

	for (i = 0; i < j; i++) {
		fstring sid1, sid2;
		DEBUG(10, ("User has SID: %s\n", 
			   sid_to_string(sid1, &all_sids[i])));
		if (sid_equal(&require_membership_of_sid, &all_sids[i])) {
			DEBUG(10, ("SID %s matches %s - user permitted to authenticate!\n", 
				   sid_to_string(sid1, &require_membership_of_sid), sid_to_string(sid2, &all_sids[i])));
			return NT_STATUS_OK;
		}
	}
	
	/* Do not distinguish this error from a wrong username/pw */

	return NT_STATUS_LOGON_FAILURE;
}

static struct winbindd_domain *find_auth_domain(const char *domain_name)
{
	struct winbindd_domain *domain;

	if (IS_DC) {
		domain = find_domain_from_name_noinit(domain_name);
		if (domain == NULL) {
			DEBUG(3, ("Authentication for domain [%s] "
				  "as it is not a trusted domain\n", 
				  domain_name));
		}
		return domain;
	}

	if (is_myname(domain_name)) {
		DEBUG(3, ("Authentication for domain %s (local domain "
			  "to this server) not supported at this "
			  "stage\n", domain_name));
		return NULL;
	}

	return find_our_domain();
}

static void set_auth_errors(struct winbindd_response *resp, NTSTATUS result)
{
	resp->data.auth.nt_status = NT_STATUS_V(result);
	fstrcpy(resp->data.auth.nt_status_string, nt_errstr(result));

	/* we might have given a more useful error above */
	if (*resp->data.auth.error_string == '\0') 
		fstrcpy(resp->data.auth.error_string,
			get_friendly_nt_error_msg(result));
	resp->data.auth.pam_error = nt_status_to_pam(result);
}

/**********************************************************************
 Authenticate a user with a clear text password
**********************************************************************/

void winbindd_pam_auth(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain;
	fstring name_domain, name_user;

	/* Ensure null termination */
	state->request.data.auth.user
		[sizeof(state->request.data.auth.user)-1]='\0';

	/* Ensure null termination */
	state->request.data.auth.pass
		[sizeof(state->request.data.auth.pass)-1]='\0';

	DEBUG(3, ("[%5lu]: pam auth %s\n", (unsigned long)state->pid,
		  state->request.data.auth.user));

	/* Parse domain and username */
	
	parse_domain_user(state->request.data.auth.user,
			  name_domain, name_user);

	domain = find_auth_domain(name_domain);

	if (domain == NULL) {
		set_auth_errors(&state->response, NT_STATUS_NO_SUCH_USER);
		DEBUG(5, ("Plain text authentication for %s returned %s "
			  "(PAM: %d)\n",
			  state->request.data.auth.user, 
			  state->response.data.auth.nt_status_string,
			  state->response.data.auth.pam_error));
		request_error(state);
		return;
	}

	sendto_domain(state, domain);
}

enum winbindd_result winbindd_dual_pam_auth(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state) 
{
	NTSTATUS result;
	fstring name_domain, name_user;
        NET_USER_INFO_3 info3;
	struct rpc_pipe_client *netlogon_pipe;
	uchar chal[8];
	DATA_BLOB lm_resp;
	DATA_BLOB nt_resp;
	int attempts = 0;
	unsigned char local_lm_response[24];
	unsigned char local_nt_response[24];
	struct winbindd_domain *contact_domain;
	BOOL retry;

	/* Ensure null termination */
	state->request.data.auth.user[sizeof(state->request.data.auth.user)-1]='\0';

	/* Ensure null termination */
	state->request.data.auth.pass[sizeof(state->request.data.auth.pass)-1]='\0';

	DEBUG(3, ("[%5lu]: pam auth %s\n", (unsigned long)state->pid,
		  state->request.data.auth.user));

	/* Parse domain and username */
	
	parse_domain_user(state->request.data.auth.user, name_domain, name_user);

	/* do password magic */
	

	generate_random_buffer(chal, 8);
	if (lp_client_ntlmv2_auth()) {
		DATA_BLOB server_chal;
		DATA_BLOB names_blob;
		DATA_BLOB nt_response;
		DATA_BLOB lm_response;
		server_chal = data_blob_talloc(state->mem_ctx, chal, 8); 
		
		/* note that the 'workgroup' here is a best guess - we don't know
		   the server's domain at this point.  The 'server name' is also
		   dodgy... 
		*/
		names_blob = NTLMv2_generate_names_blob(global_myname(), lp_workgroup());
		
		if (!SMBNTLMv2encrypt(name_user, name_domain, 
				      state->request.data.auth.pass, 
				      &server_chal, 
				      &names_blob,
				      &lm_response, &nt_response, NULL)) {
			data_blob_free(&names_blob);
			data_blob_free(&server_chal);
			DEBUG(0, ("winbindd_pam_auth: SMBNTLMv2encrypt() failed!\n"));
			result = NT_STATUS_NO_MEMORY;
			goto done;
		}
		data_blob_free(&names_blob);
		data_blob_free(&server_chal);
		lm_resp = data_blob_talloc(state->mem_ctx, lm_response.data,
					   lm_response.length);
		nt_resp = data_blob_talloc(state->mem_ctx, nt_response.data,
					   nt_response.length);
		data_blob_free(&lm_response);
		data_blob_free(&nt_response);

	} else {
		if (lp_client_lanman_auth() 
		    && SMBencrypt(state->request.data.auth.pass, 
				  chal, 
				  local_lm_response)) {
			lm_resp = data_blob_talloc(state->mem_ctx, 
						   local_lm_response, 
						   sizeof(local_lm_response));
		} else {
			lm_resp = data_blob(NULL, 0);
		}
		SMBNTencrypt(state->request.data.auth.pass, 
			     chal,
			     local_nt_response);

		nt_resp = data_blob_talloc(state->mem_ctx, 
					   local_nt_response, 
					   sizeof(local_nt_response));
	}
	
	/* what domain should we contact? */
	
	if ( IS_DC ) {
		if (!(contact_domain = find_domain_from_name(name_domain))) {
			DEBUG(3, ("Authentication for domain for [%s] -> [%s]\\[%s] failed as %s is not a trusted domain\n", 
				  state->request.data.auth.user, name_domain, name_user, name_domain)); 
			result = NT_STATUS_NO_SUCH_USER;
			goto done;
		}
		
	} else {
		if (is_myname(name_domain)) {
			DEBUG(3, ("Authentication for domain %s (local domain to this server) not supported at this stage\n", name_domain));
			result =  NT_STATUS_NO_SUCH_USER;
			goto done;
		}

		contact_domain = find_our_domain();
	}

	/* check authentication loop */

	do {

		ZERO_STRUCT(info3);
		retry = False;

		result = cm_connect_netlogon(contact_domain, &netlogon_pipe);

		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(3, ("could not open handle to NETLOGON pipe\n"));
			goto done;
		}

		result = rpccli_netlogon_sam_network_logon(netlogon_pipe,
							   state->mem_ctx,
							   0,
							   contact_domain->dcname, /* server name */
							   name_user,              /* user name */
							   name_domain,            /* target domain */
							   global_myname(),        /* workstation */
							   chal,
							   lm_resp,
							   nt_resp,
							   &info3);
		attempts += 1;

		/* We have to try a second time as cm_connect_netlogon
		   might not yet have noticed that the DC has killed
		   our connection. */

		if (NT_STATUS_EQUAL(result, NT_STATUS_UNSUCCESSFUL)) {
			retry = True;
			continue;
		}
		
		/* if we get access denied, a possible cause was that we had
		   and open connection to the DC, but someone changed our
		   machine account password out from underneath us using 'net
		   rpc changetrustpw' */
		   
		if ( NT_STATUS_EQUAL(result, NT_STATUS_ACCESS_DENIED) ) {
			DEBUG(3,("winbindd_pam_auth: sam_logon returned "
				 "ACCESS_DENIED.  Maybe the trust account "
				"password was changed and we didn't know it. "
				 "Killing connections to domain %s\n",
				name_domain));
			invalidate_cm_connection(&contact_domain->conn);
			retry = True;
		} 
		
	} while ( (attempts < 2) && retry );

	if (NT_STATUS_IS_OK(result)) {
		/* Check if the user is in the right group */

		if (!NT_STATUS_IS_OK(result = check_info3_in_group(state->mem_ctx, &info3,
					state->request.data.auth.require_membership_of_sid))) {
			DEBUG(3, ("User %s is not in the required group (%s), so plaintext authentication is rejected\n",
				  state->request.data.auth.user, 
				  state->request.data.auth.require_membership_of_sid));
		}
	}

done:

	/* give us a more useful (more correct?) error code */
	if ((NT_STATUS_EQUAL(result, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND) ||
				(NT_STATUS_EQUAL(result, NT_STATUS_UNSUCCESSFUL)))) {
		result = NT_STATUS_NO_LOGON_SERVERS;
	}
	
	state->response.data.auth.nt_status = NT_STATUS_V(result);
	fstrcpy(state->response.data.auth.nt_status_string, nt_errstr(result));

	/* we might have given a more useful error above */
	if (!*state->response.data.auth.error_string) 
		fstrcpy(state->response.data.auth.error_string, get_friendly_nt_error_msg(result));
	state->response.data.auth.pam_error = nt_status_to_pam(result);

	DEBUG(NT_STATUS_IS_OK(result) ? 5 : 2, ("Plain-text authentication for user %s returned %s (PAM: %d)\n", 
	      state->request.data.auth.user, 
	      state->response.data.auth.nt_status_string,
	      state->response.data.auth.pam_error));	      

	if ( NT_STATUS_IS_OK(result) &&
	     (state->request.flags & WBFLAG_PAM_AFS_TOKEN) ) {

		char *afsname = SMB_STRDUP(lp_afs_username_map());
		char *cell;

		if (afsname == NULL) {
			goto no_token;
		}

		afsname = realloc_string_sub(afsname, "%D", name_domain);
		afsname = realloc_string_sub(afsname, "%u", name_user);
		afsname = realloc_string_sub(afsname, "%U", name_user);

		{
			DOM_SID user_sid;
			fstring sidstr;

			sid_copy(&user_sid, &info3.dom_sid.sid);
			sid_append_rid(&user_sid, info3.user_rid);
			sid_to_string(sidstr, &user_sid);
			afsname = realloc_string_sub(afsname, "%s", sidstr);
		}

		if (afsname == NULL) {
			goto no_token;
		}

		strlower_m(afsname);

		DEBUG(10, ("Generating token for user %s\n", afsname));

		cell = strchr(afsname, '@');

		if (cell == NULL) {
			goto no_token;
		}

		*cell = '\0';
		cell += 1;

		/* Append an AFS token string */
		state->response.extra_data =
			afs_createtoken_str(afsname, cell);

		if (state->response.extra_data != NULL)
			state->response.length +=
				strlen(state->response.extra_data)+1;

	no_token:
		SAFE_FREE(afsname);
	}
		
	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

/**********************************************************************
 Challenge Response Authentication Protocol 
**********************************************************************/

void winbindd_pam_auth_crap(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain = NULL;
	const char *domain_name = NULL;
	NTSTATUS result;

	if (!state->privileged) {
		char *error_string = NULL;
		DEBUG(2, ("winbindd_pam_auth_crap: non-privileged access "
			  "denied.  !\n"));
		DEBUGADD(2, ("winbindd_pam_auth_crap: Ensure permissions "
			     "on %s are set correctly.\n",
			     get_winbind_priv_pipe_dir()));
		/* send a better message than ACCESS_DENIED */
		error_string = talloc_asprintf(state->mem_ctx,
					       "winbind client not authorized "
					       "to use winbindd_pam_auth_crap."
					       " Ensure permissions on %s "
					       "are set correctly.",
					       get_winbind_priv_pipe_dir());
		fstrcpy(state->response.data.auth.error_string, error_string);
		result = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	/* Ensure null termination */
	state->request.data.auth_crap.user
		[sizeof(state->request.data.auth_crap.user)-1]=0;
	state->request.data.auth_crap.domain
		[sizeof(state->request.data.auth_crap.domain)-1]=0;

	DEBUG(3, ("[%5lu]: pam auth crap domain: [%s] user: %s\n",
		  (unsigned long)state->pid,
		  state->request.data.auth_crap.domain,
		  state->request.data.auth_crap.user));

	if (*state->request.data.auth_crap.domain != '\0') {
		domain_name = state->request.data.auth_crap.domain;
	} else if (lp_winbind_use_default_domain()) {
		domain_name = lp_workgroup();
	}

	if (domain_name != NULL)
		domain = find_auth_domain(domain_name);

	if (domain != NULL) {
		sendto_domain(state, domain);
		return;
	}

	result = NT_STATUS_NO_SUCH_USER;

 done:
	set_auth_errors(&state->response, result);
	DEBUG(5, ("CRAP authentication for %s returned %s (PAM: %d)\n",
		  state->request.data.auth.user, 
		  state->response.data.auth.nt_status_string,
		  state->response.data.auth.pam_error));
	request_error(state);
	return;
}


enum winbindd_result winbindd_dual_pam_auth_crap(struct winbindd_domain *domain,
						 struct winbindd_cli_state *state) 
{
	NTSTATUS result;
        NET_USER_INFO_3 info3;
	struct rpc_pipe_client *netlogon_pipe;
	const char *name_user = NULL;
	const char *name_domain = NULL;
	const char *workstation;
	struct winbindd_domain *contact_domain;
	int attempts = 0;
	BOOL retry;

	DATA_BLOB lm_resp, nt_resp;

	/* This is child-only, so no check for privileged access is needed
	   anymore */

	/* Ensure null termination */
	state->request.data.auth_crap.user[sizeof(state->request.data.auth_crap.user)-1]=0;
	state->request.data.auth_crap.domain[sizeof(state->request.data.auth_crap.domain)-1]=0;

	name_user = state->request.data.auth_crap.user;

	if (*state->request.data.auth_crap.domain) {
		name_domain = state->request.data.auth_crap.domain;
	} else if (lp_winbind_use_default_domain()) {
		name_domain = lp_workgroup();
	} else {
		DEBUG(5,("no domain specified with username (%s) - failing auth\n", 
			 name_user));
		result = NT_STATUS_NO_SUCH_USER;
		goto done;
	}

	DEBUG(3, ("[%5lu]: pam auth crap domain: %s user: %s\n", (unsigned long)state->pid,
		  name_domain, name_user));
	   
	if (*state->request.data.auth_crap.workstation) {
		workstation = state->request.data.auth_crap.workstation;
	} else {
		workstation = global_myname();
	}

	if (state->request.data.auth_crap.lm_resp_len > sizeof(state->request.data.auth_crap.lm_resp)
		|| state->request.data.auth_crap.nt_resp_len > sizeof(state->request.data.auth_crap.nt_resp)) {
		DEBUG(0, ("winbindd_pam_auth_crap: invalid password length %u/%u\n", 
			  state->request.data.auth_crap.lm_resp_len, 
			  state->request.data.auth_crap.nt_resp_len));
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	lm_resp = data_blob_talloc(state->mem_ctx, state->request.data.auth_crap.lm_resp,
					state->request.data.auth_crap.lm_resp_len);
	nt_resp = data_blob_talloc(state->mem_ctx, state->request.data.auth_crap.nt_resp,
					state->request.data.auth_crap.nt_resp_len);

	/* what domain should we contact? */
	
	if ( IS_DC ) {
		if (!(contact_domain = find_domain_from_name(name_domain))) {
			DEBUG(3, ("Authentication for domain for [%s] -> [%s]\\[%s] failed as %s is not a trusted domain\n", 
				  state->request.data.auth_crap.user, name_domain, name_user, name_domain)); 
			result = NT_STATUS_NO_SUCH_USER;
			goto done;
		}
	} else {
		if (is_myname(name_domain)) {
			DEBUG(3, ("Authentication for domain %s (local domain to this server) not supported at this stage\n", name_domain));
			result =  NT_STATUS_NO_SUCH_USER;
			goto done;
		}
		contact_domain = find_our_domain();
	}

	do {
		ZERO_STRUCT(info3);
		retry = False;

		result = cm_connect_netlogon(contact_domain, &netlogon_pipe);

		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(3, ("could not open handle to NETLOGON pipe (error: %s)\n",
				  nt_errstr(result)));
			goto done;
		}

		result = rpccli_netlogon_sam_network_logon(netlogon_pipe,
							   state->mem_ctx,
							   state->request.data.auth_crap.logon_parameters,
							   contact_domain->dcname,
							   name_user,
							   name_domain, 
							   global_myname(),
							   state->request.data.auth_crap.chal,
							   lm_resp,
							   nt_resp,
							   &info3);

		attempts += 1;

		/* We have to try a second time as cm_connect_netlogon
		   might not yet have noticed that the DC has killed
		   our connection. */

		if (NT_STATUS_EQUAL(result, NT_STATUS_UNSUCCESSFUL)) {
			retry = True;
			continue;
		}

		/* if we get access denied, a possible cause was that we had and open
		   connection to the DC, but someone changed our machine account password
		   out from underneath us using 'net rpc changetrustpw' */
		   
		if ( NT_STATUS_EQUAL(result, NT_STATUS_ACCESS_DENIED) ) {
			DEBUG(3,("winbindd_pam_auth: sam_logon returned "
				 "ACCESS_DENIED.  Maybe the trust account "
				"password was changed and we didn't know it. "
				 "Killing connections to domain %s\n",
				name_domain));
			invalidate_cm_connection(&contact_domain->conn);
			retry = True;
		} 

	} while ( (attempts < 2) && retry );

	if (NT_STATUS_IS_OK(result)) {
		if (!NT_STATUS_IS_OK(result = check_info3_in_group(state->mem_ctx, &info3,
							state->request.data.auth_crap.require_membership_of_sid))) {
			DEBUG(3, ("User %s is not in the required group (%s), so plaintext authentication is rejected\n",
				  state->request.data.auth_crap.user, 
				  state->request.data.auth_crap.require_membership_of_sid));
			goto done;
		}

		if (state->request.flags & WBFLAG_PAM_INFO3_NDR) {
			result = append_info3_as_ndr(state->mem_ctx, state, &info3);
		} else if (state->request.flags & WBFLAG_PAM_UNIX_NAME) {
			/* ntlm_auth should return the unix username, per 
			   'winbind use default domain' settings and the like */

			fstring username_out;
			const char *nt_username, *nt_domain;
			if (!(nt_username = unistr2_tdup(state->mem_ctx, &(info3.uni_user_name)))) {
				/* If the server didn't give us one, just use the one we sent them */
				nt_username = name_user;
			}

			if (!(nt_domain = unistr2_tdup(state->mem_ctx, &(info3.uni_logon_dom)))) {
				/* If the server didn't give us one, just use the one we sent them */
				nt_domain = name_domain;
			}

			fill_domain_username(username_out, nt_domain, nt_username);

			DEBUG(5, ("Setting unix username to [%s]\n", username_out));

			state->response.extra_data = SMB_STRDUP(username_out);
			if (!state->response.extra_data) {
				result = NT_STATUS_NO_MEMORY;
				goto done;
			}
			state->response.length +=  strlen(state->response.extra_data)+1;
		}
		
		if (state->request.flags & WBFLAG_PAM_USER_SESSION_KEY) {
			memcpy(state->response.data.auth.user_session_key, info3.user_sess_key,
					sizeof(state->response.data.auth.user_session_key) /* 16 */);
		}
		if (state->request.flags & WBFLAG_PAM_LMKEY) {
			memcpy(state->response.data.auth.first_8_lm_hash, info3.lm_sess_key,
					sizeof(state->response.data.auth.first_8_lm_hash) /* 8 */);
		}
	}

done:

	/* give us a more useful (more correct?) error code */
	if ((NT_STATUS_EQUAL(result, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND) ||
				(NT_STATUS_EQUAL(result, NT_STATUS_UNSUCCESSFUL)))) {
		result = NT_STATUS_NO_LOGON_SERVERS;
	}

	if (state->request.flags & WBFLAG_PAM_NT_STATUS_SQUASH) {
		result = nt_status_squash(result);
	}

	state->response.data.auth.nt_status = NT_STATUS_V(result);
	fstrcpy(state->response.data.auth.nt_status_string, nt_errstr(result));

	/* we might have given a more useful error above */
	if (!*state->response.data.auth.error_string) {
		fstrcpy(state->response.data.auth.error_string, get_friendly_nt_error_msg(result));
	}
	state->response.data.auth.pam_error = nt_status_to_pam(result);

	DEBUG(NT_STATUS_IS_OK(result) ? 5 : 2, 
	      ("NTLM CRAP authentication for user [%s]\\[%s] returned %s (PAM: %d)\n", 
	       name_domain,
	       name_user,
	       state->response.data.auth.nt_status_string,
	       state->response.data.auth.pam_error));	      

	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

/* Change a user password */

void winbindd_pam_chauthtok(struct winbindd_cli_state *state)
{
	NTSTATUS result;
	char *oldpass, *newpass;
	fstring domain, user;
	POLICY_HND dom_pol;
	struct winbindd_domain *contact_domain;
	struct rpc_pipe_client *cli;

	DEBUG(3, ("[%5lu]: pam chauthtok %s\n", (unsigned long)state->pid,
		state->request.data.chauthtok.user));

	/* Setup crap */

	parse_domain_user(state->request.data.chauthtok.user, domain, user);

	if (!(contact_domain = find_domain_from_name(domain))) {
		DEBUG(3, ("Cannot change password for [%s] -> [%s]\\[%s] as %s is not a trusted domain\n", 
			  state->request.data.chauthtok.user, domain, user, domain)); 
		result = NT_STATUS_NO_SUCH_USER;
		goto done;
	}

	/* Change password */

	oldpass = state->request.data.chauthtok.oldpass;
	newpass = state->request.data.chauthtok.newpass;

	/* Get sam handle */

	result = cm_connect_sam(contact_domain, state->mem_ctx, &cli,
				&dom_pol);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(1, ("could not get SAM handle on DC for %s\n", domain));
		goto done;
	}

	result = rpccli_samr_chgpasswd_user(cli, state->mem_ctx, user, newpass,
					    oldpass);

done:    
	state->response.data.auth.nt_status = NT_STATUS_V(result);
	fstrcpy(state->response.data.auth.nt_status_string, nt_errstr(result));
	fstrcpy(state->response.data.auth.error_string, nt_errstr(result));
	state->response.data.auth.pam_error = nt_status_to_pam(result);

	DEBUG(NT_STATUS_IS_OK(result) ? 5 : 2, 
	      ("Password change for user [%s]\\[%s] returned %s (PAM: %d)\n", 
	       domain,
	       user,
	       state->response.data.auth.nt_status_string,
	       state->response.data.auth.pam_error));	      

	if (NT_STATUS_IS_OK(result))
		request_ok(state);
	else
		request_error(state);
}
