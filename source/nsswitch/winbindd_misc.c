/* 
   Unix SMB/CIFS implementation.

   Winbind daemon - miscellaneous other functions

   Copyright (C) Tim Potter      2000
   Copyright (C) Andrew Bartlett 2002
   
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

/* Check the machine account password is valid */

enum winbindd_result winbindd_check_machine_acct(struct winbindd_cli_state *state)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uchar trust_passwd[16];
        int num_retries = 0;
        struct cli_state *cli;
	uint32 sec_channel_type;
	struct winbindd_domain *contact_domain;

	DEBUG(3, ("[%5lu]: check machine account\n", (unsigned long)state->pid));

	/* Get trust account password */

 again:
	if (!secrets_fetch_trust_account_password(
		    lp_workgroup(), trust_passwd, NULL, &sec_channel_type)) {
		result = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}


	contact_domain = find_our_domain();
        if (!contact_domain) {
		result = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
                DEBUG(1, ("Cannot find our own domain!\n"));
                goto done;
        }
	
        /* This call does a cli_nt_setup_creds() which implicitly checks
           the trust account password. */
	/* Don't shut this down - it belongs to the connection cache code */
	
        result = cm_get_netlogon_cli(contact_domain,
		trust_passwd, sec_channel_type, True, &cli);

        if (!NT_STATUS_IS_OK(result)) {
                DEBUG(3, ("could not open handle to NETLOGON pipe\n"));
                goto done;
        }

        /* There is a race condition between fetching the trust account
           password and the periodic machine password change.  So it's 
	   possible that the trust account password has been changed on us.  
	   We are returned NT_STATUS_ACCESS_DENIED if this happens. */

#define MAX_RETRIES 8

        if ((num_retries < MAX_RETRIES) && 
            NT_STATUS_V(result) == NT_STATUS_V(NT_STATUS_ACCESS_DENIED)) {
                num_retries++;
                goto again;
        }

	/* Pass back result code - zero for success, other values for
	   specific failures. */

	DEBUG(3, ("secret is %s\n", NT_STATUS_IS_OK(result) ?  
                  "good" : "bad"));

 done:
	state->response.data.auth.nt_status = NT_STATUS_V(result);
	fstrcpy(state->response.data.auth.nt_status_string, nt_errstr(result));
	fstrcpy(state->response.data.auth.error_string, nt_errstr(result));
	state->response.data.auth.pam_error = nt_status_to_pam(result);

	DEBUG(NT_STATUS_IS_OK(result) ? 5 : 2, ("Checking the trust account password returned %s\n", 
						state->response.data.auth.nt_status_string));

	return NT_STATUS_IS_OK(result) ? WINBINDD_OK : WINBINDD_ERROR;
}

enum winbindd_result winbindd_list_trusted_domains(struct winbindd_cli_state
						   *state)
{
	struct winbindd_domain *domain;
	int total_entries = 0, extra_data_len = 0;
	char *ted, *extra_data = NULL;

	DEBUG(3, ("[%5lu]: list trusted domains\n", (unsigned long)state->pid));

	/* We need to refresh the trusted domain list as the domains may
	   have changed since we last looked.  There may be a sequence
	   number or something we should use but I haven't found it yet. */

	if (!init_domain_list()) {
		DEBUG(1, ("winbindd_list_trusted_domains: could not "
			  "refresh trusted domain list\n"));
		return WINBINDD_ERROR;
	}

	for(domain = domain_list(); domain; domain = domain->next) {

		/* Skip own domain */

		if (domain->primary) continue;

		/* Add domain to list */

		total_entries++;
		ted = Realloc(extra_data, sizeof(fstring) * 
                              total_entries);

		if (!ted) {
			DEBUG(0,("winbindd_list_trusted_domains: failed to enlarge buffer!\n"));
			SAFE_FREE(extra_data);
			return WINBINDD_ERROR;
		} else 
                        extra_data = ted;

		memcpy(&extra_data[extra_data_len], domain->name,
		       strlen(domain->name));

		extra_data_len  += strlen(domain->name);
		extra_data[extra_data_len++] = ',';
	}

	if (extra_data) {
		if (extra_data_len > 1) 
                        extra_data[extra_data_len - 1] = '\0';
		state->response.extra_data = extra_data;
		state->response.length += extra_data_len;
	}

	return WINBINDD_OK;
}


enum winbindd_result winbindd_show_sequence(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain;
	char *extra_data = NULL;
	const char *which_domain;

	DEBUG(3, ("[%5lu]: show sequence\n", (unsigned long)state->pid));

	/* Ensure null termination */
	state->request.domain_name[sizeof(state->request.domain_name)-1]='\0';	
	which_domain = state->request.domain_name;

	extra_data = strdup("");

	/* this makes for a very simple data format, and is easily parsable as well
	   if that is ever needed */
	for (domain = domain_list(); domain; domain = domain->next) {
		char *s;

		/* if we have a domain name restricting the request and this
		   one in the list doesn't match, then just bypass the remainder
		   of the loop */

		if ( *which_domain && !strequal(which_domain, domain->name) )
			continue;

		domain->methods->sequence_number(domain, &domain->sequence_number);
		
		if (DOM_SEQUENCE_NONE == (unsigned)domain->sequence_number) {
			asprintf(&s,"%s%s : DISCONNECTED\n", extra_data, 
				 domain->name);
		} else {
			asprintf(&s,"%s%s : %u\n", extra_data, 
				 domain->name, (unsigned)domain->sequence_number);
		}
		free(extra_data);
		extra_data = s;
	}

	state->response.extra_data = extra_data;
	/* must add one to length to copy the 0 for string termination */
	state->response.length += strlen(extra_data) + 1;

	return WINBINDD_OK;
}

enum winbindd_result winbindd_domain_info(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain;

	DEBUG(3, ("[%5lu]: domain_info [%s]\n", (unsigned long)state->pid,
		  state->request.domain_name));

	domain = find_domain_from_name(state->request.domain_name);

	if (domain == NULL) {
		DEBUG(3, ("Did not find domain [%s]\n",
			  state->request.domain_name));
		return WINBINDD_ERROR;
	}

	fstrcpy(state->response.data.domain_info.name, domain->name);
	fstrcpy(state->response.data.domain_info.alt_name, domain->alt_name);
	fstrcpy(state->response.data.domain_info.sid,
		sid_string_static(&domain->sid));
	
	state->response.data.domain_info.native_mode = domain->native_mode;
	state->response.data.domain_info.active_directory = domain->active_directory;
	state->response.data.domain_info.primary = domain->primary;

	state->response.data.domain_info.sequence_number =
		domain->sequence_number;

	return WINBINDD_OK;
}

enum winbindd_result winbindd_ping(struct winbindd_cli_state
						   *state)
{
	DEBUG(3, ("[%5lu]: ping\n", (unsigned long)state->pid));

	return WINBINDD_OK;
}

/* List various tidbits of information */

enum winbindd_result winbindd_info(struct winbindd_cli_state *state)
{

	DEBUG(3, ("[%5lu]: request misc info\n", (unsigned long)state->pid));

	state->response.data.info.winbind_separator = *lp_winbind_separator();
	fstrcpy(state->response.data.info.samba_version, SAMBA_VERSION_STRING);

	return WINBINDD_OK;
}

/* Tell the client the current interface version */

enum winbindd_result winbindd_interface_version(struct winbindd_cli_state *state)
{

	DEBUG(3, ("[%5lu]: request interface version\n", (unsigned long)state->pid));
	
	state->response.data.interface_version = WINBIND_INTERFACE_VERSION;

	return WINBINDD_OK;
}

/* What domain are we a member of? */

enum winbindd_result winbindd_domain_name(struct winbindd_cli_state *state)
{

	DEBUG(3, ("[%5lu]: request domain name\n", (unsigned long)state->pid));
	
	fstrcpy(state->response.data.domain_name, lp_workgroup());

	return WINBINDD_OK;
}

/* What's my name again? */

enum winbindd_result winbindd_netbios_name(struct winbindd_cli_state *state)
{

	DEBUG(3, ("[%5lu]: request netbios name\n", (unsigned long)state->pid));
	
	fstrcpy(state->response.data.netbios_name, global_myname());

	return WINBINDD_OK;
}

/* Where can I find the privilaged pipe? */

enum winbindd_result winbindd_priv_pipe_dir(struct winbindd_cli_state *state)
{

	DEBUG(3, ("[%5lu]: request location of privileged pipe\n", (unsigned long)state->pid));
	
	state->response.extra_data = strdup(get_winbind_priv_pipe_dir());
	if (!state->response.extra_data)
		return WINBINDD_ERROR;

	/* must add one to length to copy the 0 for string termination */
	state->response.length += strlen((char *)state->response.extra_data) + 1;

	return WINBINDD_OK;
}
