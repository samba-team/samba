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

#include "winbindd.h"

extern pstring global_myname;

/* Check the machine account password is valid */

enum winbindd_result winbindd_check_machine_acct(struct winbindd_cli_state *state)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uchar trust_passwd[16];
        int num_retries = 0;
        struct cli_state *cli;
	DEBUG(3, ("[%5d]: check machine account\n", state->pid));

	/* Get trust account password */

 again:
	if (!secrets_fetch_trust_account_password(
		    lp_workgroup(), trust_passwd, NULL)) {
		result = NT_STATUS_INTERNAL_ERROR;
		DEBUG(3, ("could not retrieve trust account pw for %s\n", lp_workgroup()));
		goto done;
	}

        /* This call does a cli_nt_setup_creds() which implicitly checks
           the trust account password. */

	/* Don't shut this down - it belongs to the connection cache code */
        result = cm_get_netlogon_cli(lp_workgroup(), trust_passwd, &cli);

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
	fstrcpy(state->response.data.auth.nt_status_string, get_nt_error_msg(result));
	fstrcpy(state->response.data.auth.error_string, get_nt_error_msg(result));
	/*state->response.data.auth.pam_error = nt_status_to_pam(result);*/

	return WINBINDD_OK;
}

enum winbindd_result winbindd_list_trusted_domains(struct winbindd_cli_state
						   *state)
{
	struct winbindd_domain *domain;
	int total_entries = 0, extra_data_len = 0;
	char *ted, *extra_data = NULL;

	DEBUG(3, ("[%5d]: list trusted domains\n", state->pid));

	/* We need to refresh the trusted domain list as the domains may
	   have changed since we last looked.  There may be a sequence
	   number or something we should use but I haven't found it yet. */

	init_domain_list();

	for(domain = domain_list(); domain; domain = domain->next) {

		/* Skip own domain */

		if (strequal(domain->name, lp_workgroup())) continue;

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

	DEBUG(3, ("[%5d]: show sequence\n", state->pid));

	extra_data = strdup("");

	/* this makes for a very simple data format, and is easily parsable as well
	   if that is ever needed */
	for (domain = domain_list(); domain; domain = domain->next) {
		char *s;

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

enum winbindd_result winbindd_ping(struct winbindd_cli_state
						   *state)
{
	DEBUG(3, ("[%5d]: ping\n", state->pid));

	return WINBINDD_OK;
}

/* List various tidbits of information */

enum winbindd_result winbindd_info(struct winbindd_cli_state *state)
{

	DEBUG(3, ("[%5d]: request misc info\n", state->pid));

	state->response.data.info.winbind_separator = *lp_winbind_separator();
	fstrcpy(state->response.data.info.samba_version, VERSION);

	return WINBINDD_OK;
}

/* Tell the client the current interface version */

enum winbindd_result winbindd_interface_version(struct winbindd_cli_state *state)
{

	DEBUG(3, ("[%5d]: request interface version\n", state->pid));
	
	state->response.data.interface_version = WINBIND_INTERFACE_VERSION;

	return WINBINDD_OK;
}

/* What domain are we a member of? */

enum winbindd_result winbindd_domain_name(struct winbindd_cli_state *state)
{

	DEBUG(3, ("[%5d]: request domain name\n", state->pid));
	
	fstrcpy(state->response.data.domain_name, lp_workgroup());

	return WINBINDD_OK;
}
