/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   Winbind daemon - miscellaneous other functions

   Copyright (C) Tim Potter 2000
   
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

/* Some routines to fetch the trust account password from a HEAD
   version of Samba.  Yuck.  )-: */

/************************************************************************
form a key for fetching a domain trust password from
************************************************************************/
static char *trust_keystr(char *domain)
{
	static fstring keystr;

	snprintf(keystr,sizeof(keystr),"%s/%s", SECRETS_MACHINE_ACCT_PASS, 
		 domain);

	return keystr;
}

/************************************************************************
 Routine to get the trust account password for a domain
************************************************************************/
BOOL _get_trust_account_password(char *domain, unsigned char *ret_pwd, 
				 time_t *pass_last_set_time)
{
	struct machine_acct_pass *pass;
	size_t size;

	if (!(pass = secrets_fetch(trust_keystr(domain), &size)) ||
	    size != sizeof(*pass)) return False;

	if (pass_last_set_time) *pass_last_set_time = pass->mod_time;
	memcpy(ret_pwd, pass->hash, 16);
	free(pass);
	return True;
}

/* Check the machine account password is valid */

enum winbindd_result winbindd_check_machine_acct(
	struct winbindd_cli_state *state)
{
	int result = WINBINDD_ERROR;
	uchar trust_passwd[16];
	struct in_addr *ip_list = NULL;
	int count;
	uint16 validation_level;
	fstring controller, trust_account;
        int num_retries = 0;

	DEBUG(3, ("[%5d]: check machine account\n", state->pid));

	/* Get trust account password */

 again:
	if (!_get_trust_account_password(lp_workgroup(), trust_passwd, 
                                         NULL)) {
		result = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	/* Get domain controller */

	if (!get_dc_list(True, lp_workgroup(), &ip_list, &count) ||
	    !lookup_pdc_name(global_myname, lp_workgroup(), &ip_list[0],
			     controller)) {
		DEBUG(0, ("could not find domain controller for "
			  "domain %s\n", lp_workgroup()));		  
		result = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
		goto done;
	}

	DEBUG(3, ("contacting controller %s to check secret\n", controller));

	/* Contact domain controller to check secret */

        slprintf(trust_account, sizeof(trust_account) - 1, "%s$",
                 global_myname);

#if 0 /* XXX */
        result = cli_nt_setup_creds(controller, lp_workgroup(), global_myname,
                                    trust_account, trust_passwd, 
                                    SEC_CHAN_WKSTA, &validation_level);	
#endif

        /* There is a race condition between fetching the trust account
           password and joining the domain so it's possible that the trust
           account password has been changed on us.  We are returned
           NT_STATUS_ACCESS_DENIED if this happens. */

#define MAX_RETRIES 8

        if ((num_retries < MAX_RETRIES) && 
            result == NT_STATUS_ACCESS_DENIED) {
                num_retries++;
                goto again;
        }

	/* Pass back result code - zero for success, other values for
	   specific failures. */

	DEBUG(3, ("secret is %s\n", (result == NT_STATUS_NOPROBLEMO) ?
		  "good" : "bad"));

 done:
	state->response.data.num_entries = result;
	return WINBINDD_OK;
}

enum winbindd_result winbindd_list_trusted_domains(struct winbindd_cli_state
						   *state)
{
	struct winbindd_domain *domain;
	int total_entries = 0, extra_data_len = 0;
	char *ted, *extra_data = NULL;

	DEBUG(3, ("[%5d]: list trusted domains\n", state->pid));

	for(domain = domain_list; domain; domain = domain->next) {

		/* Skip own domain */

		if (strequal(domain->name, lp_workgroup())) continue;

		/* Add domain to list */

		total_entries++;
		ted = Realloc(extra_data, sizeof(fstring) *
				     total_entries);

		if (!ted) {
			DEBUG(0,("winbindd_list_trusted_domains: failed to enlarge buffer!\n"));
			if (extra_data)
				free(extra_data);
			return WINBINDD_ERROR;
        } else
			extra_data = ted;

		memcpy(&extra_data[extra_data_len], domain->name,
		       strlen(domain->name));

		extra_data_len  += strlen(domain->name);
		extra_data[extra_data_len++] = ',';
	}

	if (extra_data) {
		if (extra_data_len > 1) extra_data[extra_data_len - 1] = '\0';
		state->response.extra_data = extra_data;
		state->response.length += extra_data_len;
	}

	return WINBINDD_OK;
}
