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
	fstring dos_domain;
	size_t size;

	fstrcpy(dos_domain, domain);
	unix_to_dos(dos_domain, True);

	if (!(pass = secrets_fetch(trust_keystr(dos_domain), &size)) ||
	    size != sizeof(*pass)) return False;

	if (pass_last_set_time) *pass_last_set_time = pass->mod_time;
	memcpy(ret_pwd, pass->hash, 16);
	free(pass);
	return True;
}

/* Check the machine account password is valid */

extern struct in_addr ipzero;

static uint32 check_any(char *trust_account, uchar trust_passwd[16])
{
	struct in_addr *ip_list = NULL, pdc_ip = ipzero;
	uint16 validation_level;
	fstring controller;
	uint32 result;
	int count, i;

	/* Always try the PDC first */

	if (!get_dc_list(True, lp_workgroup(), &ip_list, &count) ||
	    !lookup_pdc_name(global_myname, lp_workgroup(), &ip_list[0],
			     controller)) {

		/* Now this isn't fatal as we can still check for backup
		   domain controllers so just continue. */

		DEBUG(3, ("could not find primary domain controller for "
			  "domain %s\n", lp_workgroup()));		  
		
		goto try_others;
	}

	pdc_ip = ip_list[0];

	DEBUG(3, ("contacting PDC %s to check secret\n", controller));

        result = cli_nt_setup_creds(controller, lp_workgroup(), global_myname,
                                    trust_account, trust_passwd, 
                                    SEC_CHAN_WKSTA, &validation_level);	
	
	safe_free(ip_list);
	return 0;

	if (result == NT_STATUS_NOPROBLEMO) {
		safe_free(ip_list);
		return result;
	}

	/* OK, now try other domain controllers */
	
 try_others:

	safe_free(ip_list);
	ip_list = NULL;

	if (!get_dc_list(False, lp_workgroup(), &ip_list, &count)) {
		DEBUG(0, ("could not find domain controller for "
			  "domain %s\n", lp_workgroup()));
		safe_free(ip_list);
		return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	}

	/* If none of the domain controllers can be contacted then we
	   return domain controller not found. */

	result = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;

	for (i = 0; i < count; i++) {
		fstring srv_name;

		if (ip_equal(pdc_ip, ip_list[i]))
			continue;

		if (!name_status_find(lp_workgroup(), 0x1c, 0x20, ip_list[i], srv_name))
			continue;

		DEBUG(3, ("contacting dc %s to check secret\n", srv_name));

		result = cli_nt_setup_creds(srv_name, lp_workgroup(), 
					    global_myname, trust_account, 
					    trust_passwd, SEC_CHAN_WKSTA, 
					    &validation_level);	

		if (result == NT_STATUS_NOPROBLEMO)
			break;
	}

	safe_free(ip_list);
	return result;
}

static uint32 check_passwordserver(char *trust_account, uchar trust_passwd[16])
{
	uint32 result = NT_STATUS_INTERNAL_ERROR;
	uint16 validation_level;
	fstring remote_machine;
	char *pserver;

	pserver = lp_passwordserver();

	while(next_token(&pserver, remote_machine, LIST_SEP, 
			 sizeof(remote_machine))) {
		fstring srv_name;

		/* Look up name if ip address */
		
		if (is_ipaddress(remote_machine)) {
			struct in_addr ip;

			inet_aton(remote_machine, &ip);

			if (!name_status_find(lp_workgroup(), 0x1c, 0x20, ip, srv_name)) {
				DEBUG(3, ("invalid server %s\n",
					  remote_machine));
				continue;
			}
		} else
			fstrcpy(srv_name, remote_machine);

		/* Contact dc */

		result = cli_nt_setup_creds(srv_name, lp_workgroup(),
					    global_myname, trust_account,
					    trust_passwd, SEC_CHAN_WKSTA,
					    &validation_level);

		if (result == NT_STATUS_NOPROBLEMO)
			break;
	}

	return result;
}

enum winbindd_result winbindd_check_machine_acct(
	struct winbindd_cli_state *state)
{
	uint32 result = NT_STATUS_INTERNAL_ERROR;
	uchar trust_passwd[16];
	fstring trust_account;
        BOOL use_dc_only = False;
        int num_retries = 0;
	char *p;

	DEBUG(3, ("[%5d]: check machine account\n", state->pid));

	/* Get trust account name and password */

 again:
	if (!_get_trust_account_password(lp_workgroup(), trust_passwd, 
                                         NULL)) {
		DEBUG(0, ("unable to get trust accound password for domain "
                          "%s", lp_workgroup()));
		goto done;
	}

        slprintf(trust_account, sizeof(trust_account) - 1, "%s$",
                 global_myname);

	/* Check secret */

	p = lp_passwordserver();
	if (strequal(p, "") || use_dc_only)
		p = "*";

	if (strequal(p, "*")) {
		result = check_any(trust_account, trust_passwd);
	} else {
		result = check_passwordserver(trust_account, trust_passwd);
	}

        /* There is a race condition between fetching the trust account
           password and joining the domain so it's possible that the trust
           account password has been changed on us.  We are returned
           NT_STATUS_ACCESS_DENIED if this happens. */

#define MAX_RETRIES 8

        if ((num_retries < MAX_RETRIES) && 
            result == NT_STATUS_ACCESS_DENIED) {
                num_retries++;
                use_dc_only = True;
                goto again;
        }

	if (result != NT_STATUS_INTERNAL_ERROR) {
		DEBUG(3, ("secret is %s\n", (result == NT_STATUS_NOPROBLEMO) ?
			  "good" : "bad"));
	}

	/* Return result */

 done:
	state->response.data.num_entries = result;
	return WINBINDD_OK;
}

enum winbindd_result winbindd_list_trusted_domains(struct winbindd_cli_state
						   *state)
{
	struct winbindd_domain *domain;
	int total_entries = 0, extra_data_len = 0;
	char *extra_data = NULL;

	DEBUG(3, ("[%5d]: list trusted domains\n", state->pid));

	for(domain = domain_list; domain; domain = domain->next) {

		/* Skip own domain */

		if (strequal(domain->name, lp_workgroup())) continue;

		/* Add domain to list */

		total_entries++;
		extra_data = Realloc(extra_data, sizeof(fstring) * 
				     total_entries);

		if (!extra_data) return WINBINDD_ERROR;

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
