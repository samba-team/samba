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

/************************************************************************
form a key for fetching a domain trust password
************************************************************************/
static char *trust_keystr(char *domain)
{
	static fstring keystr;
	slprintf(keystr,sizeof(keystr),"%s/%s", SECRETS_MACHINE_ACCT_PASS, domain);
	return keystr;
}

/************************************************************************
 Routine to get the trust account password for a domain.
************************************************************************/
static BOOL _get_trust_account_password(char *domain, unsigned char *ret_pwd, 
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

enum winbindd_result winbindd_check_machine_acct(struct winbindd_cli_state
						 *state)
{
	uchar trust_passwd[16], ntpw[16], lmpw[16];
	extern pstring global_myname;
	NET_USER_INFO_3 info3;
	fstring server;
	uint32 status;

	/* Get trust account password */

	if (!_get_trust_account_password(lp_workgroup(), trust_passwd,
					 NULL)) {
		return WINBINDD_ERROR;
	}

	/* Check password of non-existent user */

	nt_lm_owf_gen("__dummy__", ntpw, lmpw);
	
	slprintf(server, sizeof(server), "\\\\%s", server_state.controller);

	ZERO_STRUCT(info3);

	status = domain_client_validate_backend(server, 
					        "__dummy__", lp_workgroup(),
						global_myname, SEC_CHAN_WKSTA,
						trust_passwd,
						NULL,
						lmpw, sizeof(lmpw),
						ntpw, sizeof(ntpw), &info3);

	/* Secret is good if status code is NT_STATUS_NO_SUCH_USER */

	state->response.data.num_entries = (status == NT_STATUS_NO_SUCH_USER);

	return WINBINDD_OK;
}

enum winbindd_result winbindd_list_trusted_domains(struct winbindd_cli_state
						   *state)
{
	struct winbindd_domain *domain;
	int total_entries = 0, extra_data_len = 0;
	char *extra_data = NULL;

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
