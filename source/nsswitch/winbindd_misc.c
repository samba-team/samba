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

enum winbindd_result winbindd_check_machine_acct(struct winbindd_cli_state
						 *state)
{
	return WINBINDD_ERROR;
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
