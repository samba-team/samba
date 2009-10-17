/* 
   Unix SMB/CIFS implementation.

   Winbind daemon - user related functions

   Copyright (C) Tim Potter 2000
   Copyright (C) Jeremy Allison 2001.
   Copyright (C) Gerald (Jerry) Carter 2003.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

/* Wrapper for domain->methods->query_user, only on the parent->child pipe */

enum winbindd_result winbindd_dual_userinfo(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state)
{
	DOM_SID sid;
	struct wbint_userinfo user_info;
	NTSTATUS status;

	/* Ensure null termination */
	state->request->data.sid[sizeof(state->request->data.sid)-1]='\0';

	DEBUG(3, ("[%5lu]: lookupsid %s\n", (unsigned long)state->pid,
		  state->request->data.sid));

	if (!string_to_sid(&sid, state->request->data.sid)) {
		DEBUG(5, ("%s not a SID\n", state->request->data.sid));
		return WINBINDD_ERROR;
	}

	status = domain->methods->query_user(domain, state->mem_ctx,
					     &sid, &user_info);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("error getting user info for sid %s\n",
			  sid_string_dbg(&sid)));
		return WINBINDD_ERROR;
	}

	fstrcpy(state->response->data.user_info.acct_name,
		user_info.acct_name);
	fstrcpy(state->response->data.user_info.full_name,
		user_info.full_name);
	fstrcpy(state->response->data.user_info.homedir, user_info.homedir);
	fstrcpy(state->response->data.user_info.shell, user_info.shell);
	state->response->data.user_info.primary_gid = user_info.primary_gid;
	if (!sid_peek_check_rid(&domain->sid, &user_info.group_sid,
				&state->response->data.user_info.group_rid)) {
		DEBUG(1, ("Could not extract group rid out of %s\n",
			  sid_string_dbg(&sid)));
		return WINBINDD_ERROR;
	}

	return WINBINDD_OK;
}
