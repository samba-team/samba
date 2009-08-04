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

bool fillup_pw_field(const char *lp_template,
			    const char *username,
			    const char *domname,
			    uid_t uid,
			    gid_t gid,
			    const char *in,
			    fstring out)
{
	char *templ;

	if (out == NULL)
		return False;

	/* The substitution of %U and %D in the 'template
	   homedir' is done by talloc_sub_specified() below.
	   If we have an in string (which means the value has already
	   been set in the nss_info backend), then use that.
	   Otherwise use the template value passed in. */

	if ( in && !strequal(in,"") && lp_security() == SEC_ADS ) {
		templ = talloc_sub_specified(NULL, in,
					     username, domname,
				     uid, gid);
	} else {
		templ = talloc_sub_specified(NULL, lp_template,
					     username, domname,
					     uid, gid);
	}

	if (!templ)
		return False;

	safe_strcpy(out, templ, sizeof(fstring) - 1);
	TALLOC_FREE(templ);

	return True;

}
/* Fill a pwent structure with information we have obtained */

static bool winbindd_fill_pwent(TALLOC_CTX *ctx, char *dom_name, char *user_name,
				DOM_SID *user_sid, DOM_SID *group_sid,
				char *full_name, char *homedir, char *shell,
				struct winbindd_pw *pw)
{
	fstring output_username;
	char *mapped_name = NULL;
	struct winbindd_domain *domain = NULL;
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;

	if (!pw || !dom_name || !user_name)
		return False;

	domain = find_domain_from_name_noinit(dom_name);
	if (domain == NULL) {
		DEBUG(5,("winbindd_fill_pwent: Failed to find domain for %s.\n",
			 dom_name));
		nt_status = NT_STATUS_NO_SUCH_DOMAIN;
		return false;
	}

	/* Resolve the uid number */

	if (!NT_STATUS_IS_OK(idmap_sid_to_uid(domain->have_idmap_config ?
					      dom_name : "", user_sid,
					      &pw->pw_uid))) {
		DEBUG(1, ("error getting user id for sid %s\n",
			  sid_string_dbg(user_sid)));
		return False;
	}

	/* Resolve the gid number */

	if (!NT_STATUS_IS_OK(idmap_sid_to_gid(domain->have_idmap_config ?
					      dom_name : "", group_sid,
					      &pw->pw_gid))) {
		DEBUG(1, ("error getting group id for sid %s\n",
			  sid_string_dbg(group_sid)));
		return False;
	}

	/* Username */

	strlower_m(user_name);
	nt_status = normalize_name_map(ctx, domain, user_name, &mapped_name);

	/* Basic removal of whitespace */
	if (NT_STATUS_IS_OK(nt_status)) {
		fill_domain_username(output_username, dom_name, mapped_name, True);
	}
	/* Complete name replacement */
	else if (NT_STATUS_EQUAL(nt_status, NT_STATUS_FILE_RENAMED)) {
		fstrcpy(output_username, mapped_name);
	}
	/* No change at all */
	else {
		fill_domain_username(output_username, dom_name, user_name, True);
	}

	safe_strcpy(pw->pw_name, output_username, sizeof(pw->pw_name) - 1);

	/* Full name (gecos) */

	safe_strcpy(pw->pw_gecos, full_name, sizeof(pw->pw_gecos) - 1);

	/* Home directory and shell */

	if (!fillup_pw_field(lp_template_homedir(), user_name, dom_name,
			     pw->pw_uid, pw->pw_gid, homedir, pw->pw_dir))
		return False;

	if (!fillup_pw_field(lp_template_shell(), user_name, dom_name,
			     pw->pw_uid, pw->pw_gid, shell, pw->pw_shell))
		return False;

	/* Password - set to "*" as we can't generate anything useful here.
	   Authentication can be done using the pam_winbind module. */

	safe_strcpy(pw->pw_passwd, "*", sizeof(pw->pw_passwd) - 1);

	return True;
}

/* Wrapper for domain->methods->query_user, only on the parent->child pipe */

enum winbindd_result winbindd_dual_userinfo(struct winbindd_domain *domain,
					    struct winbindd_cli_state *state)
{
	DOM_SID sid;
	WINBIND_USERINFO user_info;
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

/*
 * set/get/endpwent functions
 */

/* Rewind file pointer for ntdom passwd database */

static bool winbindd_setpwent_internal(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain;

	DEBUG(3, ("[%5lu]: setpwent\n", (unsigned long)state->pid));

	/* Check user has enabled this */

	if (!lp_winbind_enum_users()) {
		return False;
	}

	/* Free old static data if it exists */

	if (state->getpwent_state != NULL) {
		free_getent_state(state->getpwent_state);
		state->getpwent_state = NULL;
	}

	/* Create sam pipes for each domain we know about */

	for(domain = domain_list(); domain != NULL; domain = domain->next) {
		struct getent_state *domain_state;


		/* don't add our domaina if we are a PDC or if we
		   are a member of a Samba domain */

		if ((IS_DC || lp_winbind_trusted_domains_only())
			&& strequal(domain->name, lp_workgroup())) {
			continue;
		}

		/* Create a state record for this domain */

		domain_state = SMB_MALLOC_P(struct getent_state);
		if (!domain_state) {
			DEBUG(0, ("malloc failed\n"));
			return False;
		}

		ZERO_STRUCTP(domain_state);

		fstrcpy(domain_state->domain_name, domain->name);

		/* Add to list of open domains */

		DLIST_ADD(state->getpwent_state, domain_state);
	}

	state->getpwent_initialized = True;
	return True;
}

void winbindd_setpwent(struct winbindd_cli_state *state)
{
	if (winbindd_setpwent_internal(state)) {
		request_ok(state);
	} else {
		request_error(state);
	}
}

/* Close file pointer to ntdom passwd database */

void winbindd_endpwent(struct winbindd_cli_state *state)
{
	DEBUG(3, ("[%5lu]: endpwent\n", (unsigned long)state->pid));

	free_getent_state(state->getpwent_state);
	state->getpwent_initialized = False;
	state->getpwent_state = NULL;
	request_ok(state);
}

/* Get partial list of domain users for a domain.  We fill in the sam_entries,
   and num_sam_entries fields with domain user information.  The dispinfo_ndx
   field is incremented to the index of the next user to fetch.  Return True if
   some users were returned, False otherwise. */

static bool get_sam_user_entries(struct getent_state *ent, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	uint32 num_entries;
	WINBIND_USERINFO *info;
	struct getpwent_user *name_list = NULL;
	struct winbindd_domain *domain;
	struct winbindd_methods *methods;
	unsigned int i;

	if (ent->num_sam_entries)
		return False;

	if (!(domain = find_domain_from_name(ent->domain_name))) {
		DEBUG(3, ("no such domain %s in get_sam_user_entries\n",
			  ent->domain_name));
		return False;
	}

	methods = domain->methods;

	/* Free any existing user info */

	SAFE_FREE(ent->sam_entries);
	ent->num_sam_entries = 0;

	/* Call query_user_list to get a list of usernames and user rids */

	num_entries = 0;

	status = methods->query_user_list(domain, mem_ctx, &num_entries, &info);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("get_sam_user_entries: "
			  "query_user_list failed with %s\n",
			  nt_errstr(status)));
		return False;
	}

	if (num_entries) {
		name_list = SMB_REALLOC_ARRAY(name_list, struct getpwent_user,
					    ent->num_sam_entries + num_entries);
		if (!name_list) {
			DEBUG(0,("get_sam_user_entries realloc failed.\n"));
			return False;
		}
	}

	for (i = 0; i < num_entries; i++) {
		/* Store account name and gecos */
		if (!info[i].acct_name) {
			fstrcpy(name_list[ent->num_sam_entries + i].name, "");
		} else {
			fstrcpy(name_list[ent->num_sam_entries + i].name,
				info[i].acct_name);
		}
		if (!info[i].full_name) {
			fstrcpy(name_list[ent->num_sam_entries + i].gecos, "");
		} else {
			fstrcpy(name_list[ent->num_sam_entries + i].gecos,
				info[i].full_name);
		}
		if (!info[i].homedir) {
			fstrcpy(name_list[ent->num_sam_entries + i].homedir,"");
		} else {
			fstrcpy(name_list[ent->num_sam_entries + i].homedir,
				info[i].homedir);
		}
		if (!info[i].shell) {
			fstrcpy(name_list[ent->num_sam_entries + i].shell, "");
		} else {
			fstrcpy(name_list[ent->num_sam_entries + i].shell,
				info[i].shell);
		}


		/* User and group ids */
		sid_copy(&name_list[ent->num_sam_entries+i].user_sid,
			 &info[i].user_sid);
		sid_copy(&name_list[ent->num_sam_entries+i].group_sid,
			 &info[i].group_sid);
	}

	ent->num_sam_entries += num_entries;

	/* Fill in remaining fields */

	ent->sam_entries = name_list;
	ent->sam_entry_index = 0;
	return ent->num_sam_entries > 0;
}

/* Fetch next passwd entry from ntdom database */

#define MAX_GETPWENT_USERS 500

void winbindd_getpwent(struct winbindd_cli_state *state)
{
	struct getent_state *ent;
	struct winbindd_pw *user_list;
	int num_users, user_list_ndx;

	DEBUG(3, ("[%5lu]: getpwent\n", (unsigned long)state->pid));

	/* Check user has enabled this */

	if (!lp_winbind_enum_users()) {
		request_error(state);
		return;
	}

	/* Allocate space for returning a chunk of users */

	num_users = MIN(MAX_GETPWENT_USERS, state->request->data.num_entries);

	if (num_users == 0) {
		request_error(state);
		return;
	}

	user_list = talloc_zero_array(state->mem_ctx, struct winbindd_pw,
				      num_users);
	if (!user_list) {
		request_error(state);
		return;
	}
	state->response->extra_data.data = user_list;

	if (!state->getpwent_initialized)
		winbindd_setpwent_internal(state);

	if (!(ent = state->getpwent_state)) {
		request_error(state);
		return;
	}

	/* Start sending back users */

	for (user_list_ndx = 0; user_list_ndx < num_users; ) {
		struct getpwent_user *name_list = NULL;
		uint32 result;

		/* Do we need to fetch another chunk of users? */

		if (ent->num_sam_entries == ent->sam_entry_index) {

			while(ent &&
			      !get_sam_user_entries(ent, state->mem_ctx)) {
				struct getent_state *next_ent;

				/* Free state information for this domain */

				SAFE_FREE(ent->sam_entries);

				next_ent = ent->next;
				DLIST_REMOVE(state->getpwent_state, ent);

				SAFE_FREE(ent);
				ent = next_ent;
			}

			/* No more domains */

			if (!ent)
				break;
		}

		name_list = (struct getpwent_user *)ent->sam_entries;

		/* Lookup user info */

		result = winbindd_fill_pwent(
			state->mem_ctx,
			ent->domain_name,
			name_list[ent->sam_entry_index].name,
			&name_list[ent->sam_entry_index].user_sid,
			&name_list[ent->sam_entry_index].group_sid,
			name_list[ent->sam_entry_index].gecos,
			name_list[ent->sam_entry_index].homedir,
			name_list[ent->sam_entry_index].shell,
			&user_list[user_list_ndx]);

		/* Add user to return list */

		if (result) {

			user_list_ndx++;
			state->response->data.num_entries++;
			state->response->length += sizeof(struct winbindd_pw);

		} else
			DEBUG(1, ("could not lookup domain user %s\n",
				  name_list[ent->sam_entry_index].name));

		ent->sam_entry_index++;

	}

	/* Out of domains */

	if (user_list_ndx > 0)
		request_ok(state);
	else
		request_error(state);
}

/* List domain users without mapping to unix ids */
void winbindd_list_users(struct winbindd_cli_state *state)
{
	winbindd_list_ent(state, LIST_USERS);
}
