/* 
   Unix SMB/CIFS implementation.

   Winbind daemon - user related functions

   Copyright (C) Tim Potter 2000,2002
   Copyright (C) Jeremy Allison 2001.
   
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

/* Fill a pwent structure with information we have obtained */

static BOOL winbindd_fill_pwent(char *dom_name, char *user_name, 
				uint32 user_rid, uint32 group_rid, 
				char *full_name, struct winbindd_pw *pw)
{
	extern userdom_struct current_user_info;
	fstring output_username;
	pstring homedir;
	
	if (!pw || !dom_name || !user_name)
		return False;
	
	/* Resolve the uid number */
	
	if (!winbindd_idmap_get_uid_from_rid(dom_name, user_rid, 
					     &pw->pw_uid)) {
		DEBUG(1, ("error getting user id for rid %d\n", user_rid));
		return False;
	}
	
	/* Resolve the gid number */   
	
	if (!winbindd_idmap_get_gid_from_rid(dom_name, group_rid, 
					     &pw->pw_gid)) {
		DEBUG(1, ("error getting group id for rid %d\n", group_rid));
		return False;
	}

	/* Username */

	fill_domain_username(output_username, dom_name, user_name); 

	safe_strcpy(pw->pw_name, output_username, sizeof(pw->pw_name) - 1);
	
	/* Full name (gecos) */
	
	safe_strcpy(pw->pw_gecos, full_name, sizeof(pw->pw_gecos) - 1);

	/* Home directory and shell - use template config parameters.  The
	   defaults are /tmp for the home directory and /bin/false for
	   shell. */
	
	/* The substitution of %U and %D in the 'template homedir' is done
	   by lp_string() calling standard_sub_basic(). */

	fstrcpy(current_user_info.smb_name, user_name);
	sub_set_smb_name(user_name);
	fstrcpy(current_user_info.domain, dom_name);

	pstrcpy(homedir, lp_template_homedir());
	
	safe_strcpy(pw->pw_dir, homedir, sizeof(pw->pw_dir) - 1);
	
	safe_strcpy(pw->pw_shell, lp_template_shell(), 
		    sizeof(pw->pw_shell) - 1);
	
	/* Password - set to "x" as we can't generate anything useful here.
	   Authentication can be done using the pam_winbind module. */

	safe_strcpy(pw->pw_passwd, "x", sizeof(pw->pw_passwd) - 1);
	
	return True;
}

/* Return a password structure from a username.  */

enum winbindd_result winbindd_getpwnam(struct winbindd_cli_state *state) 
{
	uint32 user_rid;
	WINBIND_USERINFO user_info;
	DOM_SID user_sid;
	NTSTATUS status;
	fstring name_domain, name_user;
	enum SID_NAME_USE name_type;
	struct winbindd_domain *domain;
	TALLOC_CTX *mem_ctx;
	
	DEBUG(3, ("[%5d]: getpwnam %s\n", state->pid,
		  state->request.data.username));
	
	/* Parse domain and username */

	if (!parse_domain_user(state->request.data.username, name_domain, 
			       name_user))
		return WINBINDD_ERROR;
	
	if ((domain = find_domain_from_name(name_domain)) == NULL) {
		DEBUG(5, ("no such domain: %s\n", name_domain));
		return WINBINDD_ERROR;
	}
	
	/* Get rid and name type from name */

	if (!winbindd_lookup_sid_by_name(domain, name_user, &user_sid, &name_type)) {
		DEBUG(1, ("user '%s' does not exist\n", name_user));
		return WINBINDD_ERROR;
	}

	if (name_type != SID_NAME_USER) {
		DEBUG(1, ("name '%s' is not a user name: %d\n", name_user, 
			  name_type));
		return WINBINDD_ERROR;
	}
	
	/* Get some user info.  Split the user rid from the sid obtained
	   from the winbind_lookup_by_name() call and use it in a
	   winbind_lookup_userinfo() */
    
	if (!(mem_ctx = talloc_init_named("winbindd_getpwnam([%s]\\[%s])", 
					  name_domain, name_user))) {
		DEBUG(1, ("out of memory\n"));
		return WINBINDD_ERROR;
	}

	sid_split_rid(&user_sid, &user_rid);

	status = domain->methods->query_user(domain, mem_ctx, user_rid, 
					     &user_info);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("error getting user info for user '[%s]\\[%s]'\n", 
			  name_domain, name_user));
		talloc_destroy(mem_ctx);
		return WINBINDD_ERROR;
	}
    
	/* Now take all this information and fill in a passwd structure */	
	if (!winbindd_fill_pwent(name_domain, name_user, 
				 user_rid, user_info.group_rid, 
				 user_info.full_name,
				 &state->response.data.pw)) {
		talloc_destroy(mem_ctx);
		return WINBINDD_ERROR;
	}

	talloc_destroy(mem_ctx);
	
	return WINBINDD_OK;
}       

/* Return a password structure given a uid number */

enum winbindd_result winbindd_getpwuid(struct winbindd_cli_state *state)
{
	DOM_SID user_sid;
	struct winbindd_domain *domain;
	uint32 user_rid;
	fstring dom_name;
	fstring user_name;
	enum SID_NAME_USE name_type;
	WINBIND_USERINFO user_info;
	gid_t gid;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	
	/* Bug out if the uid isn't in the winbind range */

	if ((state->request.data.uid < server_state.uid_low ) ||
	    (state->request.data.uid > server_state.uid_high))
		return WINBINDD_ERROR;

	DEBUG(3, ("[%5d]: getpwuid %d\n", state->pid, 
		  state->request.data.uid));
	
	/* Get rid from uid */

	if (!winbindd_idmap_get_rid_from_uid(state->request.data.uid, 
					     &user_rid, &domain)) {
		DEBUG(1, ("could not convert uid %d to rid\n", 
			  state->request.data.uid));
		return WINBINDD_ERROR;
	}
	
	/* Get name and name type from rid */

	sid_copy(&user_sid, &domain->sid);
	sid_append_rid(&user_sid, user_rid);
	
	if (!winbindd_lookup_name_by_sid(&user_sid, dom_name, user_name, &name_type)) {
		fstring temp;
		
		sid_to_string(temp, &user_sid);
		DEBUG(1, ("could not lookup sid %s\n", temp));
		return WINBINDD_ERROR;
	}
	
	/* Get some user info */
	
	if (!(mem_ctx = talloc_init_named("winbind_getpwuid(%d)",
					  state->request.data.uid))) {

		DEBUG(1, ("out of memory\n"));
		return WINBINDD_ERROR;
	}

	status = domain->methods->query_user(domain, mem_ctx, user_rid, 
					     &user_info);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("error getting user info for user '%s'\n", 
			  user_name));
		talloc_destroy(mem_ctx);
		return WINBINDD_ERROR;
	}
	
	/* Resolve gid number */

	if (!winbindd_idmap_get_gid_from_rid(domain->name, user_info.group_rid, &gid)) {
		DEBUG(1, ("error getting group id for user %s\n", user_name));
		talloc_destroy(mem_ctx);
		return WINBINDD_ERROR;
	}

	/* Fill in password structure */

	if (!winbindd_fill_pwent(domain->name, user_name, user_rid, user_info.group_rid,
				 user_info.full_name, &state->response.data.pw)) {
		talloc_destroy(mem_ctx);
		return WINBINDD_ERROR;
	}
	
	talloc_destroy(mem_ctx);

	return WINBINDD_OK;
}

/*
 * set/get/endpwent functions
 */

/* Rewind file pointer for ntdom passwd database */

enum winbindd_result winbindd_setpwent(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain;
        
	DEBUG(3, ("[%5d]: setpwent\n", state->pid));
        
	/* Check user has enabled this */
        
	if (!lp_winbind_enum_users())
		return WINBINDD_ERROR;

	/* Free old static data if it exists */
        
	if (state->getpwent_state != NULL) {
		free_getent_state(state->getpwent_state);
		state->getpwent_state = NULL;
	}
        
	/* Create sam pipes for each domain we know about */
        
	for(domain = domain_list(); domain != NULL; domain = domain->next) {
		struct getent_state *domain_state;
                
		/*
		 * Skip domains other than WINBINDD_DOMAIN environment
		 * variable.
		 */
                
		if ((strcmp(state->request.domain, "") != 0) &&
				!check_domain_env(state->request.domain, 
						  domain->name))
			continue;

		/* Create a state record for this domain */
                
		if ((domain_state = (struct getent_state *)
		     malloc(sizeof(struct getent_state))) == NULL)
			return WINBINDD_ERROR;
                
		ZERO_STRUCTP(domain_state);

		fstrcpy(domain_state->domain_name, domain->name);

		/* Add to list of open domains */
                
		DLIST_ADD(state->getpwent_state, domain_state);
	}
        
	return WINBINDD_OK;
}

/* Close file pointer to ntdom passwd database */

enum winbindd_result winbindd_endpwent(struct winbindd_cli_state *state)
{
	DEBUG(3, ("[%5d]: endpwent\n", state->pid));

	free_getent_state(state->getpwent_state);    
	state->getpwent_state = NULL;
        
	return WINBINDD_OK;
}

/* Get partial list of domain users for a domain.  We fill in the sam_entries,
   and num_sam_entries fields with domain user information.  The dispinfo_ndx
   field is incremented to the index of the next user to fetch.  Return True if
   some users were returned, False otherwise. */

#define MAX_FETCH_SAM_ENTRIES 100

static BOOL get_sam_user_entries(struct getent_state *ent)
{
	NTSTATUS status;
	uint32 num_entries;
	WINBIND_USERINFO *info;
	struct getpwent_user *name_list = NULL;
	BOOL result = False;
	TALLOC_CTX *mem_ctx;
	struct winbindd_domain *domain;
	struct winbindd_methods *methods;
	int i;

	if (ent->num_sam_entries)
		return False;

	if (!(mem_ctx = talloc_init_named("get_sam_user_entries(%s)",
					  ent->domain_name)))
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

	status = methods->query_user_list(domain, mem_ctx, &num_entries, 
					  &info);
		
	if (num_entries) {
		struct getpwent_user *tnl;
		
		tnl = (struct getpwent_user *)Realloc(name_list, 
						      sizeof(struct getpwent_user) *
						      (ent->num_sam_entries + 
						       num_entries));
		
		if (!tnl) {
			DEBUG(0,("get_sam_user_entries realloc failed.\n"));
			SAFE_FREE(name_list);
			goto done;
		} else
			name_list = tnl;
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
		
		/* User and group ids */
		name_list[ent->num_sam_entries+i].user_rid = info[i].user_rid;
		name_list[ent->num_sam_entries+i].group_rid = info[i].group_rid;
	}
		
	ent->num_sam_entries += num_entries;
	
	/* Fill in remaining fields */
	
	ent->sam_entries = name_list;
	ent->sam_entry_index = 0;
	result = ent->num_sam_entries > 0;

 done:

	talloc_destroy(mem_ctx);

	return result;
}

/* Fetch next passwd entry from ntdom database */

#define MAX_GETPWENT_USERS 500

enum winbindd_result winbindd_getpwent(struct winbindd_cli_state *state)
{
	struct getent_state *ent;
	struct winbindd_pw *user_list;
	int num_users, user_list_ndx = 0, i;

	DEBUG(3, ("[%5d]: getpwent\n", state->pid));

	/* Check user has enabled this */

	if (!lp_winbind_enum_users())
		return WINBINDD_ERROR;

	/* Allocate space for returning a chunk of users */

	num_users = MIN(MAX_GETPWENT_USERS, state->request.data.num_entries);
	
	if ((state->response.extra_data = 
	     malloc(num_users * sizeof(struct winbindd_pw))) == NULL)
		return WINBINDD_ERROR;

	memset(state->response.extra_data, 0, num_users * 
	       sizeof(struct winbindd_pw));

	user_list = (struct winbindd_pw *)state->response.extra_data;
	
	if (!(ent = state->getpwent_state))
		return WINBINDD_ERROR;

	/* Start sending back users */

	for (i = 0; i < num_users; i++) {
		struct getpwent_user *name_list = NULL;
		fstring domain_user_name;
		uint32 result;

		/* Do we need to fetch another chunk of users? */

		if (ent->num_sam_entries == ent->sam_entry_index) {
			struct getent_state *next_ent;

			/* is this the beginning ( == 0 ) or the end ? */

			/* 
			 * for some reason this check is not needed here, but is
			 * in winbindd_getgrent().  I'm putting it in but ifdef'd 
			 * out for posterity   --jerry 
			 */
#if 0 	/* NOT NEEDED APPARENTLY */
			
			if ( ent->sam_entry_index > 0 ) {
				DEBUG(10, ("end of getpwent: freeing state info for domain %s\n", ent->domain_name));
				SAFE_FREE(ent->sam_entries);
				next_ent = ent->next;
				DLIST_REMOVE(state->getgrent_state, ent);
				SAFE_FREE(ent);
				ent = next_ent;
			}
#endif	/* NOT NEEDED APPARENTLY */

			/* find the next domain's group entries */

			while(ent && !get_sam_user_entries(ent)) {

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

		name_list = ent->sam_entries;

		/* Skip machine accounts */

		if (name_list[ent->sam_entry_index].
		    name[strlen(name_list[ent->sam_entry_index].name) - 1] 
		    == '$') {
			ent->sam_entry_index++;
			continue;
		}

		/* Lookup user info */
		
		result = winbindd_fill_pwent(
			ent->domain_name, 
			name_list[ent->sam_entry_index].name,
			name_list[ent->sam_entry_index].user_rid,
			name_list[ent->sam_entry_index].group_rid,
			name_list[ent->sam_entry_index].gecos,
			&user_list[user_list_ndx]);
		
		ent->sam_entry_index++;
		
		/* Add user to return list */
		
		if (result) {
				
			user_list_ndx++;
			state->response.data.num_entries++;
			state->response.length += 
				sizeof(struct winbindd_pw);

		} else
			DEBUG(1, ("could not lookup domain user %s\n",
				  domain_user_name));
	}

	/* Out of domains */

	return (user_list_ndx > 0) ? WINBINDD_OK : WINBINDD_ERROR;
}

/* List domain users without mapping to unix ids */

enum winbindd_result winbindd_list_users(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain;
	WINBIND_USERINFO *info;
	uint32 num_entries = 0, total_entries = 0;
	char *ted, *extra_data = NULL;
	int extra_data_len = 0;
	TALLOC_CTX *mem_ctx;
	enum winbindd_result rv = WINBINDD_ERROR;

	DEBUG(3, ("[%5d]: list users\n", state->pid));

	if (!(mem_ctx = talloc_init_named("winbindd_list_users")))
		return WINBINDD_ERROR;

	/* Enumerate over trusted domains */

	for (domain = domain_list(); domain; domain = domain->next) {
		NTSTATUS status;
		struct winbindd_methods *methods;
		int i;

		/* Skip domains other than WINBINDD_DOMAIN environment
		   variable */ 

		if ((strcmp(state->request.domain, "") != 0) &&
		    !check_domain_env(state->request.domain, domain->name))
			continue;

		methods = domain->methods;

		/* Query display info */

		status = methods->query_user_list(
			domain, mem_ctx, &num_entries, &info);

		/* If an error occured on this domain, set the extended error 
                   info and continue to the next domain. If we receive
		   NT_STATUS_MORE_PROCESSING_REQUIRED then cached data was 
                   returned but we couldn't contact the DC for the sequence 
                   number. */

		if (!NT_STATUS_IS_OK(status)) {
			state->response.nt_status = NT_STATUS_V(status);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED))
				continue;
		}

		/* No entries for this domain */

		if (num_entries == 0)
			continue;

		/* Allocate some memory for extra data */

		total_entries += num_entries;
			
		ted = Realloc(extra_data, sizeof(fstring) * total_entries);
			
		if (!ted) {
			DEBUG(0,("failed to enlarge buffer!\n"));
			SAFE_FREE(extra_data);
			goto done;
		} else 
			extra_data = ted;
			
		/* Pack user list into extra data fields */
			
		for (i = 0; i < num_entries; i++) {
			fstring acct_name, name;
			
			if (!info[i].acct_name) {
				fstrcpy(acct_name, "");
			} else {
				fstrcpy(acct_name, info[i].acct_name);
			}
			
			fill_domain_username(name, domain->name, acct_name);
			
				/* Append to extra data */
			memcpy(&extra_data[extra_data_len], name, 
			       strlen(name));
			extra_data_len += strlen(name);
			extra_data[extra_data_len++] = ',';
		}   
        }

	/* Assign extra_data fields in response structure */

	if (extra_data) {
		extra_data[extra_data_len - 1] = '\0';
		state->response.extra_data = extra_data;
		state->response.length += extra_data_len;
	}

	/* No domains responded but that's still OK so don't return an
	   error. */

	rv = WINBINDD_OK;

 done:

	talloc_destroy(mem_ctx);

	return rv;
}
