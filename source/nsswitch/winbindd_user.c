/* 
   Unix SMB/CIFS implementation.

   Winbind daemon - user related functions

   Copyright (C) Tim Potter 2000
   Copyright (C) Jeremy Allison 2001.
   Copyright (C) Gerald (Jerry) Carter 2003.
   
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

extern userdom_struct current_user_info;

/* Fill a pwent structure with information we have obtained */

static BOOL winbindd_fill_pwent(char *dom_name, char *user_name, 
				DOM_SID *user_sid, DOM_SID *group_sid,
				char *full_name, struct winbindd_pw *pw)
{
	fstring output_username;
	char *homedir;
	char *shell;
	fstring sid_string;
	
	if (!pw || !dom_name || !user_name)
		return False;
	
	/* Resolve the uid number */

	if (!NT_STATUS_IS_OK(idmap_sid_to_uid(user_sid, &(pw->pw_uid), 0))) {
		DEBUG(1, ("error getting user id for sid %s\n", sid_to_string(sid_string, user_sid)));
		return False;
	}
	
	/* Resolve the gid number */   

	if (!NT_STATUS_IS_OK(idmap_sid_to_gid(group_sid, &(pw->pw_gid), 0))) {
		DEBUG(1, ("error getting group id for sid %s\n", sid_to_string(sid_string, group_sid)));
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
	   by alloc_sub_specified() below. */

	fstrcpy(current_user_info.domain, dom_name);

	homedir = alloc_sub_specified(lp_template_homedir(), user_name, dom_name, pw->pw_uid, pw->pw_gid);

	if (!homedir)
		return False;
	
	safe_strcpy(pw->pw_dir, homedir, sizeof(pw->pw_dir) - 1);
	
	SAFE_FREE(homedir);
	
	shell = alloc_sub_specified(lp_template_shell(), user_name, dom_name, pw->pw_uid, pw->pw_gid);

	if (!shell)
		return False;

	safe_strcpy(pw->pw_shell, shell, 
		    sizeof(pw->pw_shell) - 1);
	
	/* Password - set to "x" as we can't generate anything useful here.
	   Authentication can be done using the pam_winbind module. */

	safe_strcpy(pw->pw_passwd, "x", sizeof(pw->pw_passwd) - 1);

	return True;
}

/* Return a password structure from a username.  */

enum winbindd_result winbindd_getpwnam(struct winbindd_cli_state *state) 
{
	WINBIND_USERINFO user_info;
	WINBINDD_PW *pw;
	DOM_SID user_sid;
	NTSTATUS status;
	fstring name_domain, name_user;
	enum SID_NAME_USE name_type;
	struct winbindd_domain *domain;
	TALLOC_CTX *mem_ctx;
	
	/* Ensure null termination */
	state->request.data.username[sizeof(state->request.data.username)-1]='\0';

	DEBUG(3, ("[%5lu]: getpwnam %s\n", (unsigned long)state->pid,
		  state->request.data.username));
	
	/* Parse domain and username */

	parse_domain_user(state->request.data.username, 
			  name_domain, name_user);
	
	/* if this is our local domain (or no domain), the do a local tdb search */
	
	if ( !*name_domain || strequal(name_domain, get_global_sam_name()) ) {
		if ( !(pw = wb_getpwnam(name_user)) ) {
			DEBUG(5,("winbindd_getpwnam: lookup for %s\\%s failed\n",
				name_domain, name_user));
			return WINBINDD_ERROR;
		}
		memcpy( &state->response.data.pw, pw, sizeof(WINBINDD_PW) );
		return WINBINDD_OK;
	}

	/* should we deal with users for our domain? */
	
	if ((domain = find_domain_from_name(name_domain)) == NULL) {
		DEBUG(5, ("no such domain: %s\n", name_domain));
		return WINBINDD_ERROR;
	}
	
	if ( domain->primary && lp_winbind_trusted_domains_only()) {
		DEBUG(7,("winbindd_getpwnam: My domain -- rejecting getpwnam() for %s\\%s.\n", 
			name_domain, name_user));
		return WINBINDD_ERROR;
	}	
	
	/* Get rid and name type from name */

	if (!winbindd_lookup_sid_by_name(domain, domain->name, name_user, &user_sid, &name_type)) {
		DEBUG(1, ("user '%s' does not exist\n", name_user));
		return WINBINDD_ERROR;
	}

	if (name_type != SID_NAME_USER && name_type != SID_NAME_COMPUTER) {
		DEBUG(1, ("name '%s' is not a user name: %d\n", name_user, 
			  name_type));
		return WINBINDD_ERROR;
	}
	
	/* Get some user info. */
    
	if (!(mem_ctx = talloc_init("winbindd_getpwnam([%s]\\[%s])", 
					  name_domain, name_user))) {
		DEBUG(1, ("out of memory\n"));
		return WINBINDD_ERROR;
	}

	status = domain->methods->query_user(domain, mem_ctx, &user_sid, 
					     &user_info);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("error getting user info for user '[%s]\\[%s]'\n", 
			  name_domain, name_user));
		talloc_destroy(mem_ctx);
		return WINBINDD_ERROR;
	}
    
	/* Now take all this information and fill in a passwd structure */	
	if (!winbindd_fill_pwent(name_domain, name_user, 
				 user_info.user_sid, user_info.group_sid, 
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
	WINBINDD_PW *pw;
	fstring dom_name;
	fstring user_name;
	enum SID_NAME_USE name_type;
	WINBIND_USERINFO user_info;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	gid_t gid;
	
	/* Bug out if the uid isn't in the winbind range */

	if ((state->request.data.uid < server_state.uid_low ) ||
	    (state->request.data.uid > server_state.uid_high))
		return WINBINDD_ERROR;

	DEBUG(3, ("[%5lu]: getpwuid %lu\n", (unsigned long)state->pid, 
		  (unsigned long)state->request.data.uid));

	/* always try local tdb first */
	
	if ( (pw = wb_getpwuid(state->request.data.uid)) != NULL ) {
		memcpy( &state->response.data.pw, pw, sizeof(WINBINDD_PW) );
		return WINBINDD_OK;
	}
	
	/* Get rid from uid */

	if (!NT_STATUS_IS_OK(idmap_uid_to_sid(&user_sid, state->request.data.uid))) {
		DEBUG(1, ("could not convert uid %lu to SID\n", 
			  (unsigned long)state->request.data.uid));
		return WINBINDD_ERROR;
	}
	
	/* Get name and name type from rid */

	if (!winbindd_lookup_name_by_sid(&user_sid, dom_name, user_name, &name_type)) {
		fstring temp;
		
		sid_to_string(temp, &user_sid);
		DEBUG(1, ("could not lookup sid %s\n", temp));
		return WINBINDD_ERROR;
	}
	
	domain = find_domain_from_sid(&user_sid);

	if (!domain) {
		DEBUG(1,("Can't find domain from sid\n"));
		return WINBINDD_ERROR;
	}

	/* Get some user info */
	
	if (!(mem_ctx = talloc_init("winbind_getpwuid(%lu)",
				    (unsigned long)state->request.data.uid))) {

		DEBUG(1, ("out of memory\n"));
		return WINBINDD_ERROR;
	}

	status = domain->methods->query_user(domain, mem_ctx, &user_sid, 
					     &user_info);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("error getting user info for user '%s'\n", 
			  user_name));
		talloc_destroy(mem_ctx);
		return WINBINDD_ERROR;
	}
	
	/* Check group has a gid number */

	if (!NT_STATUS_IS_OK(idmap_sid_to_gid(user_info.group_sid, &gid, 0))) {
		DEBUG(1, ("error getting group id for user %s\n", user_name));
		talloc_destroy(mem_ctx);
		return WINBINDD_ERROR;
	}

	/* Fill in password structure */

	if (!winbindd_fill_pwent(domain->name, user_name, user_info.user_sid, 
				 user_info.group_sid,
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
        
	DEBUG(3, ("[%5lu]: setpwent\n", (unsigned long)state->pid));
        
	/* Check user has enabled this */
        
	if (!lp_winbind_enum_users())
		return WINBINDD_ERROR;

	/* Free old static data if it exists */
        
	if (state->getpwent_state != NULL) {
		free_getent_state(state->getpwent_state);
		state->getpwent_state = NULL;
	}

#if 0	/* JERRY */
	/* add any local users we have */
	        
	if ( (domain_state = (struct getent_state *)malloc(sizeof(struct getent_state))) == NULL )
		return WINBINDD_ERROR;
                
	ZERO_STRUCTP(domain_state);

	/* Add to list of open domains */
                
	DLIST_ADD(state->getpwent_state, domain_state);
#endif
        
	/* Create sam pipes for each domain we know about */
        
	for(domain = domain_list(); domain != NULL; domain = domain->next) {
		struct getent_state *domain_state;
                
		
		/* don't add our domaina if we are a PDC or if we 
		   are a member of a Samba domain */
		
		if ( (IS_DC || lp_winbind_trusted_domains_only())
			&& strequal(domain->name, lp_workgroup()) )
		{
			continue;
		}
						
		/* Create a state record for this domain */
                
		if ((domain_state = (struct getent_state *)
		     malloc(sizeof(struct getent_state))) == NULL)
			return WINBINDD_ERROR;
                
		ZERO_STRUCTP(domain_state);

		fstrcpy(domain_state->domain_name, domain->name);

		/* Add to list of open domains */
                
		DLIST_ADD(state->getpwent_state, domain_state);
	}
        
	state->getpwent_initialized = True;
        
	return WINBINDD_OK;
}

/* Close file pointer to ntdom passwd database */

enum winbindd_result winbindd_endpwent(struct winbindd_cli_state *state)
{
	DEBUG(3, ("[%5lu]: endpwent\n", (unsigned long)state->pid));

	free_getent_state(state->getpwent_state);    
	state->getpwent_initialized = False;
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
	unsigned int i;

	if (ent->num_sam_entries)
		return False;

	if (!(mem_ctx = talloc_init("get_sam_user_entries(%s)",
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
		sid_copy(&name_list[ent->num_sam_entries+i].user_sid, info[i].user_sid);
		sid_copy(&name_list[ent->num_sam_entries+i].group_sid, info[i].group_sid);
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

	DEBUG(3, ("[%5lu]: getpwent\n", (unsigned long)state->pid));

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

	if (!state->getpwent_initialized)
		winbindd_setpwent(state);
	
	if (!(ent = state->getpwent_state))
		return WINBINDD_ERROR;

	/* Start sending back users */

	for (i = 0; i < num_users; i++) {
		struct getpwent_user *name_list = NULL;
		uint32 result;

		/* Do we need to fetch another chunk of users? */

		if (ent->num_sam_entries == ent->sam_entry_index) {

			while(ent && !get_sam_user_entries(ent)) {
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

		name_list = ent->sam_entries;

		/* Lookup user info */
		
		result = winbindd_fill_pwent(
			ent->domain_name, 
			name_list[ent->sam_entry_index].name,
			&name_list[ent->sam_entry_index].user_sid,
			&name_list[ent->sam_entry_index].group_sid,
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
				  name_list[ent->sam_entry_index].name));
	}

	/* Out of domains */

	return (user_list_ndx > 0) ? WINBINDD_OK : WINBINDD_ERROR;
}

/* List domain users without mapping to unix ids */

enum winbindd_result winbindd_list_users(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain;
	WINBIND_USERINFO *info;
	const char *which_domain;
	uint32 num_entries = 0, total_entries = 0;
	char *ted, *extra_data = NULL;
	int extra_data_len = 0;
	TALLOC_CTX *mem_ctx;
	enum winbindd_result rv = WINBINDD_ERROR;

	DEBUG(3, ("[%5lu]: list users\n", (unsigned long)state->pid));

	if (!(mem_ctx = talloc_init("winbindd_list_users")))
		return WINBINDD_ERROR;

	/* Ensure null termination */
	state->request.domain_name[sizeof(state->request.domain_name)-1]='\0';	
	which_domain = state->request.domain_name;
	
	/* Enumerate over trusted domains */

	for (domain = domain_list(); domain; domain = domain->next) {
		NTSTATUS status;
		struct winbindd_methods *methods;
		unsigned int i;
		
		/* if we have a domain name restricting the request and this
		   one in the list doesn't match, then just bypass the remainder
		   of the loop */
		   
		if ( *which_domain && !strequal(which_domain, domain->name) )
			continue;
			
		methods = domain->methods;

		/* Query display info */
		status = methods->query_user_list(domain, mem_ctx, 
						  &num_entries, &info);

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
