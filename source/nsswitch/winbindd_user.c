/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   Winbind daemon - user related functions

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

/* Fill a pwent structure with information we have obtained */

static BOOL winbindd_fill_pwent(char *domain_name, char *name, 
				uint32 user_rid, uint32 group_rid, 
                                char *full_name, struct winbindd_pw *pw)
{
	fstring name_domain, name_user;
	pstring homedir;
	
	if (!pw || !name) {
		return False;
	}
	
	/* Resolve the uid number */
	
	if (!winbindd_idmap_get_uid_from_rid(domain_name, user_rid, 
					     &pw->pw_uid)) {
		DEBUG(1, ("error getting user id for user %s\n", name_user));
		return False;
	}
	
	/* Resolve the gid number */   
	
	if (!winbindd_idmap_get_gid_from_rid(domain_name, group_rid, 
					     &pw->pw_gid)) {
		DEBUG(1, ("error getting group id for user %s\n", name_user));
		return False;
	}

	/* Username */
	
	safe_strcpy(pw->pw_name, name, sizeof(pw->pw_name) - 1);
	
	/* Full name (gecos) */
	
	safe_strcpy(pw->pw_gecos, full_name, sizeof(pw->pw_gecos) - 1);
	
	/* Home directory and shell - use template config parameters.  The
	   defaults are /tmp for the home directory and /bin/false for
	   shell. */
	
	parse_domain_user(name, name_domain, name_user);
	
	pstrcpy(homedir, lp_template_homedir());
	
	pstring_sub(homedir, "%U", name_user);
	pstring_sub(homedir, "%D", name_domain);
	
	safe_strcpy(pw->pw_dir, homedir, sizeof(pw->pw_dir) - 1);
	
	safe_strcpy(pw->pw_shell, lp_template_shell(), 
		    sizeof(pw->pw_shell) - 1);
	
	/* Password - set to "x" as we can't generate anything useful here.
	   Authentication can be done using the pam_ntdom module. */

	safe_strcpy(pw->pw_passwd, "x", sizeof(pw->pw_passwd) - 1);

	return True;
}

/* Return a password structure from a username.  Specify whether cached data 
   can be returned. */

enum winbindd_result winbindd_getpwnam_from_user(struct winbindd_cli_state 
						 *state) 
{
	uint32 name_type, user_rid, group_rid;
	SAM_USERINFO_CTR user_info;
	DOM_SID user_sid;
	fstring name_domain, name_user, name, gecos_name;
	struct winbindd_domain *domain;
	
	/* Parse domain and username */

	parse_domain_user(state->request.data.username, name_domain, 
			  name_user);
	
	/* Reject names that don't have a domain - i.e name_domain contains 
	   the entire name. */
 
	if (strequal(name_domain, "")) {
		return WINBINDD_ERROR;
	}
	
	/* Get info for the domain */
	
	if ((domain = find_domain_from_name(name_domain)) == NULL) {
		DEBUG(0, ("could not find domain entry for domain %s\n", 
			  name_domain));
		return WINBINDD_ERROR;
	}

	/* Check for cached user entry */

	if (winbindd_fetch_user_cache_entry(name_domain, name_user,
					    &state->response.data.pw)) {
		return WINBINDD_OK;
	}
	
	slprintf(name,sizeof(name),"%s\\%s", name_domain, name_user);
	
	/* Get rid and name type from name.  The following costs 1 packet */

	if (!winbindd_lookup_sid_by_name(name, &user_sid, &name_type)) {
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
    
	sid_split_rid(&user_sid, &user_rid);
	
	/* The following costs 3 packets */

	if (!winbindd_lookup_userinfo(domain, user_rid, &user_info)) {
		DEBUG(1, ("pwnam_from_user(): error getting user info for "
			  "user '%s'\n", name_user));
		return WINBINDD_ERROR;
	}
    
	group_rid = user_info.info.id21->group_rid;
	unistr2_to_ascii(gecos_name, &user_info.info.id21->uni_full_name,
			 sizeof(gecos_name) - 1);
	
	free_samr_userinfo_ctr(&user_info);
	
	/* Now take all this information and fill in a passwd structure */
	
	if (!winbindd_fill_pwent(domain->name, state->request.data.username, 
				 user_rid, group_rid, gecos_name,
				 &state->response.data.pw)) {
		return WINBINDD_ERROR;
	}
	
	winbindd_store_user_cache_entry(name_domain, name_user, 
					&state->response.data.pw);
	
	return WINBINDD_OK;
}       

/* Return a password structure given a uid number */

enum winbindd_result winbindd_getpwnam_from_uid(struct winbindd_cli_state 
                                                *state)
{
	DOM_SID user_sid;
	struct winbindd_domain *domain;
	uint32 user_rid, group_rid;
	fstring user_name, gecos_name;
	enum SID_NAME_USE name_type;
	SAM_USERINFO_CTR user_info;
	gid_t gid;
	
	/* Get rid from uid */

	if (!winbindd_idmap_get_rid_from_uid(state->request.data.uid, 
					     &user_rid, &domain)) {
		DEBUG(1, ("Could not convert uid %d to rid\n", 
			  state->request.data.uid));
		return WINBINDD_ERROR;
	}
	
	/* Check for cached uid entry */

	if (winbindd_fetch_uid_cache_entry(domain->name, 
					   state->request.data.uid,
					   &state->response.data.pw)) {
		return WINBINDD_OK;
	}
	
	/* Get name and name type from rid */

	sid_copy(&user_sid, &domain->sid);
	sid_append_rid(&user_sid, user_rid);
	
	if (!winbindd_lookup_name_by_sid(&user_sid, user_name, &name_type)) {
		fstring temp;
		
		sid_to_string(temp, &user_sid);
		DEBUG(1, ("Could not lookup sid %s\n", temp));
		return WINBINDD_ERROR;
	}
	
	if (strcmp("\\", lp_winbind_separator())) {
		string_sub(user_name, "\\", lp_winbind_separator(), 
			   sizeof(fstring));
	}

	/* Get some user info */
	
	if (!winbindd_lookup_userinfo(domain, user_rid, &user_info)) {
		DEBUG(1, ("pwnam_from_uid(): error getting user info for "
			  "user '%s'\n", user_name));
		return WINBINDD_ERROR;
	}
	
	group_rid = user_info.info.id21->group_rid;
	unistr2_to_ascii(gecos_name, &user_info.info.id21->uni_full_name,
			 sizeof(gecos_name) - 1);

	free_samr_userinfo_ctr(&user_info);

	/* Resolve gid number */

	if (!winbindd_idmap_get_gid_from_rid(domain->name, group_rid, &gid)) {
		DEBUG(1, ("error getting group id for user %s\n", user_name));
		return WINBINDD_ERROR;
	}

	/* Fill in password structure */

	if (!winbindd_fill_pwent(domain->name, user_name, user_rid, group_rid,
				 gecos_name, &state->response.data.pw)) {
		return WINBINDD_ERROR;
	}
	
	winbindd_store_uid_cache_entry(domain->name, state->request.data.uid,
				       &state->response.data.pw);
	
	return WINBINDD_OK;
}

/*
 * set/get/endpwent functions
 */

/* Rewind file pointer for ntdom passwd database */

enum winbindd_result winbindd_setpwent(struct winbindd_cli_state *state)
{
    struct winbindd_domain *tmp;

    if (state == NULL) return WINBINDD_ERROR;
    
    /* Free old static data if it exists */

    if (state->getpwent_state != NULL) {
        free_getent_state(state->getpwent_state);
        state->getpwent_state = NULL;
    }

    /* Create sam pipes for each domain we know about */

    for(tmp = domain_list; tmp != NULL; tmp = tmp->next) {
        struct getent_state *domain_state;

        /* Skip domains other than WINBINDD_DOMAIN environment variable */

        if ((strcmp(state->request.domain, "") != 0) &&
	    !check_domain_env(state->request.domain, tmp->name)) {
                continue;
        }

        /* Create a state record for this domain */

        if ((domain_state = (struct getent_state *)
             malloc(sizeof(struct getent_state))) == NULL) {

            return WINBINDD_ERROR;
        }

        ZERO_STRUCTP(domain_state);
        domain_state->domain = tmp;

        /* Add to list of open domains */

        DLIST_ADD(state->getpwent_state, domain_state)
    }

    return WINBINDD_OK;
}

/* Close file pointer to ntdom passwd database */

enum winbindd_result winbindd_endpwent(struct winbindd_cli_state *state)
{
    if (state == NULL) return WINBINDD_ERROR;

    free_getent_state(state->getpwent_state);    
    state->getpwent_state = NULL;

    return WINBINDD_OK;
}

/* Get list of domain users for a domain */

static BOOL get_sam_user_entries(struct getent_state *ent)
{
	uint32 status, num_entries, start_ndx = 0;
	SAM_DISPINFO_1 info1;
	SAM_DISPINFO_CTR ctr;
	struct getpwent_user *name_list = NULL;
	uint32 group_rid;
	DOM_SID group_sid;
	fstring group_name;
	enum SID_NAME_USE name_type;

	ctr.sam.info1 = &info1;
			
	/* Look in cache for entries, else get them direct */
		    
	if (winbindd_fetch_user_cache(ent->domain->name,
				      (struct getpwent_user **)
				      &ent->sam_entries, 
				      &ent->num_sam_entries)) {
		ent->got_sam_entries = True;
		return True;
	}

	/* Get hardcoded group rid */

	slprintf(group_name, sizeof(group_name), "%s\\Domain Users", 
		 ent->domain->name);
	
	if (!winbindd_lookup_sid_by_name(group_name, &group_sid, &name_type)) {
		DEBUG(1, ("%s group does not exist\n", group_name));
		group_rid = -1;
	} else {
		sid_split_rid(&group_sid, &group_rid);
	}
	
	/* Fetch the user entries */
	
	if (!domain_handles_open(ent->domain)) {
		return False;
	}

	/* Call query_dispinfo to get a list of usernames and user rids */
	
	do {
		int i;
					
		status = winbindd_query_dispinfo(ent->domain, &start_ndx, 1,
						 &num_entries, &ctr);
					
		name_list = Realloc(name_list, sizeof(struct getpwent_user) *
				    (ent->num_sam_entries + num_entries));
				
		for (i = 0; i < num_entries; i++) {

			/* Store account name and gecos */

			unistr2_to_ascii(
				name_list[ent->num_sam_entries + i].name, 
				&info1.str[i].uni_acct_name, 
				sizeof(fstring));

			unistr2_to_ascii(
				name_list[ent->num_sam_entries + i].gecos, 
				&info1.str[i].uni_full_name, 
				sizeof(fstring));

			/* User and group ids */

			name_list[ent->num_sam_entries + i].user_rid =
				info1.sam[i].rid_user;

			name_list[ent->num_sam_entries + i].
				group_rid = group_rid;

		}
		
		ent->num_sam_entries += num_entries;
		
	} while (status == STATUS_MORE_ENTRIES);
	
	/* Fill cache with received entries */
	
	winbindd_store_user_cache(ent->domain->name, ent->sam_entries, 
				  ent->num_sam_entries);
	
	ent->sam_entries = name_list;
	ent->got_sam_entries = True;

	return True;
}

/* Fetch next passwd entry from ntdom database */

#define MAX_GETPWENT_USERS 500

enum winbindd_result winbindd_getpwent(struct winbindd_cli_state *state)
{
	struct winbindd_pw *user_list;
	int i, num_users, user_list_ndx = 0;

	if (state == NULL) return WINBINDD_ERROR;

	/* Allocate space for returning a chunk of users */

	num_users = MIN(MAX_GETPWENT_USERS, state->request.data.num_entries);
	
	if ((state->response.extra_data = 
	     malloc(num_users * sizeof(struct winbindd_pw))) == NULL) {
		return WINBINDD_ERROR;
	}

	memset(state->response.extra_data, 0, num_users * 
	       sizeof(struct winbindd_pw));

	user_list = (struct winbindd_pw *)state->response.extra_data;

	/* Start sending back users */

	for (i = 0; i < num_users; i++) {

		/* Add a user entry to client response structure */

		while(state->getpwent_state != NULL) {
			struct getent_state *ent = state->getpwent_state;
			struct getpwent_user *name_list;
			enum winbindd_result result;
			fstring domain_user_name;

			/* Get list of user entries for this pipe */
		
			if (!ent->got_sam_entries && 
			    !get_sam_user_entries(ent)) {
				goto cleanup;
			}
		
			name_list = ent->sam_entries;

			/* Ignore machine accounts */

			if (name_list[ent->sam_entry_index].
			    name[strlen(name_list[ent->sam_entry_index].name)
				- 1] == '$') {
				ent->sam_entry_index++;
				goto check_cleanup;
			}

			/* Prepend domain to name */
			
			slprintf(domain_user_name, sizeof(domain_user_name),
				 "%s%s%s", ent->domain->name, 
				 lp_winbind_separator(), 
				 name_list[ent->sam_entry_index].name);
	
			result = winbindd_fill_pwent(
				ent->domain->name, 
				domain_user_name,
				name_list[ent->sam_entry_index].user_rid,
				name_list[ent->sam_entry_index].group_rid,
				name_list[ent->sam_entry_index].gecos,
				&user_list[user_list_ndx]);

			ent->sam_entry_index++;

			/* Add user to return list */

			if (result == WINBINDD_OK) {

				/* We've got a user.  Update client
				   response structure and break out of
				   while loop */

				user_list_ndx++;
				state->response.data.num_entries++;
				state->response.length += 
					sizeof(struct winbindd_pw);
				break;
			} else {
				DEBUG(1, ("could not getpwnam_from_user "
					  "for username %s\n", 
					  domain_user_name));
			}

			/* Check to see if we should move on to the next
                           pipe */

		check_cleanup:

			if (ent->sam_entry_index == ent->num_sam_entries) {
				struct getent_state *old_ent;
		
				/* Free mallocated memory for sam entries.
				   The data stored here may have been
				   allocated from the cache. */
			
			cleanup:
		
				if (ent->sam_entries != NULL) {
					free(ent->sam_entries);
				}

				ent->sam_entries = NULL;
		
				/* Free state information for this domain */
				
				old_ent = state->getpwent_state;
				DLIST_REMOVE(state->getpwent_state, 
					     state->getpwent_state);
				free(old_ent);
			}

		}
	}
	
	/* Out of pipes so we're done */

	return (user_list_ndx > 0) ? WINBINDD_OK : WINBINDD_ERROR;
}

/* List domain users without mapping to unix ids */

enum winbindd_result winbindd_list_users(struct winbindd_cli_state *state)
{
        struct winbindd_domain *domain;
        SAM_DISPINFO_CTR ctr;
	SAM_DISPINFO_1 info1;
        uint32 num_entries, total_entries = 0;
	char *extra_data = NULL;
	int extra_data_len = 0;

        /* Enumerate over trusted domains */

	ctr.sam.info1 = &info1;

        for (domain = domain_list; domain; domain = domain->next) {
		uint32 status, start_ndx = 0;

		/* Skip domains other than WINBINDD_DOMAIN environment
		   variable */ 

		if ((strcmp(state->request.domain, "") != 0) &&
		    !check_domain_env(state->request.domain, domain->name)) {
			continue;
		}

                /* Query display info */

		do {
			int i;

			status = winbindd_query_dispinfo(domain, &start_ndx, 
							 1, &num_entries, 
							 &ctr);

			/* Allocate some memory for extra data */

			total_entries += num_entries;
			extra_data = Realloc(extra_data, sizeof(fstring) * 
					     total_entries);
			
			if (!extra_data) {
				return WINBINDD_ERROR;
			}
			
			/* Pack user list into extra data fields */
			
			for (i = 0; i < num_entries; i++) {
				UNISTR2 *uni_acct_name;
				fstring acct_name, name;

				/* Convert unistring to ascii */
				
				uni_acct_name = &ctr.sam.info1->str[i]. 
					uni_acct_name;
				unistr2_to_ascii(acct_name, uni_acct_name,
						 sizeof(acct_name) - 1);
                                                 
				slprintf(name, sizeof(name), "%s%s%s",
					 domain->name, lp_winbind_separator(),
					 acct_name);

				/* Append to extra data */
			
				memcpy(&extra_data[extra_data_len], name, 
				       strlen(name));
				extra_data_len += strlen(name);
				
				extra_data[extra_data_len++] = ',';
			}   
		} while (status == STATUS_MORE_ENTRIES);
        }

	/* Assign extra_data fields in response structure */

	if (extra_data) {
		extra_data[extra_data_len - 1] = '\0';
		state->response.extra_data = extra_data;
		state->response.length += extra_data_len;
		
		return WINBINDD_OK;
	}

	/* No domains responded */

	return WINBINDD_ERROR;
}
