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

static void winbindd_fill_pwent(struct winbindd_pw *pw, char *name,
                                uid_t unix_uid, gid_t unix_gid, 
                                char *full_name)
{
    pstring homedir;
    fstring name_domain, name_user;

    if (!pw || !name) {
        return;
    }

    /* Fill in uid/gid */

    pw->pw_uid = unix_uid;
    pw->pw_gid = unix_gid;

    /* Username */

    safe_strcpy(pw->pw_name, name, sizeof(pw->pw_name) - 1);

    /* Full name (gecos) */

    safe_strcpy(pw->pw_gecos, full_name, sizeof(pw->pw_gecos) - 1);

    /* Home directory and shell - use template config parameters.  The
       defaults are /tmp for the home directory and /bin/false for shell. */

    parse_domain_user(name, name_domain, name_user);

    pstrcpy(homedir, lp_template_homedir());

    pstring_sub(homedir, "%U", name_user);
    pstring_sub(homedir, "%D", name_domain);

    safe_strcpy(pw->pw_dir, homedir, sizeof(pw->pw_dir) - 1);

    safe_strcpy(pw->pw_shell, lp_template_shell(), sizeof(pw->pw_shell) - 1);

    /* Password - set to "x" as we can't generate anything useful here.
       Authentication can be done using the pam_ntdom module. */

    safe_strcpy(pw->pw_passwd, "x", sizeof(pw->pw_passwd) - 1);
}

/* Return a password structure from a username.  Specify whether cached data 
   can be returned. */

enum winbindd_result winbindd_getpwnam_from_user(struct winbindd_cli_state *state) 
{
    uint32 name_type, user_rid, group_rid;
    SAM_USERINFO_CTR user_info;
    DOM_SID user_sid;
    fstring name_domain, name_user, name, gecos_name;
    struct winbindd_domain *domain;
    uid_t uid;
    gid_t gid;

    /* Parse domain and username */
    parse_domain_user(state->request.data.username, name_domain, name_user);

    /* Reject names that don't have a domain - i.e name_domain contains the
       entire name. */
 
    if (strequal(name_domain, "")) {
        return WINBINDD_ERROR;
    }

    /* Get info for the domain */

    if ((domain = find_domain_from_name(name_domain)) == NULL) {
        DEBUG(0, ("could not find domain entry for domain %s\n", name_domain));
        return WINBINDD_ERROR;
    }

    /* Check for cached user entry */

    if (winbindd_fetch_user_cache_entry(name_domain, name_user,
					&state->response.data.pw)) {
            return WINBINDD_OK;
    }

    slprintf(name,sizeof(name),"%s\\%s", name_domain, name_user);

    /* Get rid and name type from name */
    /* the following costs 1 packet */
    if (!winbindd_lookup_sid_by_name(domain, name, &user_sid, &name_type)) {
        DEBUG(1, ("user '%s' does not exist\n", name_user));
        return WINBINDD_ERROR;
    }

    if (name_type != SID_NAME_USER) {
        DEBUG(1, ("name '%s' is not a user name: %d\n", name_user, name_type));
        return WINBINDD_ERROR;
    }

    /* Get some user info.  Split the user rid from the sid obtained from
       the winbind_lookup_by_name() call and use it in a
       winbind_lookup_userinfo() */
    
    sid_split_rid(&user_sid, &user_rid);

    /* the following costs 3 packets */
    if (!winbindd_lookup_userinfo(domain, user_rid, &user_info)) {
        DEBUG(1, ("pwnam_from_user(): error getting user info for user '%s'\n",
                  name_user));
        return WINBINDD_ERROR;
    }
    
    group_rid = user_info.info.id21->group_rid;
    unistr2_to_ascii(gecos_name, &user_info.info.id21->uni_full_name,
                     sizeof(gecos_name) - 1);

    free_samr_userinfo_ctr(&user_info);

    /* Resolve the uid number */

    if (!winbindd_idmap_get_uid_from_rid(domain->name, user_rid, &uid)) {
        DEBUG(1, ("error getting user id for user %s\n", name_user));
        return WINBINDD_ERROR;
    }

    /* Resolve the gid number */   

    if (!winbindd_idmap_get_gid_from_rid(domain->name, group_rid, &gid)) {
        DEBUG(1, ("error getting group id for user %s\n", name_user));
        return WINBINDD_ERROR;
    }

    /* Now take all this information and fill in a passwd structure */
            
    winbindd_fill_pwent(&state->response.data.pw, 
                        state->request.data.username, uid, gid, 
                        gecos_name);
            
    winbindd_fill_user_cache_entry(name_domain, name_user, 
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
    if (!winbindd_idmap_get_rid_from_uid(state->request.data.uid, &user_rid,
                                         &domain)) {
        DEBUG(1, ("Could not convert uid %d to rid\n", 
                  state->request.data.uid));
        return WINBINDD_ERROR;
    }
    
    /* Check for cached uid entry */
    if (winbindd_fetch_uid_cache_entry(domain->name, state->request.data.uid,
				       &state->response.data.pw)) {
            return WINBINDD_OK;
    }


    /* Get name and name type from rid */

    sid_copy(&user_sid, &domain->sid);
    sid_append_rid(&user_sid, user_rid);

    if (!winbindd_lookup_name_by_sid(domain, &user_sid, user_name, 
                                     &name_type)) {
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
        DEBUG(1, ("pwnam_from_uid(): error getting user info for user '%s'\n",
                  user_name));
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

    winbindd_fill_pwent(&state->response.data.pw, user_name, 
                        state->request.data.uid, gid, gecos_name);

    winbindd_fill_uid_cache_entry(domain->name, state->request.data.uid,
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
            (strcmp(state->request.domain, tmp->name) != 0)) {
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

/* Fetch next passwd entry from ntdom database */

enum winbindd_result winbindd_getpwent(struct winbindd_cli_state *state)
{
    if (state == NULL) return WINBINDD_ERROR;

    /* Process the current head of the getent_state list */

    while(state->getpwent_state != NULL) {
        struct getent_state *ent = state->getpwent_state;

        /* Get list of user entries for this pipe */

        if (!ent->got_sam_entries) {
            uint32 status, start_ndx = 0;

            /* Look in cache for entries, else get them direct */

            if (!winbindd_fetch_user_cache(ent->domain->name, 
                                           &ent->sam_entries,
                                           &ent->num_sam_entries)) {

                /* Fetch the user entries */

                if (!domain_handles_open(ent->domain)) goto cleanup;

                do {
                    status =
                        samr_enum_dom_users(
                            &ent->domain->sam_dom_handle, &start_ndx, 0, 0, 
                            0x10000, &ent->sam_entries, &ent->num_sam_entries);
                } while (status == STATUS_MORE_ENTRIES);

                /* Fill cache with received entries */
            
                winbindd_fill_user_cache(ent->domain->name, ent->sam_entries, 
                                         ent->num_sam_entries);
            }
            
            ent->got_sam_entries = True;
        }
        
        /* Send back a user */

        while (ent->sam_entry_index < ent->num_sam_entries) {
            enum winbindd_result result;
            fstring domain_user_name;
            char *user_name = (ent->sam_entries)
                [ent->sam_entry_index].acct_name; 
                
            /* Don't bother with machine accounts */

            if (user_name[strlen(user_name) - 1] == '$') {
                ent->sam_entry_index++;
                continue;
            }

            /* Prepend domain to name */

	    slprintf(domain_user_name, sizeof(domain_user_name),
		     "%s%s%s", ent->domain->name, lp_winbind_separator(), 
		     user_name);
                
            /* Get passwd entry from user name */
                
            fstrcpy(state->request.data.username, domain_user_name);
            result = winbindd_getpwnam_from_user(state);

            ent->sam_entry_index++;
                
            /* Return if user lookup worked */
                
            if (result == WINBINDD_OK) {
                return result;
            }
                
            /* Try next user */
            
            DEBUG(1, ("could not getpwnam_from_user for username %s\n",
                      domain_user_name));
        }

        /* We've exhausted all users for this pipe - close it down and
           start on the next one. */

    cleanup:

        /* Free mallocated memory for sam entries.  The data stored here
           may have been allocated from the cache. */

        if (ent->sam_entries != NULL) free(ent->sam_entries);
        ent->sam_entries = NULL;

        /* Free state information for this domain */

        {
            struct getent_state *old_ent;

            old_ent = state->getpwent_state;
            DLIST_REMOVE(state->getpwent_state, state->getpwent_state);
            free(old_ent);
        }
    }

    /* Out of pipes so we're done */

    return WINBINDD_ERROR;
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

        for (domain = domain_list; domain; domain = domain->next) {
		int i;

		ctr.sam.info1 = &info1;

		/* Skip domains other than WINBINDD_DOMAIN environment
		   variable */ 

		if ((strcmp(state->request.domain, "") != 0) &&
		    (strcmp(state->request.domain, domain->name) != 0)) {
			continue;
		}

                /* Query display info */

                if (!winbindd_query_dispinfo(domain, 1, &num_entries, &ctr)) {
			continue;
		}

		/* Allocate some memory for extra data.  Note that we limit
		   account names to sizeof(fstring) = 128 characters.  */

		total_entries += num_entries;
		extra_data = Realloc(extra_data, 
				     sizeof(fstring) * total_entries);

		if (!extra_data) {
			return WINBINDD_ERROR;
		}

		/* Pack user list into extra data fields */

		for (i = 0; i < num_entries; i++) {
			UNISTR2 *uni_acct_name;
			fstring acct_name, name;

			/* Convert unistring to ascii */

			uni_acct_name = &ctr.sam.info1->str[i]. uni_acct_name;
			unistr2_to_ascii(acct_name, uni_acct_name,
					 sizeof(acct_name) - 1);
                                                 
			slprintf(name, sizeof(name), "%s%s%s",
				 domain->name, lp_winbind_separator(),
				 acct_name);


			DEBUG(0, ("appending name %s\n", name));

			/* Append to extra data */
			
			memcpy(&extra_data[extra_data_len], name, 
			       strlen(name));
			extra_data_len += strlen(name);

			if (i == (num_entries - 1)) {
				extra_data[extra_data_len++] = '\0';
			} else {
				extra_data[extra_data_len++] = ',';
			}   
		}
        }

	/* Assign extra_data fields in response structure */

	if (extra_data) {
		state->response.extra_data = extra_data;
		state->response.length += extra_data_len;
		
		return WINBINDD_OK;
	}

	/* No domains responded */

	return WINBINDD_ERROR;
}
