/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   Winbind daemon for ntdom nss module

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

/* Fill a grent structure from various other information */

static BOOL winbindd_fill_grent(struct winbindd_gr *gr, char *gr_name,
                                gid_t unix_gid)
{
	/* Fill in uid/gid */

	gr->gr_gid = unix_gid;
    
	/* Group name and password */
    
	safe_strcpy(gr->gr_name, gr_name, sizeof(gr->gr_name) - 1);
	safe_strcpy(gr->gr_passwd, "x", sizeof(gr->gr_passwd) - 1);

	return True;
}

/* Fill in the group membership field of a NT group given by group_rid */

static BOOL winbindd_fill_grent_mem(struct winbindd_domain *domain,
                                    uint32 group_rid, 
                                    enum SID_NAME_USE group_name_type, 
                                    struct winbindd_response *response)
{
	uint32 *rid_mem = NULL, num_names = 0;
	enum SID_NAME_USE *name_types = NULL;
	struct winbindd_gr *gr;
	int buf_len, buf_ndx, i;
	char **names = NULL, *buf;
	BOOL result;
	
	if (!response) return False;
	
	/* Initialise group membership information */
	
	gr = &response->data.gr;
	gr->num_gr_mem = 0;
	
	if (group_name_type != SID_NAME_DOM_GRP) {
		DEBUG(1, ("fill_grent_mem(): rid %d in domain %s isn't a "
			  "domain group\n", group_rid, domain->name));
		return False;
	}

	/* Lookup group members */

	if (!winbindd_lookup_groupmem(domain, group_rid, &num_names, 
				      &rid_mem, &names, &name_types)) {

		DEBUG(1, ("fill_grent_mem(): could not lookup membership "
			  "for group rid %d in domain %s\n", 
			  group_rid, domain->name));

		return False;
	}

	/* Add members to list */

	buf = NULL;
	buf_len = buf_ndx = 0;

 again:

	for (i = 0; i < num_names; i++) {
		char *the_name;
		fstring name;
		int len;
			
		the_name = names[i];

		/* Only add domain users */

		if (name_types[i] != SID_NAME_USER) {
			DEBUG(3, ("fill_grent_mem(): name %s isn't a domain "
				  "user\n", the_name));
			continue;
		}

		/* Don't bother with machine accounts */
		
		if (the_name[strlen(the_name) - 1] == '$') {
			continue;
		}

		/* Append domain name */

		snprintf(name, sizeof(name), "%s%s%s", domain->name,
			 lp_winbind_separator(), the_name);

		len = strlen(name);
		
		/* Add to list or calculate buffer length */

		if (!buf) {
			buf_len += len + 1; /* List is comma separated */
			gr->num_gr_mem++;
		} else {
			safe_strcpy(&buf[buf_ndx], name, len);
			buf_ndx += len;
			buf[buf_ndx] = ',';
			buf_ndx++;
		}
	}

	/* Allocate buffer */

	if (!buf) {
		if (!(buf = malloc(buf_len))) {
			result = False;
			goto cleanup;
		}
		memset(buf, 0, buf_len);
		goto again;
	}

	if (buf && buf_ndx > 0) {
		buf[buf_ndx - 1] = '\0';
	}

	response->extra_data = buf;
	response->length += buf_len;

	result = True;

 cleanup:
	
	/* Free memory allocated in winbindd_lookup_groupmem() */
	
	safe_free(name_types);
	safe_free(rid_mem);
	
	free_char_array(num_names, names);
	
	return result;
}

/* Return a group structure from a group name */

enum winbindd_result winbindd_getgrnam_from_group(struct winbindd_cli_state 
						  *state)
{
	DOM_SID group_sid;
	struct winbindd_domain *domain;
	enum SID_NAME_USE name_type;
	uint32 group_rid;
	fstring name_domain, name_group, name;
	char *tmp;
	gid_t gid;
	int extra_data_len;
	
	/* Parse domain and groupname */
	
	memset(name_group, 0, sizeof(fstring));

	tmp = state->request.data.groupname;
	parse_domain_user(tmp, name_domain, name_group);

	/* Reject names that don't have a domain - i.e name_domain contains 
	   the entire name. */

	if (strequal(name_group, "")) {
		return WINBINDD_ERROR;
	}    

	/* Get info for the domain */

	if ((domain = find_domain_from_name(name_domain)) == NULL) {
		DEBUG(0, ("getgrname_from_group(): could not get domain "
			  "sid for domain %s\n", name_domain));
		return WINBINDD_ERROR;
	}

	if (!domain_handles_open(domain)) {
		return False;
	}

	/* Check for cached group entry */

	if (winbindd_fetch_group_cache_entry(name_domain, name_group,
					     &state->response.data.gr,
					     &state->response.extra_data,
					     &extra_data_len)) {
		state->response.length += extra_data_len;
		return WINBINDD_OK;
	}

	snprintf(name, sizeof(name), "%s\\%s", name_domain, name_group);

	/* Get rid and name type from name */
        
	if (!winbindd_lookup_sid_by_name(name, &group_sid, &name_type)) {
		DEBUG(1, ("group %s in domain %s does not exist\n", 
			  name_group, name_domain));
		return WINBINDD_ERROR;
	}

	if ((name_type != SID_NAME_ALIAS) && (name_type != SID_NAME_DOM_GRP)) {
		DEBUG(1, ("from_group: name '%s' is not a local or domain "
			  "group: %d\n", name_group, name_type));
		return WINBINDD_ERROR;
	}

	/* Fill in group structure */

	sid_split_rid(&group_sid, &group_rid);

	if (!winbindd_idmap_get_gid_from_rid(domain->name, group_rid, &gid)) {
		DEBUG(1, ("error sursing unix gid for sid\n"));
		return WINBINDD_ERROR;
	}

	if (!winbindd_fill_grent(&state->response.data.gr, 
				 state->request.data.groupname, gid) ||
	    !winbindd_fill_grent_mem(domain, group_rid, name_type,
				     &state->response)) {
		return WINBINDD_ERROR;
	}

	/* Update cached group info */

	winbindd_store_group_cache_entry(name_domain, name_group, 
					 &state->response.data.gr,
					 state->response.extra_data,
					 state->response.length - 
					 sizeof(struct winbindd_response));

	return WINBINDD_OK;
}

/* Return a group structure from a gid number */

enum winbindd_result winbindd_getgrnam_from_gid(struct winbindd_cli_state 
                                                *state)
{
	struct winbindd_domain *domain;
	DOM_SID group_sid;
	enum SID_NAME_USE name_type;
	fstring group_name;
	uint32 group_rid;
	int extra_data_len;

	/* Get rid from gid */

	if (!winbindd_idmap_get_rid_from_gid(state->request.data.gid, 
					     &group_rid, &domain)) {
		DEBUG(1, ("Could not convert gid %d to rid\n", 
			  state->request.data.gid));
		return WINBINDD_ERROR;
	}

	if (!domain_handles_open(domain)) {
		return False;
	}

	/* Try a cached entry */

	if (winbindd_fetch_gid_cache_entry(domain->name, 
					   state->request.data.gid,
					   &state->response.data.gr,
					   &state->response.extra_data,
					   &extra_data_len)) {
		state->response.length += extra_data_len;
		return WINBINDD_OK;
	}

	/* Get sid from gid */

	sid_copy(&group_sid, &domain->sid);
	sid_append_rid(&group_sid, group_rid);

	if (!winbindd_lookup_name_by_sid(&group_sid, group_name, &name_type)) {
		DEBUG(1, ("Could not lookup sid\n"));
		return WINBINDD_ERROR;
	}

	if (strcmp(lp_winbind_separator(),"\\")) {
		string_sub(group_name, "\\", lp_winbind_separator(), 
			   sizeof(fstring));
	}

	if (!((name_type == SID_NAME_ALIAS) || 
	      (name_type == SID_NAME_DOM_GRP))) {
		DEBUG(1, ("from_gid: name '%s' is not a local or domain "
			  "group: %d\n", group_name, name_type));
		return WINBINDD_ERROR;
	}

	/* Fill in group structure */

	if (!winbindd_fill_grent(&state->response.data.gr, group_name, 
				 state->request.data.gid) ||
	    !winbindd_fill_grent_mem(domain, group_rid, name_type,
				     &state->response)) {
		return WINBINDD_ERROR;
	}

	/* Update cached group info */
	winbindd_store_gid_cache_entry(domain->name, state->request.data.gid,
				       &state->response.data.gr,
				       state->response.extra_data,
				       state->response.length - 
				       sizeof(struct winbindd_response));

	return WINBINDD_OK;
}

/*
 * set/get/endgrent functions
 */

/* "Rewind" file pointer for group database enumeration */

enum winbindd_result winbindd_setgrent(struct winbindd_cli_state *state)
{
	struct winbindd_domain *tmp;

	if (state == NULL) return WINBINDD_ERROR;
	
	/* Free old static data if it exists */
	
	if (state->getgrent_state != NULL) {
		free_getent_state(state->getgrent_state);
		state->getgrent_state = NULL;
	}
	
	/* Create sam pipes for each domain we know about */
	
	for (tmp = domain_list; tmp != NULL; tmp = tmp->next) {
		struct getent_state *domain_state;
		
		/* Skip domains other than WINBINDD_DOMAIN environment 
		   variable */
		
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
		
		/* Add to list of open domains */
		
		domain_state->domain = tmp;
		DLIST_ADD(state->getgrent_state, domain_state);
	}
	
	return WINBINDD_OK;
}

/* Close file pointer to ntdom group database */

enum winbindd_result winbindd_endgrent(struct winbindd_cli_state *state)
{
	if (state == NULL) return WINBINDD_ERROR;

	free_getent_state(state->getgrent_state);
	state->getgrent_state = NULL;
	
	return WINBINDD_OK;
}

/* Get the list of domain groups and domain aliases for a domain.  We fill in
   the sam_entries and num_sam_entries fields with domain group information.  
   The dispinfo_ndx field is incremented to the index of the next group to 
   fetch. Return True if some groups were returned, False otherwise. */

#define MAX_FETCH_SAM_ENTRIES 100

static BOOL get_sam_group_entries(struct getent_state *ent)
{
	uint32 status, num_entries, start_ndx = 0;
	struct acct_info *name_list = NULL;
        
	if (ent->got_all_sam_entries) {
		return False;
	}

#if 0
	if (winbindd_fetch_group_cache(ent->domain->name, 
				       &ent->sam_entries,
				       &ent->num_sam_entries)) {
		return True;
	}
#endif
		
	/* Fetch group entries */
		
	if (!domain_handles_open(ent->domain)) {
		return False;
	}

	/* Free any existing group info */

	if (ent->sam_entries) {
		free(ent->sam_entries);
		ent->sam_entries = NULL;
		ent->num_sam_entries = 0;
	}
		
	/* Enumerate domain groups */
		
	do {
		struct acct_info *sam_grp_entries = NULL;

		num_entries = 0;

		status =
			samr_enum_dom_groups(&ent->domain->
					     sam_dom_handle,
					     &start_ndx, 0x100000,
					     (struct acct_info **)
					     &sam_grp_entries,
					     &num_entries);

		/* Copy entries into return buffer */

		if (num_entries) {

			name_list = Realloc(name_list,
					    sizeof(struct acct_info) *
					    (ent->num_sam_entries +
					     num_entries));

			memcpy(&name_list[ent->num_sam_entries],
			       sam_grp_entries, 
			       num_entries * sizeof(struct acct_info));
		}

		ent->num_sam_entries += num_entries;

		if (status != STATUS_MORE_ENTRIES) {
			break;
		}

	} while (ent->num_sam_entries < MAX_FETCH_SAM_ENTRIES);
		
#if 0
	/* Fill cache with received entries */

	winbindd_store_group_cache(ent->domain->name, ent->sam_entries,
				   ent->num_sam_entries);
#endif

	/* Fill in remaining fields */

	DEBUG(0, ("Read %d sam group entries from domain %s\n",
		  ent->num_sam_entries, ent->domain->name));

	ent->sam_entries = name_list;
	ent->sam_entry_index = 0;
	ent->got_all_sam_entries = (status != STATUS_MORE_ENTRIES);

	if (ent->got_all_sam_entries) {
		DEBUG(0, ("Got all sam entries for this domain\n"));
	}

	return num_entries > 0;
}

/* Fetch next group entry from ntdom database */

#define MAX_GETGRENT_GROUPS 500

enum winbindd_result winbindd_getgrent(struct winbindd_cli_state *state)
{
	struct getent_state *ent;
	struct winbindd_gr *group_list = NULL;
	int num_users, group_list_ndx = 0, i;
	char *sep;

	if (state == NULL) return WINBINDD_ERROR;

	num_users = MIN(MAX_GETGRENT_GROUPS, state->request.data.num_entries);
	sep = lp_winbind_separator();

	if (!(ent = state->getgrent_state)) {
		return False;
	}

	/* Start sending back groups */

	for (i = 0; i < num_users; i++) {
		struct acct_info *name_list = NULL;
		fstring domain_group_name;
		uint32 result;
		gid_t group_gid;
		
		/* Do we need to fetch another chunk of groups? */

	tryagain:

		if (ent->num_sam_entries == ent->sam_entry_index) {

			while(ent && !get_sam_group_entries(ent)) {
				struct getent_state *next_ent;

				/* Free state information for this domain */

				safe_free(ent->sam_entries);
				ent->sam_entries = NULL;

				next_ent = ent->next;
				DLIST_REMOVE(state->getgrent_state, ent);
				
				free(ent);
				ent = next_ent;
			}

			/* No more domains */

			if (!ent) break;

			/* Reallocate group list with space for new entries */ 

			group_list = Realloc(group_list, 
					     (group_list_ndx + 
					      ent->num_sam_entries) *
					     sizeof(struct winbindd_gr));

			state->response.extra_data = group_list;

			/* Eeek! */

			if (!group_list) {
				goto done;
			}
		}
		
		name_list = ent->sam_entries;
		
		/* Lookup group info */
		
		if (!winbindd_idmap_get_gid_from_rid(
			ent->domain->name,
			name_list[ent->sam_entry_index].rid,
			&group_gid)) {
			
			DEBUG(1, ("could not look up gid for group %s\n",
				  name_list[ent->sam_entry_index].acct_name));

			ent->sam_entry_index++;
			goto tryagain;
		}
		
		slprintf(domain_group_name, sizeof(domain_group_name) - 1,
			 "%s%s%s", ent->domain->name, lp_winbind_separator(), 
			 name_list[ent->sam_entry_index].acct_name);
   
		result = winbindd_fill_grent(&group_list[i], domain_group_name,
					     group_gid);

		ent->sam_entry_index++;
		
		/* Add group to return list */
		
		if (result) {

			group_list_ndx++;
			state->response.data.num_entries++;
			
			state->response.length +=
				sizeof(struct winbindd_gr);
			
		} else {
			DEBUG(0, ("could not lookup domain group %s\n", 
				  domain_group_name));
		}
	}

	/* Out of domains */

 done:	
	return (group_list_ndx > 0) ? WINBINDD_OK : WINBINDD_ERROR;
}

#if 0


    /* Process the current head of the getent_state list */

    while(state->getgrent_state != NULL) {
        struct getent_state *ent = state->getgrent_state;

        /* Get list of entries if we haven't already got them */

        if (!ent->got_sam_entries && !get_sam_group_entries(ent)) {
		goto cleanup;
        }

        /* Send back a group */

        while (ent->sam_entry_index < ent->num_sam_entries) {
            enum winbindd_result result;
            fstring domain_group_name;
            char *group_name = ((struct acct_info *)ent->sam_entries)
                [ent->sam_entry_index].acct_name; 
   
            /* Prepend domain to name */

	    snprintf(domain_group_name, sizeof(domain_group_name),
		     "%s%s%s", ent->domain->name, lp_winbind_separator(), 
		     group_name);
   
            /* Get group entry from group name */

            fstrcpy(state->request.data.groupname, domain_group_name);
            result = winbindd_getgrnam_from_group(state);

            ent->sam_entry_index++;
                                                      
            if (result == WINBINDD_OK) {
                return result;
            }

            /* Try next group */

            DEBUG(1, ("could not getgrnam_from_group for group name %s\n",
                      domain_group_name));
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

            old_ent = state->getgrent_state;
            DLIST_REMOVE(state->getgrent_state, state->getgrent_state);
            free(old_ent);
        }
    }

    /* Out of pipes so we're done */

    return WINBINDD_ERROR;
}

#endif

/* List domain groups without mapping to unix ids */

enum winbindd_result winbindd_list_groups(struct winbindd_cli_state *state)
{
        uint32 total_entries = 0;
        struct winbindd_domain *domain;
	struct getent_state groups;
	char *extra_data = NULL;
	int extra_data_len = 0, i;

        /* Enumerate over trusted domains */

        for (domain = domain_list; domain; domain = domain->next) {

		/* Skip domains other than WINBINDD_DOMAIN environment
		   variable */ 

		if ((strcmp(state->request.domain, "") != 0) &&
		    !check_domain_env(state->request.domain, domain->name)) {
			continue;
		}

		/* Get list of sam groups */

		ZERO_STRUCT(groups);
		groups.domain = domain;

		get_sam_group_entries(&groups);

		if (groups.num_sam_entries == 0) continue;

		/* Allocate some memory for extra data.  Note that we limit
		   account names to sizeof(fstring) = 128 characters.  */

		total_entries += groups.num_sam_entries;
		extra_data = Realloc(extra_data, 
				     sizeof(fstring) * total_entries);

		if (!extra_data) {
			return WINBINDD_ERROR;
		}

		/* Pack group list into extra data fields */

		for (i = 0; i < groups.num_sam_entries; i++) {
			char *group_name = ((struct acct_info *)
					    groups.sam_entries)[i].acct_name; 
			fstring name;

			/* Convert unistring to ascii */

			snprintf(name, sizeof(name), "%s%s%s",
				 domain->name, lp_winbind_separator(),
				 group_name);

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

	/* No domains may have responded but that's still OK so don't
	   return an error. */

        return WINBINDD_OK;
}
