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

static void winbindd_fill_grent(struct winbindd_gr *gr, char *gr_name,
                                gid_t unix_gid)
{
	/* Fill in uid/gid */

	gr->gr_gid = unix_gid;
    
	/* Group name and password */
    
	safe_strcpy(gr->gr_name, gr_name, sizeof(gr->gr_name) - 1);
	safe_strcpy(gr->gr_passwd, "x", sizeof(gr->gr_passwd) - 1);
}

/* Fill in group membership */

struct grent_mem_group {
	uint32 rid;
	enum SID_NAME_USE name_type;
	fstring domain_name;
	struct winbindd_domain *domain;
	struct grent_mem_group *prev, *next;
};

struct grent_mem_list {
	fstring name;
	struct grent_mem_list *prev, *next;
};

/* Name comparison function for qsort() */

static int name_comp(struct grent_mem_list *n1, struct grent_mem_list *n2)
{
	/* Silly cases */
	
	if (!n1 && !n2) return 0;
	if (!n1) return -1;
	if (!n2) return 1;
	
	return strcmp(n1->name, n2->name);
}

static struct grent_mem_list *sort_groupmem_list(struct grent_mem_list *list,
                                                 int num_gr_mem)
{
	struct grent_mem_list *groupmem_array, *temp;
	int i;
	
	/* Allocate and zero an array to hold sorted entries */
	
	if ((groupmem_array = malloc(num_gr_mem * 
				     sizeof(struct grent_mem_list))) == NULL) {
		return NULL;
	}

	memset((char *)groupmem_array, 0, num_gr_mem * 
	       sizeof(struct grent_mem_list));

	/* Copy list to array */
	
	for(temp = list, i = 0; temp && i < num_gr_mem; 
	    temp = temp->next, i++) {
		fstrcpy(groupmem_array[i].name, temp->name);
	}

	/* Sort array */

	qsort(groupmem_array, num_gr_mem, sizeof(struct grent_mem_list), 
	      QSORT_CAST name_comp);
	
	/* Fix up resulting array to a linked list and return it */
	
	for(i = 0; i < num_gr_mem; i++) {
		
		/* Fix up previous link */
		
		if (i != 0) {
			groupmem_array[i].prev = &groupmem_array[i - 1];
		}
		
		/* Fix up next link */
		
		if (i != (num_gr_mem - 1)) {
			groupmem_array[i].next = &groupmem_array[i + 1];
		}
	}
	
	return groupmem_array;
}

/* Fill in the group membership field of a NT group given by group_rid.
   This function is *waaay* to long and needs to be split up. */

static BOOL winbindd_fill_grent_mem(struct winbindd_domain *domain,
                                    uint32 group_rid, 
                                    enum SID_NAME_USE group_name_type, 
                                    struct winbindd_response *response)
{
	struct grent_mem_group *done_groups = NULL, *todo_groups = NULL;
	struct grent_mem_group *temp_group;
	struct grent_mem_list *groupmem_list = NULL;
	struct winbindd_gr *gr;
	
	if (!response) return False;
	
	gr = &response->data.gr;
	
	/* Initialise group membership information */
	
	gr->num_gr_mem = 0;
	
	/* Add first group to todo_groups list */
	
	if ((temp_group = 
	     (struct grent_mem_group *)malloc(sizeof(*temp_group))) == NULL) {
		return False;
	}
	
	ZERO_STRUCTP(temp_group);
	
	temp_group->rid = group_rid;
	temp_group->name_type = group_name_type;
	temp_group->domain = domain;
	fstrcpy(temp_group->domain_name, domain->name);
	
	DLIST_ADD(todo_groups, temp_group);
	
	/* Iterate over all groups to find members of */
	
	while(todo_groups != NULL) {
		struct grent_mem_group *current_group = todo_groups;
		uint32 num_names = 0, *rid_mem = NULL;
		enum SID_NAME_USE *name_types = NULL;
		
		DOM_SID **sids = NULL;
		char **names = NULL;
		BOOL done_group;
		int i;
		
		/* Check we haven't looked up this group before */
		
		done_group = 0;
		
		for (temp_group = done_groups; temp_group != NULL; 
		     temp_group = temp_group->next) {
			
			if ((temp_group->rid == current_group->rid) &&
			    (strcmp(temp_group->domain_name, 
				    current_group->domain_name) == 0)) {
				
				done_group = 1;
			}
		}
		
		if (done_group) goto cleanup;
		
		/* Lookup group membership for the current group */
		
		if (current_group->name_type == SID_NAME_DOM_GRP) {
			
			if (!winbindd_lookup_groupmem(current_group->domain, 
						      current_group->rid, 
						      &num_names, &rid_mem, 
						      &names, &name_types)) {

				DEBUG(1, ("fill_grent_mem(): could not "
					  "lookup membership for group rid "
					  "%d in domain %s\n", 
					  current_group->rid,
					  current_group->domain->name));

				/* Exit if we cannot lookup the membership
				   for the group this function was called
				   to look at */

				if (current_group->rid == group_rid) {
					return False;
				} else {
					goto cleanup;
				}
			}
		}

		if (current_group->name_type == SID_NAME_ALIAS) {
			
			if (!winbindd_lookup_aliasmem(current_group->domain, 
						      current_group->rid, 
						      &num_names, &sids, 
						      &names, &name_types)) {

				DEBUG(1, ("fill_grent_mem(): group rid %d "
					  "not a local group\n", group_rid));

				/* Exit if we cannot lookup the membership
				   for the group this function was called
				   to look at */
				
				if (current_group->rid == group_rid) {
					return False;
				} else {
					goto cleanup;
				}
			}
		}
		
		/* Now for each member of the group, add it to the group
		   list if it is a user, otherwise push it onto the
		   todo_group list if it is a group or an alias. */
		
		for (i = 0; i < num_names; i++) {
			fstring name_part1, name_part2;
			char *name_dom, *name_user, *the_name;
			struct winbindd_domain *name_domain;
			
			the_name = names[i];

			/* Don't bother with machine accounts */

			if (the_name[strlen(the_name) - 1] == '$') {
				continue;
			}

			/* Lookup name */
			
			ZERO_STRUCT(name_part1);
			ZERO_STRUCT(name_part2);
			
			parse_domain_user(the_name, name_part1, name_part2);
			
			if (strcmp(name_part1, "") != 0) {
				name_dom = name_part1;
				name_user = name_part2;
				
				if ((name_domain = 
				     find_domain_from_name(name_dom)) 
				    == NULL) {
					DEBUG(0, ("unable to look up "
						  "domain record for domain "
						  "%s\n", name_dom));
					continue;
				}
				
			} else {
				name_dom = current_group->domain->name;
				name_user = name_part2;
				name_domain = current_group->domain;
			}
			
			/* Check name type */
			
			if (name_types[i] == SID_NAME_USER) {
				struct grent_mem_list *entry;
				
				/* Add to group membership list */
				
				if ((entry = (struct grent_mem_list *)
				     malloc(sizeof(*entry))) != NULL) {
					
					/* Create name */
					slprintf(entry->name, 
						 sizeof(entry->name),
						 "%s%s%s", name_dom,
						 lp_winbind_separator(), 
						 name_user);
					
					/* Add to list */
					
					DLIST_ADD(groupmem_list, entry);
					gr->num_gr_mem++;
				}
				
			} else {
				struct grent_mem_group *todo_group;
				
				/* Add group to todo list */
				
				if ((todo_group = 
				     (struct grent_mem_group *)
				     malloc(sizeof(*todo_group))) 
				    != NULL) {
					
					ZERO_STRUCTP(todo_group);
					
					todo_group->rid = rid_mem[i];
					todo_group->name_type = name_types[i];
					todo_group->domain = name_domain;
						
					fstrcpy(todo_group->domain_name, 
						name_dom);
						
					DLIST_ADD(todo_groups, todo_group);
				}
			}
		}
	
	cleanup:
	
		/* Remove group from todo list and add to done_groups list */
		
		DLIST_REMOVE(todo_groups, current_group);
		DLIST_ADD(done_groups, current_group);
		
		/* Free memory allocated in
                   winbindd_lookup_{alias,group}mem() */
		
		safe_free(name_types);
		safe_free(rid_mem);
		
		free_char_array(num_names, names);
		free_sid_array(num_names, sids);
	}
	
	/* Free done groups list */
	
	temp_group = done_groups;
	
	if (temp_group != NULL) {
		while (temp_group != NULL) {
			struct grent_mem_group *next;
			
			DLIST_REMOVE(done_groups, temp_group);
			next = temp_group->next;
			
			free(temp_group);
			temp_group = next;
		}
	}
	
	/* Remove duplicates from group member list. */
	
	if (gr->num_gr_mem > 0) {
		struct grent_mem_list *sorted_groupmem_list, *temp;
		int extra_data_len = 0;
		fstring prev_name;
		char *head;
		
		/* Sort list */
		
		sorted_groupmem_list = sort_groupmem_list(groupmem_list, 
							  gr->num_gr_mem);
		/* Remove duplicates by iteration */
		
		fstrcpy(prev_name, "");
		
		for(temp = sorted_groupmem_list; temp; temp = temp->next) {
			if (strequal(temp->name, prev_name)) {
				
				/* Got a duplicate name - delete it.  Don't
				   panic as we're only adjusting the prev
				   and next pointers so memory allocation
				   is not messed up. */
				
				DLIST_REMOVE(sorted_groupmem_list, temp);
				gr->num_gr_mem--;
				
			} else {
				
				/* Got a unique name - count how long it is */
				
				extra_data_len += strlen(temp->name) + 1;
			}
		}
		
		extra_data_len++;       /* Don't forget null a terminator */
		
		/* Convert sorted list into extra data field to send back
		   to ntdom client.  Add one to extra_data_len for null
		   termination */
		
		if ((response->extra_data = malloc(extra_data_len))) {
			
			/* Initialise extra data */
			
			memset(response->extra_data, 0, extra_data_len);
			
			head = response->extra_data;
			
			/* Fill in extra data */
			
			for(temp = sorted_groupmem_list; temp; 
			    temp = temp->next) {
				int len = strlen(temp->name) + 1;
				
				safe_strcpy(head, temp->name, len);
				head[len - 1] = ',';
				head += len;
			}
			
			*head = '\0';
			
			/* Update response length */
			
			response->length = sizeof(struct winbindd_response) +
				extra_data_len;
		}
		
		/* Free memory for sorted_groupmem_list.  It was allocated
		   as an array in sort_groupmem_list() so can be freed in
		   one go. */
		
		free(sorted_groupmem_list);
		
		/* Free groupmem_list */
		
		temp = groupmem_list;
		
		while (temp != NULL) {
			struct grent_mem_list *next;
			
			DLIST_REMOVE(groupmem_list, temp);
			next = temp->next;
			
			free(temp);
			temp = next;
		}
	}
	
	return True;
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

	/* Check for cached user entry */

	if (winbindd_fetch_group_cache_entry(name_domain, name_group,
					     &state->response.data.gr,
					     &state->response.extra_data,
					     &extra_data_len)) {
		state->response.length += extra_data_len;
		return WINBINDD_OK;
	}

	slprintf(name, sizeof(name), "%s\\%s", name_domain, name_group);

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

	winbindd_fill_grent(&state->response.data.gr, 
			    state->request.data.groupname, gid);
        
	if (!winbindd_fill_grent_mem(domain, group_rid, name_type,
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

	/* try a cached entry */
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

	winbindd_fill_grent(&state->response.data.gr, group_name, 
			    state->request.data.gid);

	if (!winbindd_fill_grent_mem(domain, group_rid, name_type,
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

/* Get the list of domain groups and domain aliases for a domain */

static BOOL get_sam_group_entries(struct getent_state *ent)
{
	uint32 status, start_ndx = 0, start_ndx2 = 0;
        
	if (!winbindd_fetch_group_cache(ent->domain->name, 
					&ent->sam_entries,
					&ent->num_sam_entries)) {
		
                /* Fetch group entries */
		
                if (!domain_handles_open(ent->domain)) return False;
		
		/* Enumerate domain groups */
		
		do {
                        status =
				samr_enum_dom_groups(&ent->domain->
						     sam_dom_handle,
						     &start_ndx, 0x100000,
						     (struct acct_info **)
						     &ent->sam_entries,
						     &ent->num_sam_entries);
		} while (status == STATUS_MORE_ENTRIES);
		
		/* Enumerate domain aliases */
		
		do {
                        status = 
				samr_enum_dom_aliases(&ent->domain->
						      sam_dom_handle,
						      &start_ndx2, 0x100000,
						      (struct acct_info **)
						      &ent->sam_entries,
						      &ent->num_sam_entries);
		} while (status == STATUS_MORE_ENTRIES);
                
                /* Fill cache with received entries */

                winbindd_store_group_cache(ent->domain->name, ent->sam_entries,
					   ent->num_sam_entries);
            }
	
	ent->got_sam_entries = True;
	return True;
}

/* Fetch next group entry from netdom database */

enum winbindd_result winbindd_getgrent(struct winbindd_cli_state *state)
{
    if (state == NULL) return WINBINDD_ERROR;

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

	    slprintf(domain_group_name, sizeof(domain_group_name),
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

		/* Pack user list into extra data fields */

		for (i = 0; i < groups.num_sam_entries; i++) {
			char *group_name = ((struct acct_info *)
					    groups.sam_entries)[i].acct_name; 
			fstring name;

			/* Convert unistring to ascii */

			slprintf(name, sizeof(name), "%s%s%s",
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
