/* 
   Unix SMB/Netbios implementation.
   Version 2.2.

   Winbind daemon for ntdom nss module

   Copyright (C) Tim Potter 2000
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

/***************************************************************
 Empty static struct for negative caching.
****************************************************************/

static struct winbindd_gr negative_gr_cache_entry;

/* Fill a grent structure from various other information */

static BOOL fill_grent(struct winbindd_gr *gr, char *gr_name,
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

static BOOL fill_grent_mem(struct winbindd_domain *domain,
			   uint32 group_rid, 
			   enum SID_NAME_USE group_name_type, 
			   int *num_gr_mem, char **gr_mem, int *gr_mem_len)
{
	uint32 *rid_mem = NULL, num_names = 0;
	uint32 *name_types = NULL;
	int buf_len, buf_ndx, i;
	char **names = NULL, *buf;
	BOOL result = False;
	TALLOC_CTX *mem_ctx;

	if (!(mem_ctx = talloc_init()))
		return False;

	/* Initialise group membership information */
	
	DEBUG(10, ("fill_grent_mem(): group %s rid 0x%x\n",
		   domain ? domain->name : "NULL", group_rid));

	*num_gr_mem = 0;
	
	if (group_name_type != SID_NAME_DOM_GRP) {
		DEBUG(1, ("fill_grent_mem(): rid %d in domain %s isn't a "
			  "domain group\n", group_rid, domain->name));
                goto done;
	}

	/* Lookup group members */

	if (!winbindd_lookup_groupmem(domain, mem_ctx, group_rid, &num_names, 
				      &rid_mem, &names, &name_types)) {

		DEBUG(1, ("fill_grent_mem(): could not lookup membership "
			  "for group rid %d in domain %s\n", 
			  group_rid, domain->name));

		goto done;
	}

	DEBUG(10, ("fill_grent_mem(): looked up %d names\n", num_names));

	if (DEBUGLEVEL >= 10) {
		for (i = 0; i < num_names; i++)
			DEBUG(10, ("\t%20s %x %d\n", names[i], rid_mem[i],
				   name_types[i]));
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

		DEBUG(10, ("fill_grent_mem(): processing name %s\n", 
                           the_name));

		/* FIXME: need to cope with groups within groups.  These
                   occur in Universal groups on a Windows 2000 native mode
                   server. */

		if (name_types[i] != SID_NAME_USER) {
			DEBUG(3, ("fill_grent_mem(): name %s isn't a domain "
				  "user\n", the_name));
			continue;
		}

		/* Don't bother with machine accounts */
		
		if (the_name[strlen(the_name) - 1] == '$') {
			DEBUG(10, ("fill_grent_mem(): %s is machine account\n",
				   the_name));
			continue;
		}

		/* Append domain name */

		snprintf(name, sizeof(name), "%s%s%s", domain->name,
			 lp_winbind_separator(), the_name);

		len = strlen(name);
		
		/* Add to list or calculate buffer length */

		if (!buf) {
			buf_len += len + 1; /* List is comma separated */
			(*num_gr_mem)++;
			DEBUG(10, ("fill_grent_mem(): buf_len + %d = %d\n", len + 1,
				   buf_len));
		} else {
			DEBUG(10, ("fill_grent_mem(): appending %s at index %d\n",
				   name, len));
			safe_strcpy(&buf[buf_ndx], name, len);
			buf_ndx += len;
			buf[buf_ndx] = ',';
			buf_ndx++;
		}
	}

	/* Allocate buffer */

	if (!buf) {
		if (!(buf = malloc(buf_len))) {
			DEBUG(1, ("fill_grent_mem(): out of memory\n"));
			result = False;
			goto done;
		}
		memset(buf, 0, buf_len);
		goto again;
	}

	if (buf && buf_ndx > 0) {
		buf[buf_ndx - 1] = '\0';
	}

	*gr_mem = buf;
	*gr_mem_len = buf_len;

	DEBUG(10, ("fill_grent_mem(): num_mem = %d, len = %d, mem = %s\n", 
                   *num_gr_mem, buf_len, num_gr_mem ? buf : "NULL"));

	result = True;

done:

	talloc_destroy(mem_ctx);
	
	DEBUG(10, ("fill_grent_mem(): returning %d\n", result));

	return result;
}

/* Return a group structure from a group name */

enum winbindd_result winbindd_getgrnam_from_group(struct winbindd_cli_state *state)
{
	DOM_SID group_sid;
	struct winbindd_domain *domain;
	enum SID_NAME_USE name_type;
	uint32 group_rid;
	fstring name_domain, name_group, name;
	char *tmp, *gr_mem;
	gid_t gid;
	int extra_data_len, gr_mem_len;
	
	DEBUG(3, ("[%5d]: getgrnam %s\n", state->pid,
		  state->request.data.groupname));

	/* Parse domain and groupname */
	
	memset(name_group, 0, sizeof(fstring));

	tmp = state->request.data.groupname;
	parse_domain_user(tmp, name_domain, name_group);

	/* Reject names that don't have a domain - i.e name_domain contains 
	   the entire name. */

	if (strequal(name_group, ""))
		return WINBINDD_ERROR;

	/* Get info for the domain */

	if ((domain = find_domain_from_name(name_domain)) == NULL) {
		DEBUG(0, ("getgrname_from_group(): could not get domain "
			  "sid for domain %s\n", name_domain));
		return WINBINDD_ERROR;
	}

	/* Check for cached group entry */

	if (winbindd_fetch_group_cache_entry(domain, name_group,
					     &state->response.data.gr,
					     &state->response.extra_data,
					     &extra_data_len)) {

		/* Check if this is a negative cache entry. */

		if (memcmp(&negative_gr_cache_entry, &state->response.data.gr,
				sizeof(state->response.data.gr)) == 0)
            return WINBINDD_ERROR;

		state->response.length += extra_data_len;
		return WINBINDD_OK;
	}

	snprintf(name, sizeof(name), "%s\\%s", name_domain, name_group);

	/* Get rid and name type from name */
        
	if (!winbindd_lookup_sid_by_name(domain, name, &group_sid, &name_type)) {
		DEBUG(1, ("group %s in domain %s does not exist\n", 
			  name_group, name_domain));

		winbindd_store_group_cache_entry(domain, name_group, 
					 &negative_gr_cache_entry, NULL, 0);

		return WINBINDD_ERROR;
	}

	if ((name_type != SID_NAME_ALIAS) && (name_type != SID_NAME_DOM_GRP)) {
		DEBUG(1, ("from_group: name '%s' is not a local or domain "
			  "group: %d\n", name_group, name_type));

		winbindd_store_group_cache_entry(domain, name_group, 
					 &negative_gr_cache_entry, NULL, 0);

		return WINBINDD_ERROR;
	}

	/* Fill in group structure */

	sid_split_rid(&group_sid, &group_rid);

	if (!winbindd_idmap_get_gid_from_rid(domain->name, group_rid, &gid)) {
		DEBUG(1, ("error sursing unix gid for sid\n"));

		winbindd_store_group_cache_entry(domain, name_group, 
					 &negative_gr_cache_entry, NULL, 0);

		return WINBINDD_ERROR;
	}

	if (!fill_grent(&state->response.data.gr, 
			state->request.data.groupname, gid) ||
	    !fill_grent_mem(domain, group_rid, name_type,
			    &state->response.data.gr.num_gr_mem,
			    &gr_mem, &gr_mem_len)) {

		winbindd_store_group_cache_entry(domain, name_group, 
					 &negative_gr_cache_entry, NULL, 0);

		return WINBINDD_ERROR;
	}

	/* Group membership lives at start of extra data */

	state->response.data.gr.gr_mem_ofs = 0;

	state->response.length += gr_mem_len;
	state->response.extra_data = gr_mem;

	/* Update cached group info */

	winbindd_store_group_cache_entry(domain, name_group, 
					 &state->response.data.gr,
					 state->response.extra_data,
					 gr_mem_len);

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
	int extra_data_len, gr_mem_len;
	char *gr_mem;

	DEBUG(3, ("[%5d]: getgrgid %d\n", state->pid, 
		  state->request.data.gid));

	/* Bug out if the gid isn't in the winbind range */

	if ((state->request.data.gid < server_state.gid_low) ||
	    (state->request.data.gid > server_state.gid_high))
		return WINBINDD_ERROR;

	/* Get rid from gid */

	if (!winbindd_idmap_get_rid_from_gid(state->request.data.gid, 
					     &group_rid, &domain)) {
		DEBUG(1, ("Could not convert gid %d to rid\n", 
			  state->request.data.gid));
		return WINBINDD_ERROR;
	}

	/* Try a cached entry */

	if (winbindd_fetch_gid_cache_entry(domain, 
					   state->request.data.gid,
					   &state->response.data.gr,
					   &state->response.extra_data,
					   &extra_data_len)) {

		/* Check if this is a negative cache entry. */

		if (memcmp(&negative_gr_cache_entry, &state->response.data.gr,
				sizeof(state->response.data.gr)) == 0)
            return WINBINDD_ERROR;

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

	if (strcmp(lp_winbind_separator(),"\\"))
		string_sub(group_name, "\\", lp_winbind_separator(), 
			   sizeof(fstring));

	if (!((name_type == SID_NAME_ALIAS) || 
	      (name_type == SID_NAME_DOM_GRP))) {
		DEBUG(1, ("from_gid: name '%s' is not a local or domain "
			  "group: %d\n", group_name, name_type));
		return WINBINDD_ERROR;
	}

	/* Fill in group structure */

	if (!fill_grent(&state->response.data.gr, group_name, 
			state->request.data.gid) ||
	    !fill_grent_mem(domain, group_rid, name_type,
			    &state->response.data.gr.num_gr_mem,
			    &gr_mem, &gr_mem_len))
		return WINBINDD_ERROR;

	/* Group membership lives at start of extra data */

	state->response.data.gr.gr_mem_ofs = 0;

	state->response.length += gr_mem_len;
	state->response.extra_data = gr_mem;

	/* Update cached group info */

	winbindd_store_gid_cache_entry(domain, state->request.data.gid,
				       &state->response.data.gr,
				       state->response.extra_data,
				       gr_mem_len);

	return WINBINDD_OK;
}

/*
 * set/get/endgrent functions
 */

/* "Rewind" file pointer for group database enumeration */

enum winbindd_result winbindd_setgrent(struct winbindd_cli_state *state)
{
	struct winbindd_domain *tmp;

	DEBUG(3, ("[%5d]: setgrent\n", state->pid));

	/* Check user has enabled this */

	if (!lp_winbind_enum_groups())
		return WINBINDD_ERROR;

	/* Free old static data if it exists */
	
	if (state->getgrent_state != NULL) {
		free_getent_state(state->getgrent_state);
		state->getgrent_state = NULL;
	}
	
	/* Create sam pipes for each domain we know about */
	
	if (domain_list == NULL)
		get_domain_info();

	for (tmp = domain_list; tmp != NULL; tmp = tmp->next) {
		struct getent_state *domain_state;
		
		/* Skip domains other than WINBINDD_DOMAIN environment 
		   variable */
		
		if ((strcmp(state->request.domain, "") != 0) &&
		    !check_domain_env(state->request.domain, tmp->name))
			continue;
		
		/* Create a state record for this domain */
		
		if ((domain_state = (struct getent_state *)
		     malloc(sizeof(struct getent_state))) == NULL)
			return WINBINDD_ERROR;
		
		ZERO_STRUCTP(domain_state);
		
		domain_state->domain = tmp;

		/* Add to list of open domains */
		
		DLIST_ADD(state->getgrent_state, domain_state);
	}
	
	return WINBINDD_OK;
}

/* Close file pointer to ntdom group database */

enum winbindd_result winbindd_endgrent(struct winbindd_cli_state *state)
{
	DEBUG(3, ("[%5d]: endgrent\n", state->pid));

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
	NTSTATUS status;
	uint32 num_entries;
	struct acct_info *name_list = NULL, *tnl;
	TALLOC_CTX *mem_ctx;
	BOOL result = False;
        
	if (ent->got_all_sam_entries)
		return False;

#if 0
	if (winbindd_fetch_group_cache(ent->domain, 
				       &ent->sam_entries,
				       &ent->num_sam_entries))
		return True;
#endif

	if (!(mem_ctx = talloc_init()))
		return False;
		
	/* Free any existing group info */

	SAFE_FREE(ent->sam_entries);
	ent->num_sam_entries = 0;
		
	/* Enumerate domain groups */
		
	do {
		struct acct_info *sam_grp_entries = NULL;

		num_entries = 0;

		status = ent->domain->methods->enum_dom_groups(ent->domain,
							       mem_ctx, 
							       &ent->grp_query_start_ndx,
							       &num_entries,
							       &sam_grp_entries);

		if (!NT_STATUS_IS_OK(status)) break;

		/* Copy entries into return buffer */

		if (num_entries) {

			tnl = Realloc(name_list,
				    sizeof(struct acct_info) *
				    (ent->num_sam_entries +
				     num_entries));

			if (tnl == NULL) {
				DEBUG(0,("get_sam_group_entries: unable to "
                                         "realloc a structure!\n"));
				SAFE_FREE(name_list);

				goto done;
			} else 
				name_list = tnl;

			memcpy(&name_list[ent->num_sam_entries],
			       sam_grp_entries, 
			       num_entries * sizeof(struct acct_info));
		}

		ent->num_sam_entries += num_entries;
		
		if (NT_STATUS_V(status) != NT_STATUS_V(STATUS_MORE_ENTRIES))
			break;

	} while (ent->num_sam_entries < MAX_FETCH_SAM_ENTRIES);
		
#if 0
	/* Fill cache with received entries */

	winbindd_store_group_cache(ent->domain, ent->sam_entries,
				   ent->num_sam_entries);
#endif

	/* Fill in remaining fields */

	ent->sam_entries = name_list;
	ent->sam_entry_index = 0;
	ent->got_all_sam_entries = (NT_STATUS_V(status) != 
                                    NT_STATUS_V(STATUS_MORE_ENTRIES));

	result = (ent->num_sam_entries > 0);

 done:

	talloc_destroy(mem_ctx);

	return result;
}

/* Fetch next group entry from ntdom database */

#define MAX_GETGRENT_GROUPS 500

enum winbindd_result winbindd_getgrent(struct winbindd_cli_state *state)
{
	struct getent_state *ent;
	struct winbindd_gr *group_list = NULL;
	int num_groups, group_list_ndx = 0, i, gr_mem_list_len = 0;
	char *sep, *new_extra_data, *gr_mem_list = NULL;

	DEBUG(3, ("[%5d]: getgrent\n", state->pid));

	/* Check user has enabled this */

	if (!lp_winbind_enum_groups())
		return WINBINDD_ERROR;

	num_groups = MIN(MAX_GETGRENT_GROUPS, state->request.data.num_entries);

	if ((state->response.extra_data = 
	     malloc(num_groups * sizeof(struct winbindd_gr))) == NULL)
		return WINBINDD_ERROR;

	state->response.data.num_entries = 0;

	group_list = (struct winbindd_gr *)state->response.extra_data;
	sep = lp_winbind_separator();

	if (!(ent = state->getgrent_state))
		return WINBINDD_ERROR;

	/* Start sending back groups */

	for (i = 0; i < num_groups; i++) {
		struct acct_info *name_list = NULL;
		fstring domain_group_name;
		uint32 result;
		gid_t group_gid;
		int gr_mem_len;
		char *gr_mem, *new_gr_mem_list;
		
		/* Do we need to fetch another chunk of groups? */

	tryagain:

		DEBUG(10, ("getgrent(): entry_index = %d, num_entries = %d\n",
			   ent->sam_entry_index, ent->num_sam_entries));

		if (ent->num_sam_entries == ent->sam_entry_index) {

			while(ent && !get_sam_group_entries(ent)) {
				struct getent_state *next_ent;

				DEBUG(10, ("getgrent(): freeing state info for "
					   "domain %s\n", ent->domain->name)); 

				/* Free state information for this domain */

				SAFE_FREE(ent->sam_entries);

				next_ent = ent->next;
				DLIST_REMOVE(state->getgrent_state, ent);
				
				SAFE_FREE(ent);
				ent = next_ent;
			}

			/* No more domains */

			if (!ent) 
                                break;
		}
		
		name_list = ent->sam_entries;
		
		/* Lookup group info */
		
		if (!winbindd_idmap_get_gid_from_rid(
			ent->domain->name,
			name_list[ent->sam_entry_index].rid,
			&group_gid)) {
			
			DEBUG(1, ("getgrent(): could not look up gid for group %s\n",
				  name_list[ent->sam_entry_index].acct_name));

			ent->sam_entry_index++;
			goto tryagain;
		}

		DEBUG(10, ("getgrent(): got gid %d for group %x\n", group_gid,
			   name_list[ent->sam_entry_index].rid));
		
		/* Fill in group entry */

		slprintf(domain_group_name, sizeof(domain_group_name) - 1,
			 "%s%s%s", ent->domain->name, lp_winbind_separator(), 
			 name_list[ent->sam_entry_index].acct_name);
   
		result = fill_grent(&group_list[group_list_ndx], 
				    domain_group_name, group_gid);

		/* Fill in group membership entry */

		if (result) {
			/* Get group membership */
			result = fill_grent_mem(
				ent->domain,
				name_list[ent->sam_entry_index].rid,
				SID_NAME_DOM_GRP,
				&group_list[group_list_ndx].num_gr_mem, 
				&gr_mem, &gr_mem_len);
		}

		if (result) {
			/* Append to group membership list */
			new_gr_mem_list = Realloc(
				gr_mem_list,
				gr_mem_list_len + gr_mem_len);

			if (!new_gr_mem_list && (group_list[group_list_ndx].num_gr_mem != 0)) {
				DEBUG(0, ("getgrent(): out of memory\n"));
				SAFE_FREE(gr_mem_list);
				gr_mem_list_len = 0;
				break;
			}

			DEBUG(10, ("getgrent(): list_len = %d, mem_len = %d\n",
				   gr_mem_list_len, gr_mem_len));

			gr_mem_list = new_gr_mem_list;

			memcpy(&gr_mem_list[gr_mem_list_len], gr_mem,
			       gr_mem_len);

			SAFE_FREE(gr_mem);

			group_list[group_list_ndx].gr_mem_ofs = 
				gr_mem_list_len;

			gr_mem_list_len += gr_mem_len;
		}

		ent->sam_entry_index++;
		
		/* Add group to return list */
		
		if (result) {

			DEBUG(10, ("getgrent(): adding group num_entries = %d\n",
				   state->response.data.num_entries));

			group_list_ndx++;
			state->response.data.num_entries++;
			
			state->response.length +=
				sizeof(struct winbindd_gr);
			
		} else {
			DEBUG(0, ("could not lookup domain group %s\n", 
				  domain_group_name));
		}
	}

	/* Copy the list of group memberships to the end of the extra data */

	if (group_list_ndx == 0)
		goto done;

	new_extra_data = Realloc(
		state->response.extra_data,
		group_list_ndx * sizeof(struct winbindd_gr) + gr_mem_list_len);

	if (!new_extra_data) {
		DEBUG(0, ("out of memory\n"));
		group_list_ndx = 0;
		SAFE_FREE(state->response.extra_data);
		SAFE_FREE(gr_mem_list);

		return WINBINDD_ERROR;
	}

	state->response.extra_data = new_extra_data;

	memcpy(&((char *)state->response.extra_data)
	       [group_list_ndx * sizeof(struct winbindd_gr)], 
	       gr_mem_list, gr_mem_list_len);

       	SAFE_FREE(gr_mem_list);

	state->response.length += gr_mem_list_len;

	DEBUG(10, ("getgrent(): returning %d groups, length = %d\n",
		   group_list_ndx, gr_mem_list_len));

	/* Out of domains */

 done:

	return (group_list_ndx > 0) ? WINBINDD_OK : WINBINDD_ERROR;
}

/* List domain groups without mapping to unix ids */

enum winbindd_result winbindd_list_groups(struct winbindd_cli_state *state)
{
	uint32 total_entries = 0;
	uint32 num_domain_entries;
	struct winbindd_domain *domain;
	struct getent_state groups;
	char *extra_data = NULL;
	char *ted = NULL;
	int extra_data_len = 0, i;
	void *sam_entries = NULL;

	DEBUG(3, ("[%5d]: list groups\n", state->pid));

	/* Enumerate over trusted domains */

	ZERO_STRUCT(groups);

	if (domain_list == NULL)
		get_domain_info();

	for (domain = domain_list; domain; domain = domain->next) {

		/* Skip domains other than WINBINDD_DOMAIN environment
		   variable */ 

		if ((strcmp(state->request.domain, "") != 0) &&
		    !check_domain_env(state->request.domain, domain->name))
			continue;

		/* Get list of sam groups */

		ZERO_STRUCT(groups);
		groups.domain = domain;

		/* 
		 * iterate through all groups 
		 * total_entries:  maintains a total count over **all domains**
		 * num_domain_entries:  is the running count for this domain
		 */
		 
		num_domain_entries = 0;

		while (get_sam_group_entries(&groups)) {
			int new_size;
			int offset;
			
			offset = sizeof(struct acct_info) * num_domain_entries;
			new_size = sizeof(struct acct_info) 
			 	* (groups.num_sam_entries + num_domain_entries);
			sam_entries = Realloc(sam_entries, new_size);
			
			if (!sam_entries)
				return WINBINDD_ERROR;
			
			num_domain_entries += groups.num_sam_entries;
			memcpy (((char *)sam_entries)+offset, 
                                groups.sam_entries, 
				sizeof(struct acct_info) * 
                                groups.num_sam_entries);
			
			groups.sam_entries = NULL;
			groups.num_sam_entries = 0;
		}

		/* skip remainder of loop if we idn;t retrieve any groups */
		
		if (num_domain_entries == 0) 
			continue;

		/* setup the groups struct to contain all the groups 
		   retrieved for this domain */
		  
		groups.num_sam_entries = num_domain_entries;
		groups.sam_entries = sam_entries;

		/* keep track the of the total number of groups seen so 
		   far over all domains */

		total_entries += groups.num_sam_entries;
		
		/* Allocate some memory for extra data.  Note that we limit
		   account names to sizeof(fstring) = 128 characters.  */
		
                ted = Realloc(extra_data, sizeof(fstring) * total_entries);
 
		if (!ted) {
			DEBUG(0,("winbindd_list_groups: failed to enlarge "
                                 "buffer!\n"));
			SAFE_FREE(extra_data);
			return WINBINDD_ERROR;
		} else
			extra_data = ted;

		/* Pack group list into extra data fields */

		for (i = 0; i < groups.num_sam_entries; i++) {
			char *group_name = ((struct acct_info *)
					    groups.sam_entries)[i].acct_name; 
			fstring name;

			/* Convert unistring to ascii */

			snprintf(name, sizeof(name), "%s%s%s", domain->name, 
				lp_winbind_separator(), group_name);

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

/* Get user supplementary groups.  This is much quicker than trying to
   invert the groups database. */

enum winbindd_result winbindd_getgroups(struct winbindd_cli_state *state)
{
	fstring name_domain, name_user, name;
	DOM_SID user_sid;
	enum SID_NAME_USE name_type;
	uint32 user_rid, num_groups, num_gids;
	NTSTATUS status;
	uint32 *user_gids;
	struct winbindd_domain *domain;
	enum winbindd_result result = WINBINDD_ERROR;
	gid_t *gid_list;
	int i;
	TALLOC_CTX *mem_ctx;
	
	DEBUG(3, ("[%5d]: getgroups %s\n", state->pid,
		  state->request.data.username));

	if (!(mem_ctx = talloc_init()))
		return WINBINDD_ERROR;

	/* Parse domain and username */

	parse_domain_user(state->request.data.username, name_domain, 
			  name_user);

	/* Reject names that don't have a domain - i.e name_domain contains 
	   the entire name. */
 
	if (strequal(name_domain, ""))
		goto done;

	/* Get info for the domain */
	
	if ((domain = find_domain_from_name(name_domain)) == NULL) {
		DEBUG(0, ("could not find domain entry for domain %s\n", 
			  name_domain));
		goto done;
	}

	slprintf(name, sizeof(name) - 1, "%s\\%s", name_domain, name_user);
	
	/* Get rid and name type from name.  The following costs 1 packet */

	if (!winbindd_lookup_sid_by_name(domain, name, &user_sid, &name_type)) {
		DEBUG(1, ("user '%s' does not exist\n", name_user));
		goto done;
	}

	if (name_type != SID_NAME_USER) {
		DEBUG(1, ("name '%s' is not a user name: %d\n", name_user, 
			  name_type));
		goto done;
	}

	sid_split_rid(&user_sid, &user_rid);

	status = domain->methods->lookup_usergroups(domain, mem_ctx, name_user, user_rid, &num_groups, &user_gids);
	if (!NT_STATUS_IS_OK(status)) goto done;

	/* Copy data back to client */

	num_gids = 0;
	gid_list = malloc(sizeof(gid_t) * num_groups);

	if (state->response.extra_data)
		goto done;

	for (i = 0; i < num_groups; i++) {
		if (!winbindd_idmap_get_gid_from_rid(domain->name, user_gids[i], &gid_list[num_gids])) {
			DEBUG(1, ("unable to convert group rid %d to gid\n", user_gids[i]));
			continue;
		}
			
		num_gids++;
	}

	state->response.data.num_entries = num_gids;
	state->response.extra_data = gid_list;
	state->response.length += num_gids * sizeof(gid_t);

	result = WINBINDD_OK;

 done:

	talloc_destroy(mem_ctx);

	return result;
}
