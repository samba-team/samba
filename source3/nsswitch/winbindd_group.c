/* 
   Unix SMB/CIFS implementation.

   Winbind daemon for ntdom nss module

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

extern BOOL opt_nocache;

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

/*********************************************************************
*********************************************************************/

static int gr_mem_buffer( char **buffer, char **members, int num_members )
{
	int i;
	int len = 0;
	int idx = 0;

	if ( num_members == 0 ) {
		*buffer = NULL;
		return 0;
	}
	
	for ( i=0; i<num_members; i++ )
		len += strlen(members[i])+1;

	*buffer = (char*)smb_xmalloc(len);
	for ( i=0; i<num_members; i++ ) {
		snprintf( &(*buffer)[idx], len-idx, "%s,", members[i]);
		idx += strlen(members[i])+1;
	}
	/* terminate with NULL */
	(*buffer)[len-1] = '\0';
	
	return len;	
}

/***************************************************************
 Empty static struct for negative caching.
****************************************************************/

/* Fill a grent structure from various other information */

static BOOL fill_grent(struct winbindd_gr *gr, const char *dom_name, 
		       const char *gr_name, gid_t unix_gid)
{
	fstring full_group_name;
	/* Fill in uid/gid */
	fill_domain_username(full_group_name, dom_name, gr_name);

	gr->gr_gid = unix_gid;
    
	/* Group name and password */
    
	safe_strcpy(gr->gr_name, full_group_name, sizeof(gr->gr_name) - 1);
	safe_strcpy(gr->gr_passwd, "x", sizeof(gr->gr_passwd) - 1);

	return True;
}

/* Fill in the group membership field of a NT group given by group_sid */

static BOOL fill_grent_mem(struct winbindd_domain *domain,
			   DOM_SID *group_sid, 
			   enum SID_NAME_USE group_name_type, 
			   int *num_gr_mem, char **gr_mem, int *gr_mem_len)
{
	DOM_SID **sid_mem = NULL;
	uint32 num_names = 0;
	uint32 *name_types = NULL;
	unsigned int buf_len, buf_ndx, i;
	char **names = NULL, *buf;
	BOOL result = False;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	fstring sid_string;

	if (!(mem_ctx = talloc_init("fill_grent_mem(%s)", domain->name)))
		return False;

	/* Initialise group membership information */
	
	DEBUG(10, ("group SID %s\n", sid_to_string(sid_string, group_sid)));

	*num_gr_mem = 0;

	/* HACK ALERT!! This whole routine does not cope with group members
	 * from more than one domain, ie aliases. Thus we have to work it out
	 * ourselves in a special routine. */

	if (domain->internal)
		return fill_passdb_alias_grmem(domain, group_sid,
					       num_gr_mem,
					       gr_mem, gr_mem_len);
	
	if ( !((group_name_type==SID_NAME_DOM_GRP) ||
		((group_name_type==SID_NAME_ALIAS) && domain->primary)) )
	{
		DEBUG(1, ("SID %s in domain %s isn't a domain group (%d)\n", 
			  sid_to_string(sid_string, group_sid), domain->name, 
			  group_name_type));
                goto done;
	}

	/* Lookup group members */
	status = domain->methods->lookup_groupmem(domain, mem_ctx, group_sid, &num_names, 
						  &sid_mem, &names, &name_types);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("could not lookup membership for group rid %s in domain %s (error: %s)\n", 
			  sid_to_string(sid_string, group_sid), domain->name, nt_errstr(status)));

		goto done;
	}

	DEBUG(10, ("looked up %d names\n", num_names));

	if (DEBUGLEVEL >= 10) {
		for (i = 0; i < num_names; i++)
			DEBUG(10, ("\t%20s %s %d\n", names[i], sid_to_string(sid_string, sid_mem[i]),
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

		DEBUG(10, ("processing name %s\n", the_name));

		/* FIXME: need to cope with groups within groups.  These
                   occur in Universal groups on a Windows 2000 native mode
                   server. */

		/* make sure to allow machine accounts */

		if (name_types[i] != SID_NAME_USER && name_types[i] != SID_NAME_COMPUTER) {
			DEBUG(3, ("name %s isn't a domain user\n", the_name));
			continue;
		}

		/* Append domain name */

		fill_domain_username(name, domain->name, the_name);

		len = strlen(name);
		
		/* Add to list or calculate buffer length */

		if (!buf) {
			buf_len += len + 1; /* List is comma separated */
			(*num_gr_mem)++;
			DEBUG(10, ("buf_len + %d = %d\n", len + 1, buf_len));
		} else {
			DEBUG(10, ("appending %s at ndx %d\n", name, len));
			safe_strcpy(&buf[buf_ndx], name, len);
			buf_ndx += len;
			buf[buf_ndx] = ',';
			buf_ndx++;
		}
	}

	/* Allocate buffer */

	if (!buf && buf_len != 0) {
		if (!(buf = malloc(buf_len))) {
			DEBUG(1, ("out of memory\n"));
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

	DEBUG(10, ("num_mem = %d, len = %d, mem = %s\n", *num_gr_mem, 
		   buf_len, *num_gr_mem ? buf : "NULL")); 
	result = True;

done:

	talloc_destroy(mem_ctx);
	
	DEBUG(10, ("fill_grent_mem returning %d\n", result));

	return result;
}

/* Return a group structure from a group name */

enum winbindd_result winbindd_getgrnam(struct winbindd_cli_state *state)
{
	DOM_SID group_sid;
	WINBINDD_GR *grp;
	struct winbindd_domain *domain;
	enum SID_NAME_USE name_type;
	fstring name_domain, name_group;
	char *tmp, *gr_mem;
	int gr_mem_len;
	gid_t gid;
	
	/* Ensure null termination */
	state->request.data.groupname[sizeof(state->request.data.groupname)-1]='\0';

	DEBUG(3, ("[%5lu]: getgrnam %s\n", (unsigned long)state->pid,
		  state->request.data.groupname));

	/* Parse domain and groupname */
	
	memset(name_group, 0, sizeof(fstring));

	tmp = state->request.data.groupname;
	
	parse_domain_user(tmp, name_domain, name_group);

	/* if no domain or our local domain, then do a local tdb search */
	
	if ( (!*name_domain || strequal(name_domain, get_global_sam_name())) &&
	     ((grp = wb_getgrnam(name_group)) != NULL) ) {

		char *buffer = NULL;
		
		memcpy( &state->response.data.gr, grp, sizeof(WINBINDD_GR) );

		gr_mem_len = gr_mem_buffer( &buffer, grp->gr_mem, grp->num_gr_mem );
		
		state->response.data.gr.gr_mem_ofs = 0;
		state->response.length += gr_mem_len;
		state->response.extra_data = buffer;	/* give the memory away */
		
		return WINBINDD_OK;
	}

	/* if no domain or our local domain and no local tdb group, default to
	 * our local domain for aliases */

	if ( !*name_domain || strequal(name_domain, get_global_sam_name()) ) {
		fstrcpy(name_domain, get_global_sam_name());
	}

	/* Get info for the domain */

	if ((domain = find_domain_from_name(name_domain)) == NULL) {
		DEBUG(3, ("could not get domain sid for domain %s\n",
			  name_domain));
		return WINBINDD_ERROR;
	}
	/* should we deal with users for our domain? */
	
	if ( lp_winbind_trusted_domains_only() && domain->primary) {
		DEBUG(7,("winbindd_getgrnam: My domain -- rejecting getgrnam() for %s\\%s.\n", 
			name_domain, name_group));
		return WINBINDD_ERROR;
	}

	/* Get rid and name type from name */
        
	if (!winbindd_lookup_sid_by_name(domain, domain->name, name_group, &group_sid, 
					 &name_type)) {
		DEBUG(1, ("group %s in domain %s does not exist\n", 
			  name_group, name_domain));
		return WINBINDD_ERROR;
	}

	if ( !((name_type==SID_NAME_DOM_GRP) ||
	       ((name_type==SID_NAME_ALIAS) && domain->primary) ||
	       ((name_type==SID_NAME_ALIAS) && domain->internal)) )
	{
		DEBUG(1, ("name '%s' is not a local or domain group: %d\n", 
			  name_group, name_type));
		return WINBINDD_ERROR;
	}

	if (!NT_STATUS_IS_OK(idmap_sid_to_gid(&group_sid, &gid, 0))) {
		DEBUG(1, ("error converting unix gid to sid\n"));
		return WINBINDD_ERROR;
	}

	if (!fill_grent(&state->response.data.gr, name_domain,
			name_group, gid) ||
	    !fill_grent_mem(domain, &group_sid, name_type,
			    &state->response.data.gr.num_gr_mem,
			    &gr_mem, &gr_mem_len)) {
		return WINBINDD_ERROR;
	}

	/* Group membership lives at start of extra data */

	state->response.data.gr.gr_mem_ofs = 0;

	state->response.length += gr_mem_len;
	state->response.extra_data = gr_mem;

	return WINBINDD_OK;
}

/* Return a group structure from a gid number */

enum winbindd_result winbindd_getgrgid(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain;
	WINBINDD_GR *grp;
	DOM_SID group_sid;
	enum SID_NAME_USE name_type;
	fstring dom_name;
	fstring group_name;
	int gr_mem_len;
	char *gr_mem;

	DEBUG(3, ("[%5lu]: getgrgid %lu\n", (unsigned long)state->pid, 
		  (unsigned long)state->request.data.gid));

	/* Bug out if the gid isn't in the winbind range */

	if ((state->request.data.gid < server_state.gid_low) ||
	    (state->request.data.gid > server_state.gid_high))
		return WINBINDD_ERROR;

	/* alway try local tdb lookup first */
	if ( ( grp=wb_getgrgid(state->request.data.gid)) != NULL ) {
		char *buffer = NULL;
		
		memcpy( &state->response.data.gr, grp, sizeof(WINBINDD_GR) );
		
		gr_mem_len = gr_mem_buffer( &buffer, grp->gr_mem, grp->num_gr_mem );
		
		state->response.data.gr.gr_mem_ofs = 0;
		state->response.length += gr_mem_len;
		state->response.extra_data = buffer;	/* give away the memory */
		
		return WINBINDD_OK;
	}

	/* Get rid from gid */
	if (!NT_STATUS_IS_OK(idmap_gid_to_sid(&group_sid, state->request.data.gid))) {
		DEBUG(1, ("could not convert gid %lu to rid\n", 
			  (unsigned long)state->request.data.gid));
		return WINBINDD_ERROR;
	}

	/* Get name from sid */

	if (!winbindd_lookup_name_by_sid(&group_sid, dom_name, group_name, &name_type)) {
		DEBUG(1, ("could not lookup sid\n"));
		return WINBINDD_ERROR;
	}

	/* Fill in group structure */

	domain = find_domain_from_sid(&group_sid);

	if (!domain) {
		DEBUG(1,("Can't find domain from sid\n"));
		return WINBINDD_ERROR;
	}

	if ( !((name_type==SID_NAME_DOM_GRP) ||
	       ((name_type==SID_NAME_ALIAS) && domain->primary) ||
	       ((name_type==SID_NAME_ALIAS) && domain->internal)) )
	{
		DEBUG(1, ("name '%s' is not a local or domain group: %d\n", 
			  group_name, name_type));
		return WINBINDD_ERROR;
	}

	if (!fill_grent(&state->response.data.gr, dom_name, group_name, 
			state->request.data.gid) ||
	    !fill_grent_mem(domain, &group_sid, name_type,
			    &state->response.data.gr.num_gr_mem,
			    &gr_mem, &gr_mem_len))
		return WINBINDD_ERROR;

	/* Group membership lives at start of extra data */

	state->response.data.gr.gr_mem_ofs = 0;

	state->response.length += gr_mem_len;
	state->response.extra_data = gr_mem;

	return WINBINDD_OK;
}

/*
 * set/get/endgrent functions
 */

/* "Rewind" file pointer for group database enumeration */

enum winbindd_result winbindd_setgrent(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain;

	DEBUG(3, ("[%5lu]: setgrent\n", (unsigned long)state->pid));

	/* Check user has enabled this */

	if (!lp_winbind_enum_groups())
		return WINBINDD_ERROR;

	/* Free old static data if it exists */
	
	if (state->getgrent_state != NULL) {
		free_getent_state(state->getgrent_state);
		state->getgrent_state = NULL;
	}
	
	/* Create sam pipes for each domain we know about */
	
	for (domain = domain_list(); domain != NULL; domain = domain->next) {
		struct getent_state *domain_state;
		
		/* Create a state record for this domain */

		/* don't add our domaina if we are a PDC or if we 
		   are a member of a Samba domain */
		
		if ( lp_winbind_trusted_domains_only() && domain->primary )
		{
			continue;
		}
						
		
		if ((domain_state = (struct getent_state *)
		     malloc(sizeof(struct getent_state))) == NULL) {
			DEBUG(1, ("winbindd_setgrent: malloc failed for domain_state!\n"));
			return WINBINDD_ERROR;
		}
		
		ZERO_STRUCTP(domain_state);
		
		fstrcpy(domain_state->domain_name, domain->name);

		/* Add to list of open domains */
		
		DLIST_ADD(state->getgrent_state, domain_state);
	}
	
	state->getgrent_initialized = True;

	return WINBINDD_OK;
}

/* Close file pointer to ntdom group database */

enum winbindd_result winbindd_endgrent(struct winbindd_cli_state *state)
{
	DEBUG(3, ("[%5lu]: endgrent\n", (unsigned long)state->pid));

	free_getent_state(state->getgrent_state);
	state->getgrent_initialized = False;
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
	struct acct_info *name_list = NULL, *tmp_name_list = NULL;
	TALLOC_CTX *mem_ctx;
	BOOL result = False;
	struct acct_info *sam_grp_entries = NULL;
	struct winbindd_domain *domain;
        
	if (ent->got_sam_entries)
		return False;

	if (!(mem_ctx = talloc_init("get_sam_group_entries(%s)",
					  ent->domain_name))) {
		DEBUG(1, ("get_sam_group_entries: could not create talloc context!\n")); 
		return False;
	}
		
	/* Free any existing group info */

	SAFE_FREE(ent->sam_entries);
	ent->num_sam_entries = 0;
	ent->got_sam_entries = True;

	/* Enumerate domain groups */

	num_entries = 0;

	if (!(domain = find_domain_from_name(ent->domain_name))) {
		DEBUG(3, ("no such domain %s in get_sam_group_entries\n", ent->domain_name));
		goto done;
	}

	/* always get the domain global groups */

	status = domain->methods->enum_dom_groups(domain, mem_ctx, &num_entries, &sam_grp_entries);
	
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("get_sam_group_entries: could not enumerate domain groups! Error: %s\n", nt_errstr(status)));
		result = False;
		goto done;
	}

	/* Copy entries into return buffer */

	if (num_entries) {
		if ( !(name_list = malloc(sizeof(struct acct_info) * num_entries)) ) {
			DEBUG(0,("get_sam_group_entries: Failed to malloc memory for %d domain groups!\n", 
				num_entries));
			result = False;
			goto done;
		}
		memcpy( name_list, sam_grp_entries, num_entries * sizeof(struct acct_info) );
	}
	
	ent->num_sam_entries = num_entries;
	
	/* get the domain local groups if we are a member of a native win2k domain
	   and are not using LDAP to get the groups */
	   
	if ( ( lp_security() != SEC_ADS && domain->native_mode 
		&& domain->primary) || domain->internal )
	{
		DEBUG(4,("get_sam_group_entries: Native Mode 2k domain; enumerating local groups as well\n"));
		
		status = domain->methods->enum_local_groups(domain, mem_ctx, &num_entries, &sam_grp_entries);
		
		if ( !NT_STATUS_IS_OK(status) ) { 
			DEBUG(3,("get_sam_group_entries: Failed to enumerate domain local groups!\n"));
			num_entries = 0;
		}
		else
			DEBUG(4,("get_sam_group_entries: Returned %d local groups\n", num_entries));
		
		/* Copy entries into return buffer */

		if ( num_entries ) {
			if ( !(tmp_name_list = Realloc( name_list, sizeof(struct acct_info) * (ent->num_sam_entries+num_entries))) )
			{
				DEBUG(0,("get_sam_group_entries: Failed to realloc more memory for %d local groups!\n", 
					num_entries));
				result = False;
				SAFE_FREE( name_list );
				goto done;
			}
			
			name_list = tmp_name_list;
				
			memcpy( &name_list[ent->num_sam_entries], sam_grp_entries, 
				num_entries * sizeof(struct acct_info) );
		}
	
		ent->num_sam_entries += num_entries;
	}
	
		
	/* Fill in remaining fields */

	ent->sam_entries = name_list;
	ent->sam_entry_index = 0;

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
	char *new_extra_data, *gr_mem_list = NULL;

	DEBUG(3, ("[%5lu]: getgrent\n", (unsigned long)state->pid));

	/* Check user has enabled this */

	if (!lp_winbind_enum_groups())
		return WINBINDD_ERROR;

	num_groups = MIN(MAX_GETGRENT_GROUPS, state->request.data.num_entries);

	if ((state->response.extra_data = 
	     malloc(num_groups * sizeof(struct winbindd_gr))) == NULL)
		return WINBINDD_ERROR;

	state->response.data.num_entries = 0;

	group_list = (struct winbindd_gr *)state->response.extra_data;

	if (!state->getgrent_initialized)
		winbindd_setgrent(state);

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
		DOM_SID group_sid;
		struct winbindd_domain *domain;
				
		/* Do we need to fetch another chunk of groups? */

	tryagain:

		DEBUG(10, ("entry_index = %d, num_entries = %d\n",
			   ent->sam_entry_index, ent->num_sam_entries));

		if (ent->num_sam_entries == ent->sam_entry_index) {

			while(ent && !get_sam_group_entries(ent)) {
				struct getent_state *next_ent;

				DEBUG(10, ("freeing state info for domain %s\n", ent->domain_name)); 

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
		
		if (!(domain = 
		      find_domain_from_name(ent->domain_name))) {
			DEBUG(3, ("No such domain %s in winbindd_getgrent\n", ent->domain_name));
			result = False;
			goto done;
		}

		/* Lookup group info */
		
		sid_copy(&group_sid, &domain->sid);
		sid_append_rid(&group_sid, name_list[ent->sam_entry_index].rid);

		if (!NT_STATUS_IS_OK(idmap_sid_to_gid(&group_sid, &group_gid, 0))) {
			
			DEBUG(1, ("could not look up gid for group %s\n", 
				  name_list[ent->sam_entry_index].acct_name));
			
			ent->sam_entry_index++;
			goto tryagain;
		}

		DEBUG(10, ("got gid %lu for group %lu\n", (unsigned long)group_gid,
			   (unsigned long)name_list[ent->sam_entry_index].rid));
		
		/* Fill in group entry */

		fill_domain_username(domain_group_name, ent->domain_name, 
			 name_list[ent->sam_entry_index].acct_name);

		result = fill_grent(&group_list[group_list_ndx], 
				    ent->domain_name,
				    name_list[ent->sam_entry_index].acct_name,
				    group_gid);

		/* Fill in group membership entry */

		if (result) {
			DOM_SID member_sid;
			group_list[group_list_ndx].num_gr_mem = 0;
			gr_mem = NULL;
			gr_mem_len = 0;
			
			/* Get group membership */			
			if (state->request.cmd == WINBINDD_GETGRLST) {
				result = True;
			} else {
				sid_copy(&member_sid, &domain->sid);
				sid_append_rid(&member_sid, name_list[ent->sam_entry_index].rid);
				result = fill_grent_mem(
					domain,
					&member_sid,
					SID_NAME_DOM_GRP,
					&group_list[group_list_ndx].num_gr_mem, 
					&gr_mem, &gr_mem_len);
			}
		}

		if (result) {
			/* Append to group membership list */
			new_gr_mem_list = Realloc(
				gr_mem_list,
				gr_mem_list_len + gr_mem_len);

			if (!new_gr_mem_list && (group_list[group_list_ndx].num_gr_mem != 0)) {
				DEBUG(0, ("out of memory\n"));
				SAFE_FREE(gr_mem_list);
				gr_mem_list_len = 0;
				break;
			}

			DEBUG(10, ("list_len = %d, mem_len = %d\n",
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

			DEBUG(10, ("adding group num_entries = %d\n",
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

	DEBUG(10, ("returning %d groups, length = %d\n",
		   group_list_ndx, gr_mem_list_len));

	/* Out of domains */

 done:

	return (group_list_ndx > 0) ? WINBINDD_OK : WINBINDD_ERROR;
}

/* List domain groups without mapping to unix ids */

enum winbindd_result winbindd_list_groups(struct winbindd_cli_state *state)
{
	uint32 total_entries = 0;
	struct winbindd_domain *domain;
	const char *which_domain;
	char *extra_data = NULL;
	char *ted = NULL;
	unsigned int extra_data_len = 0, i;

	DEBUG(3, ("[%5lu]: list groups\n", (unsigned long)state->pid));

	/* Ensure null termination */
	state->request.domain_name[sizeof(state->request.domain_name)-1]='\0';	
	which_domain = state->request.domain_name;
	
	/* Enumerate over trusted domains */

	for (domain = domain_list(); domain; domain = domain->next) {
		struct getent_state groups;

		/* if we have a domain name restricting the request and this
		   one in the list doesn't match, then just bypass the remainder
		   of the loop */
		   
		if ( *which_domain && !strequal(which_domain, domain->name) )
			continue;
			
		ZERO_STRUCT(groups);

		/* Get list of sam groups */
		
		fstrcpy(groups.domain_name, domain->name);

		get_sam_group_entries(&groups);
			
		if (groups.num_sam_entries == 0) {
			/* this domain is empty or in an error state */
			continue;
		}

		/* keep track the of the total number of groups seen so 
		   far over all domains */
		total_entries += groups.num_sam_entries;
		
		/* Allocate some memory for extra data.  Note that we limit
		   account names to sizeof(fstring) = 128 characters.  */		
                ted = Realloc(extra_data, sizeof(fstring) * total_entries);
 
		if (!ted) {
			DEBUG(0,("failed to enlarge buffer!\n"));
			SAFE_FREE(extra_data);
			return WINBINDD_ERROR;
		} else
			extra_data = ted;

		/* Pack group list into extra data fields */
		for (i = 0; i < groups.num_sam_entries; i++) {
			char *group_name = ((struct acct_info *)
					    groups.sam_entries)[i].acct_name; 
			fstring name;

			fill_domain_username(name, domain->name, group_name);
			/* Append to extra data */			
			memcpy(&extra_data[extra_data_len], name, 
                               strlen(name));
			extra_data_len += strlen(name);
			extra_data[extra_data_len++] = ',';
		}

		SAFE_FREE(groups.sam_entries);
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

static void add_gid_to_array_unique(gid_t gid, gid_t **gids, int *num)
{
	int i;

	if ((*num) >= groups_max())
		return;

	for (i=0; i<*num; i++) {
		if ((*gids)[i] == gid)
			return;
	}
	
	*gids = Realloc(*gids, (*num+1) * sizeof(gid_t));

	if (*gids == NULL)
		return;

	(*gids)[*num] = gid;
	*num += 1;
}

static void add_gids_from_sid(DOM_SID *sid, gid_t **gids, int *num)
{
	gid_t gid;
	DOM_SID *aliases;
	int j, num_aliases;

	DEBUG(10, ("Adding gids from SID: %s\n", sid_string_static(sid)));

	if (NT_STATUS_IS_OK(idmap_sid_to_gid(sid, &gid, 0)))
		add_gid_to_array_unique(gid, gids, num);

	/* Don't expand aliases if not explicitly activated -- for now
	   -- jerry */

	if (!lp_winbind_nested_groups())
		return;

	/* Add nested group memberships */

	if (!pdb_enum_alias_memberships(sid, &aliases, &num_aliases))
		return;

	for (j=0; j<num_aliases; j++) {

		if (!NT_STATUS_IS_OK(sid_to_gid(&aliases[j], &gid)))
			continue;

		add_gid_to_array_unique(gid, gids, num);
	}
	SAFE_FREE(aliases);
}

/* Get user supplementary groups.  This is much quicker than trying to
   invert the groups database.  We merge the groups from the gids and
   other_sids info3 fields as trusted domain, universal group
   memberships, and nested groups (win2k native mode only) are not
   returned by the getgroups RPC call but are present in the info3. */

enum winbindd_result winbindd_getgroups(struct winbindd_cli_state *state)
{
	fstring name_domain, name_user;
	DOM_SID user_sid, group_sid;
	enum SID_NAME_USE name_type;
	uint32 num_groups = 0;
	uint32 num_gids = 0;
	NTSTATUS status;
	DOM_SID **user_grpsids;
	struct winbindd_domain *domain;
	enum winbindd_result result = WINBINDD_ERROR;
	gid_t *gid_list = NULL;
	unsigned int i;
	TALLOC_CTX *mem_ctx;
	NET_USER_INFO_3 *info3 = NULL;
	
	/* Ensure null termination */
	state->request.data.username[sizeof(state->request.data.username)-1]='\0';

	DEBUG(3, ("[%5lu]: getgroups %s\n", (unsigned long)state->pid,
		  state->request.data.username));

	if (!(mem_ctx = talloc_init("winbindd_getgroups(%s)",
					  state->request.data.username)))
		return WINBINDD_ERROR;

	/* Parse domain and username */

	parse_domain_user(state->request.data.username, 
			  name_domain, name_user);
	
	/* Get info for the domain */
	
	if ((domain = find_domain_from_name(name_domain)) == NULL) {
		DEBUG(7, ("could not find domain entry for domain %s\n", 
			  name_domain));
		goto done;
	}

	if ( domain->primary && lp_winbind_trusted_domains_only()) {
		DEBUG(7,("winbindd_getpwnam: My domain -- rejecting getgroups() for %s\\%s.\n", 
			name_domain, name_user));
		return WINBINDD_ERROR;
	}	
	
	/* Get rid and name type from name.  The following costs 1 packet */

	if (!winbindd_lookup_sid_by_name(domain, domain->name, name_user, &user_sid, 
					 &name_type)) {
		DEBUG(1, ("user '%s' does not exist\n", name_user));
		goto done;
	}

	if (name_type != SID_NAME_USER && name_type != SID_NAME_COMPUTER) {
		DEBUG(1, ("name '%s' is not a user name: %d\n", 
			  name_user, name_type));
		goto done;
	}

	add_gids_from_sid(&user_sid, &gid_list, &num_gids);

	/* Treat the info3 cache as authoritative as the
	   lookup_usergroups() function may return cached data. */

	if ( !opt_nocache && (info3 = netsamlogon_cache_get(mem_ctx, &user_sid))) {

		DEBUG(10, ("winbindd_getgroups: info3 has %d groups, %d other sids\n",
			   info3->num_groups2, info3->num_other_sids));

		num_groups = info3->num_other_sids + info3->num_groups2;

		/* Go through each other sid and convert it to a gid */

		for (i = 0; i < info3->num_other_sids; i++) {
			fstring name;
			fstring dom_name;
			enum SID_NAME_USE sid_type;

			/* Is this sid known to us?  It can either be
                           a trusted domain sid or a foreign sid. */

			if (!winbindd_lookup_name_by_sid( &info3->other_sids[i].sid, 
				dom_name, name, &sid_type))
			{
				DEBUG(10, ("winbindd_getgroups: could not lookup name for %s\n", 
					   sid_string_static(&info3->other_sids[i].sid)));
				continue;
			}

			/* Check it is a domain group or an alias (domain local group) 
			   in a win2k native mode domain. */
			
			if ( !((sid_type==SID_NAME_DOM_GRP) ||
				((sid_type==SID_NAME_ALIAS) && domain->primary)) )
			{
				DEBUG(10, ("winbindd_getgroups: sid type %d "
					   "for %s is not a domain group\n",
					   sid_type,
					   sid_string_static(
						   &info3->other_sids[i].sid)));
				continue;
			}

			add_gids_from_sid(&info3->other_sids[i].sid,
					  &gid_list, &num_gids);

			if (gid_list == NULL)
				goto done;
		}

		for (i = 0; i < info3->num_groups2; i++) {
		
			/* create the group SID */
			
			sid_copy( &group_sid, &domain->sid );
			sid_append_rid( &group_sid, info3->gids[i].g_rid );

			add_gids_from_sid(&group_sid, &gid_list, &num_gids);

			if (gid_list == NULL)
				goto done;
		}

		SAFE_FREE(info3);

	} else {
		status = domain->methods->lookup_usergroups(domain, mem_ctx, 
						    &user_sid, &num_groups, 
						    &user_grpsids);
		if (!NT_STATUS_IS_OK(status)) 
			goto done;

		if (state->response.extra_data)
			goto done;

		for (i = 0; i < num_groups; i++) {
			add_gids_from_sid(user_grpsids[i],
					  &gid_list, &num_gids);

			if (gid_list == NULL)
				goto done;
		}
	}

	remove_duplicate_gids( &num_gids, gid_list );

	/* Send data back to client */

	state->response.data.num_entries = num_gids;
	state->response.extra_data = gid_list;
	state->response.length += num_gids * sizeof(gid_t);

	result = WINBINDD_OK;

 done:

	talloc_destroy(mem_ctx);

	return result;
}


/* Get user supplementary sids. This is equivalent to the
   winbindd_getgroups() function but it involves a SID->SIDs mapping
   rather than a NAME->SID->SIDS->GIDS mapping, which means we avoid
   idmap. This call is designed to be used with applications that need
   to do ACL evaluation themselves. Note that the cached info3 data is
   not used 

   this function assumes that the SID that comes in is a user SID. If
   you pass in another type of SID then you may get unpredictable
   results.
*/
enum winbindd_result winbindd_getusersids(struct winbindd_cli_state *state)
{
	DOM_SID user_sid;
	NTSTATUS status;
	DOM_SID **user_grpsids;
	struct winbindd_domain *domain;
	enum winbindd_result result = WINBINDD_ERROR;
	unsigned int i;
	TALLOC_CTX *mem_ctx;
	char *ret = NULL;
	uint32 num_groups;
	unsigned ofs, ret_size = 0;

	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.sid)-1]='\0';

	if (!string_to_sid(&user_sid, state->request.data.sid)) {
		DEBUG(1, ("Could not get convert sid %s from string\n", state->request.data.sid));
		return WINBINDD_ERROR;
	}

	if (!(mem_ctx = talloc_init("winbindd_getusersids(%s)",
				    state->request.data.username))) {
		return WINBINDD_ERROR;
	}

	/* Get info for the domain */	
	if ((domain = find_domain_from_sid(&user_sid)) == NULL) {
		DEBUG(0,("could not find domain entry for sid %s\n", 
			  sid_string_static(&user_sid)));
		goto done;
	}
	
	status = domain->methods->lookup_usergroups(domain, mem_ctx, 
						    &user_sid, &num_groups, 
						    &user_grpsids);
	if (!NT_STATUS_IS_OK(status)) 
		goto done;

	if (num_groups == 0) {
		goto no_groups;
	}

	/* work out the response size */
	for (i = 0; i < num_groups; i++) {
		const char *s = sid_string_static(user_grpsids[i]);
		ret_size += strlen(s) + 1;
	}

	/* build the reply */
	ret = malloc(ret_size);
	if (!ret) goto done;
	ofs = 0;
	for (i = 0; i < num_groups; i++) {
		const char *s = sid_string_static(user_grpsids[i]);
		safe_strcpy(ret + ofs, s, ret_size - ofs - 1);
		ofs += strlen(ret+ofs) + 1;
	}

no_groups:
	/* Send data back to client */
	state->response.data.num_entries = num_groups;
	state->response.extra_data = ret;
	state->response.length += ret_size;
	result = WINBINDD_OK;

 done:
	talloc_destroy(mem_ctx);

	return result;
}

