/* 
   Unix SMB/CIFS implementation.

   Winbind daemon - sid related functions

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

#include "includes.h"
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

/* Convert a string  */

enum winbindd_result winbindd_lookupsid(struct winbindd_cli_state *state)
{
	enum SID_NAME_USE type;
	DOM_SID sid;
	fstring name;
	fstring dom_name;

	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.sid)-1]='\0';

	DEBUG(3, ("[%5lu]: lookupsid %s\n", (unsigned long)state->pid, 
		  state->request.data.sid));

	/* Lookup sid from PDC using lsa_lookup_sids() */

	if (!string_to_sid(&sid, state->request.data.sid)) {
		DEBUG(5, ("%s not a SID\n", state->request.data.sid));
		return WINBINDD_ERROR;
	}

	/* Lookup the sid */

	if (!winbindd_lookup_name_by_sid(&sid, dom_name, name, &type)) {
		return WINBINDD_ERROR;
	}

	fstrcpy(state->response.data.name.dom_name, dom_name);
	fstrcpy(state->response.data.name.name, name);

	state->response.data.name.type = type;

	return WINBINDD_OK;
}


/**
 * Look up the SID for a qualified name.  
 **/
enum winbindd_result winbindd_lookupname(struct winbindd_cli_state *state)
{
	enum SID_NAME_USE type;
	fstring sid_str;
	char *name_domain, *name_user;
	DOM_SID sid;
	struct winbindd_domain *domain;
	char *p;

	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.name.dom_name)-1]='\0';

	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.name.name)-1]='\0';

	/* cope with the name being a fully qualified name */
	p = strstr(state->request.data.name.name, lp_winbind_separator());
	if (p) {
		*p = 0;
		name_domain = state->request.data.name.name;
		name_user = p+1;
	} else {
		name_domain = state->request.data.name.dom_name;
		name_user = state->request.data.name.name;
	}

	DEBUG(3, ("[%5lu]: lookupname %s%s%s\n", (unsigned long)state->pid,
		  name_domain, lp_winbind_separator(), name_user));

	if ((domain = find_lookup_domain_from_name(name_domain)) == NULL) {
		DEBUG(0, ("could not find domain entry for domain %s\n", 
			  name_domain));
		return WINBINDD_ERROR;
	}

	/* Lookup name from PDC using lsa_lookup_names() */
	if (!winbindd_lookup_sid_by_name(domain, name_domain, name_user, &sid, &type)) {
		return WINBINDD_ERROR;
	}

	sid_to_string(sid_str, &sid);
	fstrcpy(state->response.data.sid.sid, sid_str);
	state->response.data.sid.type = type;

	return WINBINDD_OK;
}

/* Convert a sid to a uid.  We assume we only have one rid attached to the
   sid. */

enum winbindd_result winbindd_sid_to_uid(struct winbindd_cli_state *state)
{
	DOM_SID sid;
	uint32 flags = 0x0;

	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.sid)-1]='\0';

	DEBUG(3, ("[%5lu]: sid to uid %s\n", (unsigned long)state->pid,
		  state->request.data.sid));

	if (!string_to_sid(&sid, state->request.data.sid)) {
		DEBUG(1, ("Could not get convert sid %s from string\n", state->request.data.sid));
		return WINBINDD_ERROR;
	}
	
	/* This gets a little tricky.  If we assume that usernames are syncd between
	   /etc/passwd and the windows domain (such as a member of a Samba domain),
	   the we need to get the uid from the OS and not alocate one ourselves */
	   
	if ( lp_winbind_trusted_domains_only() ) {
		struct winbindd_domain *domain = NULL;
		DOM_SID sid2;
		uint32 rid;
		
		domain = find_our_domain();
		if ( !domain ) {
			DEBUG(0,("winbindd_sid_to_uid: can't find my own domain!\n"));
			return WINBINDD_ERROR;
		}

		sid_copy( &sid2, &sid );
		sid_split_rid( &sid2, &rid );
		
		if ( sid_equal( &sid2, &domain->sid ) ) {
		
			fstring domain_name;
			fstring user;
			enum SID_NAME_USE type;
			struct passwd *pw = NULL;
			unid_t id;
			
			/* ok...here's we know that we are dealing with our
			   own domain (the one to which we are joined).  And
			   we know that there must be a UNIX account for this user.
			   So we lookup the sid and the call getpwnam().*/
			   
			
			/* But first check and see if we don't already have a mapping */
			   
			flags = ID_QUERY_ONLY;
			if ( NT_STATUS_IS_OK(idmap_sid_to_uid(&sid, &(state->response.data.uid), flags)) )
				return WINBINDD_OK;
				
			/* now fall back to the hard way */
			
			if ( !winbindd_lookup_name_by_sid(&sid, domain_name, user, &type) )
				return WINBINDD_ERROR;
				
			if ( !(pw = getpwnam(user)) ) {
				DEBUG(0,("winbindd_sid_to_uid: 'winbind trusted domains only' is "
					"set but this user [%s] doesn't exist!\n", user));
				return WINBINDD_ERROR;
			}
			
			state->response.data.uid = pw->pw_uid;

			id.uid = pw->pw_uid;
			idmap_set_mapping( &sid, id, ID_USERID );

			return WINBINDD_OK;
		}

	}
	
	if ( state->request.flags & WBFLAG_QUERY_ONLY ) 
		flags = ID_QUERY_ONLY;
	
	/* Find uid for this sid and return it */
	
	if ( !NT_STATUS_IS_OK(idmap_sid_to_uid(&sid, &(state->response.data.uid), flags)) ) {
		DEBUG(1, ("Could not get uid for sid %s\n", state->request.data.sid));
		return WINBINDD_ERROR;
	}

	return WINBINDD_OK;
}

/* Convert a sid to a gid.  We assume we only have one rid attached to the
   sid.*/

enum winbindd_result winbindd_sid_to_gid(struct winbindd_cli_state *state)
{
	DOM_SID sid;
	uint32 flags = 0x0;

	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.sid)-1]='\0';

	DEBUG(3, ("[%5lu]: sid to gid %s\n", (unsigned long)state->pid, 
		  state->request.data.sid));

	if (!string_to_sid(&sid, state->request.data.sid)) {
		DEBUG(1, ("Could not cvt string to sid %s\n", state->request.data.sid));
		return WINBINDD_ERROR;
	}

	/* This gets a little tricky.  If we assume that usernames are syncd between
	   /etc/passwd and the windows domain (such as a member of a Samba domain),
	   the we need to get the uid from the OS and not alocate one ourselves */
	   
	if ( lp_winbind_trusted_domains_only() ) {
		struct winbindd_domain *domain = NULL;
		DOM_SID sid2;
		uint32 rid;
		unid_t id;
		
		domain = find_our_domain();
		if ( !domain ) {
			DEBUG(0,("winbindd_sid_to_uid: can't find my own domain!\n"));
			return WINBINDD_ERROR;
		}
		
		sid_copy( &sid2, &sid );
		sid_split_rid( &sid2, &rid );

		if ( sid_equal( &sid2, &domain->sid ) ) {
		
			fstring domain_name;
			fstring group;
			enum SID_NAME_USE type;
			struct group *grp = NULL;
			
			/* ok...here's we know that we are dealing with our
			   own domain (the one to which we are joined).  And
			   we know that there must be a UNIX account for this group.
			   So we lookup the sid and the call getpwnam().*/
			
			/* But first check and see if we don't already have a mapping */
			   
			flags = ID_QUERY_ONLY;
			if ( NT_STATUS_IS_OK(idmap_sid_to_gid(&sid, &(state->response.data.gid), flags)) )
				return WINBINDD_OK;
				
			/* now fall back to the hard way */
			
			if ( !winbindd_lookup_name_by_sid(&sid, domain_name, group, &type) )
				return WINBINDD_ERROR;
				
			if ( !(grp = getgrnam(group)) ) {
				DEBUG(0,("winbindd_sid_to_uid: 'winbind trusted domains only' is "
					"set but this group [%s] doesn't exist!\n", group));
				return WINBINDD_ERROR;
			}
			
			state->response.data.gid = grp->gr_gid;

			id.gid = grp->gr_gid;
			idmap_set_mapping( &sid, id, ID_GROUPID );

			return WINBINDD_OK;
		}

	}
	
	if ( state->request.flags & WBFLAG_QUERY_ONLY ) 
		flags = ID_QUERY_ONLY;
		
	/* Find gid for this sid and return it */
	if ( !NT_STATUS_IS_OK(idmap_sid_to_gid(&sid, &(state->response.data.gid), flags)) ) {
		DEBUG(1, ("Could not get gid for sid %s\n", state->request.data.sid));
		return WINBINDD_ERROR;
	}

	return WINBINDD_OK;
}

/* Convert a uid to a sid */

enum winbindd_result winbindd_uid_to_sid(struct winbindd_cli_state *state)
{
	DOM_SID sid;

	DEBUG(3, ("[%5lu]: uid to sid %lu\n", (unsigned long)state->pid, 
		  (unsigned long)state->request.data.uid));

	if ( (state->request.data.uid < server_state.uid_low ) 
		|| (state->request.data.uid > server_state.uid_high) )
	{
		struct passwd *pw = NULL;
		enum SID_NAME_USE type;
		unid_t id;
		struct winbindd_domain *domain;

		/* SPECIAL CASE FOR MEMBERS OF SAMBA DOMAINS */
		
		/* if we don't trust /etc/password then when can't know 
		   anything about this uid */
		   
		if ( !lp_winbind_trusted_domains_only() )
			return WINBINDD_ERROR;


		/* look for an idmap entry first */
			
		if ( NT_STATUS_IS_OK(idmap_uid_to_sid(&sid, state->request.data.uid)) ) 
			goto done;
		
		/* if users exist in /etc/passwd, we should try to 
		   use that uid. Get the username and the lookup the SID */

		if ( !(pw = getpwuid(state->request.data.uid)) )
			return WINBINDD_ERROR;

		if ( !(domain = find_our_domain()) ) {
			DEBUG(0,("winbindd_uid_to_sid: can't find my own domain!\n"));
			return WINBINDD_ERROR;
		}

		if ( !winbindd_lookup_sid_by_name(domain, domain->name, pw->pw_name, &sid, &type) )
			return WINBINDD_ERROR;
		
		if ( type != SID_NAME_USER )
			return WINBINDD_ERROR;
		
		/* don't fail if we can't store it */

		id.uid = pw->pw_uid;
		idmap_set_mapping( &sid, id, ID_USERID );
		
		goto done;
	}

	/* Lookup rid for this uid */
	
	if (!NT_STATUS_IS_OK(idmap_uid_to_sid(&sid, state->request.data.uid))) {
		DEBUG(1, ("Could not convert uid %lu to rid\n",
			  (unsigned long)state->request.data.uid));
		return WINBINDD_ERROR;
	}

done:
	sid_to_string(state->response.data.sid.sid, &sid);
	state->response.data.sid.type = SID_NAME_USER;

	return WINBINDD_OK;
}

/* Convert a gid to a sid */

enum winbindd_result winbindd_gid_to_sid(struct winbindd_cli_state *state)
{
	DOM_SID sid;

	DEBUG(3, ("[%5lu]: gid to sid %lu\n", (unsigned long)state->pid,
		  (unsigned long)state->request.data.gid));
		  
	if ( (state->request.data.gid < server_state.gid_low) 
		|| (state->request.data.gid > server_state.gid_high) )
	{ 		
		struct group *grp = NULL;
		enum SID_NAME_USE type;
		unid_t id;
		struct winbindd_domain *domain;

		/* SPECIAL CASE FOR MEMBERS OF SAMBA DOMAINS */
		
		/* if we don't trust /etc/group then when can't know 
		   anything about this gid */
		   
		if ( !lp_winbind_trusted_domains_only() )
			return WINBINDD_ERROR;

		/* look for an idmap entry first */
		
		if ( NT_STATUS_IS_OK(idmap_gid_to_sid(&sid, state->request.data.gid)) )
			goto done;
			
		/* if users exist in /etc/group, we should try to 
		   use that gid. Get the username and the lookup the SID */

		if ( !(grp = getgrgid(state->request.data.gid)) )
			return WINBINDD_ERROR;

		if ( !(domain = find_our_domain()) ) {
			DEBUG(0,("winbindd_uid_to_sid: can't find my own domain!\n"));
			return WINBINDD_ERROR;
		}

		if ( !winbindd_lookup_sid_by_name(domain, domain->name, grp->gr_name, &sid, &type) )
			return WINBINDD_ERROR;
		
		if ( type!=SID_NAME_DOM_GRP && type!=SID_NAME_ALIAS )
			return WINBINDD_ERROR;
		
		/* don't fail if we can't store it */
		
		id.gid = grp->gr_gid;
		idmap_set_mapping( &sid, id, ID_GROUPID );
		
		goto done;
	}

	/* Lookup sid for this uid */
	
	if (!NT_STATUS_IS_OK(idmap_gid_to_sid(&sid, state->request.data.gid))) {
		DEBUG(1, ("Could not convert gid %lu to sid\n",
			  (unsigned long)state->request.data.gid));
		return WINBINDD_ERROR;
	}

done:
	/* Construct sid and return it */
	sid_to_string(state->response.data.sid.sid, &sid);
	state->response.data.sid.type = SID_NAME_DOM_GRP;

	return WINBINDD_OK;
}

enum winbindd_result winbindd_allocate_rid(struct winbindd_cli_state *state)
{
	if ( !state->privileged ) {
		DEBUG(2, ("winbindd_allocate_rid: non-privileged access "
			  "denied!\n"));
		return WINBINDD_ERROR;
	}

	/* We tell idmap to always allocate a user RID. There might be a good
	 * reason to keep RID allocation for users to even and groups to
	 * odd. This needs discussion I think. For now only allocate user
	 * rids. */

	if (!NT_STATUS_IS_OK(idmap_allocate_rid(&state->response.data.rid,
						USER_RID_TYPE)))
		return WINBINDD_ERROR;

	return WINBINDD_OK;
}
