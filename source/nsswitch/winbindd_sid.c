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

enum winbindd_result winbindd_lookupsid_async(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain;
	DOM_SID sid;

	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.sid)-1]='\0';

	DEBUG(3, ("[%5lu]: lookupsid %s\n", (unsigned long)state->pid, 
		  state->request.data.sid));

	if (!string_to_sid(&sid, state->request.data.sid)) {
		DEBUG(5, ("%s not a SID\n", state->request.data.sid));
		return WINBINDD_ERROR;
	}

	domain = find_lookup_domain_from_sid(&sid);

	if (domain == NULL) {
		DEBUG(1,("Can't find domain from sid\n"));
		return False;
	}

	return async_request(state->mem_ctx, &domain->child,
			     &state->request, &state->response,
			     request_finished_cont, state);
}

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

	if (!winbindd_lookup_name_by_sid(state->mem_ctx, &sid, dom_name, name,
					 &type)) {
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
enum winbindd_result winbindd_lookupname_async(struct winbindd_cli_state *state)
{
	char *name_domain, *name_user;
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

	return async_request(state->mem_ctx, &domain->child,
			     &state->request, &state->response,
			     request_finished_cont, state);
}

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
	if (!winbindd_lookup_sid_by_name(state->mem_ctx, domain, name_domain,
					 name_user, &sid, &type)) {
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
	struct winbindd_domain *domain = NULL;
	DOM_SID sid;
	NTSTATUS result;
	fstring domain_name, user_name;
	enum SID_NAME_USE type;

	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.sid)-1]='\0';

	DEBUG(3, ("[%5lu]: sid to uid %s\n", (unsigned long)state->pid,
		  state->request.data.sid));

	if (!string_to_sid(&sid, state->request.data.sid)) {
		DEBUG(1, ("Could not get convert sid %s from string\n",
			  state->request.data.sid));
		return WINBINDD_ERROR;
	}
	
	/* Find uid for this sid and return it */

	result = idmap_sid_to_uid(&sid, &(state->response.data.uid),
				  ID_QUERY_ONLY);

	if (NT_STATUS_IS_OK(result))
		return WINBINDD_OK;

	if (!winbindd_lookup_name_by_sid(state->mem_ctx, &sid,  domain_name,
					 user_name, &type)) {
		DEBUG(10, ("Could not look up sid\n"));
		return WINBINDD_ERROR;
	}

	if ((type != SID_NAME_USER) && (type != SID_NAME_COMPUTER)) {
		DEBUG(3, ("SID %s is not a user\n", state->request.data.sid));
		return WINBINDD_ERROR;
	}
				
	domain = find_our_domain();
	if (domain == NULL) {
		DEBUG(0,("winbindd_sid_to_uid: can't find my own domain!\n"));
		return WINBINDD_ERROR;
	}

	/* This gets a little tricky.  If we assume that usernames are syncd
	   between /etc/passwd and the windows domain (such as a member of a
	   Samba domain), the we need to get the uid from the OS and not
	   allocate one ourselves */
	   
	if (lp_winbind_trusted_domains_only() && 
	    (sid_compare_domain(&sid, &domain->sid) == 0)) {
		
		struct passwd *pw = NULL;
		unid_t id;
			
		/* ok...here's we know that we are dealing with our own domain
		   (the one to which we are joined).  And we know that there
		   must be a UNIX account for this user.  So we lookup the sid
		   and the call getpwnam().*/
			   
		if ( !(pw = getpwnam(user_name)) ) {
			DEBUG(0,("winbindd_sid_to_uid: 'winbind trusted "
				 "domains only' is set but this user [%s] "
				 "doesn't exist!\n", user_name));
			return WINBINDD_ERROR;
		}
			
		state->response.data.uid = pw->pw_uid;

		id.uid = pw->pw_uid;
		idmap_set_mapping( &sid, id, ID_USERID );

		return WINBINDD_OK;
	}

	if (state->request.flags & WBFLAG_QUERY_ONLY)
		return WINBINDD_ERROR;

	result = idmap_sid_to_uid(&sid, &(state->response.data.uid), 0);

	if (NT_STATUS_IS_OK(result))
		return WINBINDD_OK;

	DEBUG(4, ("Could not get uid for sid %s\n", state->request.data.sid));
	return WINBINDD_ERROR;
}

/* Convert a sid to a gid.  We assume we only have one rid attached to the
   sid.*/

enum winbindd_result winbindd_sid_to_gid(struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain = NULL;
	DOM_SID sid;
	NTSTATUS result;
	fstring domain_name, group_name;
	enum SID_NAME_USE type;

	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.sid)-1]='\0';

	DEBUG(3, ("[%5lu]: sid to gid %s\n", (unsigned long)state->pid, 
		  state->request.data.sid));

	if (!string_to_sid(&sid, state->request.data.sid)) {
		DEBUG(1, ("Could not cvt string to sid %s\n",
			  state->request.data.sid));
		return WINBINDD_ERROR;
	}

	/* Find gid for this sid and return it */

	result = idmap_sid_to_gid(&sid, &(state->response.data.gid),
				  ID_QUERY_ONLY);

	if (NT_STATUS_IS_OK(result))
		return WINBINDD_OK;

	domain = find_our_domain();
	if ( !domain ) {
		DEBUG(0,("winbindd_sid_to_uid: can't find my own domain!\n"));
		return WINBINDD_ERROR;
	}
		
	if (sid_check_is_in_our_domain(&sid)) {
		/* This is for half-created aliases during the sam
		 * call. Essentially, this is a bug and needs to be fixed more
		 * properly. */
		type = SID_NAME_ALIAS;
		fstrcpy(group_name, "");
	} else {
		/* Foreign domains need to be looked up by the DC if it's the
		 * right type */
		if (!winbindd_lookup_name_by_sid(state->mem_ctx, &sid,
						 domain_name, group_name,
						 &type)) {
			DEBUG(5, ("Could look up sid\n"));
			return WINBINDD_ERROR;
		}
	}

	if ((type != SID_NAME_DOM_GRP) && (type != SID_NAME_ALIAS) &&
	    (type != SID_NAME_WKN_GRP)) {
		DEBUG(5, ("SID is not a group\n"));
		return WINBINDD_ERROR;
	}

	/* This gets a little tricky.  If we assume that usernames are syncd
	   between /etc/passwd and the windows domain (such as a member of a
	   Samba domain), the we need to get the uid from the OS and not
	   alocate one ourselves */
	   
	if (lp_winbind_trusted_domains_only() && 
	    (sid_compare_domain(&sid, &domain->sid) == 0)) {

		unid_t id;
		struct group *grp = NULL;
			
		/* ok...here's we know that we are dealing with our own domain
		   (the one to which we are joined). And we know that there
		   must be a UNIX account for this group. So we lookup the sid
		   and the call getgrnam().*/
			
		if ( !(grp = getgrnam(group_name)) ) {
			DEBUG(0,("winbindd_sid_to_gid: 'winbind trusted "
				 "domains only' is set but this group [%s] "
				 "doesn't exist!\n", group_name));
			return WINBINDD_ERROR;
		}
			
		state->response.data.gid = grp->gr_gid;

		id.gid = grp->gr_gid;
		idmap_set_mapping( &sid, id, ID_GROUPID );

		return WINBINDD_OK;
	}

	if (state->request.flags & WBFLAG_QUERY_ONLY)
		return WINBINDD_ERROR;

	result = idmap_sid_to_gid(&sid, &(state->response.data.gid), 0);

	if (NT_STATUS_IS_OK(result))
		return WINBINDD_OK;

	DEBUG(4, ("Could not get gid for sid %s\n", state->request.data.sid));
	return WINBINDD_ERROR;
}

/* Convert a uid to a sid */

enum winbindd_result winbindd_uid_to_sid(struct winbindd_cli_state *state)
{
	DOM_SID sid;
	NTSTATUS status;
	struct passwd *pw = NULL;
	enum SID_NAME_USE type;
	unid_t id;
	struct winbindd_domain *domain;

	DEBUG(3, ("[%5lu]: uid to sid %lu\n", (unsigned long)state->pid, 
		  (unsigned long)state->request.data.uid));

	status = idmap_uid_to_sid(&sid, state->request.data.uid);

	if (NT_STATUS_IS_OK(status)) {
		sid_to_string(state->response.data.sid.sid, &sid);
		state->response.data.sid.type = SID_NAME_USER;
		return WINBINDD_OK;
	}

	if (is_in_uid_range(state->request.data.uid)) {
		/* This is winbind's, so we should better have succeeded
		 * above. */
		return WINBINDD_ERROR;
	}

	/* The only chance that this is correct is that winbind trusted
	 * domains only = yes, and the user exists in nss and the domain. */

	if (!lp_winbind_trusted_domains_only()) {
		return WINBINDD_ERROR;
	}

	pw = getpwuid(state->request.data.uid);
	if (pw == NULL)
		return WINBINDD_ERROR;

	domain = find_our_domain();
	if (domain == NULL) {
		DEBUG(0,("winbindd_uid_to_sid: can't find my own domain!\n"));
		return WINBINDD_ERROR;
	}

	if ( !winbindd_lookup_sid_by_name(state->mem_ctx, domain,
					  domain->name, pw->pw_name,
					  &sid, &type) )
		return WINBINDD_ERROR;

	if ( type != SID_NAME_USER )
		return WINBINDD_ERROR;

	/* don't fail if we can't store it */

	id.uid = pw->pw_uid;
	idmap_set_mapping( &sid, id, ID_USERID );

	sid_to_string(state->response.data.sid.sid, &sid);
	state->response.data.sid.type = SID_NAME_USER;

	return WINBINDD_OK;
}

/* Convert a gid to a sid */
enum winbindd_result winbindd_gid_to_sid(struct winbindd_cli_state *state)
{
	DOM_SID sid;
	NTSTATUS status;
	struct group *grp = NULL;
	enum SID_NAME_USE type;
	unid_t id;
	struct winbindd_domain *domain;

	DEBUG(3, ("[%5lu]: gid to sid %lu\n", (unsigned long)state->pid, 
		  (unsigned long)state->request.data.gid));

	status = idmap_gid_to_sid(&sid, state->request.data.gid);

	if (NT_STATUS_IS_OK(status)) {
		sid_to_string(state->response.data.sid.sid, &sid);
		state->response.data.sid.type = SID_NAME_DOM_GRP;
		return WINBINDD_OK;
	}

	if (is_in_gid_range(state->request.data.gid)) {
		/* This is winbind's, so we should better have succeeded
		 * above. */
		return WINBINDD_ERROR;
	}

	/* The only chance that this is correct is that winbind trusted
	 * domains only = yes, and the group exists in nss and the domain. */

	if (!lp_winbind_trusted_domains_only()) {
		return WINBINDD_ERROR;
	}

	grp = getgrgid(state->request.data.gid);
	if (grp == NULL)
		return WINBINDD_ERROR;

	domain = find_our_domain();
	if (domain == NULL) {
		DEBUG(0,("winbindd_gid_to_sid: can't find my own domain!\n"));
		return WINBINDD_ERROR;
	}

	if ( !winbindd_lookup_sid_by_name(state->mem_ctx, domain,
					  domain->name, grp->gr_name,
					  &sid, &type) )
		return WINBINDD_ERROR;

	if ( type!=SID_NAME_DOM_GRP && type!=SID_NAME_ALIAS )
		return WINBINDD_ERROR;

	/* don't fail if we can't store it */

	id.gid = grp->gr_gid;
	idmap_set_mapping( &sid, id, ID_GROUPID );

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
