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

#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

/* Convert a string  */

enum winbindd_result winbindd_lookupsid(struct winbindd_cli_state *state)
{
	extern DOM_SID global_sid_Builtin;
	enum SID_NAME_USE type;
	DOM_SID sid, tmp_sid;
	uint32 rid;
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

	/* Don't look up BUILTIN sids */

	sid_copy(&tmp_sid, &sid);
	sid_split_rid(&tmp_sid, &rid);

	if (sid_equal(&tmp_sid, &global_sid_Builtin)) {
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

	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.name.dom_name)-1]='\0';

	/* Ensure null termination */
	state->request.data.sid[sizeof(state->request.data.name.name)-1]='\0';

	DEBUG(3, ("[%5lu]: lookupname %s%s%s\n", (unsigned long)state->pid,
		  state->request.data.name.dom_name, 
		  lp_winbind_separator(),
		  state->request.data.name.name));

	name_domain = state->request.data.name.dom_name;
	name_user = state->request.data.name.name;

	if ((domain = find_domain_from_name(name_domain)) == NULL) {
		DEBUG(0, ("could not find domain entry for domain %s\n", 
			  name_domain));
		return WINBINDD_ERROR;
	}

	/* Lookup name from PDC using lsa_lookup_names() */
	if (!winbindd_lookup_sid_by_name(domain, name_user, &sid, &type)) {
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

	/* Split sid into domain sid and user rid */
	if (!string_to_sid(&sid, state->request.data.sid)) {
		DEBUG(1, ("Could not get convert sid %s from string\n", state->request.data.sid));
		return WINBINDD_ERROR;
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

#if 0	/* JERRY */
	/* we cannot do this check this anymore since a domain member of 
	   a Samba domain may share unix accounts via NIS or LDAP.  In this 
	   case the uid/gid will be out of winbindd's range but still might
	   be resolved to a SID via an ldap idmap backend */
	   
	if ((state->request.data.uid < server_state.uid_low ) ||
	    (state->request.data.uid > server_state.uid_high)) {
		return WINBINDD_ERROR;
	}
#endif

	DEBUG(3, ("[%5lu]: uid to sid %lu\n", (unsigned long)state->pid, 
		  (unsigned long)state->request.data.uid));

	/* Lookup rid for this uid */
	if (!NT_STATUS_IS_OK(idmap_uid_to_sid(&sid, state->request.data.uid))) {
		DEBUG(1, ("Could not convert uid %lu to rid\n",
			  (unsigned long)state->request.data.uid));
		return WINBINDD_ERROR;
	}

	sid_to_string(state->response.data.sid.sid, &sid);
	state->response.data.sid.type = SID_NAME_USER;

	return WINBINDD_OK;
}

/* Convert a gid to a sid */

enum winbindd_result winbindd_gid_to_sid(struct winbindd_cli_state *state)
{
	DOM_SID sid;

#if 0	/* JERRY */
	/* we cannot do this check this anymore since a domain member of 
	   a Samba domain may share unix accounts via NIS or LDAP.  In this 
	   case the uid/gid will be out of winbindd's range but still might
	   be resolved to a SID via an ldap idmap backend */
	   
	if ((state->request.data.gid < server_state.gid_low) ||
	    (state->request.data.gid > server_state.gid_high)) {
		return WINBINDD_ERROR;
	}
#endif

	DEBUG(3, ("[%5lu]: gid to sid %lu\n", (unsigned long)state->pid,
		  (unsigned long)state->request.data.gid));

	/* Lookup sid for this uid */
	if (!NT_STATUS_IS_OK(idmap_gid_to_sid(&sid, state->request.data.gid))) {
		DEBUG(1, ("Could not convert gid %lu to sid\n",
			  (unsigned long)state->request.data.gid));
		return WINBINDD_ERROR;
	}

	/* Construct sid and return it */
	sid_to_string(state->response.data.sid.sid, &sid);
	state->response.data.sid.type = SID_NAME_DOM_GRP;

	return WINBINDD_OK;
}
