/* 
   Unix SMB/Netbios implementation.
   Version 2.0

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

/* Convert a string  */

enum winbindd_result winbindd_lookupsid(struct winbindd_cli_state *state)
{
	enum SID_NAME_USE type;
	DOM_SID sid;
	fstring name;

	DEBUG(1, ("lookupsid %s\n", state->request.data.sid));

	/* Lookup sid from PDC using lsa_lookup_sids() */

	string_to_sid(&sid, state->request.data.sid);

	if (!winbindd_lookup_name_by_sid(&sid, name, &type)) {
		return WINBINDD_ERROR;
	}

	fstrcpy(state->response.data.name, name);

	return WINBINDD_OK;
}

/* Convert a sid to a string */

enum winbindd_result winbindd_lookupname(struct winbindd_cli_state *state)
{
	enum SID_NAME_USE type;
	fstring sid_str;
	DOM_SID sid;
	
	DEBUG(1, ("lookupname %s\n", state->request.data.name));

	/* Lookup name from PDC using lsa_lookup_names() */

	if (!winbindd_lookup_sid_by_name(state->request.data.name,
					 &sid, &type)) {
		return WINBINDD_ERROR;
	}

	sid_to_string(sid_str, &sid);
	fstrcpy(state->response.data.sid, sid_str);

	return WINBINDD_OK;
}
