/* 
   Unix SMB/CIFS implementation.
   Username handling
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 1997-2001.
   
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

/*****************************************************************
 Splits passed user or group name to domain and user/group name parts
 Returns True if name was splitted and False otherwise.
*****************************************************************/

BOOL split_domain_and_name(const char *name, char *domain, char* username)
{
	char *p = strchr(name,*lp_winbind_separator());
	
	
	/* Parse a string of the form DOMAIN/user into a domain and a user */
	DEBUG(10,("split_domain_and_name: checking whether name |%s| local or not\n", name));
	
	if (p) {
		fstrcpy(username, p+1);
		fstrcpy(domain, name);
		domain[PTR_DIFF(p, name)] = 0;
	} else if (lp_winbind_use_default_domain()) {
		fstrcpy(username, name);
		fstrcpy(domain, lp_workgroup());
	} else {
		return False;
	}

	DEBUG(10,("split_domain_and_name: all is fine, domain is |%s| and name is |%s|\n", domain, username));
	return True;
}
