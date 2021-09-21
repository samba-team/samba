/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2007
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) James Peach 2006
   Copyright (C) Andrew Bartlett 2010-2011

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"

/******************************************************************
 get the default domain/netbios name to be used when dealing
 with our passdb list of accounts
******************************************************************/

const char *get_global_sam_name(void)
{
	if (IS_DC) {
		return lp_workgroup();
	}
	return lp_netbios_name();
}


/******************************************************************
 Get the default domain/netbios name to be used when
 testing authentication.
******************************************************************/

const char *my_sam_name(void)
{
	if (lp_server_role() == ROLE_STANDALONE) {
		return lp_netbios_name();
	}

	return lp_workgroup();
}

bool is_allowed_domain(const char *domain_name)
{
	const char **ignored_domains = NULL;
	const char **dom = NULL;

	ignored_domains = lp_parm_string_list(-1,
					      "winbind",
					      "ignore domains",
					      NULL);

	for (dom = ignored_domains; dom != NULL && *dom != NULL; dom++) {
		if (gen_fnmatch(*dom, domain_name) == 0) {
			DBG_NOTICE("Ignoring domain '%s'\n", domain_name);
			return false;
		}
	}

	if (lp_allow_trusted_domains()) {
		return true;
	}

	if (strequal(lp_workgroup(), domain_name)) {
		return true;
	}

	if (is_myname(domain_name)) {
		return true;
	}

	DBG_NOTICE("Not trusted domain '%s'\n", domain_name);
	return false;
}
