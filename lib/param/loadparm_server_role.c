/*
   Unix SMB/CIFS implementation.
   Parameter loading functions
   Copyright (C) Karl Auer 1993-1998

   Largely re-written by Andrew Tridgell, September 1994

   Copyright (C) Simo Sorce 2001
   Copyright (C) Alexander Bokovoy 2002
   Copyright (C) Stefan (metze) Metzmacher 2002
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Michael Adam 2008
   Copyright (C) Andrew Bartlett 2010

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
#include "lib/param/loadparm.h"
#include "libds/common/roles.h"

/*******************************************************************
 Set the server type we will announce as via nmbd.
********************************************************************/

static const struct srv_role_tab {
	uint32_t role;
	const char *role_str;
} srv_role_tab [] = {
	{ ROLE_STANDALONE, "ROLE_STANDALONE" },
	{ ROLE_DOMAIN_MEMBER, "ROLE_DOMAIN_MEMBER" },
	{ ROLE_DOMAIN_BDC, "ROLE_DOMAIN_BDC" },
	{ ROLE_DOMAIN_PDC, "ROLE_DOMAIN_PDC" },
	{ ROLE_ACTIVE_DIRECTORY_DC, "ROLE_ACTIVE_DIRECTORY_DC" },
	{ ROLE_IPA_DC, "ROLE_IPA_DC"},
	{ 0, NULL }
};

const char* server_role_str(uint32_t role)
{
	int i = 0;
	for (i=0; srv_role_tab[i].role_str; i++) {
		if (role == srv_role_tab[i].role) {
			return srv_role_tab[i].role_str;
		}
	}
	return NULL;
}

/**
 * Set the server role based on security, domain logons and domain master
 */
int lp_find_server_role(int server_role, int security, int domain_logons, int domain_master)
{
	int role;

	if (server_role != ROLE_AUTO) {
		if (lp_is_security_and_server_role_valid(server_role, security)) {
			return server_role;
		}
	}

	/* If server_role is set to ROLE_AUTO, or conflicted with the
	 * chosen security setting, figure out the correct role */
	role = ROLE_STANDALONE;

	switch (security) {
		case SEC_DOMAIN:
		case SEC_ADS:
			role = ROLE_DOMAIN_MEMBER;
			break;
		case SEC_AUTO:
		case SEC_USER:
			if (domain_logons) {

				if (domain_master) {
					role = ROLE_DOMAIN_PDC;
				} else {
					role = ROLE_DOMAIN_BDC;
				}
			}
			break;
		default:
			DEBUG(0, ("Server's Role undefined due to unknown security mode\n"));
			break;
	}

	return role;
}

/**
 * Set the server role based on security, domain logons and domain master
 */
int lp_find_security(int server_role, int security)
{
	if (security != SEC_AUTO) {
		return security;
	}

	switch (server_role) {
	case ROLE_DOMAIN_MEMBER:
		return SEC_ADS;
	default:
		return SEC_USER;
	}
}


/**
 * Check if server role and security parameters are contradictory
 */
bool lp_is_security_and_server_role_valid(int server_role, int security)
{
	bool valid = false;

	if (security == SEC_AUTO) {
		return true;
	}

	switch (server_role) {
	case ROLE_AUTO:
		valid = true;
		break;
	case ROLE_DOMAIN_MEMBER:
		if (security == SEC_ADS || security == SEC_DOMAIN) {
			valid = true;
		}
		break;

	case ROLE_STANDALONE:
	case ROLE_DOMAIN_PDC:
	case ROLE_DOMAIN_BDC:
	case ROLE_ACTIVE_DIRECTORY_DC:
	case ROLE_IPA_DC:
		if (security == SEC_USER) {
			valid = true;
		}
		break;

	default:
		break;
	}

	return valid;
}
