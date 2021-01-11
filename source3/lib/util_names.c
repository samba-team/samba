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

/***********************************************************************
 Definitions for all names.
***********************************************************************/

static int smb_num_netbios_names;
static char **smb_my_netbios_names;

static void free_netbios_names_array(void)
{
	int i;

	for (i = 0; i < smb_num_netbios_names; i++)
		SAFE_FREE(smb_my_netbios_names[i]);

	SAFE_FREE(smb_my_netbios_names);
	smb_num_netbios_names = 0;
}

static bool allocate_my_netbios_names_array(size_t number)
{
	free_netbios_names_array();

	smb_num_netbios_names = number + 1;
	smb_my_netbios_names = SMB_MALLOC_ARRAY( char *, smb_num_netbios_names );

	if (!smb_my_netbios_names)
		return False;

	memset(smb_my_netbios_names, '\0', sizeof(char *) * smb_num_netbios_names);
	return True;
}

static bool set_my_netbios_names(const char *name, int i)
{
	SAFE_FREE(smb_my_netbios_names[i]);

	/*
	 * Don't include space for terminating '\0' in strndup,
	 * it is automatically added. This screws up if the name
	 * is greater than MAX_NETBIOSNAME_LEN-1 in the unix
	 * charset, but less than or equal to MAX_NETBIOSNAME_LEN-1
	 * in the DOS charset, but this is so old we have to live
	 * with that.
	 */
	smb_my_netbios_names[i] = SMB_STRNDUP(name, MAX_NETBIOSNAME_LEN-1);
	if (!smb_my_netbios_names[i])
		return False;
	return strupper_m(smb_my_netbios_names[i]);
}

/***********************************************************************
 Free memory allocated to global objects
***********************************************************************/

void gfree_names(void)
{
	free_netbios_names_array();
}

const char *my_netbios_names(int i)
{
	return smb_my_netbios_names[i];
}

bool set_netbios_aliases(const char **str_array)
{
	size_t namecount;

	/* Work out the max number of netbios aliases that we have */
	for( namecount=0; str_array && (str_array[namecount] != NULL); namecount++ )
		;

	if ( lp_netbios_name() && *lp_netbios_name())
		namecount++;

	/* Allocate space for the netbios aliases */
	if (!allocate_my_netbios_names_array(namecount))
		return False;

	/* Use the global_myname string first */
	namecount=0;
	if ( lp_netbios_name() && *lp_netbios_name()) {
		set_my_netbios_names( lp_netbios_name(), namecount );
		namecount++;
	}

	if (str_array) {
		size_t i;
		for ( i = 0; str_array[i] != NULL; i++) {
			size_t n;
			bool duplicate = False;

			/* Look for duplicates */
			for( n=0; n<namecount; n++ ) {
				if( strequal( str_array[i], my_netbios_names(n) ) ) {
					duplicate = True;
					break;
				}
			}
			if (!duplicate) {
				if (!set_my_netbios_names(str_array[i], namecount))
					return False;
				namecount++;
			}
		}
	}
	return True;
}

/****************************************************************************
  Common name initialization code.
****************************************************************************/

bool init_names(void)
{
	int n;

	if (!set_netbios_aliases(lp_netbios_aliases())) {
		DEBUG( 0, ( "init_names: malloc fail.\n" ) );
		return False;
	}

	DEBUG( 5, ("Netbios name list:-\n") );
	for( n=0; my_netbios_names(n); n++ ) {
		DEBUGADD( 5, ("my_netbios_names[%d]=\"%s\"\n",
					n, my_netbios_names(n) ) );
	}

	return( True );
}

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

	return true;
}
