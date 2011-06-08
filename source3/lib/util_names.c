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

static char *smb_myname;
static char *smb_myworkgroup;
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

	smb_my_netbios_names[i] = SMB_STRDUP(name);
	if (!smb_my_netbios_names[i])
		return False;
	strupper_m(smb_my_netbios_names[i]);
	return True;
}

/***********************************************************************
 Free memory allocated to global objects
***********************************************************************/

void gfree_names(void)
{
	gfree_netbios_names();
	free_netbios_names_array();
	free_local_machine_name();
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

	if ( global_myname() && *global_myname())
		namecount++;

	/* Allocate space for the netbios aliases */
	if (!allocate_my_netbios_names_array(namecount))
		return False;

	/* Use the global_myname string first */
	namecount=0;
	if ( global_myname() && *global_myname()) {
		set_my_netbios_names( global_myname(), namecount );
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

	if (global_myname() == NULL || *global_myname() == '\0') {
		if (!set_global_myname(myhostname())) {
			DEBUG( 0, ( "init_names: malloc fail.\n" ) );
			return False;
		}
	}

	if (!set_netbios_aliases(lp_netbios_aliases())) {
		DEBUG( 0, ( "init_names: malloc fail.\n" ) );
		return False;
	}

	set_local_machine_name(global_myname(),false);

	DEBUG( 5, ("Netbios name list:-\n") );
	for( n=0; my_netbios_names(n); n++ ) {
		DEBUGADD( 5, ("my_netbios_names[%d]=\"%s\"\n",
					n, my_netbios_names(n) ) );
	}

	return( True );
}

/***********************************************************************
 Allocate and set myname. Ensure upper case.
***********************************************************************/

bool set_global_myname(const char *myname)
{
	SAFE_FREE(smb_myname);
	smb_myname = SMB_STRDUP(myname);
	if (!smb_myname)
		return False;
	strupper_m(smb_myname);
	return True;
}

const char *global_myname(void)
{
	return smb_myname;
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
	return global_myname();
}

void gfree_netbios_names(void)
{
	SAFE_FREE( smb_myname );
	SAFE_FREE( smb_myworkgroup );
}
