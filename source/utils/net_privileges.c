/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Jean François Micouleau      1998-2001.
 *  Copyright (C) Gerald Carter                2003.
 *  Copyright (C) Simo Sorce                   2003.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "includes.h"
#include "../utils/net.h"

extern PRIVS privs[];

/*********************************************************
 utility function to parse an integer parameter from 
 "parameter = value"
**********************************************************/
static uint32 get_int_param( const char* param )
{
	char *p;
	
	p = strchr( param, '=' );
	if ( !p )
		return 0;
		
	return atoi(p+1);
}

/*********************************************************
 utility function to parse an integer parameter from 
 "parameter = value"
**********************************************************/
static char* get_string_param( const char* param )
{
	char *p;
	
	p = strchr( param, '=' );
	if ( !p )
		return NULL;
		
	return (p+1);
}

/*********************************************************
 Dump a GROUP_MAP entry to stdout (long or short listing)
**********************************************************/

static void print_priv_entry(const char *privname, const char *description, const char *sid_list)
{
	d_printf("%s\n", privname);

	if (description) {
		d_printf("\tdescription: %s\n", description);
	}

	if (sid_list) {
		d_printf("\tSIDs: %s\n", sid_list);
	} else {
		d_printf("\tNo SIDs in this privilege\n");
	}
}

/*********************************************************
 List the groups.
**********************************************************/
static int net_priv_list(int argc, const char **argv)
{
	fstring privname = "";
	fstring sid_string = "";
	int i;
	BOOL verbose = False;
	
	/* get the options */
	for ( i=0; i<argc; i++ ) {
		if (StrnCaseCmp(argv[i], "privname", strlen("privname")) == 0) {
			fstrcpy(privname, get_string_param(argv[i]));
			if (!privname[0]) {
				d_printf("must supply a name\n");
				return -1;
			}
		}
		else if (StrnCaseCmp(argv[i], "sid", strlen("sid")) == 0) {
			fstrcpy(sid_string, get_string_param(argv[i]));
			if (!sid_string[0]) {
				d_printf("must supply a SID\n");
				return -1;
			}		
		}
		else if (StrnCaseCmp(argv[i], "verbose", strlen("verbose")) == 0) {
			verbose = True;
		}
		else {
			d_printf("Bad option: %s\n", argv[i]);
			return -1;
		}
	}

	if (sid_string[0] != '\0') {
		/* list all privileges of a single sid */
		
	} else {
	       	char *sid_list = NULL;
		
		if (privname[0] != '\0') {
			const char *description = NULL;

			BOOL found = False;

			for (i=0; privs[i].se_priv != SE_ALL_PRIVS; i++) {
				if (StrCaseCmp(privs[i].priv, privname) == 0) {
					description = privs[i].description;
					found = True;
					break;
				}
			}
			if (!found) {
				d_printf("No such privilege!\n");
				return -1;
			}
			
			/* Get the current privilege from the database */
			pdb_get_privilege_entry(privname, &sid_list);
			print_priv_entry(privname, description, sid_list);

			SAFE_FREE(sid_list);

		} else for (i=0; privs[i].se_priv != SE_ALL_PRIVS; i++) {

			if (!pdb_get_privilege_entry(privs[i].priv, &sid_list)) {
				if (!verbose)
					continue;

				sid_list = NULL;
			}

			print_priv_entry(privs[i].priv, privs[i].description, sid_list);

			SAFE_FREE(sid_list);
		}
	}

	return 0;
}

/*********************************************************
 Add a sid to a privilege entry
**********************************************************/

static int net_priv_add(int argc, const char **argv)
{
	DOM_SID sid;
	fstring privname = "";
	fstring sid_string = "";
	uint32 rid = 0;	
	int i;
	
	/* get the options */
	for ( i=0; i<argc; i++ ) {
		if (StrnCaseCmp(argv[i], "rid", strlen("rid")) == 0) {
			rid = get_int_param(argv[i]);
			if (rid < DOMAIN_GROUP_RID_ADMINS) {
				d_printf("RID must be greater than %d\n", (uint32)DOMAIN_GROUP_RID_ADMINS-1);
				return -1;
			}
		}
		else if (StrnCaseCmp(argv[i], "privilege", strlen("privilege")) == 0) {
			BOOL found = False;
			int j;

			fstrcpy(privname, get_string_param(argv[i]));
			if (!privname[0]) {
				d_printf("must supply a name\n");
				return -1;
			}		
			for (j=0; privs[j].se_priv != SE_ALL_PRIVS; j++) {
				if (StrCaseCmp(privs[j].priv, privname) == 0) {
					found = True;
				}
			}
			if (!found) {
				d_printf("unknown privilege name");
				return -1;
			}
		}
		else if (StrnCaseCmp(argv[i], "sid", strlen("sid")) == 0) {
			fstrcpy(sid_string, get_string_param(argv[i]));
			if (!sid_string[0]) {
				d_printf("must supply a SID\n");
				return -1;
			}		
		}
		else {
			d_printf("Bad option: %s\n", argv[i]);
			return -1;
		}
	}

	if (privname[0] == '\0') {
		d_printf("Usage: net priv add {rid=<int>|sid=<string>} privilege=<string>\n");
		return -1;
	}
	
	if ((rid == 0) && (sid_string[0] == '\0')) {
		d_printf("No rid or sid specified\n");
		d_printf("Usage: net priv add {rid=<int>|sid=<string>} privilege=<string>\n");
		return -1;
	}

	/* append the rid to our own domain/machine SID if we don't have a full SID */
	if (sid_string[0] == '\0') {
		sid_copy(&sid, get_global_sam_sid());
		sid_append_rid(&sid, rid);
		sid_to_string(sid_string, &sid);
	} else {
		string_to_sid(&sid, sid_string);
	}

	if (!pdb_add_sid_to_privilege(privname, &sid)) {
		d_printf("adding sid %s to privilege %s failed!\n", sid_string, privname);
		return -1;
	}

	d_printf("Successully added SID %s to privilege %s\n", sid_string, privname);
	return 0;
}

/*********************************************************
 Remove a SID froma privilege entry
**********************************************************/

static int net_priv_remove(int argc, const char **argv)
{
	DOM_SID sid;
	fstring privname = "";
	fstring sid_string = "";
	uint32 rid = 0;	
	int i;
	
	/* get the options */
	for ( i=0; i<argc; i++ ) {
		if (StrnCaseCmp(argv[i], "rid", strlen("rid")) == 0) {
			rid = get_int_param(argv[i]);
			if (rid < DOMAIN_GROUP_RID_ADMINS) {
				d_printf("RID must be greater than %d\n", (uint32)DOMAIN_GROUP_RID_ADMINS-1);
				return -1;
			}
		}
		else if (StrnCaseCmp(argv[i], "privilege", strlen("privilege")) == 0) {
			BOOL found = False;
			int j;

			fstrcpy(privname, get_string_param(argv[i]));
			if (!privname[0]) {
				d_printf("must supply a name\n");
				return -1;
			}		
			for (j=0; privs[j].se_priv != SE_ALL_PRIVS; j++) {
				if (StrCaseCmp(privs[j].priv, privname) == 0) {
					found = True;
				}
			}
			if (!found) {
				d_printf("unknown privilege name");
				return -1;
			}
		}
		else if (StrnCaseCmp(argv[i], "sid", strlen("sid")) == 0) {
			fstrcpy(sid_string, get_string_param(argv[i]));
			if (!sid_string[0]) {
				d_printf("must supply a SID\n");
				return -1;
			}		
		}
		else {
			d_printf("Bad option: %s\n", argv[i]);
			return -1;
		}
	}

	if (privname[0] == '\0') {
		d_printf("Usage: net priv remove {rid=<int>|sid=<string>} privilege=<string>\n");
		return -1;
	}
	
	if ((rid == 0) && (sid_string[0] == '\0')) {
		d_printf("No rid or sid specified\n");
		d_printf("Usage: net priv remove {rid=<int>|sid=<string>} privilege=<string>\n");
		return -1;
	}

	/* append the rid to our own domain/machine SID if we don't have a full SID */
	if (sid_string[0] == '\0') {
		sid_copy(&sid, get_global_sam_sid());
		sid_append_rid(&sid, rid);
		sid_to_string(sid_string, &sid);
	} else {
		string_to_sid(&sid, sid_string);
	}

	if (!pdb_remove_sid_from_privilege(privname, &sid)) {
		d_printf("removing sid %s from privilege %s failed!\n", sid_string, privname);
		return -1;
	}

	d_printf("Successully removed SID %s from privilege %s\n", sid_string, privname);
	return 0;
}

int net_help_priv(int argc, const char **argv)
{
	d_printf("net priv add sid\n" \
		 "    Add sid to privilege\n");
	d_printf("net priv remove sid\n"\
		 "    Remove sid from privilege\n");
	d_printf("net priv list\n"\
		 "    List sids per privilege\n");
	
	return -1;
}


/***********************************************************
 migrated functionality from smbgroupedit
 **********************************************************/
int net_priv(int argc, const char **argv)
{
	struct functable func[] = {
		{"add", net_priv_add},
		{"remove", net_priv_remove},
		{"list", net_priv_list},
		{"help", net_help_priv},
		{NULL, NULL}
	};

	/* we shouldn't have silly checks like this */
	if (getuid() != 0) {
		d_printf("You must be root to edit privilege mappings.\nExiting...\n");
		return -1;
	}
	
	if ( argc )
		return net_run_function(argc, argv, func, net_help_priv);

	return net_help_priv(argc, argv);
}

