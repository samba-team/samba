/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Jean François Micouleau      1998-2001.
 *  Copyright (C) Gerald Carter                2003.
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
 Figure out if the input was an NT group or a SID string.
 Return the SID.
**********************************************************/
static BOOL get_sid_from_input(DOM_SID *sid, char *input)
{
	GROUP_MAP map;

	if (StrnCaseCmp( input, "S-", 2)) {
		/* Perhaps its the NT group name? */
		if (!pdb_getgrnam(&map, input)) {
			printf("NT Group %s doesn't exist in mapping DB\n", input);
			return False;
		} else {
			*sid = map.sid;
		}
	} else {
		if (!string_to_sid(sid, input)) {
			printf("converting sid %s from a string failed!\n", input);
			return False;
		}
	}
	return True;
}

/*********************************************************
 Dump a GROUP_MAP entry to stdout (long or short listing)
**********************************************************/

static void print_map_entry ( GROUP_MAP map, BOOL long_list )
{
	fstring string_sid;
	fstring group_type;
	
	decode_sid_name_use(group_type, map.sid_name_use);
	sid_to_string(string_sid, &map.sid);
		
	if (!long_list)
		d_printf("%s (%s) -> %s\n", map.nt_name, string_sid, gidtoname(map.gid));
	else {
		d_printf("%s\n", map.nt_name);
		d_printf("\tSID       : %s\n", string_sid);
		d_printf("\tUnix group: %s\n", gidtoname(map.gid));
		d_printf("\tGroup type: %s\n", group_type);
		d_printf("\tComment   : %s\n", map.comment);
	}

}
/*********************************************************
 List the groups.
**********************************************************/
static int net_groupmap_list(int argc, const char **argv)
{
	int entries;
	BOOL long_list = False;
	int i;
	fstring ntgroup = "";
	fstring sid_string = "";
	
	/* get the options */
	for ( i=0; i<argc; i++ ) {
		if ( !StrCaseCmp(argv[i], "verbose")) {
			long_list = True;
		}
		else if ( !StrnCaseCmp(argv[i], "ntgroup", strlen("ntgroup")) ) {
			fstrcpy( ntgroup, get_string_param( argv[i] ) );
			if ( !ntgroup[0] ) {
				d_printf("must supply a name\n");
				return -1;
			}		
		}
		else if ( !StrnCaseCmp(argv[i], "sid", strlen("sid")) ) {
			fstrcpy( sid_string, get_string_param( argv[i] ) );
			if ( !sid_string[0] ) {
				d_printf("must supply a SID\n");
				return -1;
			}		
		}
		else {
			d_printf("Bad option: %s\n", argv[i]);
			return -1;
		}
	}

	/* list a single group is given a name */
	if ( ntgroup[0] || sid_string[0] ) {
		DOM_SID sid;
		GROUP_MAP map;
		
		if ( sid_string[0] )
			fstrcpy( ntgroup, sid_string);
			
		if (!get_sid_from_input(&sid, ntgroup)) {
			return -1;
		}

		/* Get the current mapping from the database */
		if(!pdb_getgrsid(&map, sid)) {
			d_printf("Failure to local group SID in the database\n");
			return -1;
		}
	
		print_map_entry( map, long_list );
	}
	else {
		GROUP_MAP *map=NULL;
		/* enumerate all group mappings */
		if (!pdb_enum_group_mapping(SID_NAME_UNKNOWN, &map, &entries, ENUM_ALL_MAPPED))
			return -1;
	
		for (i=0; i<entries; i++) {
			print_map_entry( map[i], long_list );
		}

		SAFE_FREE(map);
	}

	return 0;
}

/*********************************************************
 Add a new group mapping entry
**********************************************************/

static int net_groupmap_add(int argc, const char **argv)
{
	DOM_SID sid;
	fstring ntgroup = "";
	fstring unixgrp = "";
	fstring string_sid = "";
	fstring type = "";
	fstring ntcomment = "";
	enum SID_NAME_USE sid_type = SID_NAME_DOM_GRP;
	uint32 rid = 0;	
	gid_t gid;
	int i;
	
	/* get the options */
	for ( i=0; i<argc; i++ ) {
		if ( !StrnCaseCmp(argv[i], "rid", strlen("rid")) ) {
			rid = get_int_param(argv[i]);
			if ( rid < DOMAIN_GROUP_RID_ADMINS ) {
				d_printf("RID must be greater than %d\n", (uint32)DOMAIN_GROUP_RID_ADMINS-1);
				return -1;
			}
		}
		else if ( !StrnCaseCmp(argv[i], "unixgroup", strlen("unixgroup")) ) {
			fstrcpy( unixgrp, get_string_param( argv[i] ) );
			if ( !unixgrp[0] ) {
				d_printf("must supply a name\n");
				return -1;
			}		
		}
		else if ( !StrnCaseCmp(argv[i], "ntgroup", strlen("ntgroup")) ) {
			fstrcpy( ntgroup, get_string_param( argv[i] ) );
			if ( !ntgroup[0] ) {
				d_printf("must supply a name\n");
				return -1;
			}		
		}
		else if ( !StrnCaseCmp(argv[i], "sid", strlen("sid")) ) {
			fstrcpy( string_sid, get_string_param( argv[i] ) );
			if ( !string_sid[0] ) {
				d_printf("must supply a SID\n");
				return -1;
			}		
		}
		else if ( !StrnCaseCmp(argv[i], "comment", strlen("comment")) ) {
			fstrcpy( ntcomment, get_string_param( argv[i] ) );
			if ( !ntcomment[0] ) {
				d_printf("must supply a comment string\n");
				return -1;
			}				
		}
		else if ( !StrnCaseCmp(argv[i], "type", strlen("type")) )  {
			fstrcpy( type, get_string_param( argv[i] ) );
			switch ( type[0] ) {
				case 'b':
				case 'B':
					sid_type = SID_NAME_WKN_GRP;
					break;
				case 'd':
				case 'D':
					sid_type = SID_NAME_DOM_GRP;
					break;
				case 'l':
				case 'L':
					sid_type = SID_NAME_ALIAS;
					break;
			}
		}
		else {
			d_printf("Bad option: %s\n", argv[i]);
			return -1;
		}
	}

	if ( !unixgrp[0] ) {
		d_printf("Usage: net groupmap add {rid=<int>|sid=<string>} unixgroup=<string> [type=<domain|local|builtin>] [ntgroup=<string>] [comment=<string>]\n");
		return -1;
	}
	
	if ( (gid = nametogid(unixgrp)) == (gid_t)-1 ) {
		d_printf("Can't lookup UNIX group %s\n", ntgroup);
		return -1;
	}
	
	if ( (rid == 0) && (string_sid[0] == '\0') ) {
		d_printf("No rid or sid specified, choosing algorithmic mapping\n");
		rid = pdb_gid_to_group_rid(gid);
	}

	/* append the rid to our own domain/machine SID if we don't have a full SID */
	if ( !string_sid[0] ) {
		sid_copy(&sid, get_global_sam_sid());
		sid_append_rid(&sid, rid);
		sid_to_string(string_sid, &sid);
	}

	if (ntcomment[0])
		fstrcpy(ntcomment, "Local Unix group");
		
	if ( !ntgroup[0] )
		fstrcpy( ntgroup, unixgrp );
		
	
	if (!add_initial_entry(gid, string_sid, sid_type, ntgroup, ntcomment)) {
		d_printf("adding entry for group %s failed!\n", ntgroup);
		return -1;
	}

	d_printf("Successully added group %s to the mapping db\n", ntgroup);
	return 0;
}

static int net_groupmap_modify(int argc, const char **argv)
{
	DOM_SID sid;
	GROUP_MAP map;
	fstring ntcomment = "";
	fstring type = "";
	fstring ntgroup = "";
	fstring unixgrp = "";
	fstring sid_string = "";
	enum SID_NAME_USE sid_type = SID_NAME_UNKNOWN;
	int i;
	gid_t gid;

	/* get the options */
	for ( i=0; i<argc; i++ ) {
		if ( !StrnCaseCmp(argv[i], "ntgroup", strlen("ntgroup")) ) {
			fstrcpy( ntgroup, get_string_param( argv[i] ) );
			if ( !ntgroup[0] ) {
				d_printf("must supply a name\n");
				return -1;
			}		
		}
		else if ( !StrnCaseCmp(argv[i], "sid", strlen("sid")) ) {
			fstrcpy( sid_string, get_string_param( argv[i] ) );
			if ( !sid_string[0] ) {
				d_printf("must supply a name\n");
				return -1;
			}		
		}
		else if ( !StrnCaseCmp(argv[i], "comment", strlen("comment")) ) {
			fstrcpy( ntcomment, get_string_param( argv[i] ) );
			if ( !ntcomment[0] ) {
				d_printf("must supply a comment string\n");
				return -1;
			}				
		}
		else if ( !StrnCaseCmp(argv[i], "unixgroup", strlen("unixgroup")) ) {
			fstrcpy( unixgrp, get_string_param( argv[i] ) );
			if ( !unixgrp[0] ) {
				d_printf("must supply a group name\n");
				return -1;
			}				
		}
		else if ( !StrnCaseCmp(argv[i], "type", strlen("type")) )  {
			fstrcpy( type, get_string_param( argv[i] ) );
			switch ( type[0] ) {
				case 'd':
				case 'D':
					sid_type = SID_NAME_DOM_GRP;
					break;
				case 'l':
				case 'L':
					sid_type = SID_NAME_ALIAS;
					break;
			}
		}
		else {
			d_printf("Bad option: %s\n", argv[i]);
			return -1;
		}
	}
	
	if ( !ntgroup[0] && !sid_string[0] ) {
		d_printf("Usage: net groupmap modify {ntgroup=<string>|sid=<SID>} [comment=<string>] [unixgroup=<string>] [type=<domain|local>]\n");
		return -1;
	}

	/* give preference to the SID; if both the ntgroup name and SID
	   are defined, use the SID and assume that the group name could be a 
	   new name */
	   	
	if ( sid_string[0] ) {	
		if (!get_sid_from_input(&sid, sid_string)) {
			return -1;
		}
	}
	else {
		if (!get_sid_from_input(&sid, ntgroup)) {
			return -1;
		}
	}	

	/* Get the current mapping from the database */
	if(!pdb_getgrsid(&map, sid)) {
		d_printf("Failure to local group SID in the database\n");
		return -1;
	}
	
	/*
	 * Allow changing of group type only between domain and local
	 * We disallow changing Builtin groups !!! (SID problem)
	 */ 
	if (sid_type != SID_NAME_UNKNOWN) { 
		if (map.sid_name_use == SID_NAME_WKN_GRP) {
			d_printf("You can only change between domain and local groups.\n");
			return -1;
		}
		
		map.sid_name_use=sid_type;
	}

	/* Change comment if new one */
	if ( ntcomment[0] )
		fstrcpy( map.comment, ntcomment );
		
	if ( ntgroup[0] )
		fstrcpy( map.nt_name, ntgroup );
		
	if ( unixgrp[0] ) {
		gid = nametogid( unixgrp );
		if ( gid == -1 ) {
			d_printf("Unable to lookup UNIX group %s.  Make sure the group exists.\n",
				unixgrp);
			return -1;
		}
		
		map.gid = gid;
	}

	if ( !pdb_update_group_mapping_entry(&map) ) {
		d_printf("Could not update group database\n");
		return -1;
	}
	
	d_printf("Updated mapping entry for %s\n", ntgroup);

	return 0;
}

static int net_groupmap_delete(int argc, const char **argv)
{
	DOM_SID sid;
	fstring ntgroup = "";
	fstring sid_string = "";
	int i;

	/* get the options */
	for ( i=0; i<argc; i++ ) {
		if ( !StrnCaseCmp(argv[i], "ntgroup", strlen("ntgroup")) ) {
			fstrcpy( ntgroup, get_string_param( argv[i] ) );
			if ( !ntgroup[0] ) {
				d_printf("must supply a name\n");
				return -1;
			}		
		}
		else if ( !StrnCaseCmp(argv[i], "sid", strlen("sid")) ) {
			fstrcpy( sid_string, get_string_param( argv[i] ) );
			if ( !sid_string[0] ) {
				d_printf("must supply a SID\n");
				return -1;
			}		
		}
		else {
			d_printf("Bad option: %s\n", argv[i]);
			return -1;
		}
	}
	
	if ( !ntgroup[0] && !sid_string[0]) {
		d_printf("Usage: net groupmap delete {ntgroup=<string>|sid=<SID>}\n");
		return -1;
	}
	
	/* give preference to the SID if we have that */
	
	if ( sid_string[0] )
		fstrcpy( ntgroup, sid_string );
		
	if ( !get_sid_from_input(&sid, ntgroup) ) {
		d_printf("Unable to resolve group %s to a SID\n", ntgroup);
		return -1;
	}

	if ( !pdb_delete_group_mapping_entry(sid) ) {
		printf("Failed to removing group %s from the mapping db!\n", ntgroup);
		return -1;
	}

	d_printf("Sucessfully removed %s from the mapping db\n", ntgroup);

	return 0;
}

int net_help_groupmap(int argc, const char **argv)
{
	d_printf("net groupmap add"\
		"\n  Create a new group mapping\n");
	d_printf("net groupmap modify"\
		"\n  Update a group mapping\n");
	d_printf("net groupmap delete"\
		"\n  Remove a group mapping\n");
	d_printf("net groupmap list"\
		"\n  List current group map\n");
	
	return -1;
}


/***********************************************************
 migrated functionality from smbgroupedit
 **********************************************************/
int net_groupmap(int argc, const char **argv)
{
	struct functable func[] = {
		{"add", net_groupmap_add},
		{"modify", net_groupmap_modify},
		{"delete", net_groupmap_delete},
		{"list", net_groupmap_list},
		{"help", net_help_groupmap},
		{NULL, NULL}
	};

	/* we shouldn't have silly checks like this */
	if (getuid() != 0) {
		d_printf("You must be root to edit group mappings.\nExiting...\n");
		return -1;
	}
	
	return net_run_function(argc, argv, func, net_help_groupmap);
	if ( 0 == argc )
		return net_help_groupmap( argc, argv );

	return net_help_groupmap( argc, argv );
}

