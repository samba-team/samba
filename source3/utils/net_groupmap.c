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
		if (!pdb_getgrnam(&map, input, MAPPING_WITHOUT_PRIV)) {
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
	fstring priv_text;
	
	decode_sid_name_use(group_type, map.sid_name_use);
	sid_to_string(string_sid, &map.sid);
	convert_priv_to_text(&(map.priv_set), priv_text);
		
	if (!long_list)
		d_printf("%s (%s) -> %s\n", map.nt_name, string_sid, gidtoname(map.gid));
	else {
		d_printf("%s\n", map.nt_name);
		d_printf("\tSID       : %s\n", string_sid);
		d_printf("\tUnix group: %s\n", gidtoname(map.gid));
		d_printf("\tGroup type: %s\n", group_type);
		d_printf("\tComment   : %s\n", map.comment);
		d_printf("\tPrivilege : %s\n\n", priv_text);
	}

}
/*********************************************************
 List the groups.
**********************************************************/
int net_groupmap_list(int argc, const char **argv)
{
	int entries;
	BOOL long_list = False;
	int i;
	fstring ntgroup = "";
	
	/* get the options */
	for ( i=0; i<argc; i++ ) {
		if ( !StrCaseCmp(argv[i], "verbose")) {
			long_list = True;
		}
		else if ( !StrnCaseCmp(argv[i], "name", strlen("name")) ) {
			fstrcpy( ntgroup, get_string_param( argv[i] ) );
			if ( !ntgroup[0] ) {
				d_printf("must supply a name\n");
				return -1;
			}		
		}
		else {
			d_printf("Bad option: %s\n", argv[i]);
			return -1;
		}
	}

	/* list a single group is given a name */
	if ( ntgroup[0] ) {
		DOM_SID sid;
		GROUP_MAP map;
			
		if (!get_sid_from_input(&sid, ntgroup)) {
			return -1;
		}

		/* Get the current mapping from the database */
		if(!pdb_getgrsid(&map, sid, MAPPING_WITH_PRIV)) {
			d_printf("Failure to local group SID in the database\n");
			return -1;
		}
	
		print_map_entry( map, long_list );
		free_privilege(&(map.priv_set));	
	}
	else {
		GROUP_MAP *map=NULL;
		/* enumerate all group mappings */
		if ( !pdb_enum_group_mapping(SID_NAME_UNKNOWN, &map, &entries, ENUM_ALL_MAPPED, MAPPING_WITH_PRIV) )
			return -1;
	
		for (i=0; i<entries; i++) {
			print_map_entry( map[i], long_list );
			free_privilege(&(map[i].priv_set));
		}
	}

	return 0;
}

/*********************************************************
 Add a new group mapping entry
**********************************************************/

int net_groupmap_add(int argc, const char **argv)
{
	PRIVILEGE_SET se_priv;
	DOM_SID sid;
	fstring ntgroup = "";
	fstring string_sid = "";
	fstring type = "";
	fstring ntcomment = "";
	enum SID_NAME_USE sid_type = SID_NAME_UNKNOWN;
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
		else if ( !StrnCaseCmp(argv[i], "name", strlen("name")) ) {
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

	if ( !ntgroup[0] || (!rid && !string_sid[0]) || sid_type==SID_NAME_UNKNOWN ) {
		d_printf("Usage: net groupmap add {rid=<int>|sid=<string>} name=<string>| type=<domain|local|builtin> [comment=<string>]\n");
		return -1;
	}
	
	/* append the rid to our own domain/machine SID if we don't have a full SID */
	if ( !string_sid[0] ) {
		sid_copy(&sid, get_global_sam_sid());
		sid_append_rid(&sid, rid);
		sid_to_string(string_sid, &sid);
	}

	if (ntcomment[0])
		fstrcpy(ntcomment, "Local Unix group");
		
	if ( !(gid = nametogid(ntgroup)) ) {
		d_printf("Can't lookup UNIX group %s\n", ntgroup);
		return -1;
	}
	
	init_privilege(&se_priv);
#if 0
	if (privilege!=NULL)
		convert_priv_from_text(&se_priv, privilege);
#endif

	if (!add_initial_entry(gid, string_sid, sid_type, ntgroup,
			      ntcomment, se_priv, PR_ACCESS_FROM_NETWORK) ) {
		d_printf("adding entry for group %s failed!\n", ntgroup);
		return -1;
	}

	free_privilege(&se_priv);
		
	d_printf("Successully added group %s to the mapping db\n", ntgroup);
	return 0;
}

int net_groupmap_modify(int argc, const char **argv)
{
	DOM_SID sid;
	GROUP_MAP map;
	fstring ntcomment = "";
	fstring type = "";
	fstring ntgroup = "";
	enum SID_NAME_USE sid_type = SID_NAME_UNKNOWN;
	int i;

	/* get the options */
	for ( i=0; i<argc; i++ ) {
		if ( !StrnCaseCmp(argv[i], "name", strlen("name")) ) {
			fstrcpy( ntgroup, get_string_param( argv[i] ) );
			if ( !ntgroup[0] ) {
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
	
	if ( !ntgroup[0] ) {
		d_printf("Usage: net groupmap modify name=<string|SID> [comment=<string>] [type=<domain|local>\n");
		return -1;
	}
	
	if (!get_sid_from_input(&sid, ntgroup)) {
		return -1;
	}

	/* Get the current mapping from the database */
	if(!pdb_getgrsid(&map, sid, MAPPING_WITH_PRIV)) {
		d_printf("Failure to local group SID in the database\n");
		return -1;
	}
	
	/*
	 * Allow changing of group type only between domain and local
	 * We disallow changing Builtin groups !!! (SID problem)
	 */ 
	if (sid_type==SID_NAME_ALIAS 
	    || sid_type==SID_NAME_DOM_GRP 
	    || sid_type==SID_NAME_UNKNOWN) 
	{
		if (map.sid_name_use==SID_NAME_ALIAS 
		    || map.sid_name_use==SID_NAME_DOM_GRP
		    || map.sid_name_use==SID_NAME_UNKNOWN) 
		{
			map.sid_name_use=sid_type;
		} else {
			printf("cannot change group type to builtin\n");
		};
	} else {
		printf("cannot change group type from builtin\n");
	}

	/* Change comment if new one */
	if ( ntcomment[0] )
		fstrcpy( map.comment, ntcomment );

#if 0
	/* Change the privilege if new one */
	if (privilege!=NULL)
		convert_priv_from_text(&map.priv_set, privilege);
#endif

	if ( !pdb_update_group_mapping_entry(&map) ) {
		d_printf("Could not update group database\n");
		free_privilege(&map.priv_set);
		return -1;
	}
	
	free_privilege(&map.priv_set);
	
	d_printf("Updated mapping entry for %s\n", ntgroup);

	return 0;
}

int net_groupmap_delete(int argc, const char **argv)
{
	DOM_SID sid;
	fstring ntgroup = "";
	int i;

	/* get the options */
	for ( i=0; i<argc; i++ ) {
		if ( !StrnCaseCmp(argv[i], "name", strlen("name")) ) {
			fstrcpy( ntgroup, get_string_param( argv[i] ) );
			if ( !ntgroup[0] ) {
				d_printf("must supply a name\n");
				return -1;
			}		
		}
		else {
			d_printf("Bad option: %s\n", argv[i]);
			return -1;
		}
	}
	
	if ( !ntgroup[0] ) {
		d_printf("Usage: net groupmap delete name=<string|SID>\n");
		return -1;
	}
	
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

#if 0 
/*********************************************************
 Change a group.
**********************************************************/
static int changegroup(char *sid_string, char *group, enum SID_NAME_USE sid_type, char *ntgroup, char *groupdesc, char *privilege)
{
}
#endif
