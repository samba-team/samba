/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Jean François Micouleau      1998-2001.
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

extern pstring global_myname;
extern pstring global_myworkgroup;
extern DOM_SID global_sam_sid;

/*
 * Next two lines needed for SunOS and don't
 * hurt anything else...
 */
extern char *optarg;
extern int optind;

/*********************************************************
 Print command usage on stderr and die.
**********************************************************/
static void usage(void)
{
	if (getuid() == 0) {
		printf("smbgroupedit options\n");
	} else {
		printf("You need to be root to use this tool!\n");
	}
	printf("options:\n");
	printf("  -a group             create new group\n");
	printf("    -n group           NT group name\n");
	printf("    -p privilege       only local\n");
	printf("  -v                   list groups\n");
	printf("    -l                 long list (include details)\n");
	printf("    -s                 short list (default)\n");
	printf("  -c SID               change group\n");
	printf("     -u unix group\n");
	printf("  -x group             delete this group\n");
	printf("\n");
	printf("    -t[b|d|l]          type: builtin, domain, local \n");
	exit(1);
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
		if (!get_group_map_from_ntname(input, &map, MAPPING_WITHOUT_PRIV)) {
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
 add a group.
**********************************************************/
static int addgroup(char *group, enum SID_NAME_USE sid_type, char *ntgroup, char *ntcomment, char *privilege)
{
	PRIVILEGE_SET se_priv;
	gid_t gid;
	DOM_SID sid;
	fstring string_sid;
	fstring name, comment;

	gid=nametogid(group);
	if (gid==-1) {
		printf("unix group %s doesn't exist!\n", group);
		return -1;
	}

	local_gid_to_sid(&sid, gid);

	sid_to_string(string_sid, &sid);
	
	if (ntgroup==NULL)
		fstrcpy(name, group);
	else
		fstrcpy(name, ntgroup);
	
	if (ntcomment==NULL)
		fstrcpy(comment, "Local Unix group");
	else
		fstrcpy(comment, ntcomment);

	init_privilege(&se_priv);
	if (privilege!=NULL)
		convert_priv_from_text(&se_priv, privilege);

	if(!add_initial_entry(gid, string_sid, sid_type, name, comment, se_priv, PR_ACCESS_FROM_NETWORK)) {
		printf("adding entry for group %s failed!\n", group);
		free_privilege(&se_priv);
		return -1;
	}

	free_privilege(&se_priv);
	return 0;
}

/*********************************************************
 Change a group.
**********************************************************/
static int changegroup(char *sid_string, char *group, enum SID_NAME_USE sid_type, char *ntgroup, char *groupdesc, char *privilege)
{
	DOM_SID sid;
	GROUP_MAP map;
	gid_t gid;

	if (!get_sid_from_input(&sid, sid_string)) {
		return -1;
	}

	/* Get the current mapping from the database */
	if(!get_group_map_from_sid(sid, &map, MAPPING_WITH_PRIV)) {
		printf("This SID does not exist in the database\n");
		return -1;
	}

	/* If a new Unix group is specified, check and change */
	if (group!=NULL) {
		gid=nametogid(group);
		if (gid==-1) {
			printf("The UNIX group does not exist\n");
			return -1;
		} else
			map.gid=gid;
	}
	
	/*
	 * Allow changing of group type only between domain and local
	 * We disallow changing Builtin groups !!! (SID problem)
	 */ 
	if (sid_type==SID_NAME_ALIAS 
	    || sid_type==SID_NAME_DOM_GRP 
	    || sid_type==SID_NAME_UNKNOWN) {
		if (map.sid_name_use==SID_NAME_ALIAS 
		    || map.sid_name_use==SID_NAME_DOM_GRP
		    || map.sid_name_use==SID_NAME_UNKNOWN) {
			map.sid_name_use=sid_type;
		} else {
			printf("cannot change group type to builtin\n");
		};
	} else {
		printf("cannot change group type from builtin\n");
	}

	if (ntgroup!=NULL)
		fstrcpy(map.nt_name, ntgroup);

	/* Change comment if new one */
	if (groupdesc!=NULL)
		fstrcpy(map.comment, groupdesc);

	/* Change the privilege if new one */
	if (privilege!=NULL)
		convert_priv_from_text(&map.priv_set, privilege);

	if (!add_mapping_entry(&map, TDB_REPLACE)) {
		printf("Count not update group database\n");
		free_privilege(&map.priv_set);
		return -1;
	}
	
	free_privilege(&map.priv_set);
	return 0;
}

/*********************************************************
 Delete the group.
**********************************************************/
static int deletegroup(char *group)
{
	DOM_SID sid;

	if (!get_sid_from_input(&sid, group)) {
		return -1;
	}

	if(!group_map_remove(sid)) {
		printf("removing group %s from the mapping db failed!\n", group);
		return -1;
	}

	return 0;
}

/*********************************************************
 List the groups.
**********************************************************/
static int listgroup(enum SID_NAME_USE sid_type, BOOL long_list)
{
	int entries,i;
	GROUP_MAP *map=NULL;
	fstring string_sid;
	fstring group_type;
	fstring priv_text;

	if (!long_list)
		printf("NT group (SID) -> Unix group\n");
		
	if (!enum_group_mapping(sid_type, &map, &entries, ENUM_ALL_MAPPED, MAPPING_WITH_PRIV))
		return -1;
	
	for (i=0; i<entries; i++) {
		decode_sid_name_use(group_type, (map[i]).sid_name_use);
		sid_to_string(string_sid, &map[i].sid);
		convert_priv_to_text(&(map[i].priv_set), priv_text);
		free_privilege(&(map[i].priv_set));
		
		if (!long_list)
			printf("%s (%s) -> %s\n", map[i].nt_name, string_sid, gidtoname(map[i].gid));
		else {
			printf("%s\n", map[i].nt_name);
			printf("\tSID       : %s\n", string_sid);
			printf("\tUnix group: %s\n", gidtoname(map[i].gid));
			printf("\tGroup type: %s\n", group_type);
			printf("\tComment   : %s\n", map[i].comment);
			printf("\tPrivilege : %s\n\n", priv_text);
		}
	}

	return 0;
}

/*********************************************************
 Start here.
**********************************************************/
int main (int argc, char **argv)
{
	int ch;
	BOOL add_group = False;
	BOOL view_group = False;
	BOOL change_group = False;
	BOOL delete_group = False;
	BOOL nt_group = False;
	BOOL priv = False;
	BOOL group_type = False;
	BOOL long_list = False;

	char *group = NULL;
	char *sid = NULL;
	char *ntgroup = NULL;
	char *privilege = NULL;
	char *groupt = NULL;
	char *group_desc = NULL;

	enum SID_NAME_USE sid_type;

	setup_logging("groupedit", True);

	if (argc < 2) {
		usage();
		return 0;
	}
	
	if (!lp_load(dyn_CONFIGFILE,True,False,False)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", 
			dyn_CONFIGFILE);
		exit(1);
	}

	if (!*global_myname) {
		char *p;
		pstrcpy( global_myname, myhostname() );
		p = strchr_m(global_myname, '.' );
		if (p) 
			*p = 0;
	}

	strupper(global_myname);

	fstrcpy(global_myworkgroup, lp_workgroup());
	
	if(!initialize_password_db(True)) {
		fprintf(stderr, "Can't setup password database vectors.\n");
		exit(1);
	}
	
	if(pdb_generate_sam_sid()==False) {
		fprintf(stderr, "Can not read machine SID\n");
		return 0;
	}

	while ((ch = getopt(argc, argv, "a:c:d:ln:p:st:u:vx:")) != EOF) {
		switch(ch) {
		case 'a':
			add_group = True;
			group=optarg;
			break;
		case 'c':
			change_group = True;
			sid=optarg;
			break;
		case 'd':
			group_desc=optarg;
			break;
		case 'l':
			long_list = True;
			break;
		case 'n':
			nt_group = True;
			ntgroup=optarg;
			break;
		case 'p':
			priv = True;
			privilege=optarg;
			break;
		case 's':
			long_list = False;
			break;
		case 't':
			group_type = True;
			groupt=optarg;
			break;
		case 'u':
			group=optarg;
			break;
		case 'v':
			view_group = True;
			break;
		case 'x':
			delete_group = True;
			group=optarg;
			break;
		/*default:
			usage();*/
		}
	}
	
	
	if (((add_group?1:0) + (view_group?1:0) + (change_group?1:0) + (delete_group?1:0)) > 1) {
		fprintf (stderr, "Incompatible options on command line!\n");
		usage();
		exit(1);
	}

	/* no option on command line -> list groups */	
	if (((add_group?1:0) + (view_group?1:0) + (change_group?1:0) + (delete_group?1:0)) == 0)
		view_group = True;

	
	if (group_type==False)
		sid_type=SID_NAME_UNKNOWN;
	else {
		switch (groupt[0]) {
			case 'l':
			case 'L':
				sid_type=SID_NAME_ALIAS;
				break;
			case 'd':
			case 'D':
				sid_type=SID_NAME_DOM_GRP;
				break;
			case 'b':
			case 'B':
				sid_type=SID_NAME_WKN_GRP;
				break;
			default:
				sid_type=SID_NAME_UNKNOWN;
				break;
		}
	}

	if (add_group)
		return addgroup(group, sid_type, ntgroup, group_desc, privilege);

	if (view_group)
		return listgroup(sid_type, long_list);

	if (delete_group)
		return deletegroup(group);
	
	if (change_group) {		
		return changegroup(sid, group, sid_type, ntgroup, group_desc, privilege);
	}
	
	usage();

	return 0;
}
