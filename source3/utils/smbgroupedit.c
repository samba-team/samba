/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
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
		printf("groupedit options\n");
	} else {
		printf("You need to be root to use this tool!\n");
	}
	printf("options:\n");
	printf("  -a group             create new group\n");
	printf("    -n group           NT group name\n");
	printf("    -p privilege       only local\n");
	printf("  -v                   list groups\n");
	printf("  -c SID               change group\n");
	printf("     -u unix group\n");
	printf("  -x group             delete this group\n");
	printf("\n");
	printf("    -t[b|d|l]          type: builtin, domain, local \n");
	exit(1);
}

/*********************************************************
 add a group.
**********************************************************/
int addgroup(char *group, enum SID_NAME_USE sid_type, char *ntgroup, char *ntcomment, char *privilege)
{
	uint32 se_priv;
	gid_t gid;
	DOM_SID sid;
	fstring string_sid;
	fstring name, comment;

/*	convert_priv_from_text(&se_priv, privilege);*/

	se_priv=0x0;

	gid=nametogid(group);
	if (gid==-1)
		return -1;

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

	if(!add_initial_entry(gid, string_sid, sid_type, name, comment, se_priv))
		return -1;

	return 0;
}

/*********************************************************
 Change a group.
**********************************************************/
int changegroup(char *sid_string, char *group, enum SID_NAME_USE sid_type, char *ntgroup, char *groupdesc, char *privilege)
{
	DOM_SID sid;
	GROUP_MAP map;
	gid_t gid;
	uint32 se_priv;

	string_to_sid(&sid, sid_string);

	/* Get the current mapping from the database */
	if(!get_group_map_from_sid(sid, &map)) {
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
	if (sid_type==SID_NAME_ALIAS || sid_type==SID_NAME_DOM_GRP)
		if (map.sid_name_use==SID_NAME_ALIAS || map.sid_name_use==SID_NAME_DOM_GRP)
			map.sid_name_use=sid_type;


	if (ntgroup!=NULL)
		fstrcpy(map.nt_name, ntgroup);

	/* Change comment if new one */
	if (groupdesc!=NULL)
		fstrcpy(map.comment, groupdesc);

	/* Change the privilege if new one */
	if (privilege!=NULL) {
		convert_priv_from_text(&se_priv, privilege);
		map.privilege=se_priv;
	}

	if (!add_mapping_entry(&map, TDB_REPLACE)) {
		printf("Count not update group database\n");
		return -1;
	}

	return 0;
}

/*********************************************************
 Delete the group.
**********************************************************/
BOOL deletegroup(char *group)
{
	DOM_SID sid;
	
	string_to_sid(&sid, group);

	if(!group_map_remove(sid))
		return False;

	return True;
}

/*********************************************************
 List the groups.
**********************************************************/
int listgroup(enum SID_NAME_USE sid_type)
{
	int entries,i;
	GROUP_MAP *map=NULL;
	fstring string_sid;
	fstring group_type;
	fstring priv_text;

	printf("Unix\tSID\ttype\tnt name\tnt comment\tprivilege\n");
		
	if (!enum_group_mapping(sid_type, &map, &entries, ENUM_ALL_MAPPED))
		return -1;
	
	for (i=0; i<entries; i++) {
		decode_sid_name_use(group_type, (map[i]).sid_name_use);
		sid_to_string(string_sid, &map[i].sid);
		convert_priv_to_text(map[i].privilege, priv_text);

		printf("%s\t%s\t%s\n\t%s\t%s\t%s\n\n", gidtoname(map[i].gid), map[i].nt_name, string_sid, 
					             group_type, map[i].comment, priv_text);
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
	
	if(!initialize_password_db(True)) {
		fprintf(stderr, "Can't setup password database vectors.\n");
		exit(1);
	}
	
	if (!lp_load(dyn_CONFIGFILE,True,False,False)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", 
			dyn_CONFIGFILE);
		exit(1);
	}
	
	while ((ch = getopt(argc, argv, "a:c:d:n:p:t:u:vx:")) != EOF) {
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
		case 'n':
			nt_group = True;
			ntgroup=optarg;
			break;
		case 'p':
			priv = True;
			privilege=optarg;
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
		
	if (init_group_mapping()==False) {
		printf("Could not open tdb mapping file.\n");
		return 0;
	}
	
	if(pdb_generate_sam_sid()==False) {
		printf("Can not read machine SID\n");
		return 0;
	}

	default_group_mapping();

	if (add_group)
		return addgroup(group, sid_type, ntgroup, group_desc, privilege);

	if (view_group)
		return listgroup(sid_type);

	if (delete_group)
		return deletegroup(group);
	
	if (change_group) {		
		return changegroup(sid, group, sid_type, ntgroup, group_desc, privilege);
	}
	
	usage();

	return 0;
}
