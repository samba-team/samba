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


static int net_groupmap_addmem(int argc, const char **argv)
{
	DOM_SID alias, member;

	if ( (argc != 2) || 
	     !string_to_sid(&alias, argv[0]) ||
	     !string_to_sid(&member, argv[1]) ) {
		d_printf("Usage: net groupmap addmem alias-sid member-sid\n");
		return -1;
	}

	if (!pdb_add_aliasmem(&alias, &member)) {
		d_printf("Could not add sid %s to alias %s\n",
			 argv[1], argv[0]);
		return -1;
	}

	return 0;
}

static int net_groupmap_delmem(int argc, const char **argv)
{
	DOM_SID alias, member;

	if ( (argc != 2) || 
	     !string_to_sid(&alias, argv[0]) ||
	     !string_to_sid(&member, argv[1]) ) {
		d_printf("Usage: net groupmap delmem alias-sid member-sid\n");
		return -1;
	}

	if (!pdb_del_aliasmem(&alias, &member)) {
		d_printf("Could not delete sid %s from alias %s\n",
			 argv[1], argv[0]);
		return -1;
	}

	return 0;
}

static int net_groupmap_listmem(int argc, const char **argv)
{
	DOM_SID alias;
	DOM_SID *members;
	int i, num;
	NTSTATUS result;

	if ( (argc != 1) || 
	     !string_to_sid(&alias, argv[0]) ) {
		d_printf("Usage: net groupmap listmem alias-sid\n");
		return -1;
	}

	if (!pdb_enum_aliasmem(&alias, &members, &num)) {
		d_printf("Could not list members for sid %s: %s\n",
			 argv[0], nt_errstr(result));
		return -1;
	}

	for (i = 0; i < num; i++) {
		printf("%s\n", sid_string_static(&(members[i])));
	}

	SAFE_FREE(members);

	return 0;
}

static int net_groupmap_memberships(int argc, const char **argv)
{
	DOM_SID member;
	DOM_SID *aliases;
	int i, num;
	NTSTATUS result;

	if ( (argc != 1) || 
	     !string_to_sid(&member, argv[0]) ) {
		d_printf("Usage: net groupmap memberof sid\n");
		return -1;
	}

	if (!pdb_enum_alias_memberships(&member, &aliases, &num)) {
		d_printf("Could not list memberships for sid %s: %s\n",
			 argv[0], nt_errstr(result));
		return -1;
	}

	for (i = 0; i < num; i++) {
		printf("%s\n", sid_string_static(&(aliases[i])));
	}

	SAFE_FREE(aliases);

	return 0;
}

static void list_aliases_internals(const DOM_SID *sid)
{
	struct acct_info *aliases = NULL;
	int i, num_aliases = 0;

	if (!pdb_enum_aliases(sid, 0, 1000000, &num_aliases, &aliases)) {
		d_printf("Could not list aliases for domain %s\n",
			 sid_string_static(sid));
		return;
	}

	for (i=0; i<num_aliases; i++) {
		DOM_SID alias_sid;

		sid_copy(&alias_sid, sid);
		sid_append_rid(&alias_sid, aliases[i].rid);

		printf("%s: sid=%s comment=[%s]\n",
		       aliases[i].acct_name, sid_string_static(&alias_sid),
		       aliases[i].acct_desc);
	}
	SAFE_FREE(aliases);
}

static int net_groupmap_aliases(int argc, const char **argv)
{
	extern DOM_SID global_sid_Builtin;

	if (argc != 0) {
		d_printf("net groupmap aliases\n");
		return -1;
	}

	list_aliases_internals(get_global_sam_sid());
	list_aliases_internals(&global_sid_Builtin);
	return 0;
}

	

static int net_groupmap_comment(int argc, const char **argv)
{
	if (argc == 1) {
		char *comment;
		pdb_get_group_comment(NULL, argv[0], &comment);
		d_printf("Comment for %s: [%s]\n", argv[0], comment);
		SAFE_FREE(comment);
	} else if (argc == 2) {
		if (pdb_set_group_comment(argv[0], argv[1])) {
			d_printf("Comment for %s set to [%s]\n",
				 argv[0], argv[1]);
		} else {
			d_printf("Could not set comment\n");
		}
	} else {
		d_printf("Usage: net groupmap comment <group> [comment]\n");
		return -1;
	}

	return 0;
}

static int net_groupmap_newalias(int argc, const char **argv)
{
	uint32 rid;
	DOM_SID sid;

	if (argc != 1) {
		d_printf("net groupmap newalias <aliasname>\n");
		return -1;
	}

	if (!NT_STATUS_IS_OK(pdb_create_alias(argv[0], &rid))) {
		d_printf("Could not create alias %s\n", argv[0]);
		return -1;
	}

	sid_copy(&sid, get_global_sam_sid());
	sid_append_rid(&sid, rid);

	printf("Created alias [%s] with SID %s\n", argv[0],
	       sid_string_static(&sid));
	return 0;
}

static int net_groupmap_delalias(int argc, const char **argv)
{
	DOM_SID sid;

	if (argc != 1) {
		d_printf("net groupmap delalias <aliasname>\n");
		return -1;
	}

	if (!pdb_find_alias(argv[0], &sid)) {
		d_printf("Could not find alias %s\n", argv[0]);
		return -1;
	}

	if (!sid_check_is_in_our_domain(&sid)) {
		d_printf("Can not delete %s as it's not in our "
			 "primary domain\n", argv[0]);
		return -1;
	}

	if (!pdb_delete_alias(&sid)) {
		d_printf("Could not delete %s\n", argv[0]);
		return -1;
	}

	printf("Deleted alias %s\n", argv[0]);
	return 0;
}

int net_help_groupmap(int argc, const char **argv)
{
	d_printf("net groupmap aliases"\
		 "\n  List aliases\n");
	d_printf("net groupmap newalias"\
		 "\n  Create an alias\n");
	d_printf("net groupmap delalias"\
		 "\n  Delete an alias\n");
	d_printf("net groupmap addmem"\
		 "\n  Add an alias member\n");
	d_printf("net groupmap delmem"\
		 "\n  Delete a foreign alias member\n");
	d_printf("net groupmap listmembers"\
		 "\n  List foreign group members\n");
	d_printf("net groupmap memberships"\
		 "\n  List foreign group memberships\n");
	d_printf("net groupmap comment"\
		 "\n  Get/Set a group comment\n");
	
	return -1;
}


/***********************************************************
 migrated functionality from smbgroupedit
 **********************************************************/
int net_groupmap(int argc, const char **argv)
{
	struct functable func[] = {
 		{"addmem", net_groupmap_addmem},
 		{"delmem", net_groupmap_delmem},
 		{"listmem", net_groupmap_listmem},
 		{"memberships", net_groupmap_memberships},
		{"comment", net_groupmap_comment},
		{"aliases", net_groupmap_aliases},
		{"newalias", net_groupmap_newalias},
		{"delalias", net_groupmap_delalias},
		{"help", net_help_groupmap},
		{NULL, NULL}
	};

	/* we shouldn't have silly checks like this */
	if (getuid() != 0) {
		d_printf("You must be root to edit group mappings.\nExiting...\n");
		return -1;
	}
	
	if ( argc )
		return net_run_function(argc, argv, func, net_help_groupmap);

	return net_help_groupmap( argc, argv );
}

