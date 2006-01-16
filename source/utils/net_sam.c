/*
 *  Unix SMB/CIFS implementation.
 *  Local SAM access routines
 *  Copyright (C) Volker Lendecke 2006
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
#include "utils/net.h"

/*
 * Create a local group
 */

static int net_sam_createlocalgroup(int argc, const char **argv)
{
	NTSTATUS status;
	uint32 rid;

	if (argc != 1) {
		d_printf("usage: net sam createlocalgroup <name>\n");
		return -1;
	}

	if (!winbind_ping()) {
		d_printf("winbind seems not to run. createlocalgroup only "
			 "works when winbind runs.\n");
		return -1;
	}

	status = pdb_create_alias(argv[0], &rid);

	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Creating %s failed with %s\n",
			 argv[0], nt_errstr(status));
		return -1;
	}

	d_printf("Created local group %s with RID %d\n", argv[0], rid);

	return 0;
}

/*
 * Add a group member
 */

static int net_sam_addmem(int argc, const char **argv)
{
	const char *groupdomain, *groupname, *memberdomain, *membername;
	DOM_SID group, member;
	enum SID_NAME_USE grouptype, membertype;
	NTSTATUS status;

	if (argc != 2) {
		d_printf("usage: net sam addmem <group> <member>\n");
		return -1;
	}

	if (!lookup_name(tmp_talloc_ctx(), argv[0], LOOKUP_NAME_ISOLATED,
			 &groupdomain, &groupname, &group, &grouptype)) {
		d_printf("Could not find group %s\n", argv[0]);
		return -1;
	}

	if (!lookup_name(tmp_talloc_ctx(), argv[1], LOOKUP_NAME_ISOLATED,
			 &memberdomain, &membername, &member, &membertype)) {
		d_printf("Could not find member %s\n", argv[1]);
		return -1;
	}

	if ((grouptype == SID_NAME_ALIAS) || (grouptype == SID_NAME_WKN_GRP)) {
		if ((membertype != SID_NAME_USER) &&
		    (membertype != SID_NAME_DOM_GRP)) {
			d_printf("%s is a local group, only users and domain "
				 "groups can be added.\n%s is a %s\n",
				 argv[0], argv[1],
				 sid_type_lookup(membertype));
			return -1;
		}
		status = pdb_add_aliasmem(&group, &member);

		if (!NT_STATUS_IS_OK(status)) {
			d_printf("Adding local group member failed with %s\n",
				 nt_errstr(status));
			return -1;
		}
	} else {
		d_printf("Can only add members to local groups so far, %s is "
			 "a %s\n", argv[0], sid_type_lookup(grouptype));
		return -1;
	}

	d_printf("Added %s\\%s to %s\\%s\n",
		 memberdomain, membername, groupdomain, groupname);

	return 0;
}

/*
 * Delete a group member
 */

static int net_sam_delmem(int argc, const char **argv)
{
	const char *groupdomain, *groupname;
	const char *memberdomain = NULL;
	const char *membername = NULL;
	DOM_SID group, member;
	enum SID_NAME_USE grouptype;
	NTSTATUS status;

	if (argc != 2) {
		d_printf("usage: net sam delmem <group> <member>\n");
		return -1;
	}

	if (!lookup_name(tmp_talloc_ctx(), argv[0], LOOKUP_NAME_ISOLATED,
			 &groupdomain, &groupname, &group, &grouptype)) {
		d_printf("Could not find group %s\n", argv[0]);
		return -1;
	}

	if (!lookup_name(tmp_talloc_ctx(), argv[1], LOOKUP_NAME_ISOLATED,
			 &memberdomain, &membername, &member, NULL)) {
		if (!string_to_sid(&member, argv[1])) {
			d_printf("Could not find member %s\n", argv[1]);
			return -1;
		}
	}

	if ((grouptype == SID_NAME_ALIAS) ||
	    (grouptype == SID_NAME_WKN_GRP)) {
		status = pdb_del_aliasmem(&group, &member);

		if (!NT_STATUS_IS_OK(status)) {
			d_printf("Deleting local group member failed with "
				 "%s\n", nt_errstr(status));
			return -1;
		}
	} else {
		d_printf("Can only delete members from local groups so far, "
			 "%s is a %s\n", argv[0], sid_type_lookup(grouptype));
		return -1;
	}

	if (membername != NULL) {
		d_printf("Deleted %s\\%s from %s\\%s\n",
			 memberdomain, membername, groupdomain, groupname);
	} else {
		d_printf("Deleted %s from %s\\%s\n",
			 sid_string_static(&member), groupdomain, groupname);
	}

	return 0;
}

/*
 * List group members
 */

static int net_sam_listmem(int argc, const char **argv)
{
	const char *groupdomain, *groupname;
	DOM_SID group;
	enum SID_NAME_USE grouptype;
	NTSTATUS status;

	if (argc != 1) {
		d_printf("usage: net sam listmem <group>\n");
		return -1;
	}

	if (!lookup_name(tmp_talloc_ctx(), argv[0], LOOKUP_NAME_ISOLATED,
			 &groupdomain, &groupname, &group, &grouptype)) {
		d_printf("Could not find group %s\n", argv[0]);
		return -1;
	}

	if ((grouptype == SID_NAME_ALIAS) ||
	    (grouptype == SID_NAME_WKN_GRP)) {
		DOM_SID *members = NULL;
		size_t i, num_members = 0;
		
		status = pdb_enum_aliasmem(&group, &members, &num_members);

		if (!NT_STATUS_IS_OK(status)) {
			d_printf("Listing group members failed with %s\n",
				 nt_errstr(status));
			return -1;
		}

		d_printf("%s\\%s has %d members\n", groupdomain, groupname,
			 num_members);
		for (i=0; i<num_members; i++) {
			const char *dom, *name;
			if (lookup_sid(tmp_talloc_ctx(), &members[i],
				       &dom, &name, NULL)) {
				d_printf(" %s\\%s\n", dom, name);
			} else {
				d_printf(" %s\n",
					 sid_string_static(&members[i]));
			}
		}
	} else {
		d_printf("Can only list local group members so far.\n"
			 "%s is a %s\n", argv[0], sid_type_lookup(grouptype));
		return -1;
	}

	return 0;
}

int net_help_sam(int argc, const char **argv)
{
	d_printf("net sam createlocalgroup\n"
		 "  Create a new local group\n");
	d_printf("net sam addmem\n"
		 "  Add a member to a group\n");
	d_printf("net sam delmem\n"
		 "  Delete a member from a group\n");
	d_printf("net sam listmem\n"
		 "  List group members\n");
	
	return -1;
}

/***********************************************************
 migrated functionality from smbgroupedit
 **********************************************************/
int net_sam(int argc, const char **argv)
{
	struct functable func[] = {
		{"createlocalgroup", net_sam_createlocalgroup},
		{"addmem", net_sam_addmem},
		{"delmem", net_sam_delmem},
		{"listmem", net_sam_listmem},
		{"help", net_help_sam},
		{NULL, NULL}
	};

	/* we shouldn't have silly checks like this */
	if (getuid() != 0) {
		d_printf("You must be root to edit the SAM directly.\n");
		return -1;
	}
	
	if ( argc )
		return net_run_function(argc, argv, func, net_help_groupmap);

	return net_help_sam( argc, argv );
}

