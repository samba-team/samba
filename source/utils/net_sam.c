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
 * Set a user's data
 */

static int net_sam_userset(int argc, const char **argv, const char *field,
			   BOOL (*fn)(SAM_ACCOUNT *, const char *,
				      enum pdb_value_state))
{
	SAM_ACCOUNT *sam_acct = NULL;
	DOM_SID sid;
	enum SID_NAME_USE type;
	const char *dom, *name;
	NTSTATUS status;

	if (argc != 2) {
		d_fprintf(stderr, "usage: net sam set %s <user> <value>\n",
			  field);
		return -1;
	}

	if (!lookup_name(tmp_talloc_ctx(), argv[0], LOOKUP_NAME_ISOLATED,
			 &dom, &name, &sid, &type)) {
		d_fprintf(stderr, "Could not find name %s\n", argv[0]);
		return -1;
	}

	if (type != SID_NAME_USER) {
		d_fprintf(stderr, "%s is a %s, not a user\n", argv[0],
			  sid_type_lookup(type));
		return -1;
	}

	if (!NT_STATUS_IS_OK(pdb_init_sam(&sam_acct))) {
		d_fprintf(stderr, "Internal error\n");
		return -1;
	}

	if (!pdb_getsampwsid(sam_acct, &sid)) {
		d_fprintf(stderr, "Loading user %s failed\n", argv[0]);
		return -1;
	}

	if (!fn(sam_acct, argv[1], PDB_CHANGED)) {
		d_fprintf(stderr, "Internal error\n");
		return -1;
	}

	status = pdb_update_sam_account(sam_acct);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "Updating sam account %s failed with %s\n",
			  argv[0], nt_errstr(status));
		return -1;
	}

	pdb_free_sam(&sam_acct);

	d_printf("Updated %s for %s\\%s to %s\n", field, dom, name, argv[1]);
	return 0;
}

static int net_sam_set_fullname(int argc, const char **argv)
{
	return net_sam_userset(argc, argv, "fullname",
			       pdb_set_fullname);
}

static int net_sam_set_logonscript(int argc, const char **argv)
{
	return net_sam_userset(argc, argv, "logonscript",
			       pdb_set_logon_script);
}

static int net_sam_set_profilepath(int argc, const char **argv)
{
	return net_sam_userset(argc, argv, "profilepath",
			       pdb_set_profile_path);
}

static int net_sam_set_homedrive(int argc, const char **argv)
{
	return net_sam_userset(argc, argv, "homedrive",
			       pdb_set_dir_drive);
}

static int net_sam_set_homedir(int argc, const char **argv)
{
	return net_sam_userset(argc, argv, "homedir",
			       pdb_set_homedir);
}

static int net_sam_set_description(int argc, const char **argv)
{
	return net_sam_userset(argc, argv, "description",
			       pdb_set_acct_desc);
}

static int net_sam_set_workstations(int argc, const char **argv)
{
	return net_sam_userset(argc, argv, "workstations",
			       pdb_set_workstations);
}

/*
 * Set account flags
 */

static int net_sam_set_userflag(int argc, const char **argv, const char *field,
				uint16 flag)
{
	SAM_ACCOUNT *sam_acct = NULL;
	DOM_SID sid;
	enum SID_NAME_USE type;
	const char *dom, *name;
	NTSTATUS status;
	uint16 acct_flags;

	if ((argc != 2) || (!strequal(argv[1], "yes") &&
			    !strequal(argv[1], "no"))) {
		d_fprintf(stderr, "usage: net sam set %s <user> [yes|no]\n",
			  field);
		return -1;
	}

	if (!lookup_name(tmp_talloc_ctx(), argv[0], LOOKUP_NAME_ISOLATED,
			 &dom, &name, &sid, &type)) {
		d_fprintf(stderr, "Could not find name %s\n", argv[0]);
		return -1;
	}

	if (type != SID_NAME_USER) {
		d_fprintf(stderr, "%s is a %s, not a user\n", argv[0],
			  sid_type_lookup(type));
		return -1;
	}

	if (!NT_STATUS_IS_OK(pdb_init_sam(&sam_acct))) {
		d_fprintf(stderr, "Internal error\n");
		return -1;
	}

	if (!pdb_getsampwsid(sam_acct, &sid)) {
		d_fprintf(stderr, "Loading user %s failed\n", argv[0]);
		return -1;
	}

	acct_flags = pdb_get_acct_ctrl(sam_acct);

	if (strequal(argv[1], "yes")) {
		acct_flags |= flag;
	} else {
		acct_flags &= ~flag;
	}

	pdb_set_acct_ctrl(sam_acct, acct_flags, PDB_CHANGED);

	status = pdb_update_sam_account(sam_acct);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "Updating sam account %s failed with %s\n",
			  argv[0], nt_errstr(status));
		return -1;
	}

	pdb_free_sam(&sam_acct);

	d_fprintf(stderr, "Updated flag %s for %s\\%s to %s\n", field, dom,
		  name, argv[1]);
	return 0;
}

static int net_sam_set_disabled(int argc, const char **argv)
{
	return net_sam_set_userflag(argc, argv, "disabled", ACB_DISABLED);
}

static int net_sam_set_pwnotreq(int argc, const char **argv)
{
	return net_sam_set_userflag(argc, argv, "pwnotreq", ACB_PWNOTREQ);
}

static int net_sam_set_autolock(int argc, const char **argv)
{
	return net_sam_set_userflag(argc, argv, "autolock", ACB_AUTOLOCK);
}

static int net_sam_set_pwnoexp(int argc, const char **argv)
{
	return net_sam_set_userflag(argc, argv, "pwnoexp", ACB_PWNOEXP);
}

/*
 * Set a user's time field
 */

static int net_sam_set_time(int argc, const char **argv, const char *field,
			    BOOL (*fn)(SAM_ACCOUNT *, time_t,
				       enum pdb_value_state))
{
	SAM_ACCOUNT *sam_acct = NULL;
	DOM_SID sid;
	enum SID_NAME_USE type;
	const char *dom, *name;
	NTSTATUS status;
	time_t new_time;

	if (argc != 2) {
		d_fprintf(stderr, "usage: net sam set %s <user> "
			  "[now|YYYY-MM-DD HH:MM]\n", field);
		return -1;
	}

	if (!lookup_name(tmp_talloc_ctx(), argv[0], LOOKUP_NAME_ISOLATED,
			 &dom, &name, &sid, &type)) {
		d_fprintf(stderr, "Could not find name %s\n", argv[0]);
		return -1;
	}

	if (type != SID_NAME_USER) {
		d_fprintf(stderr, "%s is a %s, not a user\n", argv[0],
			  sid_type_lookup(type));
		return -1;
	}

	if (strequal(argv[1], "now")) {
		new_time = time(NULL);
	} else {
		struct tm tm;
		char *end;
		ZERO_STRUCT(tm);
		end = strptime(argv[1], "%Y-%m-%d %H:%M", &tm);
		new_time = mktime(&tm);
		if ((end == NULL) || (*end != '\0') || (new_time == -1)) {
			d_fprintf(stderr, "Could not parse time string %s\n",
				  argv[1]);
			return -1;
		}
	}


	if (!NT_STATUS_IS_OK(pdb_init_sam(&sam_acct))) {
		d_fprintf(stderr, "Internal error\n");
		return -1;
	}

	if (!pdb_getsampwsid(sam_acct, &sid)) {
		d_fprintf(stderr, "Loading user %s failed\n", argv[0]);
		return -1;
	}

	if (!fn(sam_acct, new_time, PDB_CHANGED)) {
		d_fprintf(stderr, "Internal error\n");
		return -1;
	}

	status = pdb_update_sam_account(sam_acct);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "Updating sam account %s failed with %s\n",
			  argv[0], nt_errstr(status));
		return -1;
	}

	pdb_free_sam(&sam_acct);

	d_printf("Updated %s for %s\\%s to %s\n", field, dom, name, argv[1]);
	return 0;
}

static int net_sam_set_pwdmustchange(int argc, const char **argv)
{
	return net_sam_set_time(argc, argv, "pwdmustchange",
				pdb_set_pass_must_change_time);
}

static int net_sam_set_pwdcanchange(int argc, const char **argv)
{
	return net_sam_set_time(argc, argv, "pwdcanchange",
				pdb_set_pass_can_change_time);
}

/*
 * Set a group's comment
 */

static int net_sam_set_groupcomment(int argc, const char **argv)
{
	GROUP_MAP map;
	DOM_SID sid;
	enum SID_NAME_USE type;
	const char *dom, *name;
	NTSTATUS status;

	if (argc != 2) {
		d_fprintf(stderr, "usage: net sam set groupcomment <group> "
			  "<comment>\n");
		return -1;
	}

	if (!lookup_name(tmp_talloc_ctx(), argv[0], LOOKUP_NAME_ISOLATED,
			 &dom, &name, &sid, &type)) {
		d_fprintf(stderr, "Could not find name %s\n", argv[0]);
		return -1;
	}

	if ((type != SID_NAME_DOM_GRP) && (type != SID_NAME_ALIAS) &&
	    (type != SID_NAME_WKN_GRP)) {
		d_fprintf(stderr, "%s is a %s, not a group\n", argv[0],
			  sid_type_lookup(type));
		return -1;
	}

	if (!pdb_getgrsid(&map, sid)) {
		d_fprintf(stderr, "Could not load group %s\n", argv[0]);
		return -1;
	}

	fstrcpy(map.comment, argv[1]);

	status = pdb_update_group_mapping_entry(&map);

	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "Updating group mapping entry failed with "
			  "%s\n", nt_errstr(status));
		return -1;
	}

	d_printf("Updated comment of %s\\%s to %s\n", dom, name, argv[1]);

	return 0;
}

static int net_help_sam_set(int argc, const char **argv)
{
	d_printf("net sam set homedir\n"
		 "  Change a user's homedir\n");
	d_printf("net sam set fullname\n"
		 "  Change a user's fullname\n");
	d_printf("net sam set profilepath\n"
		 "  Change a user's profile path\n");
	d_printf("net sam set description\n"
		 "  Change a user's description\n");
	d_printf("net sam set logonscript\n"
		 "  Change a user's logon script\n");
	d_printf("net sam set homedrive\n"
		 "  Change a user's homedrive\n");
	d_printf("net sam set workstations\n"
		 "  Change a user's allowed workstations\n");
	d_printf("net sam set disabled\n"
		 "  Disable/Enable a user\n");
	d_printf("net sam set pwnotreq\n"
		 "  Disable/Enable the password not required flag\n");
	d_printf("net sam set autolock\n"
		 "  Disable/Enable a user's autolock flag\n");
	d_printf("net sam set pwnoexp\n"
		 "  Disable/Enable whether a user's pw does not expire\n");
	d_printf("net sam set pwdmustchange\n"
		 "  Set a users password must change time\n");
	d_printf("net sam set pwdcanchange\n"
		 "  Set a users password can change time\n");
	d_printf("net sam set groupcomment\n"
		 "  Change a group's comment\n");

	return -1;
}

static int net_sam_set(int argc, const char **argv)
{
	struct functable func[] = {
		{"homedir", net_sam_set_homedir},
		{"profilepath", net_sam_set_profilepath},
		{"groupcomment", net_sam_set_groupcomment},
		{"description", net_sam_set_description},
		{"fullname", net_sam_set_fullname},
		{"logonscript", net_sam_set_logonscript},
		{"homedrive", net_sam_set_homedrive},
		{"workstations", net_sam_set_workstations},
		{"disabled", net_sam_set_disabled},
		{"pwnotreq", net_sam_set_pwnotreq},
		{"autolock", net_sam_set_autolock},
		{"pwnoexp", net_sam_set_pwnoexp},
		{"pwdmustchange", net_sam_set_pwdmustchange},
		{"pwdcanchange", net_sam_set_pwdcanchange},
		{NULL, NULL}
	};

	if (argc != 0) {
		return net_run_function(argc, argv, func, net_help_sam_set);
	}

	return net_help_sam_set(argc, argv);
}

/*
 * Map a unix group to a domain group
 */

static int net_sam_mapunixgroup(int argc, const char **argv)
{
	NTSTATUS status;
	GROUP_MAP map;
	struct group *grp;
	const char *grpname, *dom, *name;
	uint32 rid;

	if (argc != 1) {
		d_fprintf(stderr, "usage: net sam mapunixgroup <name>\n");
		return -1;
	}

	grp = getgrnam(argv[0]);
	if (grp == NULL) {
		d_fprintf(stderr, "Could not find group %s\n", argv[0]);
		return -1;
	}

	if (pdb_getgrgid(&map, grp->gr_gid)) {
		d_fprintf(stderr, "%s already mapped to %s (%s)\n",
			  argv[0], map.nt_name,
			  sid_string_static(&map.sid));
		return -1;
	}

	map.gid = grp->gr_gid;

	grpname = argv[0];

	if (lookup_name(tmp_talloc_ctx(), grpname, LOOKUP_NAME_ISOLATED,
			&dom, &name, NULL, NULL)) {

		const char *tmp = talloc_asprintf(
			tmp_talloc_ctx(), "Unix Group %s", argv[0]);

		d_fprintf(stderr, "%s exists as %s\\%s, retrying as \"%s\"\n",
			  grpname, dom, name, tmp);
		grpname = tmp;
	}

	if (lookup_name(tmp_talloc_ctx(), grpname, LOOKUP_NAME_ISOLATED,
			NULL, NULL, NULL, NULL)) {
		d_fprintf(stderr, "\"%s\" exists, can't map it\n", argv[0]);
		return -1;
	}

	fstrcpy(map.nt_name, grpname);

	if (!pdb_new_rid(&rid)) {
		d_fprintf(stderr, "Could not get a new rid\n");
		return -1;
	}

	sid_compose(&map.sid, get_global_sam_sid(), rid);
	map.sid_name_use = SID_NAME_DOM_GRP;
	fstrcpy(map.comment, talloc_asprintf(tmp_talloc_ctx(), "Unix Group %s",
					     argv[0]));

	status = pdb_add_group_mapping_entry(&map);

	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "Mapping group %s failed with %s\n",
			  argv[0], nt_errstr(status));
		return -1;
	}

	d_printf("Mapped unix group %s to SID %s\n", argv[0],
		 sid_string_static(&map.sid));

	return 0;
}

/*
 * Create a local group
 */

static int net_sam_createlocalgroup(int argc, const char **argv)
{
	NTSTATUS status;
	uint32 rid;

	if (argc != 1) {
		d_fprintf(stderr, "usage: net sam createlocalgroup <name>\n");
		return -1;
	}

	if (!winbind_ping()) {
		d_fprintf(stderr, "winbind seems not to run. createlocalgroup "
			  "only works when winbind runs.\n");
		return -1;
	}

	status = pdb_create_alias(argv[0], &rid);

	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "Creating %s failed with %s\n",
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
		d_fprintf(stderr, "usage: net sam addmem <group> <member>\n");
		return -1;
	}

	if (!lookup_name(tmp_talloc_ctx(), argv[0], LOOKUP_NAME_ISOLATED,
			 &groupdomain, &groupname, &group, &grouptype)) {
		d_fprintf(stderr, "Could not find group %s\n", argv[0]);
		return -1;
	}

	if (!lookup_name(tmp_talloc_ctx(), argv[1], LOOKUP_NAME_ISOLATED,
			 &memberdomain, &membername, &member, &membertype)) {
		d_fprintf(stderr, "Could not find member %s\n", argv[1]);
		return -1;
	}

	if ((grouptype == SID_NAME_ALIAS) || (grouptype == SID_NAME_WKN_GRP)) {
		if ((membertype != SID_NAME_USER) &&
		    (membertype != SID_NAME_DOM_GRP)) {
			d_fprintf(stderr, "%s is a local group, only users "
				  "and domain groups can be added.\n"
				  "%s is a %s\n", argv[0], argv[1],
				  sid_type_lookup(membertype));
			return -1;
		}
		status = pdb_add_aliasmem(&group, &member);

		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr, "Adding local group member failed "
				  "with %s\n", nt_errstr(status));
			return -1;
		}
	} else {
		d_fprintf(stderr, "Can only add members to local groups so "
			  "far, %s is a %s\n", argv[0],
			  sid_type_lookup(grouptype));
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
		d_fprintf(stderr, "usage: net sam delmem <group> <member>\n");
		return -1;
	}

	if (!lookup_name(tmp_talloc_ctx(), argv[0], LOOKUP_NAME_ISOLATED,
			 &groupdomain, &groupname, &group, &grouptype)) {
		d_fprintf(stderr, "Could not find group %s\n", argv[0]);
		return -1;
	}

	if (!lookup_name(tmp_talloc_ctx(), argv[1], LOOKUP_NAME_ISOLATED,
			 &memberdomain, &membername, &member, NULL)) {
		if (!string_to_sid(&member, argv[1])) {
			d_fprintf(stderr, "Could not find member %s\n",
				  argv[1]);
			return -1;
		}
	}

	if ((grouptype == SID_NAME_ALIAS) ||
	    (grouptype == SID_NAME_WKN_GRP)) {
		status = pdb_del_aliasmem(&group, &member);

		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr, "Deleting local group member failed "
				  "with %s\n", nt_errstr(status));
			return -1;
		}
	} else {
		d_fprintf(stderr, "Can only delete members from local groups "
			  "so far, %s is a %s\n", argv[0],
			  sid_type_lookup(grouptype));
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
		d_fprintf(stderr, "usage: net sam listmem <group>\n");
		return -1;
	}

	if (!lookup_name(tmp_talloc_ctx(), argv[0], LOOKUP_NAME_ISOLATED,
			 &groupdomain, &groupname, &group, &grouptype)) {
		d_fprintf(stderr, "Could not find group %s\n", argv[0]);
		return -1;
	}

	if ((grouptype == SID_NAME_ALIAS) ||
	    (grouptype == SID_NAME_WKN_GRP)) {
		DOM_SID *members = NULL;
		size_t i, num_members = 0;
		
		status = pdb_enum_aliasmem(&group, &members, &num_members);

		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr, "Listing group members failed with "
				  "%s\n", nt_errstr(status));
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
		d_fprintf(stderr, "Can only list local group members so far.\n"
			  "%s is a %s\n", argv[0], sid_type_lookup(grouptype));
		return -1;
	}

	return 0;
}

int net_help_sam(int argc, const char **argv)
{
	d_printf("net sam mapunixgroup\n"
		 "  Map a unix group to a domain group\n");
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
		{"mapunixgroup", net_sam_mapunixgroup},
		{"addmem", net_sam_addmem},
		{"delmem", net_sam_delmem},
		{"listmem", net_sam_listmem},
		{"set", net_sam_set},
		{"help", net_help_sam},
		{NULL, NULL}
	};

	/* we shouldn't have silly checks like this */
	if (getuid() != 0) {
		d_fprintf(stderr, "You must be root to edit the SAM "
			  "directly.\n");
		return -1;
	}
	
	if ( argc )
		return net_run_function(argc, argv, func, net_help_sam);

	return net_help_sam( argc, argv );
}

