/* 
   Unix SMB/CIFS implementation.
   SAM module functions

   Copyright (C) Jelmer Vernooij 2002

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "samtest.h"

#if 0
static struct cmd_popt_user_opts [] = {
	{ NULL, 0, POPT_ARG_CALLBACK, cmd_parse_user_opts },
	{"username", 'u', POPT_ARG_STRING, NULL, 1, "Username to use"},
};

static void cmd_parse_user_opts(poptContext con,
							enum poptCallbackReason reason,
							const struct poptOption *opt,
							const char *arg, const void *data)
{
	SAM_ACCOUNT_HANDLE *account = (SAM_ACCOUNT_HANDLE *)data;
	switch(opt->val) {
		case 'u':
			sam_set_account_username(account, arg);
			break;
	}
}
#endif

static NTSTATUS cmd_load_module(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	char *plugin_arg[2];
	NTSTATUS status;
	if (argc != 2) {
		printf("Usage: load <module path>\n");
		return NT_STATUS_OK;
	}

	asprintf(&plugin_arg[0], "plugin:%s", argv[1]);
	plugin_arg[1] = NULL;
	
	if(!NT_STATUS_IS_OK(status = make_sam_context_list(&c, plugin_arg)))
	{
		return status;
	}
	printf("load: ok\n");
	return NT_STATUS_OK;
}

static NTSTATUS cmd_get_sec_desc(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_set_sec_desc(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_lookup_sid(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_lookup_name(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_lookup_account(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_lookup_group(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_update_domain(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_show_domain(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_create_account(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_update_account(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_delete_account(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_enum_accounts(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_lookup_account_sid(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_lookup_account_name(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_create_group(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_update_group(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_delete_group(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_enum_groups(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_lookup_group_sid(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_lookup_group_name(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_group_add_member(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_group_del_member(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS cmd_group_enum(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS cmd_get_sid_groups(struct sam_context *c, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

struct cmd_set sam_general_commands[] = {

	{ "General SAM Commands" },

	{ "load", cmd_load_module, "Load a module", "load <module.so>" },
	{ "get_sec_desc", cmd_get_sec_desc, "Get security descriptor info", "get_sec_desc <access-token> <sid>" },
	{ "set_sec_desc", cmd_set_sec_desc, "Set security descriptor info", "set_sec_desc <access-token> <sid>" },
	{ "lookup_sid", cmd_lookup_sid, "Lookup type of specified SID", "lookup_sid <sid>" },
	{ "lookup_name", cmd_lookup_name, "Lookup type of specified name", "lookup_name <sid>" },
	{ NULL }
};

struct cmd_set sam_domain_commands[] = {
	{ "Domain Commands" },
	{ "update_domain", cmd_update_domain, "Update domain information", "update_domain [domain-options] domain-name | domain-sid" },
	{ "show_domain", cmd_show_domain, "Show domain information", "show_domain domain-sid | domain-name" },
	{ NULL }
};

struct cmd_set sam_account_commands[] = {
	{ "Account Commands" },
	{ "create_account", cmd_create_account, "Create a new account with specified properties", "create_account [account-options]" },
	{ "update_account", cmd_update_account, "Update an existing account", "update_account [account-options] account-sid | account-name" },
	{ "delete_account", cmd_delete_account, "Delete an account", "delete_account account-sid | account-name" },
	{ "enum_accounts", cmd_enum_accounts, "Enumerate all accounts", "enum_accounts <token> <acct-ctrl>" },
	{ "lookup_account", cmd_lookup_account, "Lookup an account by either sid or name", "lookup_account account-sid | account-name" },
	{ "lookup_account_sid", cmd_lookup_account_sid, "Lookup an account by sid", "lookup_account_sid account-sid" },
	{ "lookup_account_name", cmd_lookup_account_name, "Lookup an account by name", "lookup_account_name account-name" },
	{ NULL }
};

struct cmd_set sam_group_commands[] = {
	{ "Group Commands" },
	{ "create_group", cmd_create_group, "Create a new group", "create_group [group-opts]" },
	{ "update_group", cmd_update_group, "Update an existing group", "update_group [group-opts] group-name | group-sid" },
	{ "delete_group", cmd_delete_group, "Delete an existing group", "delete_group group-name | group-sid" },
	{ "enum_groups", cmd_enum_groups, "Enumerate all groups", "enum_groups <token> <group-ctrl>" },
	{ "lookup_group", cmd_lookup_group, "Lookup a group by SID or name", "lookup_group group-sid | group-name" },
	{ "lookup_group_sid", cmd_lookup_group_sid, "Lookup a group by SID", "lookup_group_sid <sid>" },
	{ "lookup_group_name", cmd_lookup_group_name, "Lookup a group by name", "lookup_group_name <name>" },
	{ "group_add_member", cmd_group_add_member, "Add group member to group", "group_add_member <group-name | group-sid> <member-name | member-sid>" },
	{ "group_del_member", cmd_group_del_member, "Delete group member from group", "group_del_member <group-name | group-sid> <member-name | member-sid>" },
	{ "group_enum", cmd_group_enum, "Enumerate all members of specified group", "group_enum group-sid | group-name" },

	{ "get_sid_groups", cmd_get_sid_groups, "Get a list of groups specified sid is a member of", "group_enum <group-sid | group-name>" },
	{ NULL }
};
