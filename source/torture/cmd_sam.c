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

static void print_account(SAM_ACCOUNT_HANDLE *a)
{
	/* FIXME */
}

static NTSTATUS cmd_context(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	NTSTATUS status;
	char **plugins;
	int i;

	plugins = malloc(argc * sizeof(char *));

	for(i = 1; i < argc; i++)
		plugins[i-1] = argv[i];

	plugins[argc-1] = NULL;

	if(!NT_STATUS_IS_OK(status = make_sam_context_list(&st->context, plugins))) {
		printf("make_sam_context_list failed: %s\n", nt_errstr(status));
		SAFE_FREE(plugins);
		return status;
	}

	SAFE_FREE(plugins);
	
	return NT_STATUS_OK;
}

static NTSTATUS cmd_load_module(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	char *plugin_arg[2];
	NTSTATUS status;
	if (argc != 2 && argc != 3) {
		printf("Usage: load <module path> [domain-name]\n");
		return NT_STATUS_OK;
	}

	if (argc == 3)
		asprintf(&plugin_arg[0], "plugin:%s|%s", argv[1], argv[2]);
	else
		asprintf(&plugin_arg[0], "plugin:%s", argv[1]);

	plugin_arg[1] = NULL;
	
	if(!NT_STATUS_IS_OK(status = make_sam_context_list(&st->context, plugin_arg))) {
		free(plugin_arg[0]);
		return status;
	}
	
	free(plugin_arg[0]);

	printf("load: ok\n");
	return NT_STATUS_OK;
}

static NTSTATUS cmd_get_sec_desc(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_set_sec_desc(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_lookup_sid(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	char *name;
	uint32 type;
	NTSTATUS status;
	DOM_SID sid;
	if (argc != 2) {
		printf("Usage: lookup_sid <sid>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!string_to_sid(&sid, argv[1])){
		printf("Unparseable SID specified!\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!NT_STATUS_IS_OK(status = sam_lookup_sid(st->context, st->token, mem_ctx, &sid, &name, &type))) {
		printf("sam_lookup_sid failed!\n");
		return status;
	}

	printf("Name: %s\n", name);
	printf("Type: %d\n", type); /* FIXME: What kind of an integer is type ? */

	return NT_STATUS_OK;
}

static NTSTATUS cmd_lookup_name(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	DOM_SID sid;
	uint32 type;
	NTSTATUS status;
	if (argc != 3) {
		printf("Usage: lookup_name <domain> <name>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!NT_STATUS_IS_OK(status = sam_lookup_name(st->context, st->token, argv[1], argv[2], &sid, &type))) {
		printf("sam_lookup_name failed!\n");
		return status;
	}

	printf("SID: %s\n", sid_string_static(&sid));
	printf("Type: %d\n", type);
	
	return NT_STATUS_OK;
}

static NTSTATUS cmd_lookup_account(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_lookup_group(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_lookup_domain(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	DOM_SID *sid;
	NTSTATUS status;
	if (argc != 2) {
		printf("Usage: lookup_domain <domain>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!NT_STATUS_IS_OK(status = sam_lookup_domain(st->context, st->token, argv[1], &sid))) {
		printf("sam_lookup_name failed!\n");
		return status;
	}

	printf("SID: %s\n", sid_string_static(sid));
	
	return NT_STATUS_OK;
}

static NTSTATUS cmd_enum_domains(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	int32 domain_count, i;
	DOM_SID *domain_sids;
	char **domain_names;
	NTSTATUS status;

	if (!NT_STATUS_IS_OK(status = sam_enum_domains(st->context, st->token, &domain_count, &domain_sids, &domain_names))) {
		printf("sam_enum_domains failed!\n");
		return status;
	}

	if (domain_count == 0) {
		printf("No domains found!\n");
		return NT_STATUS_OK;
	}

	for (i = 0; i < domain_count; i++) {
		printf("%s %s\n", domain_names[i], sid_string_static(&domain_sids[i]));
	}

	SAFE_FREE(domain_sids);
	SAFE_FREE(domain_names);
	
	return NT_STATUS_OK;
}

static NTSTATUS cmd_update_domain(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_show_domain(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	NTSTATUS status;
	DOM_SID sid;
	SAM_DOMAIN_HANDLE *domain;
	uint32 tmp_uint32;
	uint16 tmp_uint16;
	NTTIME tmp_nttime;
	BOOL tmp_bool;
	const char *tmp_string;

	if (argc != 2) {
		printf("Usage: show_domain <sid>\n");
		return status;
	}

	if (!string_to_sid(&sid, argv[1])){
		printf("Unparseable SID specified!\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!NT_STATUS_IS_OK(status = sam_get_domain_by_sid(st->context, st->token, GENERIC_RIGHTS_DOMAIN_ALL_ACCESS, &sid, &domain))) {
		printf("sam_get_domain_by_sid failed\n");
		return status;
	}

	if (!NT_STATUS_IS_OK(status = sam_get_domain_num_accounts(domain, &tmp_uint32))) {
		printf("sam_get_domain_num_accounts failed: %s\n", nt_errstr(status));
	} else {
		printf("Number of accounts: %d\n", tmp_uint32);
	}

	if (!NT_STATUS_IS_OK(status = sam_get_domain_num_groups(domain, &tmp_uint32))) {
		printf("sam_get_domain_num_groups failed: %s\n", nt_errstr(status));
	} else {
		printf("Number of groups: %u\n", tmp_uint32);
	}
	
	if (!NT_STATUS_IS_OK(status = sam_get_domain_num_aliases(domain, &tmp_uint32))) {
		printf("sam_get_domain_num_aliases failed: %s\n", nt_errstr(status));
	} else {
		printf("Number of aliases: %u\n", tmp_uint32);
	}
	
	if (!NT_STATUS_IS_OK(status = sam_get_domain_name(domain, &tmp_string))) {
		printf("sam_get_domain_name failed: %s\n", nt_errstr(status));
	} else {
		printf("Domain Name: %s\n", tmp_string);
	}
	
	if (!NT_STATUS_IS_OK(status = sam_get_domain_lockout_count(domain, &tmp_uint16))) {
		printf("sam_get_domain_lockout_count failed: %s\n", nt_errstr(status));
	} else {
		printf("Lockout Count: %u\n", tmp_uint16);
	}

	if (!NT_STATUS_IS_OK(status = sam_get_domain_force_logoff(domain, &tmp_bool))) {
		printf("sam_get_domain_force_logoff failed: %s\n", nt_errstr(status));
	} else {
		printf("Force Logoff: %s\n", (tmp_bool?"Yes":"No"));
	}
	
	if (!NT_STATUS_IS_OK(status = sam_get_domain_lockout_duration(domain, &tmp_nttime))) {
		printf("sam_get_domain_lockout_duration failed: %s\n", nt_errstr(status));
	} else {
		printf("Lockout duration: %u\n", tmp_nttime.low);
	}

	if (!NT_STATUS_IS_OK(status = sam_get_domain_login_pwdchange(domain, &tmp_bool))) {
		printf("sam_get_domain_login_pwdchange failed: %s\n", nt_errstr(status));
	} else {
		printf("Password changing allowed: %s\n", (tmp_bool?"Yes":"No"));
	}
	
	if (!NT_STATUS_IS_OK(status = sam_get_domain_max_pwdage(domain, &tmp_nttime))) {
		printf("sam_get_domain_max_pwdage failed: %s\n", nt_errstr(status));
	} else {
		printf("Maximum password age: %u\n", tmp_nttime.low);
	}
	
	if (!NT_STATUS_IS_OK(status = sam_get_domain_min_pwdage(domain, &tmp_nttime))) {
		printf("sam_get_domain_min_pwdage failed: %s\n", nt_errstr(status));
	} else {
		printf("Minimal password age: %u\n", tmp_nttime.low);
	}
	
	if (!NT_STATUS_IS_OK(status = sam_get_domain_min_pwdlength(domain, &tmp_uint16))) {
		printf("sam_get_domain_min_pwdlength: %s\n", nt_errstr(status));
	} else {
		printf("Minimal Password Length: %u\n", tmp_uint16);
	}

	if (!NT_STATUS_IS_OK(status = sam_get_domain_pwd_history(domain, &tmp_uint16))) {
		printf("sam_get_domain_pwd_history failed: %s\n", nt_errstr(status));
	} else {
		printf("Password history: %u\n", tmp_uint16);
	}

	if (!NT_STATUS_IS_OK(status = sam_get_domain_reset_count(domain, &tmp_nttime))) {
		printf("sam_get_domain_reset_count failed: %s\n", nt_errstr(status));
	} else {
		printf("Reset count: %u\n", tmp_nttime.low);
	}

	if (!NT_STATUS_IS_OK(status = sam_get_domain_server(domain, &tmp_string))) {
		printf("sam_get_domain_server failed: %s\n", nt_errstr(status));
	} else {
		printf("Server: %s\n", tmp_string);
	}
	
	return NT_STATUS_OK;
}

static NTSTATUS cmd_create_account(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_update_account(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_delete_account(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_enum_accounts(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	NTSTATUS status;
	DOM_SID sid;
	int32 account_count, i;
	SAM_ACCOUNT_ENUM *accounts;

	if (argc != 2) {
		printf("Usage: enum_accounts <domain-sid>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!string_to_sid(&sid, argv[1])){
		printf("Unparseable SID specified!\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!NT_STATUS_IS_OK(status = sam_enum_accounts(st->context, st->token, &sid, 0, &account_count, &accounts))) {
		printf("sam_enum_accounts failed: %s\n", nt_errstr(status));
		return status;
	}

	if (account_count == 0) {
		printf("No accounts found!\n");
		return NT_STATUS_OK;
	}

	for (i = 0; i < account_count; i++)
		printf("SID: %s\nName: %s\nFullname: %s\nDescription: %s\nACB_BITS: %08X\n\n", 
			   sid_string_static(&accounts[i].sid), accounts[i].account_name,
			   accounts[i].full_name, accounts[i].account_desc, 
			   accounts[i].acct_ctrl);

	SAFE_FREE(accounts);
	
	return NT_STATUS_OK;
}

static NTSTATUS cmd_lookup_account_sid(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	NTSTATUS status;
	DOM_SID sid;
	SAM_ACCOUNT_HANDLE *account;

	if (argc != 2) {
		printf("Usage: lookup_account_sid <account-sid>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!string_to_sid(&sid, argv[1])){
		printf("Unparseable SID specified!\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!NT_STATUS_IS_OK(status = sam_get_account_by_sid(st->context, st->token, GENERIC_RIGHTS_USER_ALL_ACCESS, &sid, &account))) {
		printf("context_sam_get_account_by_sid failed: %s\n", nt_errstr(status));
		return status;
	}

	print_account(account);
	
	return NT_STATUS_OK;
}

static NTSTATUS cmd_lookup_account_name(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	NTSTATUS status;
	SAM_ACCOUNT_HANDLE *account;

	if (argc != 3) {
		printf("Usage: lookup_account_name <domain-name> <account-name>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}


	if (!NT_STATUS_IS_OK(status = sam_get_account_by_name(st->context, st->token, GENERIC_RIGHTS_USER_ALL_ACCESS, argv[1], argv[2], &account))) {
		printf("context_sam_get_account_by_sid failed: %s\n", nt_errstr(status));
		return status;
	}

	print_account(account);
	
	return NT_STATUS_OK;
}

static NTSTATUS cmd_create_group(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_update_group(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_delete_group(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_enum_groups(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_lookup_group_sid(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_lookup_group_name(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_group_add_member(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS cmd_group_del_member(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS cmd_group_enum(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS cmd_get_sid_groups(struct samtest_state *st, TALLOC_CTX *mem_ctx, int argc, char **argv)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

struct cmd_set sam_general_commands[] = {

	{ "General SAM Commands" },

	{ "load", cmd_load_module, "Load a module", "load <module.so> [domain-sid]" },
	{ "context", cmd_context, "Load specified context", "context [DOMAIN|]backend1[:options] [DOMAIN|]backend2[:options]" },
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
	{ "enum_domains", cmd_enum_domains, "Enumerate all domains", "enum_domains <token> <acct-ctrl>" },
	{ "lookup_domain", cmd_lookup_domain, "Lookup a domain by name", "lookup_domain domain-name" },
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
