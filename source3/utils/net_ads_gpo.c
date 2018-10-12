/*
   Samba Unix/Linux SMB client library
   net ads commands for Group Policy
   Copyright (C) 2005-2008 Guenther Deschner (gd@samba.org)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "utils/net.h"
#include "ads.h"
#include "../libgpo/gpo.h"
#include "libgpo/gpo_proto.h"
#include "../libds/common/flags.h"

#ifdef HAVE_ADS

static int net_ads_gpo_list_all(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	int num_reply = 0;
	LDAPMessage *msg = NULL;
	struct GROUP_POLICY_OBJECT gpo;
	TALLOC_CTX *mem_ctx;
	char *dn;
	const char *attrs[] = {
		"versionNumber",
		"flags",
		"gPCFileSysPath",
		"displayName",
		"name",
		"gPCMachineExtensionNames",
		"gPCUserExtensionNames",
		"ntSecurityDescriptor",
		NULL
	};

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net ads gpo listall\n"
			   "    %s\n",
			 _("Usage:"),
			 _("List all GPOs on the DC"));
		return 0;
	}

	mem_ctx = talloc_init("net_ads_gpo_list_all");
	if (mem_ctx == NULL) {
		return -1;
	}

	status = ads_startup(c, false, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	status = ads_do_search_all_sd_flags(ads, ads->config.bind_path,
					    LDAP_SCOPE_SUBTREE,
					    "(objectclass=groupPolicyContainer)",
					    attrs,
					    SECINFO_DACL,
					    &res);

	if (!ADS_ERR_OK(status)) {
		d_printf(_("search failed: %s\n"), ads_errstr(status));
		goto out;
	}

	num_reply = ads_count_replies(ads, res);

	d_printf(_("Got %d replies\n\n"), num_reply);

	/* dump the results */
	for (msg = ads_first_entry(ads, res);
	     msg;
	     msg = ads_next_entry(ads, msg)) {

		if ((dn = ads_get_dn(ads, mem_ctx, msg)) == NULL) {
			goto out;
		}

		status = ads_parse_gpo(ads, mem_ctx, msg, dn, &gpo);

		if (!ADS_ERR_OK(status)) {
			d_printf(_("ads_parse_gpo failed: %s\n"),
				ads_errstr(status));
			goto out;
		}

		dump_gpo(&gpo, 0);
	}

out:
	ads_msgfree(ads, res);

	TALLOC_FREE(mem_ctx);
	ads_destroy(&ads);

	return 0;
}

static int net_ads_gpo_list(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads = NULL;
	ADS_STATUS status;
	LDAPMessage *res = NULL;
	TALLOC_CTX *mem_ctx;
	const char *dn = NULL;
	uint32_t uac = 0;
	uint32_t flags = 0;
	struct GROUP_POLICY_OBJECT *gpo_list;
	struct security_token *token = NULL;

	if (argc < 1 || c->display_usage) {
		d_printf("%s\n%s\n%s",
			 _("Usage:"),
			 _("net ads gpo list <username|machinename>"),
			 _("  Lists all GPOs for machine/user\n"
			   "    username\tUser to list GPOs for\n"
			   "    machinename\tMachine to list GPOs for\n"));
		return -1;
	}

	mem_ctx = talloc_init("net_ads_gpo_list");
	if (mem_ctx == NULL) {
		goto out;
	}

	status = ads_startup(c, false, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	status = ads_find_samaccount(ads, mem_ctx, argv[0], &uac, &dn);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	if (uac & UF_WORKSTATION_TRUST_ACCOUNT) {
		flags |= GPO_LIST_FLAG_MACHINE;
	}

	d_printf(_("%s: '%s' has dn: '%s'\n"),
		(uac & UF_WORKSTATION_TRUST_ACCOUNT) ? _("machine") : _("user"),
		argv[0], dn);

	if (uac & UF_WORKSTATION_TRUST_ACCOUNT) {
		status = gp_get_machine_token(ads, mem_ctx, dn, &token);
	} else {
		status = ads_get_sid_token(ads, mem_ctx, dn, &token);
	}

	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	status = ads_get_gpo_list(ads, mem_ctx, dn, flags, token, &gpo_list);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	dump_gpo_list(gpo_list, 0);

out:
	ads_msgfree(ads, res);

	talloc_destroy(mem_ctx);
	ads_destroy(&ads);

	return 0;
}

static int net_ads_gpo_link_get(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
	TALLOC_CTX *mem_ctx;
	struct GP_LINK gp_link;

	if (argc < 1 || c->display_usage) {
		d_printf("%s\n%s\n%s",
			 _("Usage:"),
			 _("net ads gpo linkget <container>"),
			 _("  Lists gPLink of a container\n"
			   "    container\tContainer to get link for\n"));
		return -1;
	}

	mem_ctx = talloc_init("add_gpo_link");
	if (mem_ctx == NULL) {
		return -1;
	}

	status = ads_startup(c, false, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	status = ads_get_gpo_link(ads, mem_ctx, argv[0], &gp_link);
	if (!ADS_ERR_OK(status)) {
		d_printf(_("get link for %s failed: %s\n"), argv[0],
			ads_errstr(status));
		goto out;
	}

	dump_gplink(&gp_link);

out:
	talloc_destroy(mem_ctx);
	ads_destroy(&ads);

	return 0;
}

static int net_ads_gpo_link_add(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
	uint32_t gpo_opt = 0;
	TALLOC_CTX *mem_ctx;

	if (argc < 2 || c->display_usage) {
		d_printf("%s\n%s\n%s",
			 _("Usage:"),
			 _("net ads gpo linkadd <linkdn> <gpodn> [options]"),
			 _("  Link a container to a GPO\n"
			   "    linkdn\tContainer to link to a GPO\n"
			   "    gpodn\tGPO to link container to\n"));
		d_printf(_("note: DNs must be provided properly escaped.\n"
			   "See RFC 4514 for details\n"));
		return -1;
	}

	mem_ctx = talloc_init("add_gpo_link");
	if (mem_ctx == NULL) {
		return -1;
	}

	if (argc == 3) {
		gpo_opt = atoi(argv[2]);
	}

	status = ads_startup(c, false, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	status = ads_add_gpo_link(ads, mem_ctx, argv[0], argv[1], gpo_opt);
	if (!ADS_ERR_OK(status)) {
		d_printf(_("link add failed: %s\n"), ads_errstr(status));
		goto out;
	}

out:
	talloc_destroy(mem_ctx);
	ads_destroy(&ads);

	return 0;
}

#if 0 /* broken */

static int net_ads_gpo_link_delete(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
	TALLOC_CTX *mem_ctx;

	if (argc < 2 || c->display_usage) {
		d_printf("Usage:\n"
			 "net ads gpo linkdelete <linkdn> <gpodn>\n"
			 "  Delete a GPO link\n"
			 "    <linkdn>\tContainer to delete GPO from\n"
			 "    <gpodn>\tGPO to delete from container\n");
		return -1;
	}

	mem_ctx = talloc_init("delete_gpo_link");
	if (mem_ctx == NULL) {
		return -1;
	}

	status = ads_startup(c, false, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	status = ads_delete_gpo_link(ads, mem_ctx, argv[0], argv[1]);
	if (!ADS_ERR_OK(status)) {
		d_printf("delete link failed: %s\n", ads_errstr(status));
		goto out;
	}

out:
	talloc_destroy(mem_ctx);
	ads_destroy(&ads);

	return 0;
}

#endif

/*
Arguments:
- struct net_context *: Pointer to net_context*
- argc: Number of command line arguments passed to 'net ads gpo getgpo' command
- **argv: Command line argument string passed to 'net ads gpo getgpo' command

This function performs following operations:
1. Create  talloc context using talloc_init
2. Preform ads_startup()
3. Call ads_get_gpo() to retrieve gpo details inside 'struct GROUP_POLICY_OBJECT'
4. Call dumps_gpo() to dump GPO on stdout
*/
static int net_ads_gpo_get_gpo(struct net_context *c, int argc, const char **argv)
{
	ADS_STRUCT *ads;
	ADS_STATUS status;
	TALLOC_CTX *mem_ctx;
	struct GROUP_POLICY_OBJECT gpo;

	if (argc < 1 || c->display_usage) {
		d_printf("%s\n%s\n%s",
			 _("Usage:"),
			 _("net ads gpo getgpo <gpo>"),
			 _("  List specified GPO\n"
			   "    gpo\t\tGPO to list\n"));
		return -1;
	}

	mem_ctx = talloc_init("ads_gpo_get_gpo");
	if (mem_ctx == NULL) {
		return -1;
	}

	status = ads_startup(c, false, &ads);
	if (!ADS_ERR_OK(status)) {
		goto out;
	}

	if (strnequal(argv[0], "CN={", strlen("CN={"))) {
		status = ads_get_gpo(ads, mem_ctx, argv[0], NULL, NULL, &gpo);
	} else {
		status = ads_get_gpo(ads, mem_ctx, NULL, argv[0], NULL, &gpo);
	}

	if (!ADS_ERR_OK(status)) {
		d_printf(_("get gpo for [%s] failed: %s\n"), argv[0],
			ads_errstr(status));
		goto out;
	}

	dump_gpo(&gpo, 0);

out:
	talloc_destroy(mem_ctx);
	ads_destroy(&ads);

	return 0;
}

int net_ads_gpo(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"getgpo",
			net_ads_gpo_get_gpo,
			NET_TRANSPORT_ADS,
			N_("List specified GPO"),
			N_("net ads gpo getgpo\n"
			   "    List specified GPO")
		},
		{
			"linkadd",
			net_ads_gpo_link_add,
			NET_TRANSPORT_ADS,
			N_("Link a container to a GPO"),
			N_("net ads gpo linkadd\n"
			   "    Link a container to a GPO")
		},
#if 0
		{
			"linkdelete",
			net_ads_gpo_link_delete,
			NET_TRANSPORT_ADS,
			"Delete GPO link from a container",
			"net ads gpo linkdelete\n"
			"    Delete GPO link from a container"
		},
#endif
		{
			"linkget",
			net_ads_gpo_link_get,
			NET_TRANSPORT_ADS,
			N_("Lists gPLink of container"),
			N_("net ads gpo linkget\n"
			   "    Lists gPLink of container")
		},
		{
			"list",
			net_ads_gpo_list,
			NET_TRANSPORT_ADS,
			N_("Lists all GPOs for machine/user"),
			N_("net ads gpo list\n"
			   "    Lists all GPOs for machine/user")
		},
		{
			"listall",
			net_ads_gpo_list_all,
			NET_TRANSPORT_ADS,
			N_("Lists all GPOs on a DC"),
			N_("net ads gpo listall\n"
			   "    Lists all GPOs on a DC")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net ads gpo", func);
}

#endif /* HAVE_ADS */
