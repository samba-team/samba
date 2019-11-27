/*
   Samba Unix/Linux SMB client library
   Distributed SMB/CIFS Server Management Utility
   Copyright (C) 2001 Steve French  (sfrench@us.ibm.com)
   Copyright (C) 2001 Jim McDonough (jmcd@us.ibm.com)
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)
   Copyright (C) 2001 Andrew Bartlett (abartlet@samba.org)
   Copyright (C) 2008 Kai Blin (kai@samba.org)

   Originally written by Steve and Jim. Largely rewritten by tridge in
   November 2001.

   Reworked again by abartlet in December 2001

   Another overhaul, moving functionality into plug-ins loaded on demand by Kai
   in May 2008.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*****************************************************/
/*                                                   */
/*   Distributed SMB/CIFS Server Management Utility  */
/*                                                   */
/*   The intent was to make the syntax similar       */
/*   to the NET utility (first developed in DOS      */
/*   with additional interesting & useful functions  */
/*   added in later SMB server network operating     */
/*   systems).                                       */
/*                                                   */
/*****************************************************/

#include "includes.h"
#include "popt_common_cmdline.h"
#include "utils/net.h"
#include "secrets.h"
#include "lib/netapi/netapi.h"
#include "../libcli/security/security.h"
#include "passdb.h"
#include "messages.h"
#include "cmdline_contexts.h"
#include "lib/gencache.h"
#include "auth/credentials/credentials.h"
#include "source3/utils/passwd_proto.h"

#ifdef WITH_FAKE_KASERVER
#include "utils/net_afs.h"
#endif

/***********************************************************************/
/* end of internationalization section                                 */
/***********************************************************************/

enum netr_SchannelType get_sec_channel_type(const char *param)
{
	if (!(param && *param)) {
		return get_default_sec_channel();
	} else {
		if (strequal(param, "PDC")) {
			return SEC_CHAN_BDC;
		} else if (strequal(param, "BDC")) {
			return SEC_CHAN_BDC;
		} else if (strequal(param, "MEMBER")) {
			return SEC_CHAN_WKSTA;
#if 0
		} else if (strequal(param, "DOMAIN")) {
			return SEC_CHAN_DOMAIN;
#endif
		} else {
			return get_default_sec_channel();
		}
	}
}

static int net_changetrustpw(struct net_context *c, int argc, const char **argv)
{
	if (net_ads_check_our_domain(c) == 0)
		return net_ads_changetrustpw(c, argc, argv);

	return net_rpc_changetrustpw(c, argc, argv);
}

static void set_line_buffering(FILE *f)
{
	setvbuf(f, NULL, _IOLBF, 0);
}

static int net_primarytrust_dumpinfo(struct net_context *c, int argc,
				     const char **argv)
{
	int role = lp_server_role();
	const char *domain = lp_workgroup();
	struct secrets_domain_info1 *info = NULL;
	bool include_secrets = c->opt_force;
	char *str = NULL;
	NTSTATUS status;

	if (role >= ROLE_ACTIVE_DIRECTORY_DC) {
		d_printf(_("net primarytrust dumpinfo is only supported "
			 "on a DOMAIN_MEMBER for now.\n"));
		return 1;
	}

	if (c->opt_stdin) {
		set_line_buffering(stdin);
		set_line_buffering(stdout);
		set_line_buffering(stderr);
	}

	status = secrets_fetch_or_upgrade_domain_info(domain,
						      talloc_tos(),
						      &info);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr,
			  _("Unable to fetch the information for domain[%s] "
			  "in the secrets database.\n"),
			  domain);
		return 1;
	}

	str = secrets_domain_info_string(info, info, domain, include_secrets);
	if (str == NULL) {
		d_fprintf(stderr, "secrets_domain_info_string() failed.\n");
		return 1;
	}

	d_printf("%s", str);
	if (!c->opt_force) {
		d_printf(_("The password values are only included using "
			 "-f flag.\n"));
	}

	TALLOC_FREE(info);
	return 0;
}

/**
 * Entrypoint for 'net primarytrust' code.
 *
 * @param argc Standard argc.
 * @param argv Standard argv without initial components.
 *
 * @return Integer status (0 means success).
 */

static int net_primarytrust(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			.funcname         = "dumpinfo",
			.fn               = net_primarytrust_dumpinfo,
			.valid_transports = NET_TRANSPORT_LOCAL,
			.description      = N_("Dump the details of the "
					       "workstation trust"),
			.usage            = N_("  net [options] primarytrust "
					       "dumpinfo'\n"
					       "    Dump the details of the "
					       "workstation trust in "
					       "secrets.tdb.\n"
					       "    Requires the -f flag to "
					       "include the password values."),
		},
		{
			.funcname = NULL,
		},
	};

	return net_run_function(c, argc, argv, "net primarytrust", func);
}

static int net_changesecretpw(struct net_context *c, int argc,
			      const char **argv)
{
        char *trust_pw;
	int role = lp_server_role();

	if (role != ROLE_DOMAIN_MEMBER) {
		d_printf(_("Machine account password change only supported on a DOMAIN_MEMBER.\n"
			   "Do NOT use this function unless you know what it does!\n"
		           "This function will change the ADS Domain member "
			   "machine account password in the secrets.tdb file!\n"));
		return 1;
	}

	if(c->opt_force) {
		struct secrets_domain_info1 *info = NULL;
		struct secrets_domain_info1_change *prev = NULL;
		NTSTATUS status;
		struct timeval tv = timeval_current();
		NTTIME now = timeval_to_nttime(&tv);

		if (c->opt_stdin) {
			set_line_buffering(stdin);
			set_line_buffering(stdout);
			set_line_buffering(stderr);
		}

		trust_pw = get_pass(_("Enter machine password: "), c->opt_stdin);
		if (trust_pw == NULL) {
			    d_fprintf(stderr,
				      _("Error in reading machine password\n"));
			    return 1;
		}

		status = secrets_prepare_password_change(lp_workgroup(),
							 "localhost",
							 trust_pw,
							 talloc_tos(),
							 &info, &prev);
		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr,
			        _("Unable to write the machine account password in the secrets database"));
			return 1;
		}
		if (prev != NULL) {
			d_fprintf(stderr,
			        _("Pending machine account password change found - aborting."));
			status = secrets_failed_password_change("localhost",
						NT_STATUS_REQUEST_NOT_ACCEPTED,
						NT_STATUS_NOT_COMMITTED,
						info);
			if (!NT_STATUS_IS_OK(status)) {
				d_fprintf(stderr,
				        _("Failed to abort machine account password change"));
			}
			return 1;
		}
		status = secrets_finish_password_change("localhost", now, info);
		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr,
			        _("Unable to write the machine account password in the secrets database"));
			return 1;
		}

		d_printf(_("Modified trust account password in secrets database\n"));
	}
	else {
		d_printf(_("Machine account password change requires the -f flag.\n"
			   "Do NOT use this function unless you know what it does!\n"
		           "This function will change the ADS Domain member "
			   "machine account password in the secrets.tdb file!\n"));
	}

        return 0;
}

/**
 * @brief Set the authorised user for winbindd access in secrets.tdb
 */
static int net_setauthuser(struct net_context *c, int argc, const char **argv)
{
	const char *password = NULL;

	if (!secrets_init()) {
		d_fprintf(stderr, _("Failed to open secrets.tdb.\n"));
		return 1;
	}

	/* Delete the settings. */
	if (argc >= 1) {
		if (strncmp(argv[0], "delete", 6) != 0) {
			d_fprintf(stderr,_("Usage:\n"));
			d_fprintf(stderr,
				  _("    net setauthuser -U user[%%password] \n"
				    "        Set the auth user account to user"
				    "password. Prompt for password if not "
				    "specified.\n"));
			d_fprintf(stderr,
				  _("    net setauthuser delete\n"
				    "        Delete the auth user setting.\n"));
			return 1;
		}
		secrets_delete_entry(SECRETS_AUTH_USER);
		secrets_delete_entry(SECRETS_AUTH_DOMAIN);
		secrets_delete_entry(SECRETS_AUTH_PASSWORD);
		return 0;
	}

	if (!c->opt_user_specified) {
		d_fprintf(stderr, _("Usage:\n"));
		d_fprintf(stderr,
			  _("    net setauthuser -U user[%%password]\n"
			    "        Set the auth user account to user"
			    "password. Prompt for password if not "
			    "specified.\n"));
		d_fprintf(stderr,
			  _("    net setauthuser delete\n"
			    "        Delete the auth user setting.\n"));
		return 1;
	}

	password = net_prompt_pass(c, _("the auth user"));
	if (password == NULL) {
		d_fprintf(stderr,_("Failed to get the auth users password.\n"));
		return 1;
	}

	if (!secrets_store(SECRETS_AUTH_USER, c->opt_user_name,
			   strlen(c->opt_user_name) + 1)) {
		d_fprintf(stderr, _("error storing auth user name\n"));
		return 1;
	}

	if (!secrets_store(SECRETS_AUTH_DOMAIN, c->opt_workgroup,
			   strlen(c->opt_workgroup) + 1)) {
		d_fprintf(stderr, _("error storing auth user domain\n"));
		return 1;
	}

	if (!secrets_store(SECRETS_AUTH_PASSWORD, password,
			   strlen(password) + 1)) {
		d_fprintf(stderr, _("error storing auth user password\n"));
		return 1;
	}

	return 0;
}

/**
 * @brief Get the auth user settings
 */
static int net_getauthuser(struct net_context *c, int argc, const char **argv)
{
	char *user, *domain, *password;

	/* Lift data from secrets file */

	secrets_fetch_ipc_userpass(&user, &domain, &password);

	if ((!user || !*user) && (!domain || !*domain ) &&
	    (!password || !*password)){

		SAFE_FREE(user);
		SAFE_FREE(domain);
		SAFE_FREE(password);
		d_printf(_("No authorised user configured\n"));
		return 0;
	}

	/* Pretty print authorised user info */

	d_printf("%s%s%s%s%s\n", domain ? domain : "",
		 domain ? lp_winbind_separator(): "", user,
		 password ? "%" : "", password ? password : "");

	SAFE_FREE(user);
	SAFE_FREE(domain);
	SAFE_FREE(password);

	return 0;
}
/*
 Retrieve our local SID or the SID for the specified name
 */
static int net_getlocalsid(struct net_context *c, int argc, const char **argv)
{
        struct dom_sid sid;
	const char *name;
	struct dom_sid_buf sid_str;

	if (argc >= 1) {
		name = argv[0];
        }
	else {
		name = lp_netbios_name();
	}

	if(!initialize_password_db(false, NULL)) {
		d_fprintf(stderr, _("WARNING: Could not open passdb\n"));
		return 1;
	}

	/* first check to see if we can even access secrets, so we don't
	   panic when we can't. */

	if (!secrets_init()) {
		d_fprintf(stderr,
			  _("Unable to open secrets.tdb.  Can't fetch domain "
			    "SID for name: %s\n"), name);
		return 1;
	}

	/* Generate one, if it doesn't exist */
	get_global_sam_sid();

	if (!secrets_fetch_domain_sid(name, &sid)) {
		DEBUG(0, ("Can't fetch domain SID for name: %s\n", name));
		return 1;
	}
	d_printf(_("SID for domain %s is: %s\n"),
		 name,
		 dom_sid_str_buf(&sid, &sid_str));
	return 0;
}

static int net_setlocalsid(struct net_context *c, int argc, const char **argv)
{
	struct dom_sid sid;

	if ( (argc != 1)
	     || (strncmp(argv[0], "S-1-5-21-", strlen("S-1-5-21-")) != 0)
	     || (!string_to_sid(&sid, argv[0]))
	     || (sid.num_auths != 4)) {
		d_printf(_("Usage:"));
		d_printf(" net setlocalsid S-1-5-21-x-y-z\n");
		return 1;
	}

	if (!secrets_store_domain_sid(lp_netbios_name(), &sid)) {
		DEBUG(0,("Can't store domain SID as a pdc/bdc.\n"));
		return 1;
	}

	return 0;
}

static int net_setdomainsid(struct net_context *c, int argc, const char **argv)
{
	struct dom_sid sid;

	if ( (argc != 1)
	     || (strncmp(argv[0], "S-1-5-21-", strlen("S-1-5-21-")) != 0)
	     || (!string_to_sid(&sid, argv[0]))
	     || (sid.num_auths != 4)) {
		d_printf(_("Usage:"));
		d_printf(" net setdomainsid S-1-5-21-x-y-z\n");
		return 1;
	}

	if (!secrets_store_domain_sid(lp_workgroup(), &sid)) {
		DEBUG(0,("Can't store domain SID.\n"));
		return 1;
	}

	return 0;
}

static int net_getdomainsid(struct net_context *c, int argc, const char **argv)
{
	struct dom_sid domain_sid;
	struct dom_sid_buf sid_str;

	if (argc > 0) {
		d_printf(_("Usage:"));
		d_printf(" net getdomainsid\n");
		return 1;
	}

	if(!initialize_password_db(false, NULL)) {
		d_fprintf(stderr, _("WARNING: Could not open passdb\n"));
		return 1;
	}

	/* first check to see if we can even access secrets, so we don't
	   panic when we can't. */

	if (!secrets_init()) {
		d_fprintf(stderr, _("Unable to open secrets.tdb.  Can't fetch "
				    "domain SID for name: %s\n"),
			  get_global_sam_name());
		return 1;
	}

	/* Generate one, if it doesn't exist */
	get_global_sam_sid();

	if (!IS_DC) {
		if (!secrets_fetch_domain_sid(lp_netbios_name(), &domain_sid)) {
			d_fprintf(stderr, _("Could not fetch local SID\n"));
			return 1;
		}
		d_printf(_("SID for local machine %s is: %s\n"),
			 lp_netbios_name(),
			 dom_sid_str_buf(&domain_sid, &sid_str));
	}
	if (!secrets_fetch_domain_sid(c->opt_workgroup, &domain_sid)) {
		d_fprintf(stderr, _("Could not fetch domain SID\n"));
		return 1;
	}

	d_printf(_("SID for domain %s is: %s\n"),
		 c->opt_workgroup,
		 dom_sid_str_buf(&domain_sid, &sid_str));

	return 0;
}

static bool search_maxrid(struct pdb_search *search, const char *type,
			  uint32_t *max_rid)
{
	struct samr_displayentry *entries;
	uint32_t i, num_entries;

	if (search == NULL) {
		d_fprintf(stderr, _("get_maxrid: Could not search %s\n"), type);
		return false;
	}

	num_entries = pdb_search_entries(search, 0, 0xffffffff, &entries);
	for (i=0; i<num_entries; i++)
		*max_rid = MAX(*max_rid, entries[i].rid);
	TALLOC_FREE(search);
	return true;
}

static uint32_t get_maxrid(void)
{
	uint32_t max_rid = 0;

	if (!search_maxrid(pdb_search_users(talloc_tos(), 0), "users", &max_rid))
		return 0;

	if (!search_maxrid(pdb_search_groups(talloc_tos()), "groups", &max_rid))
		return 0;

	if (!search_maxrid(pdb_search_aliases(talloc_tos(),
					      get_global_sam_sid()),
			   "aliases", &max_rid))
		return 0;

	return max_rid;
}

static int net_maxrid(struct net_context *c, int argc, const char **argv)
{
	uint32_t rid;

	if (argc != 0) {
	        d_fprintf(stderr, "%s net maxrid\n", _("Usage:"));
		return 1;
	}

	if ((rid = get_maxrid()) == 0) {
		d_fprintf(stderr, _("can't get current maximum rid\n"));
		return 1;
	}

	d_printf(_("Currently used maximum rid: %d\n"), rid);

	return 0;
}

/* main function table */
static struct functable net_func[] = {
	{
		"rpc",
		net_rpc,
		NET_TRANSPORT_RPC,
		N_("Run functions using RPC transport"),
		N_("  Use 'net help rpc' to get more extensive information "
		   "about 'net rpc' commands.")
	},
	{
		"rap",
		net_rap,
		NET_TRANSPORT_RAP,
		N_("Run functions using RAP transport"),
		N_("  Use 'net help rap' to get more extensive information "
		   "about 'net rap' commands.")
	},
	{
		"ads",
		net_ads,
		NET_TRANSPORT_ADS,
		N_("Run functions using ADS transport"),
		N_("  Use 'net help ads' to get more extensive information "
		   "about 'net ads' commands.")
	},

	/* eventually these should auto-choose the transport ... */
	{
		"file",
		net_file,
		NET_TRANSPORT_RPC | NET_TRANSPORT_RAP,
		N_("Functions on remote opened files"),
		N_("  Use 'net help file' to get more information about 'net "
		   "file' commands.")
	},
	{
		"share",
		net_share,
		NET_TRANSPORT_RPC | NET_TRANSPORT_RAP,
		N_("Functions on shares"),
		N_("  Use 'net help share' to get more information about 'net "
		   "share' commands.")
	},
	{
		"session",
		net_rap_session,
		NET_TRANSPORT_RAP,
		N_("Manage sessions"),
		N_("  Use 'net help session' to get more information about "
		   "'net session' commands.")
	},
	{
		"server",
		net_rap_server,
		NET_TRANSPORT_RAP,
		N_("List servers in workgroup"),
		N_("  Use 'net help server' to get more information about 'net "
		   "server' commands.")
	},
	{
		"domain",
		net_rap_domain,
		NET_TRANSPORT_RAP,
		N_("List domains/workgroups on network"),
		N_("  Use 'net help domain' to get more information about 'net "
		   "domain' commands.")
	},
	{
		"printq",
		net_rap_printq,
		NET_TRANSPORT_RAP,
		N_("Modify printer queue"),
		N_("  Use 'net help printq' to get more information about 'net "
		   "printq' commands.")
	},
	{
		"user",
		net_user,
		NET_TRANSPORT_ADS | NET_TRANSPORT_RPC | NET_TRANSPORT_RAP,
		N_("Manage users"),
		N_("  Use 'net help user' to get more information about 'net "
		   "user' commands.")
	},
	{
		"group",
		net_group,
		NET_TRANSPORT_ADS | NET_TRANSPORT_RPC | NET_TRANSPORT_RAP,
		N_("Manage groups"),
		N_("  Use 'net help group' to get more information about 'net "
		   "group' commands.")
	},
	{
		"groupmap",
		net_groupmap,
		NET_TRANSPORT_LOCAL,
		N_("Manage group mappings"),
		N_("  Use 'net help groupmap' to get more information about "
		   "'net groupmap' commands.")
	},
	{
		"sam",
		net_sam,
		NET_TRANSPORT_LOCAL,
		N_("Functions on the SAM database"),
		N_("  Use 'net help sam' to get more information about 'net "
		   "sam' commands.")
	},
	{
		"validate",
		net_rap_validate,
		NET_TRANSPORT_RAP,
		N_("Validate username and password"),
		N_("  Use 'net help validate' to get more information about "
		   "'net validate' commands.")
	},
	{
		"groupmember",
		net_rap_groupmember,
		NET_TRANSPORT_RAP,
		N_("Modify group memberships"),
		N_("  Use 'net help groupmember' to get more information about "
		   "'net groupmember' commands.")
	},
	{	"admin",
		net_rap_admin,
		NET_TRANSPORT_RAP,
		N_("Execute remote command on a remote OS/2 server"),
		N_("  Use 'net help admin' to get more information about 'net "
		   "admin' commands.")
	},
	{	"service",
		net_rap_service,
		NET_TRANSPORT_RAP,
		N_("List/modify running services"),
		N_("  Use 'net help service' to get more information about "
		   "'net service' commands.")
	},
	{
		"password",
		net_rap_password,
		NET_TRANSPORT_RAP,
		N_("Change user password on target server"),
		N_("  Use 'net help password' to get more information about "
		   "'net password' commands.")
	},
	{
		"primarytrust",
		net_primarytrust,
		NET_TRANSPORT_RPC,
		N_("Run functions related to the primary workstation trust."),
		N_("  Use 'net help primarytrust' to get more extensive information "
		   "about 'net primarytrust' commands.")
	},
	{	"changetrustpw",
		net_changetrustpw,
		NET_TRANSPORT_ADS | NET_TRANSPORT_RPC,
		N_("Change the trust password"),
		N_("  Use 'net help changetrustpw' to get more information "
		   "about 'net changetrustpw'.")
	},
	{	"changesecretpw",
		net_changesecretpw,
		NET_TRANSPORT_LOCAL,
		N_("Change the secret password"),
		N_("  net [options] changesecretpw\n"
		   "    Change the ADS domain member machine account password "
		   "in secrets.tdb.\n"
		   "    Do NOT use this function unless you know what it does.\n"
		   "    Requires the -f flag to work.")
	},
	{
		"setauthuser",
		net_setauthuser,
		NET_TRANSPORT_LOCAL,
		N_("Set the winbind auth user"),
		N_("  net -U user[%%password] [-W domain] setauthuser\n"
		   "    Set the auth user, password (and optionally domain\n"
		   "    Will prompt for password if not given.\n"
		   "  net setauthuser delete\n"
		   "    Delete the existing auth user settings.")
	},
	{
		"getauthuser",
		net_getauthuser,
		NET_TRANSPORT_LOCAL,
		N_("Get the winbind auth user settings"),
		N_("  net getauthuser\n"
		   "    Get the current winbind auth user settings.")
	},
	{	"time",
		net_time,
		NET_TRANSPORT_LOCAL,
		N_("Show/set time"),
		N_("  Use 'net help time' to get more information about 'net "
		   "time' commands.")
	},
	{	"lookup",
		net_lookup,
		NET_TRANSPORT_LOCAL,
		N_("Look up host names/IP addresses"),
		N_("  Use 'net help lookup' to get more information about 'net "
		   "lookup' commands.")
	},
	{	"g_lock",
		net_g_lock,
		NET_TRANSPORT_LOCAL,
		N_("Manipulate the global lock table"),
		N_("  Use 'net help g_lock' to get more information about "
		   "'net g_lock' commands.")
	},
	{	"join",
		net_join,
		NET_TRANSPORT_ADS | NET_TRANSPORT_RPC,
		N_("Join a domain/AD"),
		N_("  Use 'net help join' to get more information about 'net "
		   "join'.")
	},
	{	"dom",
		net_dom,
		NET_TRANSPORT_LOCAL,
		N_("Join/unjoin (remote) machines to/from a domain/AD"),
		N_("  Use 'net help dom' to get more information about 'net "
		   "dom' commands.")
	},
	{	"cache",
		net_cache,
		NET_TRANSPORT_LOCAL,
		N_("Operate on the cache tdb file"),
		N_("  Use 'net help cache' to get more information about 'net "
		   "cache' commands.")
	},
	{	"getlocalsid",
		net_getlocalsid,
		NET_TRANSPORT_LOCAL,
		N_("Get the SID for the local domain"),
		N_("  net getlocalsid")
	},
	{	"setlocalsid",
		net_setlocalsid,
		NET_TRANSPORT_LOCAL,
		N_("Set the SID for the local domain"),
		N_("  net setlocalsid S-1-5-21-x-y-z")
	},
	{	"setdomainsid",
		net_setdomainsid,
		NET_TRANSPORT_LOCAL,
		N_("Set domain SID on member servers"),
		N_("  net setdomainsid S-1-5-21-x-y-z")
	},
	{	"getdomainsid",
		net_getdomainsid,
		NET_TRANSPORT_LOCAL,
		N_("Get domain SID on member servers"),
		N_("  net getdomainsid")
	},
	{	"maxrid",
		net_maxrid,
		NET_TRANSPORT_LOCAL,
		N_("Display the maximum RID currently used"),
		N_("  net maxrid")
	},
	{	"idmap",
		net_idmap,
		NET_TRANSPORT_LOCAL,
		N_("IDmap functions"),
		N_("  Use 'net help idmap to get more information about 'net "
		  "idmap' commands.")
	},
	{	"status",
		net_status,
		NET_TRANSPORT_LOCAL,
		N_("Display server status"),
		N_("  Use 'net help status' to get more information about 'net "
		   "status' commands.")
	},
	{	"usershare",
		net_usershare,
		NET_TRANSPORT_LOCAL,
		N_("Manage user-modifiable shares"),
		N_("  Use 'net help usershare to get more information about "
		   "'net usershare' commands.")
	},
	{	"usersidlist",
		net_usersidlist,
		NET_TRANSPORT_RPC,
		N_("Display list of all users with SID"),
		N_("  Use 'net help usersidlist' to get more information about "
		   "'net usersidlist'.")
	},
	{	"conf",
		net_conf,
		NET_TRANSPORT_LOCAL,
		N_("Manage Samba registry based configuration"),
		N_("  Use 'net help conf' to get more information about 'net "
		   "conf' commands.")
	},
	{	"registry",
		net_registry,
		NET_TRANSPORT_LOCAL,
		N_("Manage the Samba registry"),
		N_("  Use 'net help registry' to get more information about "
		   "'net registry' commands.")
	},
	{	"eventlog",
		net_eventlog,
		NET_TRANSPORT_LOCAL,
		N_("Process Win32 *.evt eventlog files"),
		N_("  Use 'net help eventlog' to get more information about "
		   "'net eventlog' commands.")
	},
	{	"printing",
		net_printing,
		NET_TRANSPORT_LOCAL,
		N_("Process tdb printer files"),
		N_("  Use 'net help printing' to get more information about "
		   "'net printing' commands.")
	},

	{	"serverid",
		net_serverid,
		NET_TRANSPORT_LOCAL,
		N_("Manage the serverid tdb"),
		N_("  Use 'net help serverid' to get more information about "
		   "'net serverid' commands.")
	},

	{	"notify",
		net_notify,
		NET_TRANSPORT_LOCAL,
		N_("notifyd client code"),
		N_("  Use 'net help notify' to get more information about "
		   "'net notify' commands.")
	},

	{	"tdb",
		net_tdb,
		NET_TRANSPORT_LOCAL,
		N_("Show information from tdb records"),
		N_("  Use 'net help tdb' to get more information about "
		   "'net tdb' commands.")
	},

	{	"vfs",
		net_vfs,
		NET_TRANSPORT_LOCAL,
		N_("Filesystem operation through the VFS stack"),
		N_("  Use 'net help vfs' to get more information about "
		   "'net vfs' commands.")
	},

#ifdef WITH_FAKE_KASERVER
	{	"afs",
		net_afs,
		NET_TRANSPORT_LOCAL,
		N_("Manage AFS tokens"),
		N_("  Use 'net help afs' to get more information about 'net "
		   "afs' commands.")
	},
#endif

	{	"help",
		net_help,
		NET_TRANSPORT_LOCAL,
		N_("Print usage information"),
		N_("  Use 'net help help' to list usage information for 'net' "
		   "commands.")
	},
	{NULL, NULL, 0, NULL, NULL}
};


static void get_credentials_file(struct net_context *c,
				 const char *file)
{
	struct cli_credentials *cred = cli_credentials_init(c);

	if (cred == NULL) {
		d_printf("ERROR: Unable to allocate memory!\n");
		exit(-1);
	}

	if (!cli_credentials_parse_file(cred, file, CRED_GUESS_FILE)) {
		exit(-1);
	}

	c->opt_user_name = cli_credentials_get_username(cred);
	c->opt_user_specified = (c->opt_user_name != NULL);
	c->opt_password = cli_credentials_get_password(cred);
	c->opt_target_workgroup = cli_credentials_get_domain(cred);
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc, char **argv)
{
	int opt,i;
	char *p;
	int rc = 0;
	int argc_new = 0;
	const char ** argv_new;
	const char **argv_const = discard_const_p(const char *, argv);
	poptContext pc;
	TALLOC_CTX *frame = talloc_stackframe();
	struct net_context *c = talloc_zero(frame, struct net_context);

	struct poptOption long_options[] = {
		{
			.longName   = "help",
			.shortName  = 'h',
			.argInfo    = POPT_ARG_NONE,
			.val        = 'h',
		},
		{
			.longName   = "workgroup",
			.shortName  = 'w',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &c->opt_target_workgroup,
		},
		{
			.longName   = "user",
			.shortName  = 'U',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &c->opt_user_name,
			.val        = 'U',
		},
		{
			.longName   = "authentication-file",
			.shortName  = 'A',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &c->opt_user_name,
			.val        = 'A',
			.descrip    = "Get the credentials from a file",
			.argDescrip = "FILE",
		},
		{
			.longName   = "ipaddress",
			.shortName  = 'I',
			.argInfo    = POPT_ARG_STRING,
			.arg        = 0,
			.val        = 'I',
		},
		{
			.longName   = "port",
			.shortName  = 'p',
			.argInfo    = POPT_ARG_INT,
			.arg        = &c->opt_port,
		},
		{
			.longName   = "myname",
			.shortName  = 'n',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &c->opt_requester_name,
		},
		{
			.longName   = "server",
			.shortName  = 'S',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &c->opt_host,
		},
		{
			.longName   = "encrypt",
			.shortName  = 'e',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'e',
			.descrip    = N_("Encrypt SMB transport"),
		},
		{
			.longName   = "container",
			.shortName  = 'c',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &c->opt_container,
		},
		{
			.longName   = "comment",
			.shortName  = 'C',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &c->opt_comment,
		},
		{
			.longName   = "maxusers",
			.shortName  = 'M',
			.argInfo    = POPT_ARG_INT,
			.arg        = &c->opt_maxusers,
		},
		{
			.longName   = "flags",
			.shortName  = 'F',
			.argInfo    = POPT_ARG_INT,
			.arg        = &c->opt_flags,
		},
		{
			.longName   = "long",
			.shortName  = 'l',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_long_list_entries,
		},
		{
			.longName   = "reboot",
			.shortName  = 'r',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_reboot,
		},
		{
			.longName   = "force",
			.shortName  = 'f',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_force,
		},
		{
			.longName   = "stdin",
			.shortName  = 'i',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_stdin,
		},
		{
			.longName   = "timeout",
			.shortName  = 't',
			.argInfo    = POPT_ARG_INT,
			.arg        = &c->opt_timeout,
		},
		{
			.longName   = "request-timeout",
			.shortName  = 0,
			.argInfo    = POPT_ARG_INT,
			.arg        = &c->opt_request_timeout,
		},
		{
			.longName   = "machine-pass",
			.shortName  = 'P',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_machine_pass,
		},
		{
			.longName   = "kerberos",
			.shortName  = 'k',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_kerberos,
		},
		{
			.longName   = "myworkgroup",
			.shortName  = 'W',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &c->opt_workgroup,
		},
		{
			.longName   = "use-ccache",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_ccache,
		},
		{
			.longName   = "verbose",
			.shortName  = 'v',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_verbose,
		},
		{
			.longName   = "test",
			.shortName  = 'T',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_testmode,
		},
		/* Options for 'net groupmap set' */
		{
			.longName   = "local",
			.shortName  = 'L',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_localgroup,
		},
		{
			.longName   = "domain",
			.shortName  = 'D',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_domaingroup,
		},
		{
			.longName   = "ntname",
			.shortName  = 'N',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &c->opt_newntname,
		},
		{
			.longName   = "rid",
			.shortName  = 'R',
			.argInfo    = POPT_ARG_INT,
			.arg        = &c->opt_rid,
		},
		/* Options for 'net rpc share migrate' */
		{
			.longName   = "acls",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_acls,
		},
		{
			.longName   = "attrs",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_attrs,
		},
		{
			.longName   = "timestamps",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_timestamps,
		},
		{
			.longName   = "exclude",
			.shortName  = 'X',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &c->opt_exclude,
		},
		{
			.longName   = "destination",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &c->opt_destination,
		},
		{
			.longName   = "tallocreport",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->do_talloc_report,
		},
		/* Options for 'net rpc vampire (keytab)' */
		{
			.longName   = "force-full-repl",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_force_full_repl,
		},
		{
			.longName   = "single-obj-repl",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_single_obj_repl,
		},
		{
			.longName   = "clean-old-entries",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_clean_old_entries,
		},
		/* Options for 'net idmap'*/
		{
			.longName   = "db",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &c->opt_db,
		},
		{
			.longName   = "lock",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        =   &c->opt_lock,
		},
		{
			.longName   = "auto",
			.shortName  = 'a',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_auto,
		},
		{
			.longName   = "repair",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        =   &c->opt_repair,
		},
		/* Options for 'net registry check'*/
		{
			.longName   = "reg-version",
			.shortName  = 0,
			.argInfo    = POPT_ARG_INT,
			.arg        = &c->opt_reg_version,
		},
		{
			.longName   = "output",
			.shortName  = 'o',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &c->opt_output,
		},
		{
			.longName   = "wipe",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_wipe,
		},
		/* Options for 'net registry import' */
		{
			.longName   = "precheck",
			.shortName  = 0,
			.argInfo    = POPT_ARG_STRING,
			.arg        = &c->opt_precheck,
		},
		/* Options for 'net ads join or leave' */
		{
			.longName   = "no-dns-updates",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_no_dns_updates,
		},
		{
			.longName   = "keep-account",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_keep_account,
		},
		{
			.longName   = "json",
			.shortName  = 0,
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_json,
		},
		/* Options for 'net vfs' */
		{
			.longName   = "continue",
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_continue_on_error,
			.descrip    = "Continue on errors",
		},
		{
			.longName   = "recursive",
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_recursive,
			.descrip    = "Traverse directory hierarchy",
		},
		{
			.longName   = "follow-symlinks",
			.argInfo    = POPT_ARG_NONE,
			.arg        = &c->opt_follow_symlink,
			.descrip    = "follow symlinks",
		},
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};

	zero_sockaddr(&c->opt_dest_ip);

	setup_logging(argv[0], DEBUG_STDERR);

	smb_init_locale();

	setlocale(LC_ALL, "");
#if defined(HAVE_BINDTEXTDOMAIN)
	bindtextdomain(MODULE_NAME, get_dyn_LOCALEDIR());
#endif
#if defined(HAVE_TEXTDOMAIN)
	textdomain(MODULE_NAME);
#endif

	/* set default debug level to 0 regardless of what smb.conf sets */
	lp_set_cmdline("log level", "0");
	c->private_data = net_func;

	pc = poptGetContext(NULL, argc, argv_const, long_options,
			    POPT_CONTEXT_KEEP_FIRST);

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'h':
			c->display_usage = true;
			break;
		case 'e':
			c->smb_encrypt = true;
			break;
		case 'I':
			if (!interpret_string_addr(&c->opt_dest_ip,
						poptGetOptArg(pc), 0)) {
				d_fprintf(stderr, _("\nInvalid ip address specified\n"));
			} else {
				c->opt_have_ip = true;
			}
			break;
		case 'U':
			c->opt_user_specified = true;
			c->opt_user_name = talloc_strdup(c, c->opt_user_name);
			p = strchr(c->opt_user_name,'%');
			if (p) {
				*p = 0;
				c->opt_password = p+1;
			}
			break;
		case 'A':
			get_credentials_file(c, c->opt_user_name);
			break;
		default:
			d_fprintf(stderr, _("\nInvalid option %s: %s\n"),
				 poptBadOption(pc, 0), poptStrerror(opt));
			net_help(c, argc, argv_const);
			exit(1);
		}
	}

	c->msg_ctx = cmdline_messaging_context(get_dyn_CONFIGFILE());

	if (!lp_load_global(get_dyn_CONFIGFILE())) {
		d_fprintf(stderr, "Can't load %s - run testparm to debug it\n",
			  get_dyn_CONFIGFILE());
		exit(1);
	}

#if defined(HAVE_BIND_TEXTDOMAIN_CODESET)
	/* Bind our gettext results to 'unix charset'
	   
	   This ensures that the translations and any embedded strings are in the
	   same charset.  It won't be the one from the user's locale (we no
	   longer auto-detect that), but it will be self-consistent.
	*/
	bind_textdomain_codeset(MODULE_NAME, lp_unix_charset());
#endif

 	argv_new = (const char **)poptGetArgs(pc);

	argc_new = argc;
	for (i=0; i<argc; i++) {
		if (argv_new[i] == NULL) {
			argc_new = i;
			break;
		}
	}

	if (c->do_talloc_report) {
		talloc_enable_leak_report();
	}

	if (c->opt_requester_name) {
		lp_set_cmdline("netbios name", c->opt_requester_name);
	}

	if (!c->opt_user_name && getenv("LOGNAME")) {
		c->opt_user_name = getenv("LOGNAME");
	}

	if (!c->opt_workgroup) {
		c->opt_workgroup = talloc_strdup(c, lp_workgroup());
	}

	if (!c->opt_target_workgroup) {
		c->opt_target_workgroup = talloc_strdup(c, lp_workgroup());
	}

	if (!init_names())
		exit(1);

	load_interfaces();

	/* this makes sure that when we do things like call scripts,
	   that it won't assert because we are not root */
	sec_init();

	if (c->opt_machine_pass) {
		/* it is very useful to be able to make ads queries as the
		   machine account for testing purposes and for domain leave */

		net_use_krb_machine_account(c);
	}

	if (!c->opt_password) {
		c->opt_password = getenv("PASSWD");
	}

	popt_burn_cmdline_password(argc, argv);

	rc = net_run_function(c, argc_new-1, argv_new+1, "net", net_func);

	DEBUG(2,("return code = %d\n", rc));

	libnetapi_free(c->netapi_ctx);

	poptFreeContext(pc);

	TALLOC_FREE(frame);
	return rc;
}
