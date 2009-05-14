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
#include "utils/net.h"

extern bool AllowDebugChange;

#ifdef WITH_FAKE_KASERVER
#include "utils/net_afs.h"
#endif

/***********************************************************************/
/* Beginning of internationalization section.  Translatable constants  */
/* should be kept in this area and referenced in the rest of the code. */
/*                                                                     */
/* No functions, outside of Samba or LSB (Linux Standards Base) should */
/* be used (if possible).                                              */
/***********************************************************************/

#define YES_STRING              "Yes"
#define NO_STRING               "No"

/***********************************************************************/
/* end of internationalization section                                 */
/***********************************************************************/

uint32 get_sec_channel_type(const char *param)
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

static int net_changesecretpw(struct net_context *c, int argc,
			      const char **argv)
{
        char *trust_pw;
        uint32 sec_channel_type = SEC_CHAN_WKSTA;

	if(c->opt_force) {
		if (c->opt_stdin) {
			set_line_buffering(stdin);
			set_line_buffering(stdout);
			set_line_buffering(stderr);
		}

		trust_pw = get_pass("Enter machine password: ", c->opt_stdin);

		if (!secrets_store_machine_password(trust_pw, lp_workgroup(), sec_channel_type)) {
			    d_fprintf(stderr, "Unable to write the machine account password in the secrets database");
			    return 1;
		}
		else {
		    d_printf("Modified trust account password in secrets database\n");
		}
	}
	else {
		d_printf("Machine account password change requires the -f flag.\n");
		d_printf("Do NOT use this function unless you know what it does!\n");
		d_printf("This function will change the ADS Domain member machine account password in the secrets.tdb file!\n");
	}

        return 0;
}

/*
 Retrieve our local SID or the SID for the specified name
 */
static int net_getlocalsid(struct net_context *c, int argc, const char **argv)
{
        DOM_SID sid;
	const char *name;
	fstring sid_str;

	if (argc >= 1) {
		name = argv[0];
        }
	else {
		name = global_myname();
	}

	if(!initialize_password_db(false, NULL)) {
		DEBUG(0, ("WARNING: Could not open passdb - local sid may not reflect passdb\n"
			  "backend knowledge (such as the sid stored in LDAP)\n"));
	}

	/* first check to see if we can even access secrets, so we don't
	   panic when we can't. */

	if (!secrets_init()) {
		d_fprintf(stderr, "Unable to open secrets.tdb.  Can't fetch domain SID for name: %s\n", name);
		return 1;
	}

	/* Generate one, if it doesn't exist */
	get_global_sam_sid();

	if (!secrets_fetch_domain_sid(name, &sid)) {
		DEBUG(0, ("Can't fetch domain SID for name: %s\n", name));
		return 1;
	}
	sid_to_fstring(sid_str, &sid);
	d_printf("SID for domain %s is: %s\n", name, sid_str);
	return 0;
}

static int net_setlocalsid(struct net_context *c, int argc, const char **argv)
{
	DOM_SID sid;

	if ( (argc != 1)
	     || (strncmp(argv[0], "S-1-5-21-", strlen("S-1-5-21-")) != 0)
	     || (!string_to_sid(&sid, argv[0]))
	     || (sid.num_auths != 4)) {
		d_printf("usage: net setlocalsid S-1-5-21-x-y-z\n");
		return 1;
	}

	if (!secrets_store_domain_sid(global_myname(), &sid)) {
		DEBUG(0,("Can't store domain SID as a pdc/bdc.\n"));
		return 1;
	}

	return 0;
}

static int net_setdomainsid(struct net_context *c, int argc, const char **argv)
{
	DOM_SID sid;

	if ( (argc != 1)
	     || (strncmp(argv[0], "S-1-5-21-", strlen("S-1-5-21-")) != 0)
	     || (!string_to_sid(&sid, argv[0]))
	     || (sid.num_auths != 4)) {
		d_printf("usage: net setdomainsid S-1-5-21-x-y-z\n");
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
	DOM_SID domain_sid;
	fstring sid_str;

	if (argc > 0) {
		d_printf("usage: net getdomainsid\n");
		return 1;
	}

	if(!initialize_password_db(false, NULL)) {
		DEBUG(0, ("WARNING: Could not open passdb - domain SID may "
			  "not reflect passdb\n"
			  "backend knowledge (such as the SID stored in "
			  "LDAP)\n"));
	}

	/* first check to see if we can even access secrets, so we don't
	   panic when we can't. */

	if (!secrets_init()) {
		d_fprintf(stderr, "Unable to open secrets.tdb.  Can't fetch domain"
				  "SID for name: %s\n", get_global_sam_name());
		return 1;
	}

	/* Generate one, if it doesn't exist */
	get_global_sam_sid();

	if (!secrets_fetch_domain_sid(global_myname(), &domain_sid)) {
		d_fprintf(stderr, "Could not fetch local SID\n");
		return 1;
	}
	sid_to_fstring(sid_str, &domain_sid);
	d_printf("SID for local machine %s is: %s\n", global_myname(), sid_str);

	if (!secrets_fetch_domain_sid(c->opt_workgroup, &domain_sid)) {
		d_fprintf(stderr, "Could not fetch domain SID\n");
		return 1;
	}

	sid_to_fstring(sid_str, &domain_sid);
	d_printf("SID for domain %s is: %s\n", c->opt_workgroup, sid_str);

	return 0;
}

static bool search_maxrid(struct pdb_search *search, const char *type,
			  uint32 *max_rid)
{
	struct samr_displayentry *entries;
	uint32 i, num_entries;

	if (search == NULL) {
		d_fprintf(stderr, "get_maxrid: Could not search %s\n", type);
		return false;
	}

	num_entries = pdb_search_entries(search, 0, 0xffffffff, &entries);
	for (i=0; i<num_entries; i++)
		*max_rid = MAX(*max_rid, entries[i].rid);
	TALLOC_FREE(search);
	return true;
}

static uint32 get_maxrid(void)
{
	uint32 max_rid = 0;

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
	uint32 rid;

	if (argc != 0) {
	        DEBUG(0, ("usage: net maxrid\n"));
		return 1;
	}

	if ((rid = get_maxrid()) == 0) {
		DEBUG(0, ("can't get current maximum rid\n"));
		return 1;
	}

	d_printf("Currently used maximum rid: %d\n", rid);

	return 0;
}

/* main function table */
static struct functable net_func[] = {
	{
		"rpc",
		net_rpc,
		NET_TRANSPORT_RPC,
		"Run functions using RPC transport",
		"  Use 'net help rpc' to get more extensive information about "
		"'net rpc' commands."
	},
	{
		"rap",
		net_rap,
		NET_TRANSPORT_RAP,
		"Run functions using RAP transport",
		"  Use 'net help rap' to get more extensive information about "
		"'net rap' commands."
	},
	{
		"ads",
		net_ads,
		NET_TRANSPORT_ADS,
		"Run functions using ADS transport",
		"  Use 'net help ads' to get more extensive information about "
		"'net ads' commands."
	},

	/* eventually these should auto-choose the transport ... */
	{
		"file",
		net_file,
		NET_TRANSPORT_RPC | NET_TRANSPORT_RAP,
		"Functions on remote opened files",
		"  Use 'net help file' to get more information about 'net "
		"file' commands."
	},
	{
		"share",
		net_share,
		NET_TRANSPORT_RPC | NET_TRANSPORT_RAP,
		"Functions on shares",
		"  Use 'net help share' to get more information about 'net "
		"share' commands."
	},
	{
		"session",
		net_rap_session,
		NET_TRANSPORT_RAP,
		"Manage sessions",
		"  Use 'net help session' to get more information about 'net "
		"session' commands."
	},
	{
		"server",
		net_rap_server,
		NET_TRANSPORT_RAP,
		"List servers in workgroup",
		"  Use 'net help server' to get more information about 'net "
		"server' commands."
	},
	{
		"domain",
		net_rap_domain,
		NET_TRANSPORT_RAP,
		"List domains/workgroups on network",
		"  Use 'net help domain' to get more information about 'net "
		"domain' commands."
	},
	{
		"printq",
		net_rap_printq,
		NET_TRANSPORT_RAP,
		"Modify printer queue",
		"  Use 'net help printq' to get more information about 'net "
		"printq' commands."
	},
	{
		"user",
		net_user,
		NET_TRANSPORT_ADS | NET_TRANSPORT_RPC | NET_TRANSPORT_RAP,
		"Manage users",
		"  Use 'net help user' to get more information about 'net "
		"user' commands."
	},
	{
		"group",
		net_group,
		NET_TRANSPORT_ADS | NET_TRANSPORT_RPC | NET_TRANSPORT_RAP,
		"Manage groups",
		"  Use 'net help group' to get more information about 'net "
		"group' commands."
	},
	{
		"groupmap",
		net_groupmap,
		NET_TRANSPORT_LOCAL,
		"Manage group mappings",
		"  Use 'net help groupmap' to get more information about 'net "
		"groupmap' commands."
	},
	{
		"sam",
		net_sam,
		NET_TRANSPORT_LOCAL,
		"Functions on the SAM database",
		"  Use 'net help sam' to get more information about 'net sam' "
		"commands."
	},
	{
		"validate",
		net_rap_validate,
		NET_TRANSPORT_RAP,
		"Validate username and password",
		"  Use 'net help validate' to get more information about 'net "
		"validate' commands."
	},
	{
		"groupmember",
		net_rap_groupmember,
		NET_TRANSPORT_RAP,
		"Modify group memberships",
		"  Use 'net help groupmember' to get more information about "
		"'net groupmember' commands."
	},
	{	"admin",
		net_rap_admin,
		NET_TRANSPORT_RAP,
		"Execute remote command on a remote OS/2 server",
		"  Use 'net help admin' to get more information about 'net "
		"admin' commands."
	},
	{	"service",
		net_rap_service,
		NET_TRANSPORT_RAP,
		"List/modify running services",
		"  Use 'net help service' to get more information about 'net "
		"service' commands."
	},
	{
		"password",
		net_rap_password,
		NET_TRANSPORT_RAP,
		"Change user password on target server",
		"  Use 'net help password' to get more information about 'net "
		"password' commands."
	},
	{	"changetrustpw",
		net_changetrustpw,
		NET_TRANSPORT_ADS | NET_TRANSPORT_RPC,
		"Change the trust password",
		"  Use 'net help changetrustpw' to get more information about "
		"'net changetrustpw'."
	},
	{	"changesecretpw",
		net_changesecretpw,
		NET_TRANSPORT_LOCAL,
		"Change the secret password",
		"  net [options] changesecretpw\n"
		"    Change the ADS domain member machine account password in "
		"secrets.tdb.\n"
		"    Do NOT use this function unless you know what it does.\n"
		"    Requires the -f flag to work."
	},
	{	"time",
		net_time,
		NET_TRANSPORT_LOCAL,
		"Show/set time",
		"  Use 'net help time' to get more information about 'net "
		"time' commands."
	},
	{	"lookup",
		net_lookup,
		NET_TRANSPORT_LOCAL,
		"Look up host names/IP addresses",
		"  Use 'net help lookup' to get more information about 'net "
		"lookup' commands."
	},
	{	"join",
		net_join,
		NET_TRANSPORT_ADS | NET_TRANSPORT_RPC,
		"Join a domain/AD",
		"  Use 'net help join' to get more information about 'net "
		"join'."
	},
	{	"dom",
		net_dom,
		NET_TRANSPORT_LOCAL,
		"Join/unjoin (remote) machines to/from a domain/AD",
		"  Use 'net help dom' to get more information about 'net dom' "
		"commands."
	},
	{	"cache",
		net_cache,
		NET_TRANSPORT_LOCAL,
		"Operate on the cache tdb file",
		"  Use 'net help cache' to get more information about 'net "
		"cache' commands."
	},
	{	"getlocalsid",
		net_getlocalsid,
		NET_TRANSPORT_LOCAL,
		"Get the SID for the local domain",
		"  net getlocalsid"
	},
	{	"setlocalsid",
		net_setlocalsid,
		NET_TRANSPORT_LOCAL,
		"Set the SID for the local domain",
		"  net setlocalsid S-1-5-21-x-y-z"
	},
	{	"setdomainsid",
		net_setdomainsid,
		NET_TRANSPORT_LOCAL,
		"Set domain SID on member servers",
		"  net setdomainsid S-1-5-21-x-y-z"
	},
	{	"getdomainsid",
		net_getdomainsid,
		NET_TRANSPORT_LOCAL,
		"Get domain SID on member servers",
		"  net getdomainsid"
	},
	{	"maxrid",
		net_maxrid,
		NET_TRANSPORT_LOCAL,
		"Display the maximul RID currently used",
		"  net maxrid"
	},
	{	"idmap",
		net_idmap,
		NET_TRANSPORT_LOCAL,
		"IDmap functions",
		"  Use 'net help idmap to get more information about 'net "
		"idmap' commands."
	},
	{	"status",
		net_status,
		NET_TRANSPORT_LOCAL,
		"Display server status",
		"  Use 'net help status' to get more information about 'net "
		"status' commands."
	},
	{	"usershare",
		net_usershare,
		NET_TRANSPORT_LOCAL,
		"Manage user-modifiable shares",
		"  Use 'net help usershare to get more information about 'net "
		"usershare' commands."
	},
	{	"usersidlist",
		net_usersidlist,
		NET_TRANSPORT_RPC,
		"Display list of all users with SID",
		"  Use 'net help usersidlist' to get more information about "
		"'net usersidlist'."
	},
	{	"conf",
		net_conf,
		NET_TRANSPORT_LOCAL,
		"Manage Samba registry based configuration",
		"  Use 'net help conf' to get more information about 'net "
		"conf' commands."
	},
	{	"registry",
		net_registry,
		NET_TRANSPORT_LOCAL,
		"Manage the Samba registry",
		"  Use 'net help registry' to get more information about 'net "
		"registry' commands."
	},
	{	"eventlog",
		net_eventlog,
		NET_TRANSPORT_LOCAL,
		"Process Win32 *.evt eventlog files",
		"  Use 'net help eventlog' to get more information about 'net "
		"eventlog' commands."
	},

#ifdef WITH_FAKE_KASERVER
	{	"afs",
		net_afs,
		NET_TRANSPORT_LOCAL,
		"Manage AFS tokens",
		"  Use 'net help afs' to get more information about 'net afs' "
		"commands."
	},
#endif

	{	"help",
		net_help,
		NET_TRANSPORT_LOCAL,
		"Print usage information",
		"  Use 'net help help' to list usage information for 'net' "
		"commands."
	},
	{NULL, NULL, 0, NULL, NULL}
};


/****************************************************************************
  main program
****************************************************************************/
 int main(int argc, const char **argv)
{
	int opt,i;
	int rc = 0;
	int argc_new = 0;
	const char ** argv_new;
	poptContext pc;
	TALLOC_CTX *frame = talloc_stackframe();
	struct net_context *c = talloc_zero(frame, struct net_context);

	struct poptOption long_options[] = {
		{"help",	'h', POPT_ARG_NONE,   0, 'h'},
		{"workgroup",	'w', POPT_ARG_STRING, &c->opt_target_workgroup},
		{"ipaddress",	'I', POPT_ARG_STRING, 0,'I'},
		{"port",	'p', POPT_ARG_INT,    &c->opt_port},
		{"myname",	'n', POPT_ARG_STRING, &c->opt_requester_name},
		{"server",	'S', POPT_ARG_STRING, &c->opt_host},
		{"container",	'c', POPT_ARG_STRING, &c->opt_container},
		{"comment",	'C', POPT_ARG_STRING, &c->opt_comment},
		{"maxusers",	'M', POPT_ARG_INT,    &c->opt_maxusers},
		{"flags",	'F', POPT_ARG_INT,    &c->opt_flags},
		{"long",	'l', POPT_ARG_NONE,   &c->opt_long_list_entries},
		{"reboot",	'r', POPT_ARG_NONE,   &c->opt_reboot},
		{"force",	'f', POPT_ARG_NONE,   &c->opt_force},
		{"stdin",	'i', POPT_ARG_NONE,   &c->opt_stdin},
		{"timeout",	't', POPT_ARG_INT,    &c->opt_timeout},
		{"request-timeout",0,POPT_ARG_INT,    &c->opt_request_timeout},
		{"myworkgroup", 'W', POPT_ARG_STRING, &c->opt_workgroup},
		{"verbose",	'v', POPT_ARG_NONE,   &c->opt_verbose},
		{"test",	'T', POPT_ARG_NONE,   &c->opt_testmode},
		/* Options for 'net groupmap set' */
		{"local",       'L', POPT_ARG_NONE,   &c->opt_localgroup},
		{"domain",      'D', POPT_ARG_NONE,   &c->opt_domaingroup},
		{"ntname",        0, POPT_ARG_STRING, &c->opt_newntname},
		{"rid",         'R', POPT_ARG_INT,    &c->opt_rid},
		/* Options for 'net rpc share migrate' */
		{"acls",	0, POPT_ARG_NONE,     &c->opt_acls},
		{"attrs",	0, POPT_ARG_NONE,     &c->opt_attrs},
		{"timestamps",	0, POPT_ARG_NONE,     &c->opt_timestamps},
		{"exclude",	'X', POPT_ARG_STRING, &c->opt_exclude},
		{"destination",	0, POPT_ARG_STRING,   &c->opt_destination},
		{"tallocreport", 0, POPT_ARG_NONE,    &c->do_talloc_report},
		/* Options for 'net rpc vampire (keytab)' */
		{"force-full-repl", 0, POPT_ARG_NONE, &c->opt_force_full_repl},
		{"single-obj-repl", 0, POPT_ARG_NONE, &c->opt_single_obj_repl},
		{"clean-old-entries", 0, POPT_ARG_NONE, &c->opt_clean_old_entries},

		POPT_COMMON_SAMBA
		POPT_COMMON_CREDENTIALS
		{ 0, 0, 0, 0}
	};


	zero_sockaddr(&c->opt_dest_ip);

	load_case_tables();

	/* set default debug level to 0 regardless of what smb.conf sets */
	DEBUGLEVEL_CLASS[DBGC_ALL] = 0;
	dbf = x_stderr;
	c->private_data = net_func;

	c->auth_info = user_auth_info_init(frame);
	if (c->auth_info == NULL) {
		d_fprintf(stderr, "\nOut of memory!\n");
		exit(1);
	}
	popt_common_set_auth_info(c->auth_info);

	pc = poptGetContext(NULL, argc, (const char **) argv, long_options,
			    POPT_CONTEXT_KEEP_FIRST);

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'h':
			c->display_usage = true;
			set_cmdline_auth_info_password(c->auth_info, "");
			break;
		case 'I':
			if (!interpret_string_addr(&c->opt_dest_ip,
						poptGetOptArg(pc), 0)) {
				d_fprintf(stderr, "\nInvalid ip address specified\n");
			} else {
				c->opt_have_ip = true;
			}
			break;
		default:
			d_fprintf(stderr, "\nInvalid option %s: %s\n",
				 poptBadOption(pc, 0), poptStrerror(opt));
			net_help(c, argc, argv);
			exit(1);
		}
	}

	/*
	 * Don't load debug level from smb.conf. It should be
	 * set by cmdline arg or remain default (0)
	 */
	AllowDebugChange = false;
	lp_load(get_dyn_CONFIGFILE(), true, false, false, true);

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
		set_global_myname(c->opt_requester_name);
	}

	if (!c->opt_workgroup) {
		c->opt_workgroup = smb_xstrdup(lp_workgroup());
	}

	if (!c->opt_target_workgroup) {
		c->opt_target_workgroup = smb_xstrdup(lp_workgroup());
	}

	if (!init_names())
		exit(1);

	load_interfaces();

	/* this makes sure that when we do things like call scripts,
	   that it won't assert becouse we are not root */
	sec_init();

	rc = net_run_function(c, argc_new-1, argv_new+1, "net", net_func);

	DEBUG(2,("return code = %d\n", rc));

	libnetapi_free(c->netapi_ctx);

	poptFreeContext(pc);

	TALLOC_FREE(frame);
	return rc;
}
