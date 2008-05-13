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

/*
  run a function from a function table. If not found then
  call the specified usage function
*/
int net_run_function(struct net_context *c, int argc, const char **argv,
		     struct functable *table,
		     int (*usage_fn)(struct net_context *c,
				     int argc, const char **argv))
{
	int i;

	if (argc < 1) {
		d_printf("\nUsage: \n");
		return usage_fn(c, argc, argv);
	}
	for (i=0; table[i].funcname; i++) {
		if (StrCaseCmp(argv[0], table[i].funcname) == 0)
			return table[i].fn(c, argc-1, argv+1);
	}
	d_fprintf(stderr, "No command: %s\n", argv[0]);
	return usage_fn(c, argc, argv);
}

/*
 * run a function from a function table.
 */
int net_run_function2(struct net_context *c, int argc, const char **argv,
		      const char *whoami, struct functable2 *table)
{
	int i;

	if (argc != 0) {
		for (i=0; table[i].funcname; i++) {
			if (StrCaseCmp(argv[0], table[i].funcname) == 0)
				return table[i].fn(c, argc-1, argv+1);
		}
	}

	for (i=0; table[i].funcname != NULL; i++) {
		d_printf("%s %-15s %s\n", whoami, table[i].funcname,
			 table[i].helptext);
	}

	return -1;
}

/****************************************************************************
 Connect to \\server\service.
****************************************************************************/

NTSTATUS connect_to_service(struct net_context *c,
					struct cli_state **cli_ctx,
					struct sockaddr_storage *server_ss,
					const char *server_name,
					const char *service_name,
					const char *service_type)
{
	NTSTATUS nt_status;

	c->opt_password = net_prompt_pass(c, c->opt_user_name);
	if (!c->opt_password) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = cli_full_connection(cli_ctx, NULL, server_name,
					server_ss, c->opt_port,
					service_name, service_type,
					c->opt_user_name, c->opt_workgroup,
					c->opt_password, 0, Undefined, NULL);
	if (!NT_STATUS_IS_OK(nt_status)) {
		d_fprintf(stderr, "Could not connect to server %s\n", server_name);

		/* Display a nicer message depending on the result */

		if (NT_STATUS_V(nt_status) ==
		    NT_STATUS_V(NT_STATUS_LOGON_FAILURE))
			d_fprintf(stderr, "The username or password was not correct.\n");

		if (NT_STATUS_V(nt_status) ==
		    NT_STATUS_V(NT_STATUS_ACCOUNT_LOCKED_OUT))
			d_fprintf(stderr, "The account was locked out.\n");

		if (NT_STATUS_V(nt_status) ==
		    NT_STATUS_V(NT_STATUS_ACCOUNT_DISABLED))
			d_fprintf(stderr, "The account was disabled.\n");
		return nt_status;
	}

	if (c->smb_encrypt) {
		nt_status = cli_force_encryption(*cli_ctx,
					c->opt_user_name,
					c->opt_password,
					c->opt_workgroup);

		if (NT_STATUS_EQUAL(nt_status,NT_STATUS_NOT_SUPPORTED)) {
			d_printf("Encryption required and "
				"server that doesn't support "
				"UNIX extensions - failing connect\n");
		} else if (NT_STATUS_EQUAL(nt_status,NT_STATUS_UNKNOWN_REVISION)) {
			d_printf("Encryption required and "
				"can't get UNIX CIFS extensions "
				"version from server.\n");
		} else if (NT_STATUS_EQUAL(nt_status,NT_STATUS_UNSUPPORTED_COMPRESSION)) {
			d_printf("Encryption required and "
				"share %s doesn't support "
				"encryption.\n", service_name);
		} else if (!NT_STATUS_IS_OK(nt_status)) {
			d_printf("Encryption required and "
				"setup failed with error %s.\n",
				nt_errstr(nt_status));
		}

		if (!NT_STATUS_IS_OK(nt_status)) {
			cli_shutdown(*cli_ctx);
			*cli_ctx = NULL;
		}
	}

	return nt_status;
}

/****************************************************************************
 Connect to \\server\ipc$.
****************************************************************************/

NTSTATUS connect_to_ipc(struct net_context *c,
			struct cli_state **cli_ctx,
			struct sockaddr_storage *server_ss,
			const char *server_name)
{
	return connect_to_service(c, cli_ctx, server_ss, server_name, "IPC$",
				  "IPC");
}

/****************************************************************************
 Connect to \\server\ipc$ anonymously.
****************************************************************************/

NTSTATUS connect_to_ipc_anonymous(struct net_context *c,
				struct cli_state **cli_ctx,
				struct sockaddr_storage *server_ss,
				const char *server_name)
{
	NTSTATUS nt_status;

	nt_status = cli_full_connection(cli_ctx, c->opt_requester_name,
					server_name, server_ss, c->opt_port,
					"IPC$", "IPC",
					"", "",
					"", 0, Undefined, NULL);

	if (NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	} else {
		DEBUG(1,("Cannot connect to server (anonymously).  Error was %s\n", nt_errstr(nt_status)));
		return nt_status;
	}
}

/****************************************************************************
 Return malloced user@realm for krb5 login.
****************************************************************************/

static char *get_user_and_realm(const char *username)
{
	char *user_and_realm = NULL;

	if (!username) {
		return NULL;
	}
	if (strchr_m(username, '@')) {
		user_and_realm = SMB_STRDUP(username);
	} else {
		if (asprintf(&user_and_realm, "%s@%s", username, lp_realm()) == -1) {
			user_and_realm = NULL;
		}
	}
	return user_and_realm;
}

/****************************************************************************
 Connect to \\server\ipc$ using KRB5.
****************************************************************************/

NTSTATUS connect_to_ipc_krb5(struct net_context *c,
			struct cli_state **cli_ctx,
			struct sockaddr_storage *server_ss,
			const char *server_name)
{
	NTSTATUS nt_status;
	char *user_and_realm = NULL;

	/* FIXME: Should get existing kerberos ticket if possible. */
	c->opt_password = net_prompt_pass(c, c->opt_user_name);
	if (!c->opt_password) {
		return NT_STATUS_NO_MEMORY;
	}

	user_and_realm = get_user_and_realm(c->opt_user_name);
	if (!user_and_realm) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = cli_full_connection(cli_ctx, NULL, server_name,
					server_ss, c->opt_port,
					"IPC$", "IPC",
					user_and_realm, c->opt_workgroup,
					c->opt_password,
					CLI_FULL_CONNECTION_USE_KERBEROS,
					Undefined, NULL);

	SAFE_FREE(user_and_realm);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1,("Cannot connect to server using kerberos.  Error was %s\n", nt_errstr(nt_status)));
		return nt_status;
	}

        if (c->smb_encrypt) {
		nt_status = cli_cm_force_encryption(*cli_ctx,
					user_and_realm,
					c->opt_password,
					c->opt_workgroup,
                                        "IPC$");
		if (!NT_STATUS_IS_OK(nt_status)) {
			cli_shutdown(*cli_ctx);
			*cli_ctx = NULL;
		}
	}

	return nt_status;
}

/**
 * Connect a server and open a given pipe
 *
 * @param cli_dst		A cli_state
 * @param pipe			The pipe to open
 * @param got_pipe		boolean that stores if we got a pipe
 *
 * @return Normal NTSTATUS return.
 **/
NTSTATUS connect_dst_pipe(struct net_context *c, struct cli_state **cli_dst,
			  struct rpc_pipe_client **pp_pipe_hnd, int pipe_num)
{
	NTSTATUS nt_status;
	char *server_name = SMB_STRDUP("127.0.0.1");
	struct cli_state *cli_tmp = NULL;
	struct rpc_pipe_client *pipe_hnd = NULL;

	if (server_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (c->opt_destination) {
		SAFE_FREE(server_name);
		if ((server_name = SMB_STRDUP(c->opt_destination)) == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* make a connection to a named pipe */
	nt_status = connect_to_ipc(c, &cli_tmp, NULL, server_name);
	if (!NT_STATUS_IS_OK(nt_status)) {
		SAFE_FREE(server_name);
		return nt_status;
	}

	pipe_hnd = cli_rpc_pipe_open_noauth(cli_tmp, pipe_num, &nt_status);
	if (!pipe_hnd) {
		DEBUG(0, ("couldn't not initialize pipe\n"));
		cli_shutdown(cli_tmp);
		SAFE_FREE(server_name);
		return nt_status;
	}

	*cli_dst = cli_tmp;
	*pp_pipe_hnd = pipe_hnd;
	SAFE_FREE(server_name);

	return nt_status;
}

/****************************************************************************
 Use the local machine account (krb) and password for this session.
****************************************************************************/

int net_use_krb_machine_account(struct net_context *c)
{
	char *user_name = NULL;

	if (!secrets_init()) {
		d_fprintf(stderr, "ERROR: Unable to open secrets database\n");
		exit(1);
	}

	c->opt_password = secrets_fetch_machine_password(
				c->opt_target_workgroup, NULL, NULL);
	if (asprintf(&user_name, "%s$@%s", global_myname(), lp_realm()) == -1) {
		return -1;
	}
	c->opt_user_name = user_name;
	return 0;
}

/****************************************************************************
 Use the machine account name and password for this session.
****************************************************************************/

int net_use_machine_account(struct net_context *c)
{
	char *user_name = NULL;

	if (!secrets_init()) {
		d_fprintf(stderr, "ERROR: Unable to open secrets database\n");
		exit(1);
	}

	c->opt_password = secrets_fetch_machine_password(
				c->opt_target_workgroup, NULL, NULL);
	if (asprintf(&user_name, "%s$", global_myname()) == -1) {
		return -1;
	}
	c->opt_user_name = user_name;
	return 0;
}

bool net_find_server(struct net_context *c,
			const char *domain,
			unsigned flags,
			struct sockaddr_storage *server_ss,
			char **server_name)
{
	const char *d = domain ? domain : c->opt_target_workgroup;

	if (c->opt_host) {
		*server_name = SMB_STRDUP(c->opt_host);
	}

	if (c->opt_have_ip) {
		*server_ss = c->opt_dest_ip;
		if (!*server_name) {
			char addr[INET6_ADDRSTRLEN];
			print_sockaddr(addr, sizeof(addr), &c->opt_dest_ip);
			*server_name = SMB_STRDUP(addr);
		}
	} else if (*server_name) {
		/* resolve the IP address */
		if (!resolve_name(*server_name, server_ss, 0x20))  {
			DEBUG(1,("Unable to resolve server name\n"));
			return false;
		}
	} else if (flags & NET_FLAGS_PDC) {
		fstring dc_name;
		struct sockaddr_storage pdc_ss;

		if (!get_pdc_ip(d, &pdc_ss)) {
			DEBUG(1,("Unable to resolve PDC server address\n"));
			return false;
		}

		if (is_zero_addr(&pdc_ss)) {
			return false;
		}

		if (!name_status_find(d, 0x1b, 0x20, &pdc_ss, dc_name)) {
			return false;
		}

		*server_name = SMB_STRDUP(dc_name);
		*server_ss = pdc_ss;
	} else if (flags & NET_FLAGS_DMB) {
		struct sockaddr_storage msbrow_ss;
		char addr[INET6_ADDRSTRLEN];

		/*  if (!resolve_name(MSBROWSE, &msbrow_ip, 1)) */
		if (!resolve_name(d, &msbrow_ss, 0x1B))  {
			DEBUG(1,("Unable to resolve domain browser via name lookup\n"));
			return false;
		}
		*server_ss = msbrow_ss;
		print_sockaddr(addr, sizeof(addr), server_ss);
		*server_name = SMB_STRDUP(addr);
	} else if (flags & NET_FLAGS_MASTER) {
		struct sockaddr_storage brow_ss;
		char addr[INET6_ADDRSTRLEN];
		if (!resolve_name(d, &brow_ss, 0x1D))  {
				/* go looking for workgroups */
			DEBUG(1,("Unable to resolve master browser via name lookup\n"));
			return false;
		}
		*server_ss = brow_ss;
		print_sockaddr(addr, sizeof(addr), server_ss);
		*server_name = SMB_STRDUP(addr);
	} else if (!(flags & NET_FLAGS_LOCALHOST_DEFAULT_INSANE)) {
		if (!interpret_string_addr(server_ss,
					"127.0.0.1", AI_NUMERICHOST)) {
			DEBUG(1,("Unable to resolve 127.0.0.1\n"));
			return false;
		}
		*server_name = SMB_STRDUP("127.0.0.1");
	}

	if (!*server_name) {
		DEBUG(1,("no server to connect to\n"));
		return false;
	}

	return true;
}

bool net_find_pdc(struct sockaddr_storage *server_ss,
		fstring server_name,
		const char *domain_name)
{
	if (!get_pdc_ip(domain_name, server_ss)) {
		return false;
	}
	if (is_zero_addr(server_ss)) {
		return false;
	}

	if (!name_status_find(domain_name, 0x1b, 0x20, server_ss, server_name)) {
		return false;
	}

	return true;
}

NTSTATUS net_make_ipc_connection(struct net_context *c, unsigned flags,
				 struct cli_state **pcli)
{
	return net_make_ipc_connection_ex(c, NULL, NULL, NULL, flags, pcli);
}

NTSTATUS net_make_ipc_connection_ex(struct net_context *c ,const char *domain,
				    const char *server,
				    struct sockaddr_storage *pss,
				    unsigned flags, struct cli_state **pcli)
{
	char *server_name = NULL;
	struct sockaddr_storage server_ss;
	struct cli_state *cli = NULL;
	NTSTATUS nt_status;

	if ( !server || !pss ) {
		if (!net_find_server(c, domain, flags, &server_ss,
				     &server_name)) {
			d_fprintf(stderr, "Unable to find a suitable server\n");
			nt_status = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
	} else {
		server_name = SMB_STRDUP( server );
		server_ss = *pss;
	}

	if (flags & NET_FLAGS_ANONYMOUS) {
		nt_status = connect_to_ipc_anonymous(c, &cli, &server_ss,
						     server_name);
	} else {
		nt_status = connect_to_ipc(c, &cli, &server_ss,
					   server_name);
	}

	/* store the server in the affinity cache if it was a PDC */

	if ( (flags & NET_FLAGS_PDC) && NT_STATUS_IS_OK(nt_status) )
		saf_store( cli->server_domain, cli->desthost );

	SAFE_FREE(server_name);
	if (!NT_STATUS_IS_OK(nt_status)) {
		d_fprintf(stderr, "Connection failed: %s\n",
			  nt_errstr(nt_status));
		cli = NULL;
	}

done:
	if (pcli != NULL) {
		*pcli = cli;
	}
	return nt_status;
}

static int net_user(struct net_context *c, int argc, const char **argv)
{
	if (net_ads_check(c) == 0)
		return net_ads_user(c, argc, argv);

	/* if server is not specified, default to PDC? */
	if (net_rpc_check(c, NET_FLAGS_PDC))
		return net_rpc_user(c, argc, argv);

	return net_rap_user(c, argc, argv);
}

static int net_group(struct net_context *c, int argc, const char **argv)
{
	if (net_ads_check(c) == 0)
		return net_ads_group(c, argc, argv);

	if (argc == 0 && net_rpc_check(c, NET_FLAGS_PDC))
		return net_rpc_group(c,argc, argv);

	return net_rap_group(c, argc, argv);
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

static int net_share(struct net_context *c, int argc, const char **argv)
{
	if (net_rpc_check(c, 0))
		return net_rpc_share(c, argc, argv);
	return net_rap_share(c, argc, argv);
}

static int net_file(struct net_context *c, int argc, const char **argv)
{
	if (net_rpc_check(c, 0))
		return net_rpc_file(c, argc, argv);
	return net_rap_file(c, argc, argv);
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

#ifdef WITH_FAKE_KASERVER

int net_help_afs(struct net_context *c, int argc, const char **argv)
{
	d_printf("  net afs key filename\n"
		 "\tImports a OpenAFS KeyFile into our secrets.tdb\n\n");
	d_printf("  net afs impersonate <user> <cell>\n"
		 "\tCreates a token for user@cell\n\n");
	return -1;
}

static int net_afs_key(struct net_context *c, int argc, const char **argv)
{
	int fd;
	struct afs_keyfile keyfile;

	if (argc != 2) {
		d_printf("usage: 'net afs key <keyfile> cell'\n");
		return -1;
	}

	if (!secrets_init()) {
		d_fprintf(stderr, "Could not open secrets.tdb\n");
		return -1;
	}

	if ((fd = open(argv[0], O_RDONLY, 0)) < 0) {
		d_fprintf(stderr, "Could not open %s\n", argv[0]);
		return -1;
	}

	if (read(fd, &keyfile, sizeof(keyfile)) != sizeof(keyfile)) {
		d_fprintf(stderr, "Could not read keyfile\n");
		return -1;
	}

	if (!secrets_store_afs_keyfile(argv[1], &keyfile)) {
		d_fprintf(stderr, "Could not write keyfile to secrets.tdb\n");
		return -1;
	}

	return 0;
}

static int net_afs_impersonate(struct net_context *c, int argc,
			       const char **argv)
{
	char *token;

	if (argc != 2) {
		fprintf(stderr, "Usage: net afs impersonate <user> <cell>\n");
	        exit(1);
	}

	token = afs_createtoken_str(argv[0], argv[1]);

	if (token == NULL) {
		fprintf(stderr, "Could not create token\n");
	        exit(1);
	}

	if (!afs_settoken_str(token)) {
		fprintf(stderr, "Could not set token into kernel\n");
	        exit(1);
	}

	printf("Success: %s@%s\n", argv[0], argv[1]);
	return 0;
}

static int net_afs(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{"key", net_afs_key},
		{"impersonate", net_afs_impersonate},
		{"help", net_help_afs},
		{NULL, NULL}
	};
	return net_run_function(c, argc, argv, func, net_help_afs);
}

#endif /* WITH_FAKE_KASERVER */

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
	pdb_search_destroy(search);
	return true;
}

static uint32 get_maxrid(void)
{
	uint32 max_rid = 0;

	if (!search_maxrid(pdb_search_users(0), "users", &max_rid))
		return 0;

	if (!search_maxrid(pdb_search_groups(), "groups", &max_rid))
		return 0;

	if (!search_maxrid(pdb_search_aliases(get_global_sam_sid()),
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

/****************************************************************************
****************************************************************************/

const char *net_prompt_pass(struct net_context *c, const char *user)
{
	char *prompt = NULL;
	const char *pass = NULL;

	if (c->opt_password) {
		return c->opt_password;
	}

	if (c->opt_machine_pass) {
		return NULL;
	}

	asprintf(&prompt, "Enter %s's password:", user);
	if (!prompt) {
		return NULL;
	}

	pass = getpass(prompt);
	SAFE_FREE(prompt);

	return pass;
}

/* main function table */
static struct functable net_func[] = {
	{"RPC", net_rpc},
	{"RAP", net_rap},
	{"ADS", net_ads},

	/* eventually these should auto-choose the transport ... */
	{"FILE", net_file},
	{"SHARE", net_share},
	{"SESSION", net_rap_session},
	{"SERVER", net_rap_server},
	{"DOMAIN", net_rap_domain},
	{"PRINTQ", net_rap_printq},
	{"USER", net_user},
	{"GROUP", net_group},
	{"GROUPMAP", net_groupmap},
	{"SAM", net_sam},
	{"VALIDATE", net_rap_validate},
	{"GROUPMEMBER", net_rap_groupmember},
	{"ADMIN", net_rap_admin},
	{"SERVICE", net_rap_service},
	{"PASSWORD", net_rap_password},
	{"CHANGETRUSTPW", net_changetrustpw},
	{"CHANGESECRETPW", net_changesecretpw},
	{"TIME", net_time},
	{"LOOKUP", net_lookup},
	{"JOIN", net_join},
	{"DOM", net_dom},
	{"CACHE", net_cache},
	{"GETLOCALSID", net_getlocalsid},
	{"SETLOCALSID", net_setlocalsid},
	{"SETDOMAINSID", net_setdomainsid},
	{"GETDOMAINSID", net_getdomainsid},
	{"MAXRID", net_maxrid},
	{"IDMAP", net_idmap},
	{"STATUS", net_status},
	{"USERSHARE", net_usershare},
	{"USERSIDLIST", net_usersidlist},
	{"CONF", net_conf},
	{"REGISTRY", net_registry},
#ifdef WITH_FAKE_KASERVER
	{"AFS", net_afs},
#endif

	{"HELP", net_help},
	{NULL, NULL}
};


/****************************************************************************
  main program
****************************************************************************/
 int main(int argc, const char **argv)
{
	int opt,i;
	char *p;
	int rc = 0;
	int argc_new = 0;
	const char ** argv_new;
	poptContext pc;
	TALLOC_CTX *frame = talloc_stackframe();
	struct net_context *c = talloc_zero(frame, struct net_context);

	struct poptOption long_options[] = {
		{"help",	'h', POPT_ARG_NONE,   0, 'h'},
		{"workgroup",	'w', POPT_ARG_STRING, &c->opt_target_workgroup},
		{"user",	'U', POPT_ARG_STRING, &c->opt_user_name, 'U'},
		{"ipaddress",	'I', POPT_ARG_STRING, 0,'I'},
		{"port",	'p', POPT_ARG_INT,    &c->opt_port},
		{"myname",	'n', POPT_ARG_STRING, &c->opt_requester_name},
		{"server",	'S', POPT_ARG_STRING, &c->opt_host},
		{"encrypt",	'e', POPT_ARG_NONE,   NULL, 'e', "Encrypt SMB transport (UNIX extended servers only)" },
		{"container",	'c', POPT_ARG_STRING, &c->opt_container},
		{"comment",	'C', POPT_ARG_STRING, &c->opt_comment},
		{"maxusers",	'M', POPT_ARG_INT,    &c->opt_maxusers},
		{"flags",	'F', POPT_ARG_INT,    &c->opt_flags},
		{"long",	'l', POPT_ARG_NONE,   &c->opt_long_list_entries},
		{"reboot",	'r', POPT_ARG_NONE,   &c->opt_reboot},
		{"force",	'f', POPT_ARG_NONE,   &c->opt_force},
		{"stdin",	'i', POPT_ARG_NONE,   &c->opt_stdin},
		{"timeout",	't', POPT_ARG_INT,    &c->opt_timeout},
		{"machine-pass",'P', POPT_ARG_NONE,   &c->opt_machine_pass},
		{"myworkgroup", 'W', POPT_ARG_STRING, &c->opt_workgroup},
		{"verbose",	'v', POPT_ARG_NONE,   &c->opt_verbose},
		{"test",	'T', POPT_ARG_NONE,   &c->opt_testmode},
		/* Options for 'net groupmap set' */
		{"local",       'L', POPT_ARG_NONE,   &c->opt_localgroup},
		{"domain",      'D', POPT_ARG_NONE,   &c->opt_domaingroup},
		{"ntname",      'N', POPT_ARG_STRING, &c->opt_newntname},
		{"rid",         'R', POPT_ARG_INT,    &c->opt_rid},
		/* Options for 'net rpc share migrate' */
		{"acls",	0, POPT_ARG_NONE,     &c->opt_acls},
		{"attrs",	0, POPT_ARG_NONE,     &c->opt_attrs},
		{"timestamps",	0, POPT_ARG_NONE,     &c->opt_timestamps},
		{"exclude",	'X', POPT_ARG_STRING, &c->opt_exclude},
		{"destination",	0, POPT_ARG_STRING,   &c->opt_destination},
		{"tallocreport", 0, POPT_ARG_NONE,    &c->do_talloc_report},

		POPT_COMMON_SAMBA
		{ 0, 0, 0, 0}
	};


	zero_addr(&c->opt_dest_ip);

	load_case_tables();

	/* set default debug level to 0 regardless of what smb.conf sets */
	DEBUGLEVEL_CLASS[DBGC_ALL] = 0;
	dbf = x_stderr;

	pc = poptGetContext(NULL, argc, (const char **) argv, long_options,
			    POPT_CONTEXT_KEEP_FIRST);

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'h':
			net_help(c, argc, argv);
			exit(0);
			break;
		case 'e':
			c->smb_encrypt = true;
			break;
		case 'I':
			if (!interpret_string_addr(&c->opt_dest_ip,
						poptGetOptArg(pc), 0)) {
				d_fprintf(stderr, "\nInvalid ip address specified\n");
			} else {
				c->opt_have_ip = true;
			}
			break;
		case 'U':
			c->opt_user_specified = true;
			c->opt_user_name = SMB_STRDUP(c->opt_user_name);
			p = strchr(c->opt_user_name,'%');
			if (p) {
				*p = 0;
				c->opt_password = p+1;
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
	c->AllowDebugChange = false;
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

	if (!c->opt_user_name && getenv("LOGNAME")) {
		c->opt_user_name = getenv("LOGNAME");
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

	if (c->opt_machine_pass) {
		/* it is very useful to be able to make ads queries as the
		   machine account for testing purposes and for domain leave */

		net_use_krb_machine_account(c);
	}

	if (!c->opt_password) {
		c->opt_password = getenv("PASSWD");
	}

	rc = net_run_function(c, argc_new-1, argv_new+1, net_func, net_help);

	DEBUG(2,("return code = %d\n", rc));

	libnetapi_free(c->netapi_ctx);

	TALLOC_FREE(frame);
	return rc;
}
