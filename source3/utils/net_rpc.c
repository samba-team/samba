/* 
   Samba Unix/Linux SMB client library 
   Distributed SMB/CIFS Server Management Utility 
   Copyright (C) 2001 Andrew Bartlett (abartlet@samba.org)

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
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */
 
#include "includes.h"
#include "../utils/net.h"

/**
 * @file net_rpc.c
 *
 * @brief RPC based subcommands for the 'net' utility.
 *
 * This file should contain much of the functionality that used to
 * be found in rpcclient, execpt that the commands should change 
 * less often, and the fucntionality should be sane (the user is not 
 * expected to know a rid/sid before they conduct an operation etc.)
 *
 * @todo Perhaps eventually these should be split out into a number
 * of files, as this could get quite big.
 **/


/* A function of this type is passed to the 'run_rpc_command' wrapper */
typedef NTSTATUS (*rpc_command_fn)(const DOM_SID *, struct cli_state *, TALLOC_CTX *, int, const char **);

/**
 * Many of the RPC functions need the domain sid.  This function gets
 *  it at the start of every run 
 *
 * @param cli A cli_state already connected to the remote machine
 *
 * @return The Domain SID of the remote machine.
 **/

static DOM_SID *net_get_remote_domain_sid(struct cli_state *cli)
{
	DOM_SID *domain_sid;
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_OK;
	uint32 info_class = 5;
	fstring domain_name;
	TALLOC_CTX *mem_ctx;
	
	if (!(domain_sid = malloc(sizeof(DOM_SID)))){
		DEBUG(0,("fetch_domain_sid: malloc returned NULL!\n"));
		goto error;
	}
	    
	if (!(mem_ctx=talloc_init()))
	{
		DEBUG(0,("fetch_domain_sid: talloc_init returned NULL!\n"));
		goto error;
	}


	if (!cli_nt_session_open (cli, PIPE_LSARPC)) {
		fprintf(stderr, "could not initialise lsa pipe\n");
		goto error;
	}
	
	result = cli_lsa_open_policy(cli, mem_ctx, True, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto error;
	}

	result = cli_lsa_query_info_policy(cli, mem_ctx, &pol, info_class, 
					   domain_name, domain_sid);
	if (!NT_STATUS_IS_OK(result)) {
		goto error;
	}

	cli_lsa_close(cli, mem_ctx, &pol);
	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return domain_sid;

 error:
	fprintf(stderr, "could not obtain sid for domain %s\n", cli->domain);

	if (!NT_STATUS_IS_OK(result)) {
		fprintf(stderr, "error: %s\n", get_nt_error_msg(result));
	}

	exit(1);
}

/**
 * Run a single RPC command, from start to finish.
 *
 * @param pipe_name the pipe to connect to (usually a PIPE_ constant)
 * @param conn_flag a NET_FLAG_ combination.  Passed to 
 *                   net_make_ipc_connection.
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 * @return A shell status integer (0 for success)
 */

static int run_rpc_command(const char *pipe_name, int conn_flags,
			   rpc_command_fn fn,
			   int argc, const char **argv) 
{
	struct cli_state *cli = net_make_ipc_connection(conn_flags);
	TALLOC_CTX *mem_ctx;
	NTSTATUS nt_status;
	DOM_SID *domain_sid;

	if (!cli) {
		return -1;
	}

	domain_sid = net_get_remote_domain_sid(cli);

	/* Create mem_ctx */
	
	if (!(mem_ctx = talloc_init())) {
		DEBUG(0, ("talloc_init() failed\n"));
		cli_shutdown(cli);
		return -1;
	}
	
	if (!cli_nt_session_open(cli, pipe_name)) {
		DEBUG(0, ("Could not initialise samr pipe\n"));
	}
	
	nt_status = fn(domain_sid, cli, mem_ctx, argc, argv);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("rpc command function failed! (%s)\n", get_nt_error_msg(nt_status)));
	} else {
		DEBUG(5, ("rpc command function succedded\n"));
	}
		
	    
	if (cli->nt_pipe_fnum)
		cli_nt_session_close(cli);
	
	talloc_destroy(mem_ctx);

	return (!NT_STATUS_IS_OK(nt_status));
}


/****************************************************************************/


/** 
 * Force a change of the trust acccount password.
 *
 * All paramaters are provided by the run_rpc_command funcion, except for
 * argc, argv which are passes through. 
 *
 * @param domain_sid The domain sid aquired from the remote server
 * @param cli A cli_state connected to the server.
 * @param mem_ctx Talloc context, destoyed on compleation of the function.
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return Normal NTSTATUS return.
 **/

static NTSTATUS rpc_changetrustpw_internals(const DOM_SID *domain_sid, struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				       int argc, const char **argv) {
	
	return trust_pw_find_change_and_store_it(cli, mem_ctx, opt_target_workgroup);
}

/** 
 * Force a change of the trust acccount password.
 *
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return A shell status integer (0 for success)
 **/

static int rpc_changetrustpw(int argc, const char **argv) 
{
	return run_rpc_command(PIPE_NETLOGON, NET_FLAGS_ANONYMOUS | NET_FLAGS_PDC, rpc_changetrustpw_internals,
			       argc, argv);
}


/****************************************************************************/


/** 
 * Join a domain, the old way.
 *
 * This uses 'machinename' as the inital password, and changes it. 
 *
 * The password should be created with 'server manager' or eqiv first.
 *
 * All paramaters are provided by the run_rpc_command funcion, except for
 * argc, argv which are passes through. 
 *
 * @param domain_sid The domain sid aquired from the remote server
 * @param cli A cli_state connected to the server.
 * @param mem_ctx Talloc context, destoyed on compleation of the function.
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return Normal NTSTATUS return.
 **/

static NTSTATUS rpc_join_oldstyle_internals(const DOM_SID *domain_sid, struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				       int argc, const char **argv) {
	
	extern pstring global_myname;
	fstring trust_passwd;
	unsigned char orig_trust_passwd_hash[16];

	fstrcpy(trust_passwd, global_myname);
	strlower(trust_passwd);
	E_md4hash( (uchar *)trust_passwd, orig_trust_passwd_hash);

	return trust_pw_change_and_store_it(cli, mem_ctx, orig_trust_passwd_hash);
}

/** 
 * Join a domain, the old way.
 *
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return A shell status integer (0 for success)
 **/

static int rpc_join_oldstyle(int argc, const char **argv) 
{
	return run_rpc_command(PIPE_NETLOGON, NET_FLAGS_ANONYMOUS | NET_FLAGS_PDC, rpc_join_oldstyle_internals,
			       argc, argv);
}

/** 
 * Basic usage function for 'net rpc join'
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 **/

static int rpc_join_usage(int argc, const char **argv) 
{	
	d_printf("  net rpc join \t to join a domain with admin username & password\n");
	d_printf("  net rpc join oldstyle \t to join a domain created in server manager\n");
	return -1;
}

/** 
 * 'net rpc join' entrypoint.
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * Main 'net_rpc_join()' (where the admain username/password is used) is 
 * in net_rpc_join.c
 **/

static int rpc_join(int argc, const char **argv) 
{
	struct functable func[] = {
		{"oldstyle", rpc_join_oldstyle},
		{NULL, NULL}
	};
	
	if (argc == 0) {
		return net_rpc_join(argc, argv);
	}

	return net_run_function(argc, argv, func, rpc_join_usage);
}


/****************************************************************************/


/** 
 * Add a new user to a remote RPC server
 *
 * All paramaters are provided by the run_rpc_command funcion, except for
 * argc, argv which are passes through. 
 *
 * @param domain_sid The domain sid aquired from the remote server
 * @param cli A cli_state connected to the server.
 * @param mem_ctx Talloc context, destoyed on compleation of the function.
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return Normal NTSTATUS return.
 **/

static NTSTATUS rpc_user_add_internals(const DOM_SID *domain_sid, struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				       int argc, const char **argv) {
	
	POLICY_HND connect_pol, domain_pol, user_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	const char *acct_name;
	uint16 acb_info;
	uint32 unknown, user_rid;

	if (argc != 1) {
		d_printf("Usage: net rpc user add username\n");
		return NT_STATUS_OK;
	}

	acct_name = argv[0];

	/* Get sam policy handle */
	
	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}
	
	/* Get domain policy handle */
	
	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      domain_sid, &domain_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Create domain user */

	acb_info = ACB_NORMAL;
	unknown = 0xe005000b; /* No idea what this is - a permission mask? */

	result = cli_samr_create_dom_user(cli, mem_ctx, &domain_pol,
					  acct_name, acb_info, unknown,
					  &user_pol, &user_rid);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

 done:
	return result;
}

/** 
 * Add a new user to a remote RPC server
 *
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return A shell status integer (0 for success)
 **/

static int rpc_user_add(int argc, const char **argv) 
{
	return run_rpc_command(PIPE_SAMR, 0, rpc_user_add_internals,
			       argc, argv);
}

/** 
 * Basic usage function for 'net rpc user'
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 **/

static int rpc_user_usage(int argc, const char **argv) 
{
	d_printf("  net rpc user add \t to add a user\n");
	return -1;
}

/** 
 * 'net rpc user' entrypoint.
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 **/

static int rpc_user(int argc, const char **argv) 
{
	struct functable func[] = {
		{"add", rpc_user_add},
		{NULL, NULL}
	};
	
	if (argc == 0) {
		return rpc_user_usage(argc, argv);
	}

	return net_run_function(argc, argv, func, rpc_user_usage);
}


/****************************************************************************/



/** 
 * ABORT the shutdown of a remote RPC Server
 *
 * All paramaters are provided by the run_rpc_command funcion, except for
 * argc, argv which are passed through. 
 *
 * @param domain_sid The domain sid aquired from the remote server
 * @param cli A cli_state connected to the server.
 * @param mem_ctx Talloc context, destoyed on compleation of the function.
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return Normal NTSTATUS return.
 **/

static NTSTATUS rpc_shutdown_abort_internals(const DOM_SID *domain_sid, struct cli_state *cli, TALLOC_CTX *mem_ctx, 
					     int argc, const char **argv) 
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	
	result = cli_reg_abort_shutdown(cli, mem_ctx);
	
	if (NT_STATUS_IS_OK(result))
		DEBUG(5,("cmd_reg_abort_shutdown: query succeeded\n"));
	else
		DEBUG(5,("cmd_reg_abort_shutdown: query failed\n"));
	
	return result;
}


/** 
 * ABORT the Shut down of a remote RPC server
 *
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return A shell status integer (0 for success)
 **/

static int rpc_shutdown_abort(int argc, const char **argv) 
{
	return run_rpc_command(PIPE_WINREG, 0, rpc_shutdown_abort_internals,
			       argc, argv);
}

/** 
 * Shut down a remote RPC Server
 *
 * All paramaters are provided by the run_rpc_command funcion, except for
 * argc, argv which are passes through. 
 *
 * @param domain_sid The domain sid aquired from the remote server
 * @param cli A cli_state connected to the server.
 * @param mem_ctx Talloc context, destoyed on compleation of the function.
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return Normal NTSTATUS return.
 **/

static NTSTATUS rpc_shutdown_internals(const DOM_SID *domain_sid, struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				       int argc, const char **argv) 
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        char *msg = "This machine will be shutdown shortly";
	uint32 timeout = 20;
	uint16 flgs = 0;
	BOOL reboot = opt_reboot;
	BOOL force = opt_force;
#if 0
	poptContext pc;
	int rc;

	struct poptOption long_options[] = {
		{"message",    'm', POPT_ARG_STRING, &msg},
		{"timeout",    't', POPT_ARG_INT,    &timeout},
		{"reboot",     'r', POPT_ARG_NONE,   &reboot},
		{"force",      'f', POPT_ARG_NONE,   &force},
		{ 0, 0, 0, 0}
	};

	pc = poptGetContext(NULL, argc, (const char **) argv, long_options, 
			    POPT_CONTEXT_KEEP_FIRST);

	rc = poptGetNextOpt(pc);
	
	if (rc < -1) {
		/* an error occurred during option processing */
		DEBUG(0, ("%s: %s\n",
			  poptBadOption(pc, POPT_BADOPTION_NOALIAS),
			  poptStrerror(rc)));
		return NT_STATUS_INVALID_PARAMETER;
	}
#endif
	if (reboot) {
		flgs |= REG_REBOOT_ON_SHUTDOWN;
	}
	if (force) {
		flgs |= REG_FORCE_SHUTDOWN;
	}
	if (opt_comment) {
		msg = opt_comment;
	}
	if (opt_timeout) {
		timeout = opt_timeout;
	}

	/* create an entry */
	result = cli_reg_shutdown(cli, mem_ctx, msg, timeout, flgs);

	if (NT_STATUS_IS_OK(result))
		DEBUG(5,("Shutdown of remote machine succeeded\n"));
	else
		DEBUG(0,("Shutdown of remote machine failed!\n"));

	return result;
}

/** 
 * Shut down a remote RPC server
 *
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return A shell status integer (0 for success)
 **/

static int rpc_shutdown(int argc, const char **argv) 
{
	return run_rpc_command(PIPE_WINREG, 0, rpc_shutdown_internals,
				       argc, argv);
}

/****************************************************************************/


/** 
 * Basic usage function for 'net rpc'
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 **/

int net_rpc_usage(int argc, const char **argv) 
{
	d_printf("  net rpc join \tto join a domain \n");
	d_printf("  net rpc user \tto add, delete and list users\n");
	d_printf("  net rpc changetrustpw \tto change the trust account password\n");
	d_printf("  net rpc abortshutdown \tto to abort the shutdown of a remote server\n");
	d_printf("  net rpc shutdown \tto to shutdown a remote server\n");
	d_printf("\n");
	d_printf("'net rpc shutdown' also accepts the following miscellaneous options:\n"); /* misc options */
	d_printf("\t-r or --reboot\trequest remote server reboot on shutdown\n");
	d_printf("\t-f or --force\trequest the remote server force its shutdown\n");
	d_printf("\t-t or --timeout=<timeout>\tnumber of seconds before shutdown\n");
	d_printf("\t-c or --comment=<message>\ttext message to display on impending shutdown\n");
	return -1;
}

/** 
 * 'net rpc' entrypoint.
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 **/

int net_rpc(int argc, const char **argv)
{
	struct functable func[] = {
		{"join", rpc_join},
		{"user", rpc_user},
		{"changetrustpw", rpc_changetrustpw},
		{"abortshutdown", rpc_shutdown_abort},
		{"shutdown", rpc_shutdown},
		{NULL, NULL}
	};
	return net_run_function(argc, argv, func, net_rpc_usage);
}
