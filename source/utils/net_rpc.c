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

extern pstring global_myname;

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
		fprintf(stderr, "error: %s\n", nt_errstr(result));
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
		DEBUG(0, ("rpc command function failed! (%s)\n", nt_errstr(nt_status)));
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

static int net_rpc_join_oldstyle(int argc, const char **argv) 
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
	d_printf("net rpc join -U <username>[%%password] [options]\n"\
		 "\t to join a domain with admin username & password\n"\
		 "\t\t password will be prompted if none is specified\n");
	d_printf("net rpc join [options except -U]\n"\
		 "\t to join a domain created in server manager\n\n\n");

	net_common_flags_usage(argc, argv);
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
 * Assume if a -U is specified, it's the new style, otherwise it's the
 * old style
 **/

int net_rpc_join(int argc, const char **argv) 
{
	if ((net_rpc_join_oldstyle(argc, argv) == 0))
		return 0;
	
	return net_rpc_join_newstyle(argc, argv);
}


/****************************************************************************/

/**
 * Basic usage function for 'net rpc user'
 * @param argc	Standard main() style argc.
 * @param argv	Standard main() style argv.  Initial components are already
 *		stripped.
 **/

static int rpc_user_usage(int argc, const char **argv)
{
	return net_help_user(argc, argv);
}

/** 
 * Add a new user to a remote RPC server
 *
 * All paramaters are provided by the run_rpc_command funcion, except for
 * argc, argv which are passes through. 
 *
 * @param domain_sid The domain sid acquired from the remote server
 * @param cli A cli_state connected to the server.
 * @param mem_ctx Talloc context, destoyed on completion of the function.
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
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
		d_printf("User must be specified\n");
		rpc_user_usage(argc, argv);
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
	if (!NT_STATUS_IS_OK(result)) {
		d_printf("Failed to add user %s - %s\n", acct_name, 
			 nt_errstr(result));
	} else {
		d_printf("Added user %s\n", acct_name);
	}
	return result;
}

/** 
 * Add a new user to a remote RPC server
 *
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
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
 * Delete a user from a remote RPC server
 *
 * All paramaters are provided by the run_rpc_command funcion, except for
 * argc, argv which are passes through. 
 *
 * @param domain_sid The domain sid acquired from the remote server
 * @param cli A cli_state connected to the server.
 * @param mem_ctx Talloc context, destoyed on completion of the function.
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return Normal NTSTATUS return.
 **/

static NTSTATUS rpc_user_del_internals(const DOM_SID *domain_sid, 
				       struct cli_state *cli, 
				       TALLOC_CTX *mem_ctx, 
				       int argc, const char **argv)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	POLICY_HND connect_pol, domain_pol, user_pol;

	if (argc < 1) {
		d_printf("User must be specified\n");
		rpc_user_usage(argc, argv);
		return NT_STATUS_OK;
	}
	/* Get sam policy and domain handles */

	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      domain_sid, &domain_pol);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Get handle on user */

	{
		uint32 *user_rids, num_rids, *name_types;
		uint32 flags = 0x000003e8; /* Unknown */

		result = cli_samr_lookup_names(cli, mem_ctx, &domain_pol,
					       flags, 1, (char **) &argv[0],
					       &num_rids, &user_rids,
					       &name_types);

		if (!NT_STATUS_IS_OK(result)) {
			goto done;
		}

		result = cli_samr_open_user(cli, mem_ctx, &domain_pol,
					    MAXIMUM_ALLOWED_ACCESS,
					    user_rids[0], &user_pol);

		if (!NT_STATUS_IS_OK(result)) {
			goto done;
		}
	}

	/* Delete user */

	result = cli_samr_delete_dom_user(cli, mem_ctx, &user_pol);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Display results */

 done:
	return result;

}	

/** 
 * Delete a user from a remote RPC server
 *
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return A shell status integer (0 for success)
 **/

static int rpc_user_delete(int argc, const char **argv) 
{
	return run_rpc_command(PIPE_SAMR, 0, rpc_user_del_internals,
			       argc, argv);
}

/** 
 * List user's groups on a remote RPC server
 *
 * All paramaters are provided by the run_rpc_command funcion, except for
 * argc, argv which are passes through. 
 *
 * @param domain_sid The domain sid acquired from the remote server
 * @param cli A cli_state connected to the server.
 * @param mem_ctx Talloc context, destoyed on completion of the function.
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return Normal NTSTATUS return.
 **/

static NTSTATUS 
rpc_user_info_internals(const DOM_SID *domain_sid, struct cli_state *cli,
			TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	POLICY_HND connect_pol, domain_pol, user_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 *rids, num_rids, *name_types, num_names;
	uint32 flags = 0x000003e8; /* Unknown */
	int i;
	char **names;
	DOM_GID *user_gids;

	if (argc < 1) {
		d_printf("User must be specified\n");
		rpc_user_usage(argc, argv);
		return NT_STATUS_OK;
	}
	/* Get sam policy handle */
	
	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);
	if (!NT_STATUS_IS_OK(result)) goto done;
	
	/* Get domain policy handle */
	
	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      domain_sid, &domain_pol);
	if (!NT_STATUS_IS_OK(result)) goto done;

	/* Get handle on user */

	result = cli_samr_lookup_names(cli, mem_ctx, &domain_pol,
				       flags, 1, (char **) &argv[0],
				       &num_rids, &rids, &name_types);

	if (!NT_STATUS_IS_OK(result)) goto done;

	result = cli_samr_open_user(cli, mem_ctx, &domain_pol,
				    MAXIMUM_ALLOWED_ACCESS,
				    rids[0], &user_pol);
	if (!NT_STATUS_IS_OK(result)) goto done;

	result = cli_samr_query_usergroups(cli, mem_ctx, &user_pol,
					   &num_rids, &user_gids);

	/* Look up rids */

	rids = (uint32 *)talloc(mem_ctx, sizeof(uint32) * num_rids);

	for (i = 0; i < num_rids; i++)
                rids[i] = user_gids[i].g_rid;

	result = cli_samr_lookup_rids(cli, mem_ctx, &domain_pol,
				      flags, num_rids, rids,
				      &num_names, &names, &name_types);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Display results */

	for (i = 0; i < num_names; i++)
		printf("%s\n", names[i]);

 done:
	return result;
}

/** 
 * List a user's groups from a remote RPC server
 *
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return A shell status integer (0 for success)
 **/

static int rpc_user_info(int argc, const char **argv) 
{
	return run_rpc_command(PIPE_SAMR, 0, rpc_user_info_internals,
			       argc, argv);
}

/** 
 * List users on a remote RPC server
 *
 * All paramaters are provided by the run_rpc_command funcion, except for
 * argc, argv which are passes through. 
 *
 * @param domain_sid The domain sid acquired from the remote server
 * @param cli A cli_state connected to the server.
 * @param mem_ctx Talloc context, destoyed on completion of the function.
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return Normal NTSTATUS return.
 **/

static NTSTATUS 
rpc_user_list_internals(const DOM_SID *domain_sid, struct cli_state *cli,
			TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	POLICY_HND connect_pol, domain_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 start_idx=0, max_entries=250, num_entries, i;
	SAM_DISPINFO_CTR ctr;
	SAM_DISPINFO_1 info1;

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

	/* Query domain users */
	ZERO_STRUCT(ctr);
	ZERO_STRUCT(info1);
	ctr.sam.info1 = &info1;
	if (opt_long_list_entries)
		d_printf("\nUser name             Comment"\
			 "\n-----------------------------\n");
	do {
		fstring user, desc;
		result = cli_samr_query_dispinfo(cli, mem_ctx, &domain_pol,
						 &start_idx, 1, &num_entries,
						 max_entries, &ctr);
		for (i = 0; i < num_entries; i++) {
			unistr2_to_ascii(user, &(&ctr.sam.info1->str[i])->uni_acct_name, sizeof(user)-1);
			if (opt_long_list_entries) 
				unistr2_to_ascii(desc, &(&ctr.sam.info1->str[i])->uni_acct_desc, sizeof(desc)-1);
			
			if (opt_long_list_entries)
				printf("%-21.21s %-50.50s\n", user, desc);
			else
				printf("%-21.21s\n", user);
		}
	} while (!NT_STATUS_IS_OK(result));

 done:
	return result;
}

/** 
 * 'net rpc user' entrypoint.
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 **/

int net_rpc_user(int argc, const char **argv) 
{
	struct functable func[] = {
		{"add", rpc_user_add},
		{"info", rpc_user_info},
		{"delete", rpc_user_delete},
		{NULL, NULL}
	};
	
	if (argc == 0) {
		if (opt_long_list_entries) {
		} else {
		}
			return run_rpc_command(PIPE_SAMR, 0, 
					       rpc_user_list_internals,
					       argc, argv);
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

/***************************************************************************
  NT Domain trusts code (i.e. 'net rpc trustdom' functionality)
  
 ***************************************************************************/

/**
 * Add interdomain trust account to the RPC server.
 * All parameters (except for argc and argv) are passed by run_rpc_command
 * function.
 *
 * @param domain_sid The domain sid acquired from the server
 * @param cli A cli_state connected to the server.
 * @param mem_ctx Talloc context, destoyed on completion of the function.
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return normal NTSTATUS return code
 */

static NTSTATUS rpc_trustdom_add_internals(const DOM_SID *domain_sid, struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				       int argc, const char **argv) {

	POLICY_HND connect_pol, domain_pol, user_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	char *acct_name;
	uint16 acb_info;
	uint32 unknown, user_rid;

	if (argc != 1) {
		d_printf("Usage: net rpc trustdom add <domain_name>\n");
		return NT_STATUS_OK;
	}

	/* 
	 * Make valid trusting domain account (ie. uppercased and with '$' appended)
	 */
	 
	if (asprintf(&acct_name, "%s$", argv[0]) < 0) {
		return NT_STATUS_NO_MEMORY;
	}

	strupper(acct_name);

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

	/* Create trusting domain's account */

	acb_info = ACB_DOMTRUST;
	unknown = 0xe005000b; /* No idea what this is - a permission mask? 
				 Is it needed for interdomain account also ? */

	result = cli_samr_create_dom_user(cli, mem_ctx, &domain_pol,
					  acct_name, acb_info, unknown,
					  &user_pol, &user_rid);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

 done:
	SAFE_FREE(acct_name);
	return result;
}

/**
 * Create interdomain trust account for a remote domain.
 *
 * @param argc standard argc
 * @param argv standard argv without initial components
 *
 * @return Integer status (0 means success)
 **/

static int rpc_trustdom_add(int argc, const char **argv)
{
	return run_rpc_command(PIPE_SAMR, 0, rpc_trustdom_add_internals,
			       argc, argv);
}


/**
 * Delete interdomain trust account for a remote domain.
 *
 * @param argc standard argc
 * @param argv standard argv without initial components
 *
 * @return Integer status (0 means success)
 **/
 
static int rpc_trustdom_del(int argc, const char **argv)
{
	d_printf("Sorry, not yet implemented.\n");
	return -1;
}

 
/**
 * Establish trust relationship to a trusting domain.
 * Interdomain account must already be created on remote PDC.
 *
 * @param argc standard argc
 * @param argv standard argv without initial components
 *
 * @return Integer status (0 means success)
 **/

extern char *opt_user_name;
extern char *opt_password;

static int rpc_trustdom_establish(int argc, const char **argv) {

	struct cli_state *cli;
	struct in_addr server_ip;
	POLICY_HND connect_hnd;
	TALLOC_CTX *mem_ctx;
	NTSTATUS nt_status;
	DOM_SID domain_sid;
	WKS_INFO_100 wks_info;
	
	char* domain_name;
	char* acct_name;
	fstring pdc_name;

	/*
	 * Connect to \\server\ipc$ as 'our domain' account with password
	 */

	domain_name = smb_xstrdup(argv[0]);
	strupper(domain_name);
	
	asprintf(&acct_name, "%s$", lp_workgroup());
	strupper(acct_name);
	
	opt_user_name = (char*)malloc(strlen(acct_name) + 1);
	safe_strcpy(opt_user_name, acct_name, strlen(acct_name) + 1);

	/* find the domain controller */
	if (!net_find_dc(&server_ip, pdc_name, domain_name)) {
		DEBUG(0, ("Coulnd find domain controller for domain %s\n", domain_name));
		return -1;
	}

	/* connect to ipc$ as username/password */
	nt_status = connect_to_ipc(&cli, &server_ip, pdc_name);
	if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT)) {

		/* Is it trusting domain account for sure ? */
		DEBUG(0, ("Couldn't verify trusting domain account. Error was %s\n",
			nt_errstr(nt_status)));
		return -1;
	}
	
	/*
	 * Connect to \\server\ipc$ again (this time anonymously)
	 */
	
	nt_status = connect_to_ipc_anonymous(&cli, &server_ip, (char*)pdc_name);
	
	if (NT_STATUS_IS_ERR(nt_status)) {
		DEBUG(0, ("Couldn't connect to domain %s controller. Error was %s.\n",
			domain_name, nt_errstr(nt_status)));
	}

	/*
	 * Use NetServerEnum2 to make sure we're talking to a proper server
	 */
	 
	if (!cli_get_pdc_name(cli, domain_name, (char*)pdc_name)) {
		DEBUG(0, ("NetServerEnum2 error: Couldn't find primary domain controller\
			 for domain %s\n", domain_name));
	}
	 
	/*
	 * Call WksQueryInfo to check remote server's capabilities
	 * FIXME:Is really necessary ? nt serv does this, but from samba's
	 *       point of view it doesn't seem to make the difference
	 * IDEA: It may be used to get info about type of pdc we're talking to
	 *       (e.g. WinNT or Win2k)
	 */
	
	if (!cli_nt_session_open(cli, PIPE_WKSSVC)) {
		DEBUG(0, ("Couldn't not initialise wkssvc pipe\n"));
		return -1;
	}

	/* TODO: convert this call from rpc_client/cli_wkssvc.c
	   to cli_wks_query_info() in libsmb/cli_wkssvc.c
	   UPDATE: already done :)
	*/

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0, ("talloc_init() failed\n"));
		cli_shutdown(cli);
		return -1;
	}
	
   	nt_status = cli_wks_query_info(cli, mem_ctx, &wks_info);
	
	if (NT_STATUS_IS_ERR(nt_status)) {
		DEBUG(0, ("WksQueryInfo call failed.\n"));
		return -1;
	}

	if (cli->nt_pipe_fnum) {
		cli_nt_session_close(cli);
		talloc_destroy(mem_ctx);
	}


	/*
	 * Call LsaOpenPolicy and LsaQueryInfo
	 */
	 
	if (!(mem_ctx = talloc_init())) {
		DEBUG(0, ("talloc_init() failed\n"));
		cli_shutdown(cli);
		return -1;
	}

	if (!cli_nt_session_open(cli, PIPE_LSARPC)) {
		DEBUG(0, ("Could not initialise lsa pipe\n"));
	}

	nt_status = cli_lsa_open_policy2(cli, mem_ctx, True, SEC_RIGHTS_QUERY_VALUE,
					&connect_hnd);
	if (NT_STATUS_IS_ERR(nt_status)) {
		DEBUG(0, ("Couldn't open policy handle. Error was %s\n",
			nt_errstr(nt_status)));
		return -1;
	}

	/* Querying info level 5 */
	
	nt_status = cli_lsa_query_info_policy(cli, mem_ctx, &connect_hnd,
					5 /* info level */, domain_name, &domain_sid);
	if (NT_STATUS_IS_ERR(nt_status)) {
		DEBUG(0, ("LSA Query Info failed. Returned error was %s\n",
			nt_errstr(nt_status)));
		return -1;
	}


	/* There should be actually query info level 3 (following nt serv behaviour),
	   but I still don't know if it's _really_ necessary */
			
	/*
	 * Close the pipes and clean up
	 */
	 
	nt_status = cli_lsa_close(cli, mem_ctx, &connect_hnd);
	if (NT_STATUS_IS_ERR(nt_status)) {
		DEBUG(0, ("Couldn't close LSA pipe. Error was %s\n",
			nt_errstr(nt_status)));
		return -1;
	}

	if (cli->nt_pipe_fnum)
		cli_nt_session_close(cli);

	talloc_destroy(mem_ctx);
	 
	 
	/*
	 * Store the password in secrets db
	 */

	if (!secrets_store_trusted_domain_password(domain_name, opt_password,
						   domain_sid)) {
		DEBUG(0, ("Storing password for trusted domain failed.\n"));
		return -1;
	}
	
	DEBUG(0, ("Success!\n"));
	return 0;
}

/**
 * Revoke trust relationship to the remote domain
 *
 * @param argc standard argc
 * @param argv standard argv without initial components
 *
 * @return Integer status (0 means success)
 **/

static int rpc_trustdom_revoke(int argc, const char **argv) {

	char* domain_name;

	if (argc < 1) return -1;
	
	/* generate upper cased domain name */
	domain_name = smb_xstrdup(argv[0]);
	strupper(domain_name);

	/* delete password of the trust */
	if (!trusted_domain_password_delete(domain_name)) {
		DEBUG(0, ("Failed to revoke relationship to the trusted domain %s\n",
			  domain_name));
		return -1;
	};
	
	return 0;
}

/**
 * Usage for 'net rpc trustdom' command
 *
 * @param argc standard argc
 * @param argv standard argv without inital components
 *
 * @return Integer status returned to shell
 **/
 
static int rpc_trustdom_usage(int argc, const char **argv) {
	d_printf("  net rpc trustdom add \t\t add trusting domain's account\n");
	d_printf("  net rpc trustdom del \t\t delete trusting domain's account\n");
	d_printf("  net rpc trustdom establish \t establish relationship to trusted domain\n");
	d_printf("  net rpc trustdom revoke \t abandon relationship to trusted domain\n");
	d_printf("  net rpc trustdom list \t show current interdomain trust relationships\n");
	return -1;
}


/**
 * Entrypoint for 'net rpc trustdom' code
 *
 * @param argc standard argc
 * @param argv standard argv without initial components
 *
 * @return Integer status (0 means success)
 */

static int rpc_trustdom(int argc, const char **argv)
{
	struct functable func[] = {
		{"add", rpc_trustdom_add},
		{"del", rpc_trustdom_del},
		{"establish", rpc_trustdom_establish},
		{"revoke", rpc_trustdom_revoke},
		{"help", rpc_trustdom_usage},
		{NULL, NULL}
	};

	if (argc == 0) {
		rpc_trustdom_usage(argc, argv);
		return -1;
	}

	return (net_run_function(argc, argv, func, rpc_user_usage));
}

/**
 * Check if a server will take rpc commands
 * @param flags	Type of server to connect to (PDC, DMB, localhost)
 *		if the host is not explicitly specified
 * @return  BOOL (true means rpc supported)
 */
BOOL net_rpc_check(unsigned flags)
{
	struct cli_state cli;
	BOOL ret = False;
	struct in_addr server_ip;
	char *server_name = NULL;

	/* flags (i.e. server type) may depend on command */
	if (!net_find_server(flags, &server_ip, &server_name))
		goto done;

	ZERO_STRUCT(cli);
	if (cli_initialise(&cli) == False)
		return False;

	if (!cli_connect(&cli, server_name, &server_ip))
		goto done;
	if (!attempt_netbios_session_request(&cli, global_myname, 
					     server_name, &server_ip))
		goto done;
	if (!cli_negprot(&cli))
		goto done;
	if (cli.protocol < PROTOCOL_NT1)
		goto done;

	ret = True;
 done:
	cli_shutdown(&cli);
	return ret;
}


/****************************************************************************/


/** 
 * Basic usage function for 'net rpc'
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
 *              stripped
 **/

int net_rpc_usage(int argc, const char **argv) 
{
	d_printf("  net rpc join \t\t\tto join a domain \n");
	d_printf("  net rpc user \t\t\tto add, delete and list users\n");
	d_printf("  net rpc changetrustpw \tto change the trust account password\n");
	d_printf("  net rpc trustdom \t\tto create trusting domain's account or establish trust\n");
	d_printf("  net rpc abortshutdown \tto to abort the shutdown of a remote server\n");
	d_printf("  net rpc shutdown \t\tto to shutdown a remote server\n");
	d_printf("\n");
	d_printf("'net rpc shutdown' also accepts the following miscellaneous options:\n"); /* misc options */
	d_printf("\t-r or --reboot\trequest remote server reboot on shutdown\n");
	d_printf("\t-f or --force\trequest the remote server force its shutdown\n");
	d_printf("\t-t or --timeout=<timeout>\tnumber of seconds before shutdown\n");
	d_printf("\t-c or --comment=<message>\ttext message to display on impending shutdown\n");
	return -1;
}


/**
 * Help function for 'net rpc'.  Calls command specific help if requested
 * or displays usage of net rpc
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
 *              stripped
 **/

int net_rpc_help(int argc, const char **argv)
{
	struct functable func[] = {
		{"join", rpc_join_usage},
		{"user", net_help_user},
		/*{"changetrustpw", rpc_changetrustpw_usage}, */
		{"trustdom", rpc_trustdom_usage},
		/*{"abortshutdown", rpc_shutdown_abort_usage},*/
		/*{"shutdown", rpc_shutdown_usage}, */
		{NULL, NULL}
	};

	if (argc == 0) {
		net_rpc_usage(argc, argv);
		return -1;
	}

	return (net_run_function(argc, argv, func, rpc_user_usage));
}


/** 
 * 'net rpc' entrypoint.
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
 *              stripped
 **/

int net_rpc(int argc, const char **argv)
{
	struct functable func[] = {
		{"join", net_rpc_join},
		{"user", net_rpc_user},
		{"changetrustpw", rpc_changetrustpw},
		{"trustdom", rpc_trustdom},
		{"abortshutdown", rpc_shutdown_abort},
		{"shutdown", rpc_shutdown},
		{"help", net_rpc_help},
		{NULL, NULL}
	};
	return net_run_function(argc, argv, func, net_rpc_usage);
}
