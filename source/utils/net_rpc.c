/* 
   Samba Unix/Linux SMB client library 
   Distributed SMB/CIFS Server Management Utility 
   Copyright (C) 2001 Andrew Bartlett (abartlet@samba.org)
   Copyright (C) 2002 Jim McDonough (jmcd@us.ibm.com)

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
	uint32_t info_class = 5;
	fstring domain_name;
	TALLOC_CTX *mem_ctx;
	
	if (!(domain_sid = malloc(sizeof(DOM_SID)))){
		DEBUG(0,("net_get_remote_domain_sid: malloc returned NULL!\n"));
		goto error;
	}
	    
	if (!(mem_ctx=talloc_init("net_get_remote_domain_sid")))
	{
		DEBUG(0,("net_get_remote_domain_sid: talloc_init returned NULL!\n"));
		goto error;
	}


	if (!cli_nt_session_open (cli, PI_LSARPC)) {
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

static int run_rpc_command(struct cli_state *cli_arg, const int pipe_idx, int conn_flags,
                           rpc_command_fn fn,
                           int argc, const char **argv) 
{
	struct cli_state *cli = NULL;
	TALLOC_CTX *mem_ctx;
	NTSTATUS nt_status;
	DOM_SID *domain_sid;

	/* make use of cli_state handed over as an argument, if possible */
	if (!cli_arg)
		cli = net_make_ipc_connection(conn_flags);
	else
		cli = cli_arg;

	if (!cli) {
		return -1;
	}

	domain_sid = net_get_remote_domain_sid(cli);

	/* Create mem_ctx */
	
	if (!(mem_ctx = talloc_init("run_rpc_command"))) {
		DEBUG(0, ("talloc_init() failed\n"));
		cli_shutdown(cli);
		return -1;
	}
	
	if (!cli_nt_session_open(cli, pipe_idx)) {
		DEBUG(0, ("Could not initialise pipe\n"));
	}
	
	nt_status = fn(domain_sid, cli, mem_ctx, argc, argv);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("rpc command function failed! (%s)\n", nt_errstr(nt_status)));
	} else {
		DEBUG(5, ("rpc command function succedded\n"));
	}
		
	    
	if (cli->nt_pipe_fnum)
		cli_nt_session_close(cli);
	
	/* close the connection only if it was opened here */
	if (!cli_arg)
		cli_shutdown(cli);
	
	talloc_destroy(mem_ctx);

	return (!NT_STATUS_IS_OK(nt_status));
}


/****************************************************************************/


/** 
 * Force a change of the trust acccount password.
 *
 * All parameters are provided by the run_rpc_command function, except for
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
	return run_rpc_command(NULL, PI_NETLOGON, NET_FLAGS_ANONYMOUS | NET_FLAGS_PDC, rpc_changetrustpw_internals,
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
 * All parameters are provided by the run_rpc_command function, except for
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
	
	fstring trust_passwd;
	unsigned char orig_trust_passwd_hash[16];
	NTSTATUS result;

	fstrcpy(trust_passwd, lp_netbios_name());
	strlower(trust_passwd);

	/*
	 * Machine names can be 15 characters, but the max length on
	 * a password is 14.  --jerry
	 */

	trust_passwd[14] = '\0';

	E_md4hash(trust_passwd, orig_trust_passwd_hash);

	result = trust_pw_change_and_store_it(cli, mem_ctx, orig_trust_passwd_hash);

	if (NT_STATUS_IS_OK(result))
		printf("Joined domain %s.\n",lp_workgroup());

	return result;
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
	return run_rpc_command(NULL, PI_NETLOGON, NET_FLAGS_ANONYMOUS | NET_FLAGS_PDC, rpc_join_oldstyle_internals,
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
 * old style.  If 'oldstyle' is specfied explicity, do it and don't prompt.
 **/

int net_rpc_join(int argc, const char **argv) 
{
	struct functable func[] = {
		{"oldstyle", net_rpc_join_oldstyle},
		{NULL, NULL}
	};

	if (argc == 0) {
		if ((net_rpc_join_oldstyle(argc, argv) == 0))
			return 0;
		
		return net_rpc_join_newstyle(argc, argv);
	}

	return net_run_function(argc, argv, func, rpc_join_usage);
}



/** 
 * display info about a rpc domain
 *
 * All parameters are provided by the run_rpc_command function, except for
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
rpc_info_internals(const DOM_SID *domain_sid, struct cli_state *cli,
		   TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	POLICY_HND connect_pol, domain_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	SAM_UNK_CTR ctr;
	fstring sid_str;

	sid_to_string(sid_str, domain_sid);

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

	ZERO_STRUCT(ctr);
	result = cli_samr_query_dom_info(cli, mem_ctx, &domain_pol,
					 2, &ctr);
	if (NT_STATUS_IS_OK(result)) {
		TALLOC_CTX *ctx = talloc_init("rpc_info_internals");
		d_printf("Domain Name: %s\n", unistr2_tdup(ctx, &ctr.info.inf2.uni_domain));
		d_printf("Domain SID: %s\n", sid_str);
		d_printf("Sequence number: %u\n", ctr.info.inf2.seq_num);
		d_printf("Num users: %u\n", ctr.info.inf2.num_domain_usrs);
		d_printf("Num domain groups: %u\n", ctr.info.inf2.num_domain_grps);
		d_printf("Num local groups: %u\n", ctr.info.inf2.num_local_grps);
		talloc_destroy(ctx);
	}

 done:
	return result;
}


/** 
 * 'net rpc info' entrypoint.
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 **/
int net_rpc_info(int argc, const char **argv) 
{
	return run_rpc_command(NULL, PI_SAMR, NET_FLAGS_ANONYMOUS | NET_FLAGS_PDC, 
			       rpc_info_internals,
			       argc, argv);
}


/** 
 * Fetch domain SID into the local secrets.tdb
 *
 * All parameters are provided by the run_rpc_command function, except for
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
rpc_getsid_internals(const DOM_SID *domain_sid, struct cli_state *cli,
		   TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	fstring sid_str;

	sid_to_string(sid_str, domain_sid);
	d_printf("Storing SID %s for Domain %s in secrets.tdb\n",
		 sid_str, lp_workgroup());

	if (!secrets_store_domain_sid(lp_netbios_name(), domain_sid)) {
		DEBUG(0,("Can't store domain SID\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}


/** 
 * 'net rpc getsid' entrypoint.
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 **/
int net_rpc_getsid(int argc, const char **argv) 
{
	return run_rpc_command(NULL, PI_SAMR, NET_FLAGS_ANONYMOUS | NET_FLAGS_PDC, 
			       rpc_getsid_internals,
			       argc, argv);
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
 * All parameters are provided by the run_rpc_command function, except for
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
	uint16_t acb_info;
	uint32_t unknown, user_rid;

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
	return run_rpc_command(NULL, PI_SAMR, 0, rpc_user_add_internals,
			       argc, argv);
}

/** 
 * Delete a user from a remote RPC server
 *
 * All parameters are provided by the run_rpc_command function, except for
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
		uint32_t *user_rids, num_rids, *name_types;
		uint32_t flags = 0x000003e8; /* Unknown */

		result = cli_samr_lookup_names(cli, mem_ctx, &domain_pol,
					       flags, 1, &argv[0],
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
	return run_rpc_command(NULL, PI_SAMR, 0, rpc_user_del_internals,
			       argc, argv);
}

/** 
 * List user's groups on a remote RPC server
 *
 * All parameters are provided by the run_rpc_command function, except for
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
	uint32_t *rids, num_rids, *name_types, num_names;
	uint32_t flags = 0x000003e8; /* Unknown */
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
				       flags, 1, &argv[0],
				       &num_rids, &rids, &name_types);

	if (!NT_STATUS_IS_OK(result)) goto done;

	result = cli_samr_open_user(cli, mem_ctx, &domain_pol,
				    MAXIMUM_ALLOWED_ACCESS,
				    rids[0], &user_pol);
	if (!NT_STATUS_IS_OK(result)) goto done;

	result = cli_samr_query_usergroups(cli, mem_ctx, &user_pol,
					   &num_rids, &user_gids);

	/* Look up rids */

	rids = (uint32_t *)talloc(mem_ctx, sizeof(uint32_t) * num_rids);

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
	return run_rpc_command(NULL, PI_SAMR, 0, rpc_user_info_internals,
			       argc, argv);
}

/** 
 * List users on a remote RPC server
 *
 * All parameters are provided by the run_rpc_command function, except for
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
	uint32_t start_idx=0, num_entries, i, loop_count = 0;
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
		uint32_t max_entries, max_size;

		get_query_dispinfo_params(
			loop_count, &max_entries, &max_size);

		result = cli_samr_query_dispinfo(cli, mem_ctx, &domain_pol,
						 &start_idx, 1, &num_entries,
						 max_entries, max_size, &ctr);
		loop_count++;

		for (i = 0; i < num_entries; i++) {
			unistr2_to_ascii(user, &(&ctr.sam.info1->str[i])->uni_acct_name, sizeof(user)-1);
			if (opt_long_list_entries) 
				unistr2_to_ascii(desc, &(&ctr.sam.info1->str[i])->uni_acct_desc, sizeof(desc)-1);
			
			if (opt_long_list_entries)
				printf("%-21.21s %-50.50s\n", user, desc);
			else
				printf("%s\n", user);
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
			return run_rpc_command(NULL,PI_SAMR, 0, 
					       rpc_user_list_internals,
					       argc, argv);
	}

	return net_run_function(argc, argv, func, rpc_user_usage);
}


/****************************************************************************/

/**
 * Basic usage function for 'net rpc group'
 * @param argc	Standard main() style argc.
 * @param argv	Standard main() style argv.  Initial components are already
 *		stripped.
 **/

static int rpc_group_usage(int argc, const char **argv)
{
	return net_help_group(argc, argv);
}

/** 
 * List groups on a remote RPC server
 *
 * All parameters are provided by the run_rpc_command function, except for
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
rpc_group_list_internals(const DOM_SID *domain_sid, struct cli_state *cli,
			 TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	POLICY_HND connect_pol, domain_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32_t start_idx=0, max_entries=250, num_entries, i;
	struct acct_info *groups;
	DOM_SID global_sid_Builtin;

	string_to_sid(&global_sid_Builtin, "S-1-5-32");

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

	/* Query domain groups */
	if (opt_long_list_entries)
		d_printf("\nGroup name            Comment"\
			 "\n-----------------------------\n");
	do {
		result = cli_samr_enum_dom_groups(cli, mem_ctx, &domain_pol,
						  &start_idx, max_entries,
						  &groups, &num_entries);
						 
		for (i = 0; i < num_entries; i++) {
			if (opt_long_list_entries)
				printf("%-21.21s %-50.50s\n", 
				       groups[i].acct_name,
				       groups[i].acct_desc);
			else
				printf("%-21.21s\n", groups[i].acct_name);
		}
	} while (!NT_STATUS_IS_OK(result));
	/* query domain aliases */
	do {
		result = cli_samr_enum_als_groups(cli, mem_ctx, &domain_pol,
						  &start_idx, max_entries,
						  &groups, &num_entries);
						 
		for (i = 0; i < num_entries; i++) {
			if (opt_long_list_entries)
				printf("%-21.21s %-50.50s\n", 
				       groups[i].acct_name,
				       groups[i].acct_desc);
			else
				printf("%-21.21s\n", groups[i].acct_name);
		}
	} while (!NT_STATUS_IS_OK(result));
	cli_samr_close(cli, mem_ctx, &domain_pol);
	/* Get builtin policy handle */
	
	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &global_sid_Builtin, &domain_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}
	/* query builtin aliases */
	do {
		result = cli_samr_enum_als_groups(cli, mem_ctx, &domain_pol,
						  &start_idx, max_entries,
						  &groups, &num_entries);
						 
		for (i = 0; i < num_entries; i++) {
			if (opt_long_list_entries)
				printf("%-21.21s %-50.50s\n", 
				       groups[i].acct_name,
				       groups[i].acct_desc);
			else
				printf("%s\n", groups[i].acct_name);
		}
	} while (!NT_STATUS_IS_OK(result));

 done:
	return result;
}

/** 
 * 'net rpc group' entrypoint.
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 **/

int net_rpc_group(int argc, const char **argv) 
{
	struct functable func[] = {
#if 0
		{"add", rpc_group_add},
		{"delete", rpc_group_delete},
#endif
		{NULL, NULL}
	};
	
	if (argc == 0) {
		if (opt_long_list_entries) {
		} else {
		}
		return run_rpc_command(NULL, PI_SAMR, 0, 
				       rpc_group_list_internals,
				       argc, argv);
	}

	return net_run_function(argc, argv, func, rpc_group_usage);
}

/****************************************************************************/

static int rpc_share_usage(int argc, const char **argv)
{
	return net_help_share(argc, argv);
}

/** 
 * Add a share on a remote RPC server
 *
 * All parameters are provided by the run_rpc_command function, except for
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
rpc_share_add_internals(const DOM_SID *domain_sid, struct cli_state *cli,
			TALLOC_CTX *mem_ctx,int argc, const char **argv)
{
	WERROR result;
	char *sharename=talloc_strdup(mem_ctx, argv[0]);
	char *path;
	uint32_t type=0; /* only allow disk shares to be added */
	uint32_t num_users=0, perms=0;
	char *password=NULL; /* don't allow a share password */

	path = strchr(sharename, '=');
	if (!path)
		return NT_STATUS_UNSUCCESSFUL;
	*path++ = '\0';

	result = cli_srvsvc_net_share_add(cli, mem_ctx, sharename, type,
					  opt_comment, perms, opt_maxusers,
					  num_users, path, password);
	return W_ERROR_IS_OK(result) ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static int rpc_share_add(int argc, const char **argv)
{
	if ((argc < 1) || !strchr(argv[0], '=')) {
		DEBUG(1,("Sharename or path not specified on add\n"));
		return rpc_share_usage(argc, argv);
	}
	return run_rpc_command(NULL, PI_SRVSVC, 0, 
			       rpc_share_add_internals,
			       argc, argv);
}

/** 
 * Delete a share on a remote RPC server
 *
 * All parameters are provided by the run_rpc_command function, except for
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
rpc_share_del_internals(const DOM_SID *domain_sid, struct cli_state *cli,
			TALLOC_CTX *mem_ctx,int argc, const char **argv)
{
	WERROR result;

	result = cli_srvsvc_net_share_del(cli, mem_ctx, argv[0]);
	return W_ERROR_IS_OK(result) ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

/** 
 * Delete a share on a remote RPC server
 *
 * @param domain_sid The domain sid acquired from the remote server
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return A shell status integer (0 for success)
 **/
static int rpc_share_delete(int argc, const char **argv)
{
	if (argc < 1) {
		DEBUG(1,("Sharename not specified on delete\n"));
		return rpc_share_usage(argc, argv);
	}
	return run_rpc_command(NULL, PI_SRVSVC, 0, 
			       rpc_share_del_internals,
			       argc, argv);
}

/**
 * Formatted print of share info
 *
 * @param info1  pointer to SRV_SHARE_INFO_1 to format
 **/
 
static void display_share_info_1(SRV_SHARE_INFO_1 *info1)
{
	fstring netname = "", remark = "";

	rpcstr_pull_unistr2_fstring(netname, &info1->info_1_str.uni_netname);
	rpcstr_pull_unistr2_fstring(remark, &info1->info_1_str.uni_remark);

	if (opt_long_list_entries) {
		d_printf("%-12.12s %-8.8s %-50.50s\n",
			 netname, share_type[info1->info_1.type], remark);
	} else {
		d_printf("%-12.12s\n", netname);
	}

}

/** 
 * List shares on a remote RPC server
 *
 * All parameters are provided by the run_rpc_command function, except for
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
rpc_share_list_internals(const DOM_SID *domain_sid, struct cli_state *cli,
			 TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	SRV_SHARE_INFO_CTR ctr;
	WERROR result;
	ENUM_HND hnd;
	uint32_t preferred_len = 0xffffffff, i;

	init_enum_hnd(&hnd, 0);

	result = cli_srvsvc_net_share_enum(
		cli, mem_ctx, 1, &ctr, preferred_len, &hnd);

	if (!W_ERROR_IS_OK(result))
		goto done;

	/* Display results */

	if (opt_long_list_entries) {
		d_printf(
	"\nEnumerating shared resources (exports) on remote server:\n\n"\
	"\nShare name   Type     Description\n"\
	"----------   ----     -----------\n");
	}
	for (i = 0; i < ctr.num_entries; i++)
		display_share_info_1(&ctr.share.info1[i]);
 done:
	return W_ERROR_IS_OK(result) ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

/** 
 * 'net rpc share' entrypoint.
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
 *              stripped
 **/

int net_rpc_share(int argc, const char **argv) 
{
	struct functable func[] = {
		{"add", rpc_share_add},
		{"delete", rpc_share_delete},
		{NULL, NULL}
	};

	if (argc == 0)
		return run_rpc_command(NULL, PI_SRVSVC, 0, 
				       rpc_share_list_internals,
				       argc, argv);

	return net_run_function(argc, argv, func, rpc_share_usage);
}

/****************************************************************************/

static int rpc_file_usage(int argc, const char **argv)
{
	return net_help_file(argc, argv);
}

/** 
 * Close a file on a remote RPC server
 *
 * All parameters are provided by the run_rpc_command function, except for
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
rpc_file_close_internals(const DOM_SID *domain_sid, struct cli_state *cli,
			 TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	WERROR result;
	result = cli_srvsvc_net_file_close(cli, mem_ctx, atoi(argv[0]));
	return W_ERROR_IS_OK(result) ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

/** 
 * Close a file on a remote RPC server
 *
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return A shell status integer (0 for success)
 **/
static int rpc_file_close(int argc, const char **argv)
{
	if (argc < 1) {
		DEBUG(1, ("No fileid given on close\n"));
		return(rpc_file_usage(argc, argv));
	}

	return run_rpc_command(NULL, PI_SRVSVC, 0, 
			       rpc_file_close_internals,
			       argc, argv);
}

/** 
 * Formatted print of open file info 
 *
 * @param info3  FILE_INFO_3 contents
 * @param str3   strings for FILE_INFO_3
 **/

static void display_file_info_3(FILE_INFO_3 *info3, FILE_INFO_3_STR *str3)
{
	fstring user = "", path = "";

	rpcstr_pull_unistr2_fstring(user, &str3->uni_user_name);
	rpcstr_pull_unistr2_fstring(path, &str3->uni_path_name);

	d_printf("%-7.1d %-20.20s 0x%-4.2x %-6.1d %s\n",
		 info3->id, user, info3->perms, info3->num_locks, path);
}

/** 
 * List open files on a remote RPC server
 *
 * All parameters are provided by the run_rpc_command function, except for
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
rpc_file_list_internals(const DOM_SID *domain_sid, struct cli_state *cli,
			TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	SRV_FILE_INFO_CTR ctr;
	WERROR result;
	ENUM_HND hnd;
	uint32_t preferred_len = 0xffffffff, i;
	const char *username=NULL;

	init_enum_hnd(&hnd, 0);

	/* if argc > 0, must be user command */
	if (argc > 0)
		username = smb_xstrdup(argv[0]);
		
	result = cli_srvsvc_net_file_enum(
		cli, mem_ctx, 3, username, &ctr, preferred_len, &hnd);

	if (!W_ERROR_IS_OK(result))
		goto done;

	/* Display results */

	d_printf(
		 "\nEnumerating open files on remote server:\n\n"\
		 "\nFileId  Opened by            Perms  Locks  Path"\
		 "\n------  ---------            -----  -----  ---- \n");
	for (i = 0; i < ctr.num_entries; i++)
		display_file_info_3(&ctr.file.info3[i].info_3, 
				    &ctr.file.info3[i].info_3_str);
 done:
	return W_ERROR_IS_OK(result) ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}


/** 
 * List files for a user on a remote RPC server
 *
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return A shell status integer (0 for success)
 **/
static int rpc_file_user(int argc, const char **argv)
{
	if (argc < 1) {
		DEBUG(1, ("No username given\n"));
		return(rpc_file_usage(argc, argv));
	}

	return run_rpc_command(NULL, PI_SRVSVC, 0, 
			       rpc_file_list_internals,
			       argc, argv);
}


/** 
 * 'net rpc file' entrypoint.
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
 *              stripped
 **/

int net_rpc_file(int argc, const char **argv) 
{
	struct functable func[] = {
		{"close", rpc_file_close},
		{"user", rpc_file_user},
#if 0
		{"info", rpc_file_info},
#endif
		{NULL, NULL}
	};

	if (argc == 0)
		return run_rpc_command(NULL, PI_SRVSVC, 0, 
				       rpc_file_list_internals,
				       argc, argv);

	return net_run_function(argc, argv, func, rpc_file_usage);
}

/****************************************************************************/



/** 
 * ABORT the shutdown of a remote RPC Server
 *
 * All parameters are provided by the run_rpc_command function, except for
 * argc, argv which are passed through. 
 *
 * @param domain_sid The domain sid aquired from the remote server
 * @param cli A cli_state connected to the server.
 * @param mem_ctx Talloc context, destoyed on compleation of the function.
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
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
 * @param argv  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return A shell status integer (0 for success)
 **/

static int rpc_shutdown_abort(int argc, const char **argv) 
{
	return run_rpc_command(NULL, PI_WINREG, 0, rpc_shutdown_abort_internals,
			       argc, argv);
}

/** 
 * Shut down a remote RPC Server
 *
 * All parameters are provided by the run_rpc_command function, except for
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
        const char *msg = "This machine will be shutdown shortly";
	uint32_t timeout = 20;
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
	if (opt_comment) {
		msg = opt_comment;
	}
	if (opt_timeout) {
		timeout = opt_timeout;
	}

	/* create an entry */
	result = cli_reg_shutdown(cli, mem_ctx, msg, timeout, opt_reboot, opt_force);

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
	return run_rpc_command(NULL, PI_WINREG, 0, rpc_shutdown_internals,
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
	uint16_t acb_info;
	uint32_t unknown, user_rid;

	if (argc != 1) {
		d_printf("Usage: net rpc trustdom add <domain_name>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* 
	 * Make valid trusting domain account (ie. uppercased and with '$' appended)
	 */
	 
	if (asprintf(&acct_name, "%s$", argv[0]) < 0) {
		return NT_STATUS_NO_MEMORY;
	}

	strupper(acct_name);

	/* Get samr policy handle */
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
	                         mimir: yes, most probably it is */

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
	return run_rpc_command(NULL, PI_SAMR, 0, rpc_trustdom_add_internals,
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

static int rpc_trustdom_establish(int argc, const char **argv)
{
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

	if (argc != 1) {
		d_printf("Usage: net rpc trustdom establish <domain_name>\n");
		return -1;
	}

	domain_name = smb_xstrdup(argv[0]);
	strupper(domain_name);

	/* account name used at first is our domain's name with '$' */
	asprintf(&acct_name, "%s$", lp_workgroup());
	strupper(acct_name);
	
	/*
	 * opt_workgroup will be used by connection functions further,
	 * hence it should be set to remote domain name instead of ours
	 */
	if (opt_workgroup) {
		opt_workgroup = smb_xstrdup(domain_name);
	};
	
	opt_user_name = acct_name;

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
	 * note: It is now used only to get unicode domain name
	 */
	
	if (!cli_nt_session_open(cli, PI_WKSSVC)) {
		DEBUG(0, ("Couldn't not initialise wkssvc pipe\n"));
		return -1;
	}

	if (!(mem_ctx = talloc_init("establishing trust relationship to domain %s",
	                domain_name))) {
		DEBUG(0, ("talloc_init() failed\n"));
		cli_shutdown(cli);
		return -1;
	}
	
   	nt_status = cli_wks_query_info(cli, mem_ctx, &wks_info);
	
	if (NT_STATUS_IS_ERR(nt_status)) {
		DEBUG(0, ("WksQueryInfo call failed.\n"));
		return -1;
	}

	if (cli->nt_pipe_fnum)
		cli_nt_session_close(cli);


	/*
	 * Call LsaOpenPolicy and LsaQueryInfo
	 */
	 
	if (!(mem_ctx = talloc_init("rpc_trustdom_establish"))) {
		DEBUG(0, ("talloc_init() failed\n"));
		cli_shutdown(cli);
		return -1;
	}

	if (!cli_nt_session_open(cli, PI_LSARPC)) {
		DEBUG(0, ("Could not initialise lsa pipe\n"));
		cli_shutdown(cli);
		return -1;
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
	                                      5 /* info level */, domain_name,
	                                      &domain_sid);
	if (NT_STATUS_IS_ERR(nt_status)) {
		DEBUG(0, ("LSA Query Info failed. Returned error was %s\n",
			nt_errstr(nt_status)));
		return -1;
	}




	/* There should be actually query info level 3 (following nt serv behaviour),
	   but I still don't know if it's _really_ necessary */
			
	/*
	 * Store the password in secrets db
	 */

	if (!secrets_store_trusted_domain_password(domain_name, wks_info.uni_lan_grp.buffer,
						   wks_info.uni_lan_grp.uni_str_len, opt_password,
						   domain_sid)) {
		DEBUG(0, ("Storing password for trusted domain failed.\n"));
		return -1;
	}
	
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

static int rpc_trustdom_revoke(int argc, const char **argv)
{
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
 
static int rpc_trustdom_usage(int argc, const char **argv)
{
	d_printf("  net rpc trustdom add \t\t add trusting domain's account\n");
	d_printf("  net rpc trustdom del \t\t delete trusting domain's account\n");
	d_printf("  net rpc trustdom establish \t establish relationship to trusted domain\n");
	d_printf("  net rpc trustdom revoke \t abandon relationship to trusted domain\n");
	d_printf("  net rpc trustdom list \t show current interdomain trust relationships\n");
	return -1;
}


static NTSTATUS rpc_query_domain_sid(const DOM_SID *domain_sid, struct cli_state *cli, TALLOC_CTX *mem_ctx,
                              int argc, const char **argv)
{
	fstring str_sid;
	sid_to_string(str_sid, domain_sid);
	d_printf("%s\n", str_sid);
	return NT_STATUS_OK;
};


static int rpc_trustdom_list(int argc, const char **argv)
{
	/* common variables */
	TALLOC_CTX* mem_ctx;
	struct cli_state *cli, *remote_cli;
	NTSTATUS nt_status;
	const char *domain_name = NULL;
	DOM_SID queried_dom_sid;
	fstring ascii_sid, padding;
	int ascii_dom_name_len;
	POLICY_HND connect_hnd;
	
	/* trusted domains listing variables */
	int enum_ctx = 0;
	int num_domains, i, pad_len, col_len = 20;
	DOM_SID *domain_sids;
	char **trusted_dom_names;
	fstring pdc_name;
	
	/* trusting domains listing variables */
	POLICY_HND domain_hnd;
	char **trusting_dom_names;
	uint32_t *trusting_dom_rids;
	
	/*
	 * Listing trusted domains (stored in secrets.tdb, if local)
	 */

	mem_ctx = talloc_init("trust relationships listing");

	/*
	 * set domain and pdc name to local samba server (default)
	 * or to remote one given in command line
	 */
	
	if (StrCaseCmp(opt_workgroup, lp_workgroup())) {
		domain_name = opt_workgroup;
		opt_target_workgroup = opt_workgroup;
	} else {
		fstrcpy(pdc_name, lp_netbios_name());
		domain_name = talloc_strdup(mem_ctx, lp_workgroup());
		opt_target_workgroup = domain_name;
	};

	/* open \PIPE\lsarpc and open policy handle */
	if (!(cli = net_make_ipc_connection(NET_FLAGS_PDC))) {
		DEBUG(0, ("Couldn't connect to domain controller\n"));
		return -1;
	};

	if (!cli_nt_session_open(cli, PI_LSARPC)) {
		DEBUG(0, ("Could not initialise lsa pipe\n"));
		return -1;
	};

	nt_status = cli_lsa_open_policy2(cli, mem_ctx, True, SEC_RIGHTS_QUERY_VALUE,
					&connect_hnd);
	if (NT_STATUS_IS_ERR(nt_status)) {
		DEBUG(0, ("Couldn't open policy handle. Error was %s\n",
 			nt_errstr(nt_status)));
		return -1;
	};
	
	/* query info level 5 to obtain sid of a domain being queried */
	nt_status = cli_lsa_query_info_policy(cli, mem_ctx, &connect_hnd,
					5 /* info level */, domain_name, &queried_dom_sid);
	if (NT_STATUS_IS_ERR(nt_status)) {
		DEBUG(0, ("LSA Query Info failed. Returned error was %s\n",
			nt_errstr(nt_status)));
		return -1;
	}
		
	/*
	 * Keep calling LsaEnumTrustdom over opened pipe until
	 * the end of enumeration is reached
	 */
	 
	d_printf("Trusted domains list:\n\n");

	do {
		nt_status = cli_lsa_enum_trust_dom(cli, mem_ctx, &connect_hnd, &enum_ctx,
						   &num_domains,
						   &trusted_dom_names, &domain_sids);
		
		if (NT_STATUS_IS_ERR(nt_status)) {
			DEBUG(0, ("Couldn't enumerate trusted domains. Error was %s\n",
				nt_errstr(nt_status)));
			return -1;
		};
		
		for (i = 0; i < num_domains; i++) {
			/* convert sid into ascii string */
			sid_to_string(ascii_sid, &(domain_sids[i]));
		
			/* calculate padding space for d_printf to look nicer */
			pad_len = col_len - strlen(trusted_dom_names[i]);
			padding[pad_len] = 0;
			do padding[--pad_len] = ' '; while (pad_len);
			
			d_printf("%s%s%s\n", trusted_dom_names[i], padding, ascii_sid);
		};
		
		/*
		 * in case of no trusted domains say something rather
		 * than just display blank line
		 */
		if (!num_domains) d_printf("none\n");

	} while (NT_STATUS_EQUAL(nt_status, STATUS_MORE_ENTRIES));

	/* close this connection before doing next one */
	nt_status = cli_lsa_close(cli, mem_ctx, &connect_hnd);
	if (NT_STATUS_IS_ERR(nt_status)) {
		DEBUG(0, ("Couldn't properly close lsa policy handle. Error was %s\n",
			nt_errstr(nt_status)));
		return -1;
	};
	
	cli_nt_session_close(cli);

	/*
	 * Listing trusting domains (stored in passdb backend, if local)
	 */
	
	d_printf("\nTrusting domains list:\n\n");

	/*
	 * Open \PIPE\samr and get needed policy handles
	 */
	if (!cli_nt_session_open(cli, PI_SAMR)) {
		DEBUG(0, ("Could not initialise samr pipe\n"));
		return -1;
	};
	
	/* SamrConnect */
	nt_status = cli_samr_connect(cli, mem_ctx, SA_RIGHT_SAM_OPEN_DOMAIN,
								 &connect_hnd);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Couldn't open SAMR policy handle. Error was %s\n",
			nt_errstr(nt_status)));
		return -1;
	};
	
	/* SamrOpenDomain - we have to open domain policy handle in order to be
	   able to enumerate accounts*/
	nt_status = cli_samr_open_domain(cli, mem_ctx, &connect_hnd,
									 SA_RIGHT_DOMAIN_ENUM_ACCOUNTS,
									 &queried_dom_sid, &domain_hnd);									 
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Couldn't open domain object. Error was %s\n",
			nt_errstr(nt_status)));
		return -1;
	};
	
	/*
	 * perform actual enumeration
	 */
	 
	enum_ctx = 0;	/* reset enumeration context from last enumeration */
	do {
			
		nt_status = cli_samr_enum_dom_users(cli, mem_ctx, &domain_hnd,
		                                    &enum_ctx, ACB_DOMTRUST, 0xffff,
		                                    &trusting_dom_names, &trusting_dom_rids,
		                                    &num_domains);
		if (NT_STATUS_IS_ERR(nt_status)) {
			DEBUG(0, ("Couldn't enumerate accounts. Error was: %s\n",
				nt_errstr(nt_status)));
			return -1;
		};
		
		for (i = 0; i < num_domains; i++) {

			/*
			 * get each single domain's sid (do we _really_ need this ?):
			 *  1) connect to domain's pdc
			 *  2) query the pdc for domain's sid
			 */

			/* get rid of '$' tail */
			ascii_dom_name_len = strlen(trusting_dom_names[i]);
			if (ascii_dom_name_len && ascii_dom_name_len < FSTRING_LEN)
				trusting_dom_names[i][ascii_dom_name_len - 1] = '\0';
			
			/* calculate padding space for d_printf to look nicer */
			pad_len = col_len - strlen(trusting_dom_names[i]);
			padding[pad_len] = 0;
			do padding[--pad_len] = ' '; while (pad_len);

			/* set opt_* variables to remote domain */
			strupper(trusting_dom_names[i]);
			opt_workgroup = talloc_strdup(mem_ctx, trusting_dom_names[i]);
			opt_target_workgroup = opt_workgroup;
			
			d_printf("%s%s", trusting_dom_names[i], padding);
			
			/* connect to remote domain controller */
			remote_cli = net_make_ipc_connection(NET_FLAGS_PDC | NET_FLAGS_ANONYMOUS);
			if (remote_cli) {			
				/* query for domain's sid */
				if (run_rpc_command(remote_cli, PI_LSARPC, 0, rpc_query_domain_sid, argc, argv))
					d_printf("couldn't get domain's sid\n");

				cli_shutdown(remote_cli);
			
			} else {
				d_printf("domain controller is not responding\n");
			};
		};
		
		if (!num_domains) d_printf("none\n");
		
	} while (NT_STATUS_EQUAL(nt_status, STATUS_MORE_ENTRIES));

	/* close opened samr and domain policy handles */
	nt_status = cli_samr_close(cli, mem_ctx, &domain_hnd);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Couldn't properly close domain policy handle for domain %s\n", domain_name));
	};
	
	nt_status = cli_samr_close(cli, mem_ctx, &connect_hnd);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Couldn't properly close samr policy handle for domain %s\n", domain_name));
	};
	
	/* close samr pipe and connection to IPC$ */
	cli_nt_session_close(cli);
	cli_shutdown(cli);

	talloc_destroy(mem_ctx);	 
	return 0;
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
		{"list", rpc_trustdom_list},
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
		return False;

	ZERO_STRUCT(cli);
	if (cli_initialise(&cli) == False)
		return False;

	if (!cli_connect(&cli, server_name, &server_ip))
		goto done;
	if (!attempt_netbios_session_request(&cli, lp_netbios_name(), 
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
	d_printf("  net rpc info \t\t\tshow basic info about a domain \n");
	d_printf("  net rpc join \t\t\tto join a domain \n");
	d_printf("  net rpc testjoin \t\ttests that a join is valid\n");
	d_printf("  net rpc user \t\t\tto add, delete and list users\n");
	d_printf("  net rpc group \t\tto list groups\n");
	d_printf("  net rpc share \t\tto add, delete, and list shares\n");
	d_printf("  net rpc file \t\t\tto list open files\n");
	d_printf("  net rpc changetrustpw \tto change the trust account password\n");
	d_printf("  net rpc getsid \t\tfetch the domain sid into the local secrets.tdb\n");
	d_printf("  net rpc vampire \t\tsyncronise an NT PDC's users and groups into the local passdb\n");
	d_printf("  net rpc samdump \t\tdiplay an NT PDC's users, groups and other data\n");
	d_printf("  net rpc trustdom \t\tto create trusting domain's account\n"
		 "\t\t\t\t\tor establish trust\n");
	d_printf("  net rpc abortshutdown \tto abort the shutdown of a remote server\n");
	d_printf("  net rpc shutdown \t\tto shutdown a remote server\n");
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
		{"user", rpc_user_usage},
		{"group", rpc_group_usage},
		{"share", rpc_share_usage},
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
		{"info", net_rpc_info},
		{"join", net_rpc_join},
		{"testjoin", net_rpc_testjoin},
		{"user", net_rpc_user},
		{"group", net_rpc_group},
		{"share", net_rpc_share},
		{"file", net_rpc_file},
		{"changetrustpw", rpc_changetrustpw},
		{"trustdom", rpc_trustdom},
		{"abortshutdown", rpc_shutdown_abort},
		{"shutdown", rpc_shutdown},
		{"samdump", rpc_samdump},
		{"vampire", rpc_vampire},
		{"getsid", net_rpc_getsid},
		{"help", net_rpc_help},
		{NULL, NULL}
	};
	return net_run_function(argc, argv, func, net_rpc_usage);
}
