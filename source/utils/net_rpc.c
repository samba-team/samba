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
typedef NTSTATUS (*rpc_command_fn)(const DOM_SID *, const char *, 
				   struct cli_state *, TALLOC_CTX *, int, const char **);

/**
 * Many of the RPC functions need the domain sid.  This function gets
 *  it at the start of every run 
 *
 * @param cli A cli_state already connected to the remote machine
 *
 * @return The Domain SID of the remote machine.
 **/

static DOM_SID *net_get_remote_domain_sid(struct cli_state *cli, TALLOC_CTX *mem_ctx, char **domain_name)
{
	DOM_SID *domain_sid;
	POLICY_HND pol;
	NTSTATUS result = NT_STATUS_OK;
	uint32 info_class = 5;
	
	if (!cli_nt_session_open (cli, PI_LSARPC)) {
		fprintf(stderr, "could not initialise lsa pipe\n");
		goto error;
	}
	
	result = cli_lsa_open_policy(cli, mem_ctx, False, 
				     SEC_RIGHTS_MAXIMUM_ALLOWED,
				     &pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto error;
	}

	result = cli_lsa_query_info_policy(cli, mem_ctx, &pol, info_class, 
					   domain_name, &domain_sid);
	if (!NT_STATUS_IS_OK(result)) {
 error:
		fprintf(stderr, "could not obtain sid for domain %s\n", cli->domain);

		if (!NT_STATUS_IS_OK(result)) {
			fprintf(stderr, "error: %s\n", nt_errstr(result));
		}

		exit(1);
	}

	cli_lsa_close(cli, mem_ctx, &pol);
	cli_nt_session_close(cli);

	return domain_sid;
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
	char *domain_name;

	/* make use of cli_state handed over as an argument, if possible */
	if (!cli_arg)
		cli = net_make_ipc_connection(conn_flags);
	else
		cli = cli_arg;

	if (!cli) {
		return -1;
	}

	/* Create mem_ctx */
	
	if (!(mem_ctx = talloc_init("run_rpc_command"))) {
		DEBUG(0, ("talloc_init() failed\n"));
		cli_shutdown(cli);
		return -1;
	}
	
	domain_sid = net_get_remote_domain_sid(cli, mem_ctx, &domain_name);

	if (!(conn_flags & NET_FLAGS_NO_PIPE)) {
		if (!cli_nt_session_open(cli, pipe_idx)) {
			DEBUG(0, ("Could not initialise pipe\n"));
		}
	}
	
	nt_status = fn(domain_sid, domain_name, cli, mem_ctx, argc, argv);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(1, ("rpc command function failed! (%s)\n", nt_errstr(nt_status)));
	} else {
		DEBUG(5, ("rpc command function succedded\n"));
	}
		
	if (!(conn_flags & NET_FLAGS_NO_PIPE)) {
		if (cli->nt_pipe_fnum)
			cli_nt_session_close(cli);
	}

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

static NTSTATUS rpc_changetrustpw_internals(const DOM_SID *domain_sid, const char *domain_name, 
					    struct cli_state *cli, TALLOC_CTX *mem_ctx, 
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

int net_rpc_changetrustpw(int argc, const char **argv) 
{
	return run_rpc_command(NULL, PI_NETLOGON, NET_FLAGS_ANONYMOUS | NET_FLAGS_PDC, 
			       rpc_changetrustpw_internals,
			       argc, argv);
}


/****************************************************************************/


/** 
 * Join a domain, the old way.
 *
 * This uses 'machinename' as the inital password, and changes it. 
 *
 * The password should be created with 'server manager' or equiv first.
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

static NTSTATUS rpc_oldjoin_internals(const DOM_SID *domain_sid, const char *domain_name, 
				      struct cli_state *cli, 
				      TALLOC_CTX *mem_ctx, 
				      int argc, const char **argv) {
	
	fstring trust_passwd;
	unsigned char orig_trust_passwd_hash[16];
	NTSTATUS result;
	uint32 sec_channel_type;

	/* 
	   check what type of join - if the user want's to join as
	   a BDC, the server must agree that we are a BDC.
	*/
	if (argc >= 0) {
		sec_channel_type = get_sec_channel_type(argv[0]);
	} else {
		sec_channel_type = get_sec_channel_type(NULL);
	}
	
	fstrcpy(trust_passwd, global_myname());
	strlower_m(trust_passwd);

	/*
	 * Machine names can be 15 characters, but the max length on
	 * a password is 14.  --jerry
	 */

	trust_passwd[14] = '\0';

	E_md4hash(trust_passwd, orig_trust_passwd_hash);

	result = trust_pw_change_and_store_it(cli, mem_ctx, opt_target_workgroup,
					      orig_trust_passwd_hash,
					      sec_channel_type);

	if (NT_STATUS_IS_OK(result))
		printf("Joined domain %s.\n",opt_target_workgroup);


	if (!secrets_store_domain_sid(opt_target_workgroup, domain_sid)) {
		DEBUG(0, ("error storing domain sid for %s\n", opt_target_workgroup));
		result = NT_STATUS_UNSUCCESSFUL;
	}

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

static int net_rpc_perform_oldjoin(int argc, const char **argv)
{
	return run_rpc_command(NULL, PI_NETLOGON, 
			       NET_FLAGS_ANONYMOUS | NET_FLAGS_PDC, 
			       rpc_oldjoin_internals,
			       argc, argv);
}

/** 
 * Join a domain, the old way.  This function exists to allow
 * the message to be displayed when oldjoin was explicitly 
 * requested, but not when it was implied by "net rpc join"
 *
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return A shell status integer (0 for success)
 **/

static int net_rpc_oldjoin(int argc, const char **argv) 
{
	int rc = net_rpc_perform_oldjoin(argc, argv);

	if (rc) {
		d_printf("Failed to join domain\n");
	}

	return rc;
}

/** 
 * Basic usage function for 'net rpc join'
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 **/

static int rpc_join_usage(int argc, const char **argv) 
{	
	d_printf("net rpc join -U <username>[%%password] <type>[options]\n"\
		 "\t to join a domain with admin username & password\n"\
		 "\t\t password will be prompted if needed and none is specified\n"\
		 "\t <type> can be (default MEMBER)\n"\
		 "\t\t BDC - Join as a BDC\n"\
		 "\t\t PDC - Join as a PDC\n"\
		 "\t\t MEMBER - Join as a MEMBER server\n");

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
 * Try to just change the password, but if that doesn't work, use/prompt
 * for a username/password.
 **/

int net_rpc_join(int argc, const char **argv) 
{
	if ((net_rpc_perform_oldjoin(argc, argv) == 0))
		return 0;
	
	return net_rpc_join_newstyle(argc, argv);
}



/** 
 * display info about a rpc domain
 *
 * All parameters are provided by the run_rpc_command function, except for
 * argc, argv which are passed through. 
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
rpc_info_internals(const DOM_SID *domain_sid, const char *domain_name, 
		   struct cli_state *cli,
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
rpc_getsid_internals(const DOM_SID *domain_sid, const char *domain_name, 
		     struct cli_state *cli,
		     TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	fstring sid_str;

	sid_to_string(sid_str, domain_sid);
	d_printf("Storing SID %s for Domain %s in secrets.tdb\n",
		 sid_str, domain_name);

	if (!secrets_store_domain_sid(domain_name, domain_sid)) {
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

static NTSTATUS rpc_user_add_internals(const DOM_SID *domain_sid, const char *domain_name, 
				       struct cli_state *cli, TALLOC_CTX *mem_ctx, 
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
				       const char *domain_name, 
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
 * Set a password for a user on a remote RPC server
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

static NTSTATUS rpc_user_password_internals(const DOM_SID *domain_sid, 
					    const char *domain_name, 
					    struct cli_state *cli, 
					    TALLOC_CTX *mem_ctx, 
					    int argc, const char **argv)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	POLICY_HND connect_pol, domain_pol, user_pol;
	SAM_USERINFO_CTR ctr;
	SAM_USER_INFO_24 p24;
	uchar pwbuf[516];
	const char *user;
	const char *new_password;
	char *prompt = NULL;

	if (argc < 1) {
		d_printf("User must be specified\n");
		rpc_user_usage(argc, argv);
		return NT_STATUS_OK;
	}
	
	user = argv[0];

	if (argv[1]) {
		new_password = argv[1];
	} else {
		asprintf(&prompt, "Enter new password for %s:", user);
		new_password = getpass(prompt);
		SAFE_FREE(prompt);
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
					       flags, 1, &user,
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

	/* Set password on account */

	ZERO_STRUCT(ctr);
	ZERO_STRUCT(p24);

	encode_pw_buffer(pwbuf, new_password, STR_UNICODE);

	init_sam_user_info24(&p24, (char *)pwbuf,24);

	ctr.switch_value = 24;
	ctr.info.id24 = &p24;

	result = cli_samr_set_userinfo(cli, mem_ctx, &user_pol, 24, 
				       &cli->user_session_key, &ctr);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Display results */

 done:
	return result;

}	

/** 
 * Set a user's password on a remote RPC server
 *
 * @param argc  Standard main() style argc
 * @param argv  Standard main() style argv.  Initial components are already
 *              stripped
 *
 * @return A shell status integer (0 for success)
 **/

static int rpc_user_password(int argc, const char **argv) 
{
	return run_rpc_command(NULL, PI_SAMR, 0, rpc_user_password_internals,
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
rpc_user_info_internals(const DOM_SID *domain_sid, const char *domain_name, 
			struct cli_state *cli,
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
rpc_user_list_internals(const DOM_SID *domain_sid, const char *domain_name, 
			struct cli_state *cli,
			TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	POLICY_HND connect_pol, domain_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 start_idx=0, num_entries, i, loop_count = 0;
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
		uint32 max_entries, max_size;

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
				printf("%-21.21s %s\n", user, desc);
			else
				printf("%s\n", user);
		}
	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

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
		{"password", rpc_user_password},
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
 * Delete group on a remote RPC server
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
                                                                                                             
static NTSTATUS rpc_group_delete_internals(const DOM_SID *domain_sid,
                                           const char *domain_name,
                                           struct cli_state *cli,
                                           TALLOC_CTX *mem_ctx,
                                           int argc, const char **argv)
{
	POLICY_HND connect_pol, domain_pol, group_pol, user_pol;
	BOOL group_is_primary = False;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	uint32 *group_rids, num_rids, *name_types, num_members, 
               *group_attrs, group_rid;
	uint32 flags = 0x000003e8; /* Unknown */
	/* char **names; */
	int i;
	/* DOM_GID *user_gids; */
	SAM_USERINFO_CTR *user_ctr;
	fstring temp;

	if (argc < 1) {
        	d_printf("specify group\n");
		rpc_group_usage(argc,argv);
		return NT_STATUS_OK; /* ok? */
	}

        result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS,
                                  &connect_pol);

        if (!NT_STATUS_IS_OK(result)) {
		d_printf("Request samr_connect failed\n");
        	goto done;
        }
        
        result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
                                      MAXIMUM_ALLOWED_ACCESS,
                                      domain_sid, &domain_pol);
        
        if (!NT_STATUS_IS_OK(result)) {
		d_printf("Request open_domain failed\n");
        	goto done;
        }
	
	result = cli_samr_lookup_names(cli, mem_ctx, &domain_pol,
				       flags, 1, &argv[0],
				       &num_rids, &group_rids,
				       &name_types);

	if (!NT_STATUS_IS_OK(result)) {
		d_printf("Lookup of '%s' failed\n",argv[0]);
   		goto done;
	}

	switch (name_types[0])
	{
	case SID_NAME_DOM_GRP:
		result = cli_samr_open_group(cli, mem_ctx, &domain_pol,
					     MAXIMUM_ALLOWED_ACCESS,
					     group_rids[0], &group_pol);
		if (!NT_STATUS_IS_OK(result)) {
			d_printf("Request open_group failed");
   			goto done;
		}
                
		group_rid = group_rids[0];
                
		result = cli_samr_query_groupmem(cli, mem_ctx, &group_pol,
                                 &num_members, &group_rids,
                                 &group_attrs);
		
		if (!NT_STATUS_IS_OK(result)) {
			d_printf("Unable to query group members of %s",argv[0]);
   			goto done;
		}
		
		if (opt_verbose) {
			d_printf("Domain Group %s (rid: %d) has %d members\n",
				argv[0],group_rid,num_members);
		}

		/* Check if group is anyone's primary group */
                for (i = 0; i < num_members; i++)
		{
	                result = cli_samr_open_user(cli, mem_ctx, &domain_pol,
					            MAXIMUM_ALLOWED_ACCESS,
					            group_rids[i], &user_pol);
	
	        	if (!NT_STATUS_IS_OK(result)) {
				d_printf("Unable to open group member %d\n",group_rids[i]);
	           		goto done;
	        	}
	
	                ZERO_STRUCT(user_ctr);

	                result = cli_samr_query_userinfo(cli, mem_ctx, &user_pol,
	                                                 21, &user_ctr);
	
	        	if (!NT_STATUS_IS_OK(result)) {
				d_printf("Unable to lookup userinfo for group member %d\n",group_rids[i]);
	           		goto done;
	        	}
	
			if (user_ctr->info.id21->group_rid == group_rid) {
				unistr2_to_ascii(temp, &(user_ctr->info.id21)->uni_user_name, 
						sizeof(temp)-1);
				if (opt_verbose) 
					d_printf("Group is primary group of %s\n",temp);
				group_is_primary = True;
                        }

			cli_samr_close(cli, mem_ctx, &user_pol);
		}
                
		if (group_is_primary) {
			d_printf("Unable to delete group because some of it's "
				 "members have it as primary group\n");
			result = NT_STATUS_MEMBERS_PRIMARY_GROUP;
			goto done;
		}
     
		/* remove all group members */
		for (i = 0; i < num_members; i++)
		{
			if (opt_verbose) 
				d_printf("Remove group member %d...",group_rids[i]);
			result = cli_samr_del_groupmem(cli, mem_ctx, &group_pol, group_rids[i]);

			if (NT_STATUS_IS_OK(result)) {
				if (opt_verbose)
					d_printf("ok\n");
			} else {
				if (opt_verbose)
					d_printf("failed\n");
				goto done;
			}	
		}

		result = cli_samr_delete_dom_group(cli, mem_ctx, &group_pol);

		break;
	/* removing a local group is easier... */
	case SID_NAME_ALIAS:
		result = cli_samr_open_alias(cli, mem_ctx, &domain_pol,
					     MAXIMUM_ALLOWED_ACCESS,
					     group_rids[0], &group_pol);

		if (!NT_STATUS_IS_OK(result)) {
			d_printf("Request open_alias failed\n");
   			goto done;
		}
		
		result = cli_samr_delete_dom_alias(cli, mem_ctx, &group_pol);
		break;
	default:
		d_printf("%s is of type %s. This command is only for deleting local or global groups\n",
			argv[0],sid_type_lookup(name_types[0]));
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
         
	
	if (NT_STATUS_IS_OK(result)) {
		if (opt_verbose)
			d_printf("Deleted %s '%s'\n",sid_type_lookup(name_types[0]),argv[0]);
	} else {
		d_printf("Deleting of %s failed: %s\n",argv[0],
			get_friendly_nt_error_msg(result));
	}
	
 done:
	return result;	
        
}

static int rpc_group_delete(int argc, const char **argv)
{
	return run_rpc_command(NULL, PI_SAMR, 0, rpc_group_delete_internals,
                               argc,argv);
}

static NTSTATUS 
rpc_group_add_internals(const DOM_SID *domain_sid, const char *domain_name, 
			struct cli_state *cli,
			TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	POLICY_HND connect_pol, domain_pol, group_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	GROUP_INFO_CTR group_info;

	if (argc != 1) {
		d_printf("Group name must be specified\n");
		rpc_group_usage(argc, argv);
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

	/* Create the group */

	result = cli_samr_create_dom_group(cli, mem_ctx, &domain_pol,
					   argv[0], MAXIMUM_ALLOWED_ACCESS,
					   &group_pol);
	if (!NT_STATUS_IS_OK(result)) goto done;

	if (strlen(opt_comment) == 0) goto done;

	/* We've got a comment to set */

	group_info.switch_value1 = 4;
	init_samr_group_info4(&group_info.group.info4, opt_comment);

	result = cli_samr_set_groupinfo(cli, mem_ctx, &group_pol, &group_info);
	if (!NT_STATUS_IS_OK(result)) goto done;
	
 done:
	if (NT_STATUS_IS_OK(result))
		DEBUG(5, ("add group succeeded\n"));
	else
		d_printf("add group failed: %s\n", nt_errstr(result));

	return result;
}

static NTSTATUS 
rpc_alias_add_internals(const DOM_SID *domain_sid, const char *domain_name, 
			struct cli_state *cli,
			TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	POLICY_HND connect_pol, domain_pol, alias_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	ALIAS_INFO_CTR alias_info;

	if (argc != 1) {
		d_printf("Group name must be specified\n");
		rpc_group_usage(argc, argv);
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

	/* Create the group */

	result = cli_samr_create_dom_alias(cli, mem_ctx, &domain_pol,
					   argv[0], &alias_pol);
	if (!NT_STATUS_IS_OK(result)) goto done;

	if (strlen(opt_comment) == 0) goto done;

	/* We've got a comment to set */

	alias_info.switch_value1 = 3;
	alias_info.switch_value2 = 3;
	init_samr_alias_info3(&alias_info.alias.info3, opt_comment);

	result = cli_samr_set_aliasinfo(cli, mem_ctx, &alias_pol, &alias_info);
	if (!NT_STATUS_IS_OK(result)) goto done;
	
 done:
	if (NT_STATUS_IS_OK(result))
		DEBUG(5, ("add group succeeded\n"));
	else
		d_printf("add group failed: %s\n", nt_errstr(result));

	return result;
}

static int rpc_group_add(int argc, const char **argv)
{
	if (opt_localgroup)
		return run_rpc_command(NULL, PI_SAMR, 0,
				       rpc_alias_add_internals,
				       argc, argv);

	return run_rpc_command(NULL, PI_SAMR, 0,
			       rpc_group_add_internals,
			       argc, argv);
}

static NTSTATUS
get_sid_from_name(struct cli_state *cli, TALLOC_CTX *mem_ctx, const char *name,
		  DOM_SID *sid, enum SID_NAME_USE *type)
{
	int current_pipe = cli->pipe_idx;

	DOM_SID *sids = NULL;
	uint32 *types = NULL;
	POLICY_HND lsa_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (current_pipe != PI_LSARPC) {

		if (current_pipe != -1)
			cli_nt_session_close(cli);

		if (!cli_nt_session_open(cli, PI_LSARPC))
			goto done;
	}

	result = cli_lsa_open_policy(cli, mem_ctx, False,
				     SEC_RIGHTS_MAXIMUM_ALLOWED, &lsa_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_lsa_lookup_names(cli, mem_ctx, &lsa_pol, 1,
				      &name, &sids, &types);

	if (NT_STATUS_IS_OK(result)) {
		sid_copy(sid, &sids[0]);
		*type = types[0];
	}

	cli_lsa_close(cli, mem_ctx, &lsa_pol);

 done:
	if (current_pipe != PI_LSARPC) {
		cli_nt_session_close(cli);
		if (current_pipe != -1)
			cli_nt_session_open(cli, current_pipe);
	}

	if (!NT_STATUS_IS_OK(result) && (StrnCaseCmp(name, "S-", 2) == 0)) {

		/* Try as S-1-5-whatever */

		DOM_SID tmp_sid;

		if (string_to_sid(&tmp_sid, name)) {
			sid_copy(sid, &tmp_sid);
			*type = SID_NAME_UNKNOWN;
			result = NT_STATUS_OK;
		}
	}

	return result;
}

static NTSTATUS
rpc_add_groupmem(struct cli_state *cli, TALLOC_CTX *mem_ctx,
		 const DOM_SID *group_sid, const char *member)
{
	POLICY_HND connect_pol, domain_pol;
	NTSTATUS result;
	uint32 group_rid;
	POLICY_HND group_pol;

	uint32 num_rids;
	uint32 *rids = NULL;
	uint32 *rid_types = NULL;

	DOM_SID sid;

	sid_copy(&sid, group_sid);

	if (!sid_split_rid(&sid, &group_rid))
		return NT_STATUS_UNSUCCESSFUL;

	/* Get sam policy handle */	
	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);
	if (!NT_STATUS_IS_OK(result))
		return result;
	
	/* Get domain policy handle */
	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &sid, &domain_pol);
	if (!NT_STATUS_IS_OK(result))
		return result;

	result = cli_samr_lookup_names(cli, mem_ctx, &domain_pol, 1000,
				       1, &member,
				       &num_rids, &rids, &rid_types);

	if (!NT_STATUS_IS_OK(result)) {
		d_printf("Could not lookup up group member %s\n", member);
		goto done;
	}

	result = cli_samr_open_group(cli, mem_ctx, &domain_pol,
				     MAXIMUM_ALLOWED_ACCESS,
				     group_rid, &group_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_samr_add_groupmem(cli, mem_ctx, &group_pol, rids[0]);

 done:
	cli_samr_close(cli, mem_ctx, &connect_pol);
	return result;
}

static NTSTATUS
rpc_add_aliasmem(struct cli_state *cli, TALLOC_CTX *mem_ctx,
		 const DOM_SID *alias_sid, const char *member)
{
	POLICY_HND connect_pol, domain_pol;
	NTSTATUS result;
	uint32 alias_rid;
	POLICY_HND alias_pol;

	DOM_SID member_sid;
	enum SID_NAME_USE member_type;

	DOM_SID sid;

	sid_copy(&sid, alias_sid);

	if (!sid_split_rid(&sid, &alias_rid))
		return NT_STATUS_UNSUCCESSFUL;

	result = get_sid_from_name(cli, mem_ctx, member,
				   &member_sid, &member_type);

	if (!NT_STATUS_IS_OK(result)) {
		d_printf("Could not lookup up group member %s\n", member);
		return result;
	}

	/* Get sam policy handle */	
	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}
	
	/* Get domain policy handle */
	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &sid, &domain_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	result = cli_samr_open_alias(cli, mem_ctx, &domain_pol,
				     MAXIMUM_ALLOWED_ACCESS,
				     alias_rid, &alias_pol);

	if (!NT_STATUS_IS_OK(result))
		return result;

	result = cli_samr_add_aliasmem(cli, mem_ctx, &alias_pol, &member_sid);

	if (!NT_STATUS_IS_OK(result))
		return result;

 done:
	cli_samr_close(cli, mem_ctx, &connect_pol);
	return result;
}

static NTSTATUS 
rpc_group_addmem_internals(const DOM_SID *domain_sid, const char *domain_name, 
			   struct cli_state *cli,
			   TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	DOM_SID group_sid;
	enum SID_NAME_USE group_type;

	if (argc != 2) {
		d_printf("Usage: 'net rpc group addmem <group> <member>\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!NT_STATUS_IS_OK(get_sid_from_name(cli, mem_ctx, argv[0],
					       &group_sid, &group_type))) {
		d_printf("Could not lookup group name %s\n", argv[0]);
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (group_type == SID_NAME_DOM_GRP) {
		NTSTATUS result = rpc_add_groupmem(cli, mem_ctx,
						   &group_sid, argv[1]);

		if (!NT_STATUS_IS_OK(result)) {
			d_printf("Could not add %s to %s: %s\n",
				 argv[1], argv[0], nt_errstr(result));
		}
		return result;
	}

	if (group_type == SID_NAME_ALIAS) {
		NTSTATUS result = rpc_add_aliasmem(cli, mem_ctx,
						   &group_sid, argv[1]);

		if (!NT_STATUS_IS_OK(result)) {
			d_printf("Could not add %s to %s: %s\n",
				 argv[1], argv[0], nt_errstr(result));
		}
		return result;
	}

	d_printf("Can only add members to global or local groups which "
		 "%s is not\n", argv[0]);

	return NT_STATUS_UNSUCCESSFUL;
}

static int rpc_group_addmem(int argc, const char **argv)
{
	return run_rpc_command(NULL, PI_SAMR, 0,
			       rpc_group_addmem_internals,
			       argc, argv);
}

static NTSTATUS
rpc_del_groupmem(struct cli_state *cli, TALLOC_CTX *mem_ctx,
		 const DOM_SID *group_sid, const char *member)
{
	POLICY_HND connect_pol, domain_pol;
	NTSTATUS result;
	uint32 group_rid;
	POLICY_HND group_pol;

	uint32 num_rids;
	uint32 *rids = NULL;
	uint32 *rid_types = NULL;

	DOM_SID sid;

	sid_copy(&sid, group_sid);

	if (!sid_split_rid(&sid, &group_rid))
		return NT_STATUS_UNSUCCESSFUL;

	/* Get sam policy handle */	
	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);
	if (!NT_STATUS_IS_OK(result))
		return result;
	
	/* Get domain policy handle */
	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &sid, &domain_pol);
	if (!NT_STATUS_IS_OK(result))
		return result;

	result = cli_samr_lookup_names(cli, mem_ctx, &domain_pol, 1000,
				       1, &member,
				       &num_rids, &rids, &rid_types);

	if (!NT_STATUS_IS_OK(result)) {
		d_printf("Could not lookup up group member %s\n", member);
		goto done;
	}

	result = cli_samr_open_group(cli, mem_ctx, &domain_pol,
				     MAXIMUM_ALLOWED_ACCESS,
				     group_rid, &group_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_samr_del_groupmem(cli, mem_ctx, &group_pol, rids[0]);

 done:
	cli_samr_close(cli, mem_ctx, &connect_pol);
	return result;
}

static NTSTATUS
rpc_del_aliasmem(struct cli_state *cli, TALLOC_CTX *mem_ctx,
		 const DOM_SID *alias_sid, const char *member)
{
	POLICY_HND connect_pol, domain_pol;
	NTSTATUS result;
	uint32 alias_rid;
	POLICY_HND alias_pol;

	DOM_SID member_sid;
	enum SID_NAME_USE member_type;

	DOM_SID sid;

	sid_copy(&sid, alias_sid);

	if (!sid_split_rid(&sid, &alias_rid))
		return NT_STATUS_UNSUCCESSFUL;

	result = get_sid_from_name(cli, mem_ctx, member,
				   &member_sid, &member_type);

	if (!NT_STATUS_IS_OK(result)) {
		d_printf("Could not lookup up group member %s\n", member);
		return result;
	}

	/* Get sam policy handle */	
	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}
	
	/* Get domain policy handle */
	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &sid, &domain_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	result = cli_samr_open_alias(cli, mem_ctx, &domain_pol,
				     MAXIMUM_ALLOWED_ACCESS,
				     alias_rid, &alias_pol);

	if (!NT_STATUS_IS_OK(result))
		return result;

	result = cli_samr_del_aliasmem(cli, mem_ctx, &alias_pol, &member_sid);

	if (!NT_STATUS_IS_OK(result))
		return result;

 done:
	cli_samr_close(cli, mem_ctx, &connect_pol);
	return result;
}

static NTSTATUS 
rpc_group_delmem_internals(const DOM_SID *domain_sid, const char *domain_name, 
			   struct cli_state *cli,
			   TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	DOM_SID group_sid;
	enum SID_NAME_USE group_type;

	if (argc != 2) {
		d_printf("Usage: 'net rpc group delmem <group> <member>\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!NT_STATUS_IS_OK(get_sid_from_name(cli, mem_ctx, argv[0],
					       &group_sid, &group_type))) {
		d_printf("Could not lookup group name %s\n", argv[0]);
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (group_type == SID_NAME_DOM_GRP) {
		NTSTATUS result = rpc_del_groupmem(cli, mem_ctx,
						   &group_sid, argv[1]);

		if (!NT_STATUS_IS_OK(result)) {
			d_printf("Could not del %s from %s: %s\n",
				 argv[1], argv[0], nt_errstr(result));
		}
		return result;
	}

	if (group_type == SID_NAME_ALIAS) {
		NTSTATUS result = rpc_del_aliasmem(cli, mem_ctx, 
						   &group_sid, argv[1]);

		if (!NT_STATUS_IS_OK(result)) {
			d_printf("Could not del %s from %s: %s\n",
				 argv[1], argv[0], nt_errstr(result));
		}
		return result;
	}

	d_printf("Can only delete members from global or local groups which "
		 "%s is not\n", argv[0]);

	return NT_STATUS_UNSUCCESSFUL;
}

static int rpc_group_delmem(int argc, const char **argv)
{
	return run_rpc_command(NULL, PI_SAMR, 0,
			       rpc_group_delmem_internals,
			       argc, argv);
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
rpc_group_list_internals(const DOM_SID *domain_sid, const char *domain_name, 
			 struct cli_state *cli,
			 TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	POLICY_HND connect_pol, domain_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 start_idx=0, max_entries=250, num_entries, i, loop_count = 0;
	struct acct_info *groups;
	DOM_SID global_sid_Builtin;
	BOOL global = False;
	BOOL local = False;
	BOOL builtin = False;

	if (argc == 0) {
		global = True;
		local = True;
		builtin = True;
	}

	for (i=0; i<argc; i++) {
		if (strequal(argv[i], "global"))
			global = True;

		if (strequal(argv[i], "local"))
			local = True;

		if (strequal(argv[i], "builtin"))
			builtin = True;
	}

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
		SAM_DISPINFO_CTR ctr;
		SAM_DISPINFO_3 info3;
		uint32 max_size;

		ZERO_STRUCT(ctr);
		ZERO_STRUCT(info3);
		ctr.sam.info3 = &info3;

		if (!global) break;

		get_query_dispinfo_params(
			loop_count, &max_entries, &max_size);

		result = cli_samr_query_dispinfo(cli, mem_ctx, &domain_pol,
						 &start_idx, 3, &num_entries,
						 max_entries, max_size, &ctr);

		if (!NT_STATUS_IS_OK(result) &&
		    !NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES))
			break;
						 
		for (i = 0; i < num_entries; i++) {

			fstring group, desc;

			unistr2_to_ascii(group, &(&ctr.sam.info3->str[i])->uni_grp_name, sizeof(group)-1);
			unistr2_to_ascii(desc, &(&ctr.sam.info3->str[i])->uni_grp_desc, sizeof(desc)-1);
			
			if (opt_long_list_entries)
				printf("%-21.21s %-50.50s\n",
				       group, desc);
			else
				printf("%s\n", group);
		}
	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));
	/* query domain aliases */
	start_idx = 0;
	do {
		if (!local) break;

		result = cli_samr_enum_als_groups(cli, mem_ctx, &domain_pol,
						  &start_idx, max_entries,
						  &groups, &num_entries);

		if (!NT_STATUS_IS_OK(result) &&
		    !NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES))
			break;
						 
		for (i = 0; i < num_entries; i++) {

			char *description = NULL;

			if (opt_long_list_entries) {

				POLICY_HND alias_pol;
				ALIAS_INFO_CTR ctr;

				if ((NT_STATUS_IS_OK(cli_samr_open_alias(cli, mem_ctx,
									 &domain_pol,
									 0x8,
									 groups[i].rid,
									 &alias_pol))) &&
				    (NT_STATUS_IS_OK(cli_samr_query_alias_info(cli, mem_ctx,
									       &alias_pol, 3,
									       &ctr))) &&
				    (NT_STATUS_IS_OK(cli_samr_close(cli, mem_ctx,
								    &alias_pol)))) {
					description = unistr2_tdup(mem_ctx,
								   &ctr.alias.info3.uni_acct_desc);
				}
			}
			
			if (description != NULL) {
				printf("%-21.21s %-50.50s\n", 
				       groups[i].acct_name,
				       description);
			} else {
				printf("%s\n", groups[i].acct_name);
			}
		}
	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));
	cli_samr_close(cli, mem_ctx, &domain_pol);
	/* Get builtin policy handle */
	
	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &global_sid_Builtin, &domain_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}
	/* query builtin aliases */
	start_idx = 0;
	do {
		if (!builtin) break;

		result = cli_samr_enum_als_groups(cli, mem_ctx, &domain_pol,
						  &start_idx, max_entries,
						  &groups, &num_entries);
						 
		if (!NT_STATUS_IS_OK(result) &&
		    !NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES))
			break;
						 
		for (i = 0; i < num_entries; i++) {

			char *description = NULL;

			if (opt_long_list_entries) {

				POLICY_HND alias_pol;
				ALIAS_INFO_CTR ctr;

				if ((NT_STATUS_IS_OK(cli_samr_open_alias(cli, mem_ctx,
									 &domain_pol,
									 0x8,
									 groups[i].rid,
									 &alias_pol))) &&
				    (NT_STATUS_IS_OK(cli_samr_query_alias_info(cli, mem_ctx,
									       &alias_pol, 3,
									       &ctr))) &&
				    (NT_STATUS_IS_OK(cli_samr_close(cli, mem_ctx,
								    &alias_pol)))) {
					description = unistr2_tdup(mem_ctx,
								   &ctr.alias.info3.uni_acct_desc);
				}
			}
			
			if (description != NULL) {
				printf("%-21.21s %-50.50s\n", 
				       groups[i].acct_name,
				       description);
			} else {
				printf("%s\n", groups[i].acct_name);
			}
		}
	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

 done:
	return result;
}

static int rpc_group_list(int argc, const char **argv)
{
	return run_rpc_command(NULL, PI_SAMR, 0,
			       rpc_group_list_internals,
			       argc, argv);
}

static NTSTATUS
rpc_list_group_members(struct cli_state *cli, TALLOC_CTX *mem_ctx,
		       const char *domain_name, const DOM_SID *domain_sid,
		       POLICY_HND *domain_pol, uint32 rid)
{
	NTSTATUS result;
	POLICY_HND group_pol;
	uint32 num_members, *group_rids, *group_attrs;
	uint32 num_names;
	char **names;
	uint32 *name_types;
	int i;

	fstring sid_str;
	sid_to_string(sid_str, domain_sid);

	result = cli_samr_open_group(cli, mem_ctx, domain_pol,
				     MAXIMUM_ALLOWED_ACCESS,
				     rid, &group_pol);

	if (!NT_STATUS_IS_OK(result))
		return result;

	result = cli_samr_query_groupmem(cli, mem_ctx, &group_pol,
					 &num_members, &group_rids,
					 &group_attrs);

	if (!NT_STATUS_IS_OK(result))
		return result;

	while (num_members > 0) {
		int this_time = 512;

		if (num_members < this_time)
			this_time = num_members;

		result = cli_samr_lookup_rids(cli, mem_ctx, domain_pol, 1000,
					      this_time, group_rids,
					      &num_names, &names, &name_types);

		if (!NT_STATUS_IS_OK(result))
			return result;

		/* We only have users as members, but make the output
		   the same as the output of alias members */

		for (i = 0; i < this_time; i++) {

			if (opt_long_list_entries) {
				printf("%s-%d %s\\%s %d\n", sid_str,
				       group_rids[i], domain_name, names[i],
				       SID_NAME_USER);
			} else {
				printf("%s\\%s\n", domain_name, names[i]);
			}
		}

		num_members -= this_time;
		group_rids += 512;
	}

	return NT_STATUS_OK;
}

static NTSTATUS
rpc_list_alias_members(struct cli_state *cli, TALLOC_CTX *mem_ctx,
		       POLICY_HND *domain_pol, uint32 rid)
{
	NTSTATUS result;
	POLICY_HND alias_pol, lsa_pol;
	uint32 num_members;
	DOM_SID *alias_sids;
	char **domains;
	char **names;
	uint32 *types;
	int i;

	result = cli_samr_open_alias(cli, mem_ctx, domain_pol,
				     MAXIMUM_ALLOWED_ACCESS, rid, &alias_pol);

	if (!NT_STATUS_IS_OK(result))
		return result;

	result = cli_samr_query_aliasmem(cli, mem_ctx, &alias_pol,
					 &num_members, &alias_sids);

	if (!NT_STATUS_IS_OK(result)) {
		d_printf("Couldn't list alias members\n");
		return result;
	}

	if (num_members == 0) {
		return NT_STATUS_OK;
	}

	cli_nt_session_close(cli);

	if (!cli_nt_session_open(cli, PI_LSARPC)) {
		d_printf("Couldn't open LSA pipe\n");
		return result;
	}

	result = cli_lsa_open_policy(cli, mem_ctx, True,
				     SEC_RIGHTS_MAXIMUM_ALLOWED, &lsa_pol);

	if (!NT_STATUS_IS_OK(result)) {
		d_printf("Couldn't open LSA policy handle\n");
		return result;
	}

	result = cli_lsa_lookup_sids(cli, mem_ctx, &lsa_pol, num_members,
				     alias_sids, 
				     &domains, &names, &types);

	if (!NT_STATUS_IS_OK(result) &&
	    !NT_STATUS_EQUAL(result, STATUS_SOME_UNMAPPED)) {
		d_printf("Couldn't lookup SIDs\n");
		return result;
	}

	for (i = 0; i < num_members; i++) {
		fstring sid_str;
		sid_to_string(sid_str, &alias_sids[i]);

		if (opt_long_list_entries) {
			printf("%s %s\\%s %d\n", sid_str, 
			       domains[i] ? domains[i] : "*unknown*", 
			       names[i] ? names[i] : "*unknown*", types[i]);
		} else {
			if (domains[i])
				printf("%s\\%s\n", domains[i], names[i]);
			else
				printf("%s\n", sid_str);
		}
	}

	return NT_STATUS_OK;
}
 
static NTSTATUS 
rpc_group_members_internals(const DOM_SID *domain_sid,
			    const char *domain_name, 
			    struct cli_state *cli,
			    TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	NTSTATUS result;
	POLICY_HND connect_pol, domain_pol;
	uint32 num_rids, *rids, *rid_types;

	/* Get sam policy handle */
	
	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);

	if (!NT_STATUS_IS_OK(result))
		return result;
	
	/* Get domain policy handle */
	
	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      domain_sid, &domain_pol);

	if (!NT_STATUS_IS_OK(result))
		return result;

	result = cli_samr_lookup_names(cli, mem_ctx, &domain_pol, 1000,
				       1, argv, &num_rids, &rids, &rid_types);

	if (!NT_STATUS_IS_OK(result)) {

		/* Ok, did not find it in the global sam, try with builtin */

		DOM_SID sid_Builtin;

		cli_samr_close(cli, mem_ctx, &domain_pol);

		string_to_sid(&sid_Builtin, "S-1-5-32");		

		result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					      MAXIMUM_ALLOWED_ACCESS,
					      &sid_Builtin, &domain_pol);

		if (!NT_STATUS_IS_OK(result)) {
			d_printf("Couldn't find group %s\n", argv[0]);
			return result;
		}

		result = cli_samr_lookup_names(cli, mem_ctx, &domain_pol, 1000,
					       1, argv, &num_rids,
					       &rids, &rid_types);

		if (!NT_STATUS_IS_OK(result)) {
			d_printf("Couldn't find group %s\n", argv[0]);
			return result;
		}
	}

	if (num_rids != 1) {
		d_printf("Couldn't find group %s\n", argv[0]);
		return result;
	}

	if (rid_types[0] == SID_NAME_DOM_GRP) {
		return rpc_list_group_members(cli, mem_ctx, domain_name,
					      domain_sid, &domain_pol,
					      rids[0]);
	}

	if (rid_types[0] == SID_NAME_ALIAS) {
		return rpc_list_alias_members(cli, mem_ctx, &domain_pol,
					      rids[0]);
	}

	return NT_STATUS_NO_SUCH_GROUP;
}

static int rpc_group_members(int argc, const char **argv)
{
	if (argc != 1) {
		return rpc_group_usage(argc, argv);
	}

	return run_rpc_command(NULL, PI_SAMR, 0,
			       rpc_group_members_internals,
			       argc, argv);
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
		{"add", rpc_group_add},
		{"delete", rpc_group_delete},
		{"addmem", rpc_group_addmem},
		{"delmem", rpc_group_delmem},
		{"list", rpc_group_list},
		{"members", rpc_group_members},
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
rpc_share_add_internals(const DOM_SID *domain_sid, const char *domain_name, 
			struct cli_state *cli,
			TALLOC_CTX *mem_ctx,int argc, const char **argv)
{
	WERROR result;
	char *sharename=talloc_strdup(mem_ctx, argv[0]);
	char *path;
	uint32 type=0; /* only allow disk shares to be added */
	uint32 num_users=0, perms=0;
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
rpc_share_del_internals(const DOM_SID *domain_sid, const char *domain_name, 
			struct cli_state *cli,
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
		d_printf("%-12s %-8.8s %-50s\n",
			 netname, share_type[info1->info_1.type], remark);
	} else {
		d_printf("%s\n", netname);
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
rpc_share_list_internals(const DOM_SID *domain_sid, const char *domain_name, 
			 struct cli_state *cli,
			 TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	SRV_SHARE_INFO_CTR ctr;
	WERROR result;
	ENUM_HND hnd;
	uint32 preferred_len = 0xffffffff, i;

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
rpc_file_close_internals(const DOM_SID *domain_sid, const char *domain_name, 
			 struct cli_state *cli,
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
rpc_file_list_internals(const DOM_SID *domain_sid, const char *domain_name, 
			struct cli_state *cli,
			TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	SRV_FILE_INFO_CTR ctr;
	WERROR result;
	ENUM_HND hnd;
	uint32 preferred_len = 0xffffffff, i;
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
 * ABORT the shutdown of a remote RPC Server over, initshutdown pipe
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

static NTSTATUS rpc_shutdown_abort_internals(const DOM_SID *domain_sid, 
					     const char *domain_name, 
					     struct cli_state *cli, 
					     TALLOC_CTX *mem_ctx, 
					     int argc, const char **argv) 
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	
	result = cli_shutdown_abort(cli, mem_ctx);
	
	if (NT_STATUS_IS_OK(result))
		DEBUG(5,("cmd_shutdown_abort: query succeeded\n"));
	else
		DEBUG(5,("cmd_shutdown_abort: query failed\n"));
	
	return result;
}


/** 
 * ABORT the shutdown of a remote RPC Server,  over winreg pipe
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

static NTSTATUS rpc_reg_shutdown_abort_internals(const DOM_SID *domain_sid, 
						 const char *domain_name, 
						 struct cli_state *cli, 
						 TALLOC_CTX *mem_ctx, 
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
	int rc = run_rpc_command(NULL, PI_SHUTDOWN, 0, 
				 rpc_shutdown_abort_internals,
				 argc, argv);

	if (rc == 0)
		return rc;

	DEBUG(1, ("initshutdown pipe didn't work, trying winreg pipe\n"));

	return run_rpc_command(NULL, PI_WINREG, 0, 
			       rpc_reg_shutdown_abort_internals,
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

static NTSTATUS rpc_shutdown_internals(const DOM_SID *domain_sid, 
				       const char *domain_name, 
				       struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				       int argc, const char **argv) 
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        const char *msg = "This machine will be shutdown shortly";
	uint32 timeout = 20;
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

static NTSTATUS rpc_trustdom_add_internals(const DOM_SID *domain_sid, 
					   const char *domain_name, 
					   struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                                           int argc, const char **argv) {

	POLICY_HND connect_pol, domain_pol, user_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	char *acct_name;
	uint16 acb_info;
	uint32 unknown, user_rid;

	if (argc != 2) {
		d_printf("Usage: net rpc trustdom add <domain_name> <pw>\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* 
	 * Make valid trusting domain account (ie. uppercased and with '$' appended)
	 */
	 
	if (asprintf(&acct_name, "%s$", argv[0]) < 0) {
		return NT_STATUS_NO_MEMORY;
	}

	strupper_m(acct_name);

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
	unknown = 0xe00500b0; /* No idea what this is - a permission mask?
	                         mimir: yes, most probably it is */

	result = cli_samr_create_dom_user(cli, mem_ctx, &domain_pol,
					  acct_name, acb_info, unknown,
					  &user_pol, &user_rid);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	{
		SAM_USERINFO_CTR ctr;
		SAM_USER_INFO_24 p24;
		uchar pwbuf[516];

		encode_pw_buffer((char *)pwbuf, argv[1], STR_UNICODE);

		ZERO_STRUCT(ctr);
		ZERO_STRUCT(p24);

		init_sam_user_info24(&p24, (char *)pwbuf, 24);

		ctr.switch_value = 24;
		ctr.info.id24 = &p24;

		result = cli_samr_set_userinfo(cli, mem_ctx, &user_pol, 24,
					       &cli->user_session_key, &ctr);

		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(0,("Could not set trust account password: %s\n",
				 nt_errstr(result)));
			goto done;
		}
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
	if (argc > 0) {
		return run_rpc_command(NULL, PI_SAMR, 0, rpc_trustdom_add_internals,
		                       argc, argv);
	} else {
		d_printf("Usage: net rpc trustdom add <domain>\n");
		return -1;
	}
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
	d_printf("Use 'smbpasswd -x -i' instead.\n");
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
	DOM_SID *domain_sid;
	WKS_INFO_100 wks_info;
	
	char* domain_name;
	char* domain_name_pol;
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
	strupper_m(domain_name);

	/* account name used at first is our domain's name with '$' */
	asprintf(&acct_name, "%s$", lp_workgroup());
	strupper_m(acct_name);
	
	/*
	 * opt_workgroup will be used by connection functions further,
	 * hence it should be set to remote domain name instead of ours
	 */
	if (opt_workgroup) {
		opt_workgroup = smb_xstrdup(domain_name);
	};
	
	opt_user_name = acct_name;

	/* find the domain controller */
	if (!net_find_pdc(&server_ip, pdc_name, domain_name)) {
		DEBUG(0, ("Couldn't find domain controller for domain %s\n", domain_name));
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
	                                      5 /* info level */, &domain_name_pol,
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
						   *domain_sid)) {
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
	 
	d_printf("Trust to domain %s established\n", domain_name);
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
	strupper_m(domain_name);

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


static NTSTATUS rpc_query_domain_sid(const DOM_SID *domain_sid, 
				     const char *domain_name, 
				     struct cli_state *cli, TALLOC_CTX *mem_ctx,
				     int argc, const char **argv)
{
	fstring str_sid;
	sid_to_string(str_sid, domain_sid);
	d_printf("%s\n", str_sid);
	return NT_STATUS_OK;
}


static int rpc_trustdom_list(int argc, const char **argv)
{
	/* common variables */
	TALLOC_CTX* mem_ctx;
	struct cli_state *cli, *remote_cli;
	NTSTATUS nt_status;
	const char *domain_name = NULL;
	DOM_SID *queried_dom_sid;
	fstring ascii_sid, padding;
	int ascii_dom_name_len;
	POLICY_HND connect_hnd;
	
	/* trusted domains listing variables */
	unsigned int num_domains, enum_ctx = 0;
	int i, pad_len, col_len = 20;
	DOM_SID *domain_sids;
	char **trusted_dom_names;
	fstring pdc_name;
	char *dummy;
	
	/* trusting domains listing variables */
	POLICY_HND domain_hnd;
	char **trusting_dom_names;
	uint32 *trusting_dom_rids;
	
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
		fstrcpy(pdc_name, global_myname());
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

	nt_status = cli_lsa_open_policy2(cli, mem_ctx, False, SEC_RIGHTS_QUERY_VALUE,
					&connect_hnd);
	if (NT_STATUS_IS_ERR(nt_status)) {
		DEBUG(0, ("Couldn't open policy handle. Error was %s\n",
 			nt_errstr(nt_status)));
		return -1;
	};
	
	/* query info level 5 to obtain sid of a domain being queried */
	nt_status = cli_lsa_query_info_policy(
		cli, mem_ctx, &connect_hnd, 5 /* info level */, 
		&dummy, &queried_dom_sid);

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
					 queried_dom_sid, &domain_hnd);									 
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
			strupper_m(trusting_dom_names[i]);
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
	if (!attempt_netbios_session_request(&cli, global_myname(), 
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

/* dump sam database via samsync rpc calls */
static int rpc_samdump(int argc, const char **argv) {
	return run_rpc_command(NULL, PI_NETLOGON, NET_FLAGS_ANONYMOUS, rpc_samdump_internals,
			       argc, argv);
}

/* syncronise sam database via samsync rpc calls */
static int rpc_vampire(int argc, const char **argv) {
	return run_rpc_command(NULL, PI_NETLOGON, NET_FLAGS_ANONYMOUS, rpc_vampire_internals,
			       argc, argv);
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
	d_printf("  net rpc oldjoin \t\t\tto join a domain created in server manager\n\n\n");
	d_printf("  net rpc testjoin \t\ttests that a join is valid\n");
	d_printf("  net rpc user \t\t\tto add, delete and list users\n");
        d_printf("  net rpc password <username> [<password>] -Uadmin_username%%admin_pass");
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
		{"oldjoin", net_rpc_oldjoin},
		{"testjoin", net_rpc_testjoin},
		{"user", net_rpc_user},
		{"password", rpc_user_password},
		{"group", net_rpc_group},
		{"share", net_rpc_share},
		{"file", net_rpc_file},
		{"changetrustpw", net_rpc_changetrustpw},
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
