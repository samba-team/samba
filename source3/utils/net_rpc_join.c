/* 
   Samba Unix/Linux SMB client library 
   Distributed SMB/CIFS Server Management Utility 
   Copyright (C) 2001 Andrew Bartlett (abartlet@samba.org)
   Copyright (C) Tim Potter     2001

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

/* Macro for checking RPC error codes to make things more readable */

#define CHECK_RPC_ERR(rpc, msg) \
        if (!NT_STATUS_IS_OK(result = rpc)) { \
                DEBUG(0, (msg ": %s\n", nt_errstr(result))); \
                goto done; \
        }

#define CHECK_RPC_ERR_DEBUG(rpc, debug_args) \
        if (!NT_STATUS_IS_OK(result = rpc)) { \
                DEBUG(0, debug_args); \
                goto done; \
        }

/**
 * Join a domain using the administrator username and password
 *
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped.  Currently not used.
 * @return A shell status integer (0 for success)
 *
 **/

int net_rpc_join_newstyle(int argc, const char **argv) 
{

	extern pstring global_myname;

	/* libsmb variables */

	struct cli_state *cli;
	fstring acct_name;
	TALLOC_CTX *mem_ctx;
        uint32 acb_info;

	/* rpc variables */

	POLICY_HND lsa_pol, sam_pol, domain_pol, user_pol;
	DOM_SID domain_sid;
	uint32 user_rid;

	/* Password stuff */

	char *clear_trust_password = NULL;
	fstring ucs2_trust_password;
	int ucs2_pw_len;
	uchar stored_md4_trust_password[16];
	uchar pwbuf[516], sess_key[16];
	SAM_USERINFO_CTR ctr;
	SAM_USER_INFO_24 p24;
	SAM_USER_INFO_10 p10;

	/* Misc */

	NTSTATUS result;
	int retval = 1;
	fstring domain;
	uint32 num_rids, *name_types, *user_rids;
	uint32 flags = 0x3e8;
	char *names;
	
	/* Connect to remote machine */

	if (!(cli = net_make_ipc_connection(NET_FLAGS_PDC))) 
		return 1;

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0, ("Could not initialise talloc context\n"));
		goto done;
	}

	/* Fetch domain sid */

	if (!cli_nt_session_open(cli, PIPE_LSARPC)) {
		DEBUG(0, ("Error connecting to SAM pipe\n"));
		goto done;
	}


	CHECK_RPC_ERR(cli_lsa_open_policy(cli, mem_ctx, True,
					  SEC_RIGHTS_MAXIMUM_ALLOWED,
					  &lsa_pol),
		      "error opening lsa policy handle");

	CHECK_RPC_ERR(cli_lsa_query_info_policy(cli, mem_ctx, &lsa_pol,
						5, domain, &domain_sid),
		      "error querying info policy");

	cli_lsa_close(cli, mem_ctx, &lsa_pol);

	cli_nt_session_close(cli); /* Done with this pipe */

	/* Create domain user */
	if (!cli_nt_session_open(cli, PIPE_SAMR)) {
		DEBUG(0, ("Error connecting to SAM pipe\n"));
		goto done;
	}

	CHECK_RPC_ERR(cli_samr_connect(cli, mem_ctx, 
				       SEC_RIGHTS_MAXIMUM_ALLOWED,
				       &sam_pol),
		      "could not connect to SAM database");

	
	CHECK_RPC_ERR(cli_samr_open_domain(cli, mem_ctx, &sam_pol,
					   SEC_RIGHTS_MAXIMUM_ALLOWED,
					   &domain_sid, &domain_pol),
		      "could not open domain");

	/* Create domain user */
	fstrcpy(acct_name, global_myname);
	fstrcat(acct_name, "$");
	strlower(acct_name);

        acb_info = (lp_server_role() == ROLE_DOMAIN_BDC) ? ACB_SVRTRUST : ACB_WSTRUST;

	result = cli_samr_create_dom_user(cli, mem_ctx, &domain_pol,
					  acct_name, acb_info,
					  0xe005000b, &user_pol, 
					  &user_rid);

	if (!NT_STATUS_IS_OK(result) && 
	    !NT_STATUS_EQUAL(result, NT_STATUS_USER_EXISTS)) {
		d_printf("Create of workstation account failed\n");

		/* If NT_STATUS_ACCESS_DENIED then we have a valid
		   username/password combo but the user does not have
		   administrator access. */

		if (NT_STATUS_V(result) == NT_STATUS_V(NT_STATUS_ACCESS_DENIED))
			d_printf("User specified does not have administrator privileges\n");

		goto done;
	}

	/* We *must* do this.... don't ask... */

	if (NT_STATUS_IS_OK(result))
		cli_samr_close(cli, mem_ctx, &user_pol);

	names = (char *)&acct_name[0];

	CHECK_RPC_ERR_DEBUG(cli_samr_lookup_names(cli, mem_ctx,
						  &domain_pol, flags,
						  1, &names, &num_rids,
						  &user_rids, &name_types),
			    ("error looking up rid for user %s: %s\n",
			     acct_name, nt_errstr(result)));

	if (name_types[0] != SID_NAME_USER) {
		DEBUG(0, ("%s is not a user account\n", acct_name));
		goto done;
	}

	user_rid = user_rids[0];
		
	/* Open handle on user */

	CHECK_RPC_ERR_DEBUG(
		cli_samr_open_user(cli, mem_ctx, &domain_pol,
				   SEC_RIGHTS_MAXIMUM_ALLOWED,
				   user_rid, &user_pol),
		("could not re-open existing user %s: %s\n",
		 acct_name, nt_errstr(result)));
	
	/* Create a random machine account password */

	{ 
		char *str;
		str = generate_random_str(DEFAULT_TRUST_ACCOUNT_PASSWORD_LENGTH);
		clear_trust_password = strdup(str);
	}

	ucs2_pw_len = push_ucs2(NULL, ucs2_trust_password, 
				clear_trust_password, 
				sizeof(ucs2_trust_password), 0);
		  
	encode_pw_buffer((char *)pwbuf, ucs2_trust_password,
			 ucs2_pw_len);

	/* Set password on machine account */

	ZERO_STRUCT(ctr);
	ZERO_STRUCT(p24);

	init_sam_user_info24(&p24, (char *)pwbuf,24);

	ctr.switch_value = 24;
	ctr.info.id24 = &p24;

	/* I don't think this is quite the right place for this
	   calculation.  It should be moved somewhere where the credentials
	   are calculated. )-: */

	mdfour(sess_key, cli->pwd.smb_nt_pwd, 16);

	CHECK_RPC_ERR(cli_samr_set_userinfo(cli, mem_ctx, &user_pol, 24, 
					    sess_key, &ctr),
		      "error setting trust account password");

	/* Why do we have to try to (re-)set the ACB to be the same as what
	   we passed in the samr_create_dom_user() call?  When a NT
	   workstation is joined to a domain by an administrator the
	   acb_info is set to 0x80.  For a normal user with "Add
	   workstations to the domain" rights the acb_info is 0x84.  I'm
	   not sure whether it is supposed to make a difference or not.  NT
	   seems to cope with either value so don't bomb out if the set
	   userinfo2 level 0x10 fails.  -tpot */

	ZERO_STRUCT(ctr);
	ctr.switch_value = 0x10;
	ctr.info.id10 = &p10;

	init_sam_user_info10(&p10, acb_info);

	/* Ignoring the return value is necessary for joining a domain
	   as a normal user with "Add workstation to domain" privilege. */

	result = cli_samr_set_userinfo2(cli, mem_ctx, &user_pol, 0x10, 
					sess_key, &ctr);

	/* Now store the secret in the secrets database */

	strupper(domain);

	if (!secrets_store_domain_sid(domain, &domain_sid)) {
		DEBUG(0, ("error storing domain sid for %s\n", domain));
		goto done;
	}

	if (!secrets_store_machine_password(clear_trust_password)) {
		DEBUG(0, ("error storing plaintext domain secrets for %s\n", domain));
	}

	/* Now check the whole process from top-to-bottom */

	cli_samr_close(cli, mem_ctx, &user_pol);

	cli_nt_session_close(cli); /* Done with this pipe */

	if (!cli_nt_session_open(cli, PIPE_NETLOGON)) {
		DEBUG(0, ("Error connecting to NETLOGON pipe\n"));
		goto done;
	}

	if (!secrets_fetch_trust_account_password(domain, 
						  stored_md4_trust_password, NULL)) {
		DEBUG(0, ("Could not reterive secrets we just stored!"));
		goto done;
	}
	
	CHECK_RPC_ERR(new_cli_nt_setup_creds(cli, 
					     (acb_info & ACB_SVRTRUST) ? SEC_CHAN_BDC : SEC_CHAN_WKSTA, 
					     stored_md4_trust_password),
			  "error in domain join verification");
	
	retval = 0;		/* Success! */
	
done:
	/* Close down pipe - this will clean up open policy handles */

	if (cli->nt_pipe_fnum)
		cli_nt_session_close(cli);

	/* Display success or failure */

	if (retval != 0) {
		trust_password_delete(domain);
		fprintf(stderr,"Unable to join domain %s.\n",domain);
	} else {
		printf("Joined domain %s.\n",domain);
	}
	
	cli_shutdown(cli);

	SAFE_FREE(clear_trust_password);

	return retval;
}
