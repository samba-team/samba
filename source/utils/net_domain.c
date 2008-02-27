/* 
   Samba Unix/Linux SMB client library 
   net ads commands
   Copyright (C) 2001 Andrew Tridgell (tridge@samba.org)
   Copyright (C) 2001 Remus Koos (remuskoos@yahoo.com)
   Copyright (C) 2002 Jim McDonough (jmcd@us.ibm.com)
   Copyright (C) 2006 Gerald (Jerry) Carter (jerry@samba.org)
   Copyright (C) 2008 Guenther Deschner (gd@samba.org)

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

/*******************************************************************
 Leave an AD domain.  Windows XP disables the machine account.
 We'll try the same.  The old code would do an LDAP delete.
 That only worked using the machine creds because added the machine
 with full control to the computer object's ACL.
*******************************************************************/

NTSTATUS netdom_leave_domain( TALLOC_CTX *mem_ctx, struct cli_state *cli, 
                         DOM_SID *dom_sid )
{	
	struct rpc_pipe_client *pipe_hnd = NULL;
	POLICY_HND sam_pol, domain_pol, user_pol;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	char *acct_name;
	uint32 user_rid;
	struct lsa_String lsa_acct_name;
	struct samr_Ids user_rids;
	struct samr_Ids name_types;
	union samr_UserInfo *info = NULL;

	/* Open the domain */
	
	if ( (pipe_hnd = cli_rpc_pipe_open_noauth(cli, PI_SAMR, &status)) == NULL ) {
		DEBUG(0, ("Error connecting to SAM pipe. Error was %s\n",
			nt_errstr(status) ));
		return status;
	}

	status = rpccli_samr_Connect2(pipe_hnd, mem_ctx,
				      pipe_hnd->cli->desthost,
				      SEC_RIGHTS_MAXIMUM_ALLOWED,
				      &sam_pol);
	if ( !NT_STATUS_IS_OK(status) )
		return status;


	status = rpccli_samr_OpenDomain(pipe_hnd, mem_ctx,
					&sam_pol,
					SEC_RIGHTS_MAXIMUM_ALLOWED,
					dom_sid,
					&domain_pol);
	if ( !NT_STATUS_IS_OK(status) )
		return status;

	/* Create domain user */
	
	acct_name = talloc_asprintf(mem_ctx, "%s$", global_myname()); 
	strlower_m(acct_name);

	init_lsa_String(&lsa_acct_name, acct_name);

	status = rpccli_samr_LookupNames(pipe_hnd, mem_ctx,
					 &domain_pol,
					 1,
					 &lsa_acct_name,
					 &user_rids,
					 &name_types);
	if ( !NT_STATUS_IS_OK(status) )
		return status;

	if ( name_types.ids[0] != SID_NAME_USER) {
		DEBUG(0, ("%s is not a user account (type=%d)\n", acct_name, name_types.ids[0]));
		return NT_STATUS_INVALID_WORKSTATION;
	}

	user_rid = user_rids.ids[0];
		
	/* Open handle on user */

	status = rpccli_samr_OpenUser(pipe_hnd, mem_ctx,
				      &domain_pol,
				      SEC_RIGHTS_MAXIMUM_ALLOWED,
				      user_rid,
				      &user_pol);
	if ( !NT_STATUS_IS_OK(status) ) {
		goto done;
	}
	
	/* Get user info */

	status = rpccli_samr_QueryUserInfo(pipe_hnd, mem_ctx,
					   &user_pol,
					   16,
					   &info);
	if ( !NT_STATUS_IS_OK(status) ) {
		rpccli_samr_Close(pipe_hnd, mem_ctx, &user_pol);
		goto done;
	}

	/* now disable and setuser info */

	info->info16.acct_flags |= ACB_DISABLED;

	status = rpccli_samr_SetUserInfo(pipe_hnd, mem_ctx,
					 &user_pol,
					 16,
					 info);

	rpccli_samr_Close(pipe_hnd, mem_ctx, &user_pol);

done:
	rpccli_samr_Close(pipe_hnd, mem_ctx, &domain_pol);
	rpccli_samr_Close(pipe_hnd, mem_ctx, &sam_pol);
	
	cli_rpc_pipe_close(pipe_hnd); /* Done with this pipe */
	
	return status;
}

/*******************************************************************
 Store the machine password and domain SID
 ********************************************************************/

int netdom_store_machine_account( const char *domain, DOM_SID *sid, const char *pw )
{
	if (!secrets_store_domain_sid(domain, sid)) {
		DEBUG(1,("Failed to save domain sid\n"));
		return -1;
	}

	if (!secrets_store_machine_password(pw, domain, SEC_CHAN_WKSTA)) {
		DEBUG(1,("Failed to save machine password\n"));
		return -1;
	}

	return 0;
}

/*******************************************************************
 ********************************************************************/

NTSTATUS netdom_get_domain_sid( TALLOC_CTX *mem_ctx, struct cli_state *cli, 
				const char **domain, DOM_SID **sid )
{
	struct rpc_pipe_client *pipe_hnd = NULL;
	POLICY_HND lsa_pol;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	union lsa_PolicyInformation *info = NULL;

	if ( (pipe_hnd = cli_rpc_pipe_open_noauth(cli, PI_LSARPC, &status)) == NULL ) {
		DEBUG(0, ("Error connecting to LSA pipe. Error was %s\n",
			nt_errstr(status) ));
		return status;
	}

	status = rpccli_lsa_open_policy(pipe_hnd, mem_ctx, True,
			SEC_RIGHTS_MAXIMUM_ALLOWED, &lsa_pol);
	if ( !NT_STATUS_IS_OK(status) )
		return status;

	status = rpccli_lsa_QueryInfoPolicy(pipe_hnd, mem_ctx,
					    &lsa_pol,
					    LSA_POLICY_INFO_ACCOUNT_DOMAIN,
					    &info);
	if ( !NT_STATUS_IS_OK(status) )
		return status;

	*domain = info->account_domain.name.string;
	*sid = info->account_domain.sid;

	rpccli_lsa_Close(pipe_hnd, mem_ctx, &lsa_pol);
	cli_rpc_pipe_close(pipe_hnd); /* Done with this pipe */

	/* Bail out if domain didn't get set. */
	if (!domain) {
		DEBUG(0, ("Could not get domain name.\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	return NT_STATUS_OK;
}

/*******************************************************************
 Do the domain join
 ********************************************************************/
 
NTSTATUS netdom_join_domain( TALLOC_CTX *mem_ctx, struct cli_state *cli, 
                           DOM_SID *dom_sid, const char *clear_pw,
                           enum netdom_domain_t dom_type )
{	
	struct rpc_pipe_client *pipe_hnd = NULL;
	POLICY_HND sam_pol, domain_pol, user_pol;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	char *acct_name;
	struct lsa_String lsa_acct_name;
	uint32 user_rid;
	uint32 acb_info = ACB_WSTRUST;
	uint32 acct_flags;
	uchar pwbuf[532];
	struct MD5Context md5ctx;
	uchar md5buffer[16];
	DATA_BLOB digested_session_key;
	uchar md4_trust_password[16];
	uint32_t access_granted = 0;
	struct samr_Ids user_rids;
	struct samr_Ids name_types;
	union samr_UserInfo info;

	/* Open the domain */
	
	if ( (pipe_hnd = cli_rpc_pipe_open_noauth(cli, PI_SAMR, &status)) == NULL ) {
		DEBUG(0, ("Error connecting to SAM pipe. Error was %s\n",
			nt_errstr(status) ));
		return status;
	}

	status = rpccli_samr_Connect2(pipe_hnd, mem_ctx,
				      pipe_hnd->cli->desthost,
				      SEC_RIGHTS_MAXIMUM_ALLOWED,
				      &sam_pol);
	if ( !NT_STATUS_IS_OK(status) )
		return status;


	status = rpccli_samr_OpenDomain(pipe_hnd, mem_ctx,
					&sam_pol,
					SEC_RIGHTS_MAXIMUM_ALLOWED,
					dom_sid,
					&domain_pol);
	if ( !NT_STATUS_IS_OK(status) )
		return status;

	/* Create domain user */
	
	acct_name = talloc_asprintf(mem_ctx, "%s$", global_myname()); 
	strlower_m(acct_name);

	init_lsa_String(&lsa_acct_name, acct_name);

	/* Don't try to set any acb_info flags other than ACB_WSTRUST */
	acct_flags = SEC_GENERIC_READ | SEC_GENERIC_WRITE | SEC_GENERIC_EXECUTE |
		     SEC_STD_WRITE_DAC | SEC_STD_DELETE |
		     SAMR_USER_ACCESS_SET_PASSWORD |
		     SAMR_USER_ACCESS_GET_ATTRIBUTES |
		     SAMR_USER_ACCESS_SET_ATTRIBUTES;

	DEBUG(10, ("Creating account with flags: %d\n",acct_flags));

	status = rpccli_samr_CreateUser2(pipe_hnd, mem_ctx,
					 &domain_pol,
					 &lsa_acct_name,
					 acb_info,
					 acct_flags,
					 &user_pol,
					 &access_granted,
					 &user_rid);

	if ( !NT_STATUS_IS_OK(status) 
		&& !NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) 
	{
		d_fprintf(stderr, "Creation of workstation account failed\n");

		/* If NT_STATUS_ACCESS_DENIED then we have a valid
		   username/password combo but the user does not have
		   administrator access. */

		if (NT_STATUS_V(status) == NT_STATUS_V(NT_STATUS_ACCESS_DENIED))
			d_fprintf(stderr, "User specified does not have administrator privileges\n");

		return status;
	}

	/* We *must* do this.... don't ask... */

	if (NT_STATUS_IS_OK(status)) {
		rpccli_samr_Close(pipe_hnd, mem_ctx, &user_pol);
	}

	status = rpccli_samr_LookupNames(pipe_hnd, mem_ctx,
					 &domain_pol,
					 1,
					 &lsa_acct_name,
					 &user_rids,
					 &name_types);
	if ( !NT_STATUS_IS_OK(status) )
		return status;

	if ( name_types.ids[0] != SID_NAME_USER) {
		DEBUG(0, ("%s is not a user account (type=%d)\n", acct_name, name_types.ids[0]));
		return NT_STATUS_INVALID_WORKSTATION;
	}

	user_rid = user_rids.ids[0];
		
	/* Open handle on user */

	status = rpccli_samr_OpenUser(pipe_hnd, mem_ctx,
				      &domain_pol,
				      SEC_RIGHTS_MAXIMUM_ALLOWED,
				      user_rid,
				      &user_pol);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	/* Create a random machine account password and generate the hash */

	E_md4hash(clear_pw, md4_trust_password);
	encode_pw_buffer(pwbuf, clear_pw, STR_UNICODE);
	
	generate_random_buffer((uint8*)md5buffer, sizeof(md5buffer));
	digested_session_key = data_blob_talloc(mem_ctx, 0, 16);
	
	MD5Init(&md5ctx);
	MD5Update(&md5ctx, md5buffer, sizeof(md5buffer));
	MD5Update(&md5ctx, cli->user_session_key.data, cli->user_session_key.length);
	MD5Final(digested_session_key.data, &md5ctx);
	
	SamOEMhashBlob(pwbuf, sizeof(pwbuf), &digested_session_key);
	memcpy(&pwbuf[516], md5buffer, sizeof(md5buffer));

	/* Fill in the additional account flags now */

	acb_info |= ACB_PWNOEXP;
	if ( dom_type == ND_TYPE_AD ) {
#if !defined(ENCTYPE_ARCFOUR_HMAC)
		acb_info |= ACB_USE_DES_KEY_ONLY;
#endif
		;;
	}

	/* Set password and account flags on machine account */
	ZERO_STRUCT(info.info25);
	info.info25.info.fields_present = ACCT_NT_PWD_SET |
					  ACCT_LM_PWD_SET |
					  SAMR_FIELD_ACCT_FLAGS;
	info.info25.info.acct_flags = acb_info;
	memcpy(&info.info25.password.data, pwbuf, sizeof(pwbuf));


	status = rpccli_samr_SetUserInfo(pipe_hnd, mem_ctx,
					 &user_pol,
					 25,
					 &info);

	if ( !NT_STATUS_IS_OK(status) ) {
		d_fprintf( stderr, "Failed to set password for machine account (%s)\n", 
			nt_errstr(status));
		return status;
	}

	rpccli_samr_Close(pipe_hnd, mem_ctx, &user_pol);
	cli_rpc_pipe_close(pipe_hnd); /* Done with this pipe */
	
	return status;
}

