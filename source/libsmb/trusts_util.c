/*
 *  Unix SMB/CIFS implementation.
 *  Routines to operate on various trust relationships
 *  Copyright (C) Andrew Bartlett                   2001
 *  Copyright (C) Rafal Szczesniak                  2003
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

/*********************************************************
 Change the domain password on the PDC.

 Just changes the password betwen the two values specified.

 Caller must have the cli connected to the netlogon pipe
 already.
**********************************************************/
static NTSTATUS just_change_the_password(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
					 unsigned char orig_trust_passwd_hash[16],
					 unsigned char new_trust_passwd_hash[16],
					 uint32 sec_channel_type)
{
	NTSTATUS result;

	/* ensure that schannel uses the right domain */
	fstrcpy(cli->domain, lp_workgroup());
	if (! NT_STATUS_IS_OK(result = cli_nt_establish_netlogon(cli, sec_channel_type, orig_trust_passwd_hash))) {
		DEBUG(3,("just_change_the_password: unable to setup creds (%s)!\n",
			 nt_errstr(result)));
		return result;
	}
	
	result = cli_net_srv_pwset(cli, mem_ctx, global_myname(), new_trust_passwd_hash);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0,("just_change_the_password: unable to change password (%s)!\n",
			 nt_errstr(result)));
	}
	return result;
}

/*********************************************************
 Change the domain password on the PDC.
 Store the password ourselves, but use the supplied password
 Caller must have already setup the connection to the NETLOGON pipe
**********************************************************/

NTSTATUS trust_pw_change_and_store_it(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				      const char *domain,
				      unsigned char orig_trust_passwd_hash[16],
				      uint32 sec_channel_type)
{
	unsigned char new_trust_passwd_hash[16];
	char *new_trust_passwd;
	char *str;
	NTSTATUS nt_status;
		
	/* Create a random machine account password */
	str = generate_random_str(DEFAULT_TRUST_ACCOUNT_PASSWORD_LENGTH);
	new_trust_passwd = talloc_strdup(mem_ctx, str);
	
	E_md4hash(new_trust_passwd, new_trust_passwd_hash);

	nt_status = just_change_the_password(cli, mem_ctx, orig_trust_passwd_hash,
					     new_trust_passwd_hash, sec_channel_type);
	
	if (NT_STATUS_IS_OK(nt_status)) {
		DEBUG(3,("%s : trust_pw_change_and_store_it: Changed password.\n", 
			 timestring(False)));
		/*
		 * Return the result of trying to write the new password
		 * back into the trust account file.
		 */
		if (!secrets_store_machine_password(new_trust_passwd, domain, sec_channel_type)) {
			nt_status = NT_STATUS_UNSUCCESSFUL;
		}
	}

	return nt_status;
}

/*********************************************************
 Change the domain password on the PDC.
 Do most of the legwork ourselfs.  Caller must have
 already setup the connection to the NETLOGON pipe
**********************************************************/

NTSTATUS trust_pw_find_change_and_store_it(struct cli_state *cli, 
					   TALLOC_CTX *mem_ctx, 
					   const char *domain) 
{
	unsigned char old_trust_passwd_hash[16];
	char *up_domain;
	uint32 sec_channel_type = 0;

	up_domain = talloc_strdup(mem_ctx, domain);

	if (!secrets_fetch_trust_account_password(domain,
						  old_trust_passwd_hash, 
						  NULL, &sec_channel_type)) {
		DEBUG(0, ("could not fetch domain secrets for domain %s!\n", domain));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	return trust_pw_change_and_store_it(cli, mem_ctx, domain,
					    old_trust_passwd_hash,
					    sec_channel_type);
	
}

/*********************************************************************
 Enumerate the list of trusted domains from a DC
*********************************************************************/

BOOL enumerate_domain_trusts( TALLOC_CTX *mem_ctx, const char *domain,
                                     char ***domain_names, uint32 *num_domains,
				     DOM_SID **sids )
{
	POLICY_HND 	pol;
	NTSTATUS 	result = NT_STATUS_UNSUCCESSFUL;
	fstring 	dc_name;
	struct in_addr 	dc_ip;
	uint32 		enum_ctx = 0;
	struct cli_state *cli = NULL;
	BOOL 		retry;

	*domain_names = NULL;
	*num_domains = 0;
	*sids = NULL;

	/* lookup a DC first */

	if ( !get_dc_name(domain, NULL, dc_name, &dc_ip) ) {
		DEBUG(3,("enumerate_domain_trusts: can't locate a DC for domain %s\n",
			domain));
		return False;
	}

	/* setup the anonymous connection */

	result = cli_full_connection( &cli, global_myname(), dc_name, &dc_ip, 0, "IPC$", "IPC",
		"", "", "", 0, Undefined, &retry);
	if ( !NT_STATUS_IS_OK(result) )
		goto done;

	/* open the LSARPC_PIPE	*/

	if ( !cli_nt_session_open( cli, PI_LSARPC ) ) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* get a handle */

	result = cli_lsa_open_policy(cli, mem_ctx, True,
		POLICY_VIEW_LOCAL_INFORMATION, &pol);
	if ( !NT_STATUS_IS_OK(result) )
		goto done;

	/* Lookup list of trusted domains */

	result = cli_lsa_enum_trust_dom(cli, mem_ctx, &pol, &enum_ctx,
		num_domains, domain_names, sids);
	if ( !NT_STATUS_IS_OK(result) )
		goto done;

done:
	/* cleanup */
	if (cli) {
		DEBUG(10,("enumerate_domain_trusts: shutting down connection...\n"));
		cli_shutdown( cli );
	}

	return NT_STATUS_IS_OK(result);
}


/**
 * Migrates trust passwords from previous location (secrets.tdb) to current pdb backend
 * and puts a marker in secrets.tdb to avoid doing this again. This function should be
 * called only once.
 *
 * @return number of passwords migrated
 */

int migrate_trust_passwords(struct pdb_context *pdb_ctx)
{
	int migrated = 0, i;
	NTSTATUS nt_status;
	SAM_TRUST_PASSWD trust;
	const size_t max_name_len = sizeof(trust.private.uni_name)/2;
	time_t lct;
	/* nt workstation trust */
	const char* dom_name = lp_workgroup();
	uint8 wks_pass[16];
	uint32 chan = 0;
	DOM_SID dom_sid;
	/* nt domain trust */
	TALLOC_CTX *mem_ctx = NULL;
	const unsigned int max_trusts = 10;
	int enum_ctx = 0, num_trusts;
	TRUSTDOM **trusts;
	char *trust_name = NULL, *pass;
	size_t trust_name_len = 0;
	DOM_SID sid;

	/* sanity-check */
	if (!pdb_ctx) return 0;

	/* Checking whether passwords have already been migrated */
	if (secrets_passwords_migrated(False)) return migrated;

	/* NT Workstation trust passwords */
	if (secrets_fetch_trust_account_password(dom_name, wks_pass, &lct, &chan)) {
		memset(&trust, 0, sizeof(trust));

		/* TODO: put a lock on trust wks password */

		/* flags */
		trust.private.flags = PASS_TRUST_NT;
		switch (chan) {
		case SEC_CHAN_WKSTA:
			trust.private.flags |= PASS_TRUST_MACHINE;
			break;
		case SEC_CHAN_BDC:
			trust.private.flags |= PASS_TRUST_SERVER;
			break;
		default:
			return 0;
		}

		/* unicode name length */
		trust.private.uni_name_len = strlen(dom_name);
		/* unicode name */
		push_ucs2(NULL, &trust.private.uni_name, dom_name, max_name_len, STR_UPPER);
		/* password */
		strncpy(trust.private.pass, wks_pass, sizeof(trust.private.pass));
		/* last change time */
		trust.private.mod_time = lct;
		
		/* domain sid */
		if (secrets_fetch_domain_sid(dom_name, &dom_sid))
			sid_copy(&trust.private.domain_sid, &dom_sid);
		else
			return 0;
		
		nt_status = pdb_ctx->pdb_add_trust_passwd(pdb_ctx, &trust);
		migrated++;
	}

	/* NT Domain trust passwords */
	mem_ctx = talloc_init("trust password migration");
	do {
		nt_status = secrets_get_trusted_domains(mem_ctx, &enum_ctx, max_trusts,
							&num_trusts, &trusts);
		for (i = 0; i < (num_trusts - enum_ctx); i++) {
			memset(&trust, 0, sizeof(trust));
			trust.private.flags = PASS_TRUST_NT | PASS_TRUST_DOMAIN;
			pull_ucs2_allocate(&trust_name, trusts[i]->name);
			trust_name_len = strlen_w(trusts[i]->name);

			if (secrets_fetch_trusted_domain_password(trust_name, &pass, &sid, &lct)) {
				strncpy_w(trust.private.uni_name, trusts[i]->name, trust_name_len);
				trust.private.uni_name_len = trust_name_len;
				sid_copy(&trust.private.domain_sid, &sid);
				trust.private.mod_time = lct;
			}

			nt_status = pdb_ctx->pdb_add_trust_passwd(pdb_ctx, &trust);
			migrated++;

			SAFE_FREE(trust_name);
		}

	} while (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_MORE_ENTRIES));
	talloc_destroy(mem_ctx);

	/* ADS Workstation trust passwords */
	memset(&trust, 0, sizeof(trust));
	

	/* We're done with migration */
	secrets_passwords_migrated(True);

	return migrated;
}
