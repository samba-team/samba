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
	SAM_TRUST_PASSWD *trust = NULL;
	unsigned char new_trust_passwd_hash[16];
	char *new_trust_passwd;
	char *str;
	NTSTATUS nt_status;
	
	/* Get trust password before updating it */
	nt_status = pdb_init_trustpw_talloc(mem_ctx, &trust);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Couldn't init trust password\n"));
		return nt_status;
	}

	nt_status = pdb_gettrustpwnam(trust, domain);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Couldn't get trust password for domain [%s]\n", domain));
		return nt_status;
	}
		
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

		/* copying new password to trust password structure */
		if (trust->private.flags & PASS_TRUST_NT) {
			trust->private.pass = data_blob_talloc(mem_ctx, new_trust_passwd_hash,
							       NT_HASH_LEN);
		} else if (trust->private.flags & PASS_TRUST_ADS) {
			trust->private.pass = data_blob_talloc(mem_ctx, new_trust_passwd_hash,
							       strlen(new_trust_passwd_hash) + 1);
			trust->private.pass.data[trust->private.pass.length] = '\0';
		}

		/* trust password flags (according to sec channel type) */
		sec_channel_type = SCHANNEL_TYPE(trust->private.flags);
		
		nt_status = pdb_update_trust_passwd(trust);
		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(0, ("Error when updating trust password for domain [%s]\n",
				  domain));
			return nt_status;
		}
	}

	return nt_status;
}

/*********************************************************
 Change the domain password on the PDC.
 Do most of the legwork ourselves.  Caller must have
 already setup the connection to the NETLOGON pipe
**********************************************************/

NTSTATUS trust_pw_find_change_and_store_it(struct cli_state *cli, 
					   TALLOC_CTX *mem_ctx, 
					   const char *domain) 
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	SAM_TRUST_PASSWD *trust = NULL;
	unsigned char old_trust_passwd_hash[16];
	char *up_domain;
	uint32 sec_channel_type = 0;

	up_domain = talloc_strdup(mem_ctx, domain);
	
	nt_status = pdb_init_trustpw_talloc(mem_ctx, &trust);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Could not init trust password\n"));
		return NT_STATUS_NO_MEMORY;
	}
	
	nt_status = pdb_gettrustpwnam(trust, domain);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("could not fetch trust password for domain %s!\n", domain));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* TODO: here should actually be a test verifying whether trust
	   password is really a NT trust password */

	memcpy(old_trust_passwd_hash, trust->private.pass.data,
	       trust->private.pass.length);
	
	sec_channel_type = SCHANNEL_TYPE(trust->private.flags);
	
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
 * and puts a marker in secrets.tdb to avoid doing this again. This function needs to be
 * called only once.
 *
 * @return number of passwords migrated
 */

int migrate_trust_passwords(void)
{
	int migrated = 0, i;
	struct pdb_context *pdb_ctx = NULL;
	NTSTATUS nt_status;
	SAM_TRUST_PASSWD *trust = NULL;
	time_t lct;
	/* nt workstation trust */
	const char* dom_name = lp_workgroup();
	uint8 nt_wks_pass[NT_HASH_LEN];
	char* ads_wks_pass;
	uint32 chan = 0;
	DOM_SID dom_sid;
	/* nt domain trust */
	TALLOC_CTX *mem_ctx = NULL;
	const unsigned int max_trusts = 10;
	int enum_ctx = 0, num_trusts;
	TRUSTDOM **trusts;
	char *trust_name = NULL, *pass = NULL, nt_dom_pass[NT_HASH_LEN];
	DOM_SID sid;

	/* Checking whether passwords have already been migrated */
	if (secrets_passwords_migrated(False)) return migrated;

	nt_status = make_pdb_context_list(&pdb_ctx, lp_passdb_backend());
	if (!NT_STATUS_IS_OK(nt_status)) return -1;
	    
	if (!pdb_ctx) return -1;

	mem_ctx = talloc_init("trust password migration");

	nt_status = pdb_init_trustpw_talloc(mem_ctx, &trust);
	if (!NT_STATUS_IS_OK(nt_status)) return -1;

	/* NT Workstation trust passwords */
	if (lp_security() == SEC_DOMAIN &&
	    secrets_lock_trust_account_password(dom_name, True) &&
	    secrets_fetch_trust_account_password(dom_name, nt_wks_pass, &lct, &chan)) {

		pdb_set_tp_flags(trust, PASS_TRUST_NT);

		/* sec channel type and its corresponding flags */
		switch (chan) {
		case SEC_CHAN_WKSTA:  trust->private.flags |= PASS_TRUST_MACHINE;
			break;
		case SEC_CHAN_BDC:    trust->private.flags |= PASS_TRUST_SERVER;
			break;
		case SEC_CHAN_DOMAIN: trust->private.flags |= PASS_TRUST_DOMAIN;
			break;
		default:
			return 0;
		}

		/* unicode name */
		pdb_set_tp_domain_name_c(trust, dom_name);
		/* password (nt hash) */
		pdb_set_tp_pass(trust, nt_wks_pass, NT_HASH_LEN);
		/* last change time */
		pdb_set_tp_mod_time(trust, lct);
		
		/* domain sid */
		if (secrets_fetch_domain_sid(dom_name, &dom_sid))
			pdb_set_tp_domain_sid(trust, &dom_sid);
		else
			return 0;

		/* release mutex on secrets.tdb record */
		secrets_lock_trust_account_password(dom_name, False);
		
		nt_status = pdb_ctx->pdb_add_trust_passwd(pdb_ctx, trust);
		if (NT_STATUS_IS_OK(nt_status) ||
		    NT_STATUS_EQUAL(nt_status, NT_STATUS_USER_EXISTS))
			migrated++;
		else
			return -1;
	}

	/* NT Domain trust passwords */
	do {
		nt_status = secrets_get_trusted_domains(mem_ctx, &enum_ctx, max_trusts,
							&num_trusts, &trusts);
		for (i = 0; i < num_trusts; i++) {
			pdb_set_tp_flags(trust, PASS_TRUST_NT | PASS_TRUST_DOMAIN);
			pull_ucs2_talloc(mem_ctx, &trust_name, trusts[i]->name);

			if (secrets_fetch_trusted_domain_password(trust_name, &pass, &sid, &lct)) {
				pdb_set_tp_domain_name(trust, trusts[i]->name);
				E_md4hash(pass, nt_dom_pass);
				memset(pass, 0, strlen(pass));
				SAFE_FREE(pass);
				pdb_set_tp_pass(trust, nt_dom_pass, sizeof(nt_dom_pass));
				pdb_set_tp_domain_sid(trust, &sid);
				pdb_set_tp_mod_time(trust, lct);
			}

			nt_status = pdb_ctx->pdb_add_trust_passwd(pdb_ctx, trust);
			if (NT_STATUS_IS_OK(nt_status) ||
			    NT_STATUS_EQUAL(nt_status, NT_STATUS_USER_EXISTS))
				migrated++;
			else
				return -1;
		}

	} while (NT_STATUS_EQUAL(nt_status, STATUS_MORE_ENTRIES));

	/* ADS Workstation trust passwords */
	if (lp_security() == SEC_ADS &&
	    secrets_lock_trust_account_password(dom_name, True) &&
	    (ads_wks_pass = secrets_fetch_machine_password(dom_name, &lct, &chan))) {

		pdb_set_tp_flags(trust, PASS_TRUST_ADS);

		/* sec channel type and its corresponding flags */
		switch (chan) {
		case SEC_CHAN_WKSTA:  trust->private.flags |= PASS_TRUST_MACHINE;
			break;
		case SEC_CHAN_DOMAIN: trust->private.flags |= PASS_TRUST_DOMAIN;
			break;
		default:
			return 0;
		}

		/* domain name */
		pdb_set_tp_domain_name_c(trust, dom_name);
		/* password (plaintext) */
		pdb_set_tp_pass(trust, ads_wks_pass, strlen(ads_wks_pass) + 1);
		/* last change time */
		pdb_set_tp_mod_time(trust, lct);
		
		/* domain sid */
		if (secrets_fetch_domain_sid(dom_name, &dom_sid))
			pdb_set_tp_domain_sid(trust, &dom_sid);
		else
			return 0;
		
		/* release mutex on secrets.tdb record */
		secrets_lock_trust_account_password(dom_name, False);
		
		nt_status = pdb_ctx->pdb_add_trust_passwd(pdb_ctx, trust);
		if (NT_STATUS_IS_OK(nt_status) ||
		    NT_STATUS_EQUAL(nt_status, NT_STATUS_USER_EXISTS))
			migrated++;
		else
			return -1;
	}


	talloc_destroy(mem_ctx);

	/* We're done with migration process and don't need to repeat it */
	secrets_passwords_migrated(True);

	return migrated;
}
