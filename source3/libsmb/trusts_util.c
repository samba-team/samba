/*
 *  Unix SMB/CIFS implementation.
 *  Routines to operate on various trust relationships
 *  Copyright (C) Andrew Bartlett                   2001
 *  Copyright (C) Rafal Szczesniak                  2003
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "../libcli/auth/libcli_auth.h"
#include "rpc_client/cli_netlogon.h"
#include "rpc_client/cli_pipe.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "secrets.h"
#include "passdb.h"
#include "libsmb/libsmb.h"

/*********************************************************
 Change the domain password on the PDC.
 Store the password ourselves, but use the supplied password
 Caller must have already setup the connection to the NETLOGON pipe
**********************************************************/

NTSTATUS trust_pw_change_and_store_it(struct rpc_pipe_client *cli, TALLOC_CTX *mem_ctx, 
				      const char *domain,
				      const char *account_name,
				      unsigned char orig_trust_passwd_hash[16],
				      enum netr_SchannelType sec_channel_type)
{
	unsigned char new_trust_passwd_hash[16];
	char *new_trust_passwd;
	NTSTATUS nt_status;

	switch (sec_channel_type) {
	case SEC_CHAN_WKSTA:
	case SEC_CHAN_DOMAIN:
		break;
	default:
		return NT_STATUS_NOT_SUPPORTED;
	}

	/* Create a random machine account password */
	new_trust_passwd = generate_random_password(mem_ctx,
				DEFAULT_TRUST_ACCOUNT_PASSWORD_LENGTH,
				DEFAULT_TRUST_ACCOUNT_PASSWORD_LENGTH);
	if (new_trust_passwd == NULL) {
		DEBUG(0, ("generate_random_password failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	E_md4hash(new_trust_passwd, new_trust_passwd_hash);

	nt_status = rpccli_netlogon_set_trust_password(cli, mem_ctx,
						       account_name,
						       orig_trust_passwd_hash,
						       new_trust_passwd,
						       new_trust_passwd_hash,
						       sec_channel_type);

	if (NT_STATUS_IS_OK(nt_status)) {
		DEBUG(3,("%s : trust_pw_change_and_store_it: Changed password.\n", 
			 current_timestring(talloc_tos(), False)));
		/*
		 * Return the result of trying to write the new password
		 * back into the trust account file.
		 */

		switch (sec_channel_type) {

		case SEC_CHAN_WKSTA:
			if (!secrets_store_machine_password(new_trust_passwd, domain, sec_channel_type)) {
				nt_status = NT_STATUS_UNSUCCESSFUL;
			}
			break;

		case SEC_CHAN_DOMAIN: {
			char *pwd;
			struct dom_sid sid;
			time_t pass_last_set_time;

			/* we need to get the sid first for the
			 * pdb_set_trusteddom_pw call */

			if (!pdb_get_trusteddom_pw(domain, &pwd, &sid, &pass_last_set_time)) {
				nt_status = NT_STATUS_TRUSTED_RELATIONSHIP_FAILURE;
			}
			if (!pdb_set_trusteddom_pw(domain, new_trust_passwd, &sid)) {
				nt_status = NT_STATUS_INTERNAL_DB_CORRUPTION;
			}
			break;
		}
		default:
			break;
		}
	}

	return nt_status;
}

/*********************************************************
 Change the domain password on the PDC.
 Do most of the legwork ourselfs.  Caller must have
 already setup the connection to the NETLOGON pipe
**********************************************************/

NTSTATUS trust_pw_find_change_and_store_it(struct rpc_pipe_client *cli, 
					   TALLOC_CTX *mem_ctx, 
					   const char *domain) 
{
	unsigned char old_trust_passwd_hash[16];
	enum netr_SchannelType sec_channel_type = SEC_CHAN_NULL;
	const char *account_name;

	if (!get_trust_pw_hash(domain, old_trust_passwd_hash, &account_name,
			       &sec_channel_type)) {
		DEBUG(0, ("could not fetch domain secrets for domain %s!\n", domain));
		return NT_STATUS_UNSUCCESSFUL;
	}

	return trust_pw_change_and_store_it(cli, mem_ctx, domain,
					    account_name,
					    old_trust_passwd_hash,
					    sec_channel_type);
}

