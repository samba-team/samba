/*
   Unix SMB/CIFS implementation.
   Samba Active Directory authentication policy functions

   Copyright (C) Catalyst.Net Ltd 2023

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

#include "lib/replace/replace.h"
#include "auth/authn_policy.h"
#include "auth/authn_policy_impl.h"

bool authn_policy_is_enforced(const struct authn_policy *policy)
{
	return policy->enforced;
}

/* Authentication policies for Kerberos clients. */

/* Get the TGT lifetime enforced by an authentication policy. */
int64_t authn_policy_enforced_tgt_lifetime(const struct authn_kerberos_client_policy *policy)
{
	if (policy == NULL) {
		return 0;
	}

	if (!authn_policy_is_enforced(&policy->policy)) {
		return 0;
	}

	return policy->tgt_lifetime;
}

/* Authentication policies for NTLM clients. */

/* Return whether an authentication policy enforces device restrictions. */
static bool authn_policy_ntlm_device_restrictions_present(const struct authn_ntlm_client_policy *policy)
{
	if (policy == NULL) {
		return false;
	}

	return policy->allowed_to_authenticate_from.data != NULL;
}

/* Check whether the client is allowed to authenticate using NTLM. */
NTSTATUS authn_policy_ntlm_apply_device_restriction(const char *client_account_name,
						    const char *device_account_name,
						    const struct authn_ntlm_client_policy *client_policy)
{
	/*
	 * If NTLM authentication is disallowed and the policy enforces a device
	 * restriction, deny the authentication.
	 */

	if (!authn_policy_ntlm_device_restrictions_present(client_policy)) {
		return NT_STATUS_OK;
	}

	/*
	 * Although MS-APDS doesn’t state it, AllowedNTLMNetworkAuthentication
	 * applies to interactive logons too.
	 */
	if (client_policy->allowed_ntlm_network_auth) {
		return NT_STATUS_OK;
	}

	if (authn_policy_is_enforced(&client_policy->policy)) {
		return NT_STATUS_ACCOUNT_RESTRICTION;
	} else {
		return NT_STATUS_OK;
	}
}
