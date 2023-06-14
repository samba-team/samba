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

/* Is an authentication policy enforced? */
bool authn_kerberos_client_policy_is_enforced(const struct authn_kerberos_client_policy *policy)
{
	return authn_policy_is_enforced(&policy->policy);
}

/* Get the raw TGT lifetime enforced by an authentication policy. */
int64_t authn_policy_enforced_tgt_lifetime_raw(const struct authn_kerberos_client_policy *policy)
{
	if (policy == NULL) {
		return 0;
	}

	if (!authn_policy_is_enforced(&policy->policy)) {
		return 0;
	}

	return policy->tgt_lifetime_raw;
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

/* Auditing information. */

enum auth_event_id_type authn_audit_info_event_id(const struct authn_audit_info *audit_info)
{
	bool is_enforced;

	if (audit_info->event == AUTHN_AUDIT_EVENT_OK) {
		/* We didn’t get an error. */
		return AUTH_EVT_ID_NONE;
	}

	if (audit_info->policy == NULL) {
		/*
		 * We got an error, but there’s no policy, so it must have
		 * stemmed from something else.
		 */
		return AUTH_EVT_ID_NONE;
	}

	is_enforced = authn_policy_is_enforced(audit_info->policy);

	switch (audit_info->event) {
	case AUTHN_AUDIT_EVENT_KERBEROS_DEVICE_RESTRICTION:
		if (is_enforced) {
			return AUTH_EVT_ID_KERBEROS_DEVICE_RESTRICTION;
		}

		return AUTH_EVT_ID_KERBEROS_DEVICE_RESTRICTION_AUDIT;

	case AUTHN_AUDIT_EVENT_KERBEROS_SERVER_RESTRICTION:
		if (is_enforced) {
			return AUTH_EVT_ID_KERBEROS_SERVER_RESTRICTION;
		}

		return AUTH_EVT_ID_KERBEROS_SERVER_RESTRICTION_AUDIT;

	case AUTHN_AUDIT_EVENT_NTLM_DEVICE_RESTRICTION:
		if (is_enforced) {
			return AUTH_EVT_ID_NTLM_DEVICE_RESTRICTION;
		}

		/* No relevant event ID. */
		break;

	case AUTHN_AUDIT_EVENT_NTLM_SERVER_RESTRICTION:
	case AUTHN_AUDIT_EVENT_OTHER_ERROR:
	default:
		/* No relevant event ID. */
		break;
	}

	return AUTH_EVT_ID_NONE;
}

const char *authn_audit_info_silo_name(const struct authn_audit_info *audit_info)
{
	if (audit_info->policy == NULL) {
		return NULL;
	}

	return audit_info->policy->silo_name;
}

const char *authn_audit_info_policy_name(const struct authn_audit_info *audit_info)
{
	if (audit_info->policy == NULL) {
		return NULL;
	}

	return audit_info->policy->policy_name;
}

const bool *authn_audit_info_policy_enforced(const struct authn_audit_info *audit_info)
{
	if (audit_info->policy == NULL) {
		return NULL;
	}

	return &audit_info->policy->enforced;
}

const struct auth_user_info_dc *authn_audit_info_client_info(const struct authn_audit_info *audit_info)
{
	return audit_info->client_info;
}

const char *authn_audit_info_event(const struct authn_audit_info *audit_info)
{
	switch (audit_info->event) {
	case AUTHN_AUDIT_EVENT_OK:
		return "OK";
	case AUTHN_AUDIT_EVENT_KERBEROS_DEVICE_RESTRICTION:
		return "KERBEROS_DEVICE_RESTRICTION";
	case AUTHN_AUDIT_EVENT_KERBEROS_SERVER_RESTRICTION:
		return "KERBEROS_SERVER_RESTRICTION";
	case AUTHN_AUDIT_EVENT_NTLM_DEVICE_RESTRICTION:
		return "NTLM_DEVICE_RESTRICTION";
	case AUTHN_AUDIT_EVENT_NTLM_SERVER_RESTRICTION:
		return "NTLM_SERVER_RESTRICTION";
	case AUTHN_AUDIT_EVENT_OTHER_ERROR:
	default:
		return "OTHER_ERROR";
	}
}

const char *authn_audit_info_reason(const struct authn_audit_info *audit_info)
{
	switch (audit_info->reason) {
	case AUTHN_AUDIT_REASON_DESCRIPTOR_INVALID:
		return "DESCRIPTOR_INVALID";
	case AUTHN_AUDIT_REASON_DESCRIPTOR_NO_OWNER:
		return "DESCRIPTOR_NO_OWNER";
	case AUTHN_AUDIT_REASON_SECURITY_TOKEN_FAILURE:
		return "SECURITY_TOKEN_FAILURE";
	case AUTHN_AUDIT_REASON_ACCESS_DENIED:
		return "ACCESS_DENIED";
	case AUTHN_AUDIT_REASON_FAST_REQUIRED:
		return "FAST_REQUIRED";
	case AUTHN_AUDIT_REASON_NONE:
	default:
		return NULL;
	}
}

NTSTATUS authn_audit_info_policy_status(const struct authn_audit_info *audit_info)
{
	return audit_info->policy_status;
}

const char *authn_audit_info_location(const struct authn_audit_info *audit_info)
{
	return audit_info->location;
}

struct authn_int64_optional authn_audit_info_policy_tgt_lifetime_mins(const struct authn_audit_info *audit_info)
{
	int64_t lifetime;

	if (!audit_info->tgt_lifetime_raw.is_present) {
		return authn_int64_none();
	}

	lifetime = audit_info->tgt_lifetime_raw.val;
	lifetime /= INT64_C(1000) * 1000 * 10 * 60;

	return authn_int64_some(lifetime);
}
