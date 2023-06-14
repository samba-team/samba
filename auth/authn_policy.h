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

#ifndef KDC_AUTHN_POLICY_H
#define KDC_AUTHN_POLICY_H

#include "lib/replace/replace.h"
#include "libcli/util/ntstatus.h"
#include "librpc/gen_ndr/windows_event_ids.h"

/* Authentication policies for Kerberos clients. */

struct authn_kerberos_client_policy;

/* Get the raw TGT lifetime enforced by an authentication policy. */
int64_t authn_policy_enforced_tgt_lifetime_raw(const struct authn_kerberos_client_policy *policy);

/* Authentication policies for NTLM clients. */

struct authn_ntlm_client_policy;

/* Check whether the client is allowed to authenticate using NTLM. */
NTSTATUS authn_policy_ntlm_apply_device_restriction(const char *client_account_name,
						    const char *device_account_name,
						    const struct authn_ntlm_client_policy *client_policy);

enum authn_audit_event {
	AUTHN_AUDIT_EVENT_OK = 0,
	AUTHN_AUDIT_EVENT_KERBEROS_DEVICE_RESTRICTION,
	AUTHN_AUDIT_EVENT_KERBEROS_SERVER_RESTRICTION,
	AUTHN_AUDIT_EVENT_NTLM_DEVICE_RESTRICTION,
	AUTHN_AUDIT_EVENT_NTLM_SERVER_RESTRICTION,
	AUTHN_AUDIT_EVENT_OTHER_ERROR,
};

enum authn_audit_reason {
	AUTHN_AUDIT_REASON_NONE = 0,
	AUTHN_AUDIT_REASON_DESCRIPTOR_INVALID,
	AUTHN_AUDIT_REASON_DESCRIPTOR_NO_OWNER,
	AUTHN_AUDIT_REASON_SECURITY_TOKEN_FAILURE,
	AUTHN_AUDIT_REASON_ACCESS_DENIED,
	AUTHN_AUDIT_REASON_FAST_REQUIRED,
};

struct authn_int64_optional {
	bool is_present;
	int64_t val;
};

#endif
