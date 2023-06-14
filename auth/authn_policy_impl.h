/*
   Unix SMB/CIFS implementation.
   Samba Active Directory authentication policy private implementation details

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

#ifndef KDC_AUTHN_POLICY_IMPL_H
#define KDC_AUTHN_POLICY_IMPL_H

#include "lib/replace/replace.h"

#include "auth/authn_policy.h"
#include "lib/util/data_blob.h"
#include "libcli/util/ntstatus.h"

struct authn_policy {
	const char *silo_name;
	const char *policy_name;
	bool enforced;
};

bool authn_policy_is_enforced(const struct authn_policy *policy);

struct authn_kerberos_client_policy {
	struct authn_policy policy;
	DATA_BLOB allowed_to_authenticate_from;
	int64_t tgt_lifetime_raw;
};

struct authn_ntlm_client_policy {
	struct authn_policy policy;
	DATA_BLOB allowed_to_authenticate_from;
	bool allowed_ntlm_network_auth;
};

struct authn_server_policy {
	struct authn_policy policy;
	DATA_BLOB allowed_to_authenticate_to;
};

#endif
