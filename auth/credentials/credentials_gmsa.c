/*
   Unix SMB/CIFS implementation.

   User credentials handling for Group Managed Service Accounts

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2023

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
#include "librpc/gen_ndr/samr.h" /* for struct samrPassword */
#include "librpc/gen_ndr/ndr_gmsa.h" /* for struct MANAGEDPASSWORD_BLOB */
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_internal.h"
#include "lib/util/charset/charset.h"

NTSTATUS cli_credentials_set_gmsa_passwords(struct cli_credentials *creds,
					    const DATA_BLOB *managed_password_blob,
					    const char **error_string)
{
	struct MANAGEDPASSWORD_BLOB managed_password;
	DATA_BLOB managed_pw_utf16;
	DATA_BLOB previous_managed_pw_utf16;
	enum ndr_err_code ndr_err;

	TALLOC_CTX *frame = talloc_stackframe();

	ndr_err = ndr_pull_struct_blob_all(managed_password_blob,
					   frame,
					   &managed_password,
					   (ndr_pull_flags_fn_t)ndr_pull_MANAGEDPASSWORD_BLOB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		*error_string = talloc_asprintf(creds,
						"Failed to parse msDS-ManagedPassword "
						"as MANAGEDPASSWORD_BLOB");
		TALLOC_FREE(frame);
		return NT_STATUS_ILL_FORMED_PASSWORD;
	}

	if (managed_password.passwords.current == NULL) {
		*error_string = talloc_asprintf(creds,
						"Failed to find new password in msDS-ManagedPassword "
						"MANAGEDPASSWORD_BLOB");
		TALLOC_FREE(frame);
		return NT_STATUS_ILL_FORMED_PASSWORD;
	}

	managed_pw_utf16
		= data_blob_const(managed_password.passwords.current,
				  utf16_len(managed_password.passwords.current));

	cli_credentials_set_utf16_password(creds, &managed_pw_utf16,
					   CRED_SPECIFIED);

	if (managed_password.passwords.previous == NULL) {
		*error_string = talloc_asprintf(creds,
						"Failed to find previous password in msDS-ManagedPassword "
						"MANAGEDPASSWORD_BLOB");
		TALLOC_FREE(frame);
		return NT_STATUS_ILL_FORMED_PASSWORD;
	}

	previous_managed_pw_utf16
		= data_blob_const(managed_password.passwords.previous,
				  utf16_len(managed_password.passwords.previous));

	cli_credentials_set_old_utf16_password(creds, &previous_managed_pw_utf16);

	/*
	 * Group Managed Service Accounts are type
	 * UF_WORKSTATION_TRUST_ACCOUNT and will follow those salting
	 * rules
	 */
	cli_credentials_set_secure_channel_type(creds, SEC_CHAN_WKSTA);

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

