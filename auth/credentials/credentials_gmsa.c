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
#include "librpc/gen_ndr/ndr_gmsa.h" /* for struct MANAGEDPASSWORD_BLOB */
#include "auth/credentials/credentials.h"
#include "auth/credentials/credentials_internal.h"
#include "lib/util/charset/charset.h"
#include "lib/crypto/gkdi.h"
/*
 * All current callers set "for_keytab = true", but if we start using
 * this for getting a TGT we need the logic to ignore a very new
 * key
 */
NTSTATUS cli_credentials_set_gmsa_passwords(struct cli_credentials *creds,
					    const DATA_BLOB *managed_password_blob,
					    bool for_keytab,
					    const char **error_string)
{
	struct MANAGEDPASSWORD_BLOB managed_password;
	DATA_BLOB managed_pw_utf16;
	DATA_BLOB previous_managed_pw_utf16;
	enum ndr_err_code ndr_err;
	TALLOC_CTX *frame = talloc_stackframe();
	bool only_use_previous_pw;

	/*
	 * Group Managed Service Accounts are type
	 * UF_WORKSTATION_TRUST_ACCOUNT and will follow those salting
	 * rules
	 */
	cli_credentials_set_secure_channel_type(creds, SEC_CHAN_WKSTA);

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

	/*
	 * We check if this is 'for keytab' as a keytab wants to know
	 * about a near-future password as it will be on disk for some
	 * time
	 */
	only_use_previous_pw =
		managed_password.passwords.query_interval != NULL
		&& *managed_password.passwords.query_interval <= gkdi_max_clock_skew
		&& for_keytab == false;

	/*
	 * We look at the old password first as we might bail out
	 * early if the new password is "too fresh"
	 */
	if (managed_password.passwords.previous) {
		previous_managed_pw_utf16
			= data_blob_const(managed_password.passwords.previous,
					  utf16_len(managed_password.passwords.previous));

		cli_credentials_set_old_utf16_password(creds, &previous_managed_pw_utf16);

		if (only_use_previous_pw) {
			/* We are in the 5 mins where we know the next
			 * password, but it will not be available yet, just
			 * use the old password for now.
			 */
			cli_credentials_set_utf16_password(creds, &previous_managed_pw_utf16,
							   CRED_SPECIFIED);

			/*
			 * We are done, the new password is of no
			 * interest to us
			 */
			TALLOC_FREE(frame);
			return NT_STATUS_OK;
		}

	}

	if (only_use_previous_pw) {
		*error_string = talloc_asprintf(creds,
						"No old password but new password is too new "
						"(< 5min) in msDS-ManagedPassword "
						"MANAGEDPASSWORD_BLOB");
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

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}
