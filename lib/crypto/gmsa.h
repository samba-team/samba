/*
   Unix SMB/CIFS implementation.
   Group Managed Service Account functions

   Copyright (C) Catalyst.Net Ltd 2024

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef LIB_CRYPTO_GMSA_H
#define LIB_CRYPTO_GMSA_H

#include "lib/crypto/gkdi.h"

enum {
	GMSA_PASSWORD_LEN = 256,
	GMSA_PASSWORD_NULL_TERMINATED_LEN = GMSA_PASSWORD_LEN + 2,
};

struct gmsa_null_terminated_password {
	uint8_t buf[GMSA_PASSWORD_NULL_TERMINATED_LEN];
};

struct dom_sid;
NTSTATUS gmsa_password_based_on_key_id(
	TALLOC_CTX *mem_ctx,
	const struct Gkid gkid,
	const NTTIME current_time,
	const struct ProvRootKey *const root_key,
	const struct dom_sid *const account_sid,
	uint8_t password[static const GMSA_PASSWORD_NULL_TERMINATED_LEN]);

NTSTATUS gmsa_talloc_password_based_on_key_id(
	TALLOC_CTX *mem_ctx,
	const struct Gkid gkid,
	const NTTIME current_time,
	const struct ProvRootKey *const root_key,
	const struct dom_sid *const account_sid,
	struct gmsa_null_terminated_password **password_out);

bool gmsa_current_time(NTTIME *current_time_out);

#endif /* LIB_CRYPTO_GMSA_H */
