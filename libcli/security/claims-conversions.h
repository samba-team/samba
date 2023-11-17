/*
 *  Unix SMB implementation.
 *  Utility functions for converting between claims formats.
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

#ifndef LIBCLI_SECURITY_CLAIMS_CONVERSIONS_H
#define LIBCLI_SECURITY_CLAIMS_CONVERSIONS_H

#include "replace.h"
#include <talloc.h>
#include "libcli/util/ntstatus.h"

struct CLAIMS_SET;
struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1;
struct ace_condition_token;
struct security_token;

bool claim_v1_to_ace_token(TALLOC_CTX *mem_ctx,
			   const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
			   struct ace_condition_token *result);

bool ace_token_to_claim_v1(TALLOC_CTX *mem_ctx,
			   const char *name,
			   const struct ace_condition_token *tok,
			   struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 **claim,
			   uint32_t flags);

bool add_claim_to_token(TALLOC_CTX *mem_ctx,
			struct security_token *token,
			const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
			const char *claim_type);

NTSTATUS token_claims_to_claims_v1(TALLOC_CTX *mem_ctx,
				   const struct CLAIMS_SET *claims_set,
				   struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 **out_claims,
				   uint32_t *out_n_claims);

bool claim_v1_to_ace_composite_unchecked(TALLOC_CTX *mem_ctx,
					 const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
					 struct ace_condition_token *result);

NTSTATUS claim_v1_check_and_sort(
	TALLOC_CTX *mem_ctx,
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
	bool case_sensitive);

#endif /* LIBCLI_SECURITY_CLAIMS_CONVERSIONS_H */
