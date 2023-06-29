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



bool claim_v1_to_ace_token(TALLOC_CTX *mem_ctx,
			   const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
			   struct ace_condition_token *result);

bool ace_token_to_claim_v1(TALLOC_CTX *mem_ctx,
			   const char *name,
			   struct ace_condition_token *tok,
			   struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 **claim,
			   uint32_t flags);

bool add_claim_to_token(TALLOC_CTX *mem_ctx,
			struct security_token *token,
			struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
			const char *claim_type);
