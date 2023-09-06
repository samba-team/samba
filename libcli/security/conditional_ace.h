/*
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright © Catalyst

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

#ifndef _CONDITIONAL_ACE_H_
#define _CONDITIONAL_ACE_H_


struct ace_condition_script *parse_conditional_ace(TALLOC_CTX *mem_ctx,
						   DATA_BLOB data);

int run_conditional_ace(TALLOC_CTX *mem_ctx,
			const struct security_token *token,
			struct ace_condition_script *program,
			const struct security_descriptor *sd);


bool access_check_conditional_ace(const struct security_ace *ace,
				  const struct security_token *token,
				  const struct security_descriptor *sd,
				  int *result);

bool conditional_ace_encode_binary(TALLOC_CTX *mem_ctx,
				   struct ace_condition_script *program,
				   DATA_BLOB *dest);

struct ace_condition_script * ace_conditions_compile_sddl(TALLOC_CTX *mem_ctx,
							  const char *sddl,
							  const char **message,
							  size_t *message_offset,
							  size_t *consumed_length);

char *debug_conditional_ace(TALLOC_CTX *mem_ctx,
			    struct ace_condition_script *program);

char *sddl_from_conditional_ace(TALLOC_CTX *mem_ctx,
				struct ace_condition_script *program);

struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *parse_sddl_literal_as_claim(
	TALLOC_CTX *mem_ctx,
	const char *name,
	const char *str);

struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *sddl_decode_resource_attr (
	TALLOC_CTX *mem_ctx,
	const char *str,
	size_t *length);

char *sddl_resource_attr_from_claim(
	TALLOC_CTX *mem_ctx,
	const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim);


#endif /*_CONDITIONAL_ACE_H_*/
