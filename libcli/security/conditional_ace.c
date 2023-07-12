/*
 *  Unix SMB implementation.
 *  Functions for understanding conditional ACEs
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

#include "replace.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/conditional_ace.h"
#include "libcli/security/security.h"
#include "libcli/security/conditional_ace.h"


struct ace_condition_script *parse_conditional_ace(TALLOC_CTX *mem_ctx,
						   DATA_BLOB data)
{
	return NULL;
}



int run_conditional_ace(TALLOC_CTX *mem_ctx,
			const struct security_token *token,
			struct ace_condition_script *program,
			const struct security_descriptor *sd)
{
	return ACE_CONDITION_UNKNOWN;
}


/** access_check_conditional_ace()
 *
 * Run the conditional ACE from the blob form. Return false if it is
 * not a valid conditional ACE, true if it is, even if there is some
 * other error in running it. The *result parameter is set to
 * ACE_CONDITION_FALSE, ACE_CONDITION_TRUE, or ACE_CONDITION_UNKNOWN.
 *
 * ACE_CONDITION_UNKNOWN should be treated pessimistically, as if were
 * TRUE for deny ACEs, and FALSE for allow ACEs.
 *
 * @param[in] ace - the ACE being processed.
 * @param[in] token - the security token the ACE is processing.
 * @param[out] result - a ternary result value.
 *
 * @return true if it is a valid conditional ACE.
 */

bool access_check_conditional_ace(const struct security_ace *ace,
				  const struct security_token *token,
				  const struct security_descriptor *sd,
				  int *result)
{
	return false;
}


bool conditional_ace_encode_binary(TALLOC_CTX *mem_ctx,
				   struct ace_condition_script *program,
				   DATA_BLOB *dest)
{
	return false;
}
