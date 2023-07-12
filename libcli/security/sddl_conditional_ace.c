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

#include "includes.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/conditional_ace.h"
#include "libcli/security/security.h"
#include "libcli/security/conditional_ace.h"



/*
 * This is a helper function to create a representation of a
 * conditional ACE. This is not SDDL, more like a disassembly,
 * but it uses some of the same tables.
 */
char *debug_conditional_ace(TALLOC_CTX *mem_ctx,
			    struct ace_condition_script *program)
{
	return NULL;
}


/*
 * Convert conditional ACE conditions into SDDL conditions.
 *
 * @param mem_ctx
 * @param program
 * @return a string or NULL on error.
 */
char *sddl_from_conditional_ace(TALLOC_CTX *mem_ctx,
				struct ace_condition_script *program)
{
	return NULL;
}


/*
 * Compile SDDL conditional ACE conditions.
 *
 * @param mem_ctx
 * @param sddl - the string to be parsed
 * @param message - on error, a pointer to a compiler message
 * @param message_offset - where the error occurred
 * @param consumed_length - how much of the SDDL was used
 * @return a struct ace_condition_script (or NULL).
 */
struct ace_condition_script * ace_conditions_compile_sddl(
	TALLOC_CTX *mem_ctx,
	const char *sddl,
	const char **message,
	size_t *message_offset,
	size_t *consumed_length)
{
	return NULL;
}
