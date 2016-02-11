/*
   Unix SMB/CIFS implementation.
   Implement a stack of talloc contexts
   Copyright (C) Volker Lendecke 2007

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

/*
 * Implement a stack of talloc frames.
 *
 * When a new talloc stackframe is allocated with talloc_stackframe(), then
 * the TALLOC_CTX returned with talloc_tos() is reset to that new
 * frame. Whenever that stack frame is TALLOC_FREE()'ed, then the reverse
 * happens: The previous talloc_tos() is restored.
 *
 * This API is designed to be robust in the sense that if someone forgets to
 * TALLOC_FREE() a stackframe, then the next outer one correctly cleans up and
 * resets the talloc_tos().
 *
 */

#ifndef _TALLOC_STACK_H
#define _TALLOC_STACK_H

#include <talloc.h>

/*
 * Create a new talloc stack frame.
 *
 * When free'd, it frees all stack frames that were created after this one and
 * not explicitly freed.
 */

#define talloc_stackframe() _talloc_stackframe(__location__)
#define talloc_stackframe_pool(sz) _talloc_stackframe_pool(__location__, (sz))
TALLOC_CTX *_talloc_stackframe(const char *location);
TALLOC_CTX *_talloc_stackframe_pool(const char *location, size_t poolsize);

/*
 * Get us the current top of the talloc stack.
 */

#define talloc_tos() _talloc_tos(__location__)
TALLOC_CTX *_talloc_tos(const char *location);

/*
 * return true if a talloc stackframe exists
 * this can be used to prevent memory leaks for code that can
 * optionally use a talloc stackframe (eg. nt_errstr())
 */

bool talloc_stackframe_exists(void);

#endif
