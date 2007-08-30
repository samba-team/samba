/*
   Unix SMB/CIFS implementation.
   Implement a stack of talloc contexts
   Copyright (C) Volker Lendecke 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
 * This robustness feature means that we can't rely on a linked list with
 * talloc destructors because in a hierarchy of talloc destructors the parent
 * destructor is called before its children destructors. The child destructor
 * called after the parent would set the talloc_tos() to the wrong value.
 */

#include "includes.h"

static int talloc_stacksize;
static TALLOC_CTX **talloc_stack;

static int talloc_pop(int *ptr)
{
	int tos = *ptr;
	int i;

	for (i=talloc_stacksize-1; i>=tos; i--) {
		talloc_free(talloc_stack[i]);
	}

	talloc_stacksize = tos;
	return 0;
}

/*
 * Create a new talloc stack frame.
 *
 * When free'd, it frees all stack frames that were created after this one and
 * not explicitly freed.
 */

TALLOC_CTX *talloc_stackframe(void)
{
	TALLOC_CTX **tmp, *top;
	int *cleanup;

	if (!(tmp = TALLOC_REALLOC_ARRAY(NULL, talloc_stack, TALLOC_CTX *,
					 talloc_stacksize + 1))) {
		goto fail;
	}

	talloc_stack = tmp;

	if (!(top = talloc_new(talloc_stack))) {
		goto fail;
	}

	if (!(cleanup = talloc(top, int))) {
		goto fail;
	}

	*cleanup = talloc_stacksize;
	talloc_set_destructor(cleanup, talloc_pop);

	talloc_stack[talloc_stacksize++] = top;

	return top;

 fail:
	smb_panic("talloc_stackframe failed");
	return NULL;
}

/*
 * Get us the current top of the talloc stack.
 */

TALLOC_CTX *talloc_tos(void)
{
	if (talloc_stacksize == 0) {
		DEBUG(0, ("no talloc stackframe around, leaking memory\n"));
		talloc_stackframe();
	}

	return talloc_stack[talloc_stacksize-1];
}
