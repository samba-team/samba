/*
   Unix SMB/CIFS implementation.
   Global contexts

   Copyright (C) Simo Sorce <idra@samba.org> 2010

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
#include "messages.h"

static struct tevent_context *global_event_ctx = NULL;

struct tevent_context *global_event_context(void)
{
	if (!global_event_ctx) {
		/*
		 * Note we MUST use the NULL context here, not the
		 * autofree context, to avoid side effects in forked
		 * children exiting.
		 */
		global_event_ctx = samba_tevent_context_init(NULL);
	}
	if (!global_event_ctx) {
		smb_panic("Could not init global event context");
	}
	return global_event_ctx;
}

void global_event_context_free(void)
{
	TALLOC_FREE(global_event_ctx);
}

static struct messaging_context *global_msg_ctx = NULL;

struct messaging_context *global_messaging_context(void)
{
	if (global_msg_ctx == NULL) {
		/*
		 * Note we MUST use the NULL context here, not the
		 * autofree context, to avoid side effects in forked
		 * children exiting.
		 */
		global_msg_ctx = messaging_init(NULL,
					        global_event_context());
	}
	return global_msg_ctx;
}

void global_messaging_context_free(void)
{
	TALLOC_FREE(global_msg_ctx);
}
