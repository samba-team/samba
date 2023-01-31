/*
   Unix SMB/CIFS implementation.
   Copyright (C) Andrew Tridgell 2003

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
#include <tevent.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_TEVENT

static void samba_tevent_debug(void *context,
			       enum tevent_debug_level level,
			       const char *fmt,
			       va_list ap)  PRINTF_ATTRIBUTE(3,0);

static void samba_tevent_debug(void *context,
			       enum tevent_debug_level level,
			       const char *fmt,
			       va_list ap)
{
	int samba_level = -1;

	switch (level) {
	case TEVENT_DEBUG_FATAL:
		samba_level = 0;
		break;
	case TEVENT_DEBUG_ERROR:
		samba_level = 1;
		break;
	case TEVENT_DEBUG_WARNING:
		samba_level = 2;
		break;
	case TEVENT_DEBUG_TRACE:
		samba_level = 50;
		break;
	};

	if (CHECK_DEBUGLVL(samba_level)) {
		const char *name = (const char *)context;
		char *message = NULL;
		int ret;

		ret = vasprintf(&message, fmt, ap);
		if (ret == -1) {
			return;
		}

		if (name == NULL) {
			name = "samba_tevent";
		}

		DEBUG(samba_level, ("%s: %s", name, message));
		free(message);
	}
}

static void samba_tevent_abort_fn(const char *reason)
{
	smb_panic(reason);
}

static void samba_tevent_setup_abort_fn(void)
{
	static bool abort_fn_done;

	if (!abort_fn_done) {
		tevent_set_abort_fn(samba_tevent_abort_fn);
		abort_fn_done = true;
	}
}

void samba_tevent_set_debug(struct tevent_context *ev, const char *name)
{
	void *p = discard_const(name);
	samba_tevent_setup_abort_fn();
	tevent_set_debug(ev, samba_tevent_debug, p);

	/* these values should match samba_tevent_debug() */
	if (CHECK_DEBUGLVL(50)) {
		tevent_set_max_debug_level(ev, TEVENT_DEBUG_TRACE);
	} else if (CHECK_DEBUGLVL(2)) {
		tevent_set_max_debug_level(ev, TEVENT_DEBUG_WARNING);
	} else if (CHECK_DEBUGLVL(1)) {
		tevent_set_max_debug_level(ev, TEVENT_DEBUG_ERROR);
	} else {
		tevent_set_max_debug_level(ev, TEVENT_DEBUG_FATAL);
	}
}

struct tevent_context *samba_tevent_context_init(TALLOC_CTX *mem_ctx)
{
	struct tevent_context *ev;

	samba_tevent_setup_abort_fn();

	ev = tevent_context_init(mem_ctx);
	if (ev) {
		samba_tevent_set_debug(ev, NULL);
	}

	return ev;
}
