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

void samba_tevent_set_debug(struct tevent_context *ev, const char *name)
{
	void *p = discard_const(name);
	tevent_set_debug(ev, samba_tevent_debug, p);
}

struct tevent_context *samba_tevent_context_init(TALLOC_CTX *mem_ctx)
{
	struct tevent_context *ev;

	ev = tevent_context_init(mem_ctx);
	if (ev) {
		samba_tevent_set_debug(ev, NULL);
	}

	return ev;
}
