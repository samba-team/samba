/*
   CTDB event daemon - protocol utilities

   Copyright (C) Amitay Isaacs  2018

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"

#include "event/event_protocol.h"
#include "event/event_protocol_api.h"

static struct {
	enum ctdb_event_command command;
	const char *label;
} event_command_map[] = {
	{ CTDB_EVENT_CMD_RUN, "RUN" },
	{ CTDB_EVENT_CMD_STATUS, "STATUS" },
	{ CTDB_EVENT_CMD_SCRIPT, "SCRIPT" },
	{ CTDB_EVENT_CMD_MAX, NULL },
};

const char *ctdb_event_command_to_string(enum ctdb_event_command command)
{
	int i;

	for (i=0; event_command_map[i].label != NULL; i++) {
		if (event_command_map[i].command == command) {
			return event_command_map[i].label;
		}
	}

	return "UNKNOWN";
}
