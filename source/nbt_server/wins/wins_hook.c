/* 
   Unix SMB/CIFS implementation.

   wins hook feature, we run a specified script
   which can then do some custom actions

   Copyright (C) Stefan Metzmacher	2005
      
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

#include "includes.h"
#include "nbt_server/nbt_server.h"
#include "nbt_server/wins/winsdb.h"

static const char *wins_hook_action_string(enum wins_hook_action action)
{
	switch (action) {
	case WINS_HOOK_ADD:	return "WINS_HOOK_ADD";
	case WINS_HOOK_MODIFY:	return "WINS_HOOK_MODIFY";
	case WINS_HOOK_DELETE:	return "WINS_HOOK_DELETE";
	}

	return "WINS_HOOK_ACTION_UNKNOWN";
}

void wins_hook(struct winsdb_handle *h, struct winsdb_record *rec, enum wins_hook_action action)
{
	const char *script = lp_wins_hook();
	if (!script || !script[0]) return;

	DEBUG(0,("TODO: call wins hook '%s' '%s' for name '%s'\n",
		script, wins_hook_action_string(action),
		nbt_name_string(rec, rec->name)));
}
