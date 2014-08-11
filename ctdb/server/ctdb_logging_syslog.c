/*
   ctdb logging code - syslog backend

   Copyright (C) Andrew Tridgell  2008
   Copyright (C) Martin Schwenke  2014

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
#include "system/syslog.h"
#include "lib/util/debug.h"
#include "ctdb_logging.h"

static int ctdb_debug_to_syslog_level(int dbglevel)
{
	int level;

	switch (dbglevel) {
	case DEBUG_ERR:
		level = LOG_ERR;
		break;
	case DEBUG_WARNING:
		level = LOG_WARNING;
		break;
	case DEBUG_NOTICE:
		level = LOG_NOTICE;
		break;
	case DEBUG_INFO:
		level = LOG_INFO;
		break;
	default:
		level = LOG_DEBUG;
		break;
	}

	return level;
}

static void ctdb_log_to_syslog(void *private_ptr, int dbglevel, const char *s)
{
	syslog(ctdb_debug_to_syslog_level(dbglevel),
	       "%s%s", debug_extra, s);
}

static int ctdb_log_setup_syslog(TALLOC_CTX *mem_ctx,
				 const char *logging,
				 const char *app_name)
{
	debug_set_callback(NULL, ctdb_log_to_syslog);
	return 0;
}

void ctdb_log_init_syslog(void)
{
	ctdb_log_register_backend("syslog", ctdb_log_setup_syslog);
}
