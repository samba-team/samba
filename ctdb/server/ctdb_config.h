/*
   CTDB daemon config handling

   Copyright (C) Martin Schwenke  2018

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

#ifndef __CTDB_CONFIG_H__
#define __CTDB_CONFIG_H__

#include "common/conf.h"

struct ctdb_config {
	/* Cluster */
	const char *transport;
	const char *node_address;
	const char *recovery_lock;

	/* Database */
	const char *dbdir_volatile;
	const char *dbdir_persistent;
	const char *dbdir_state;
	const char *lock_debug_script;
	bool tdb_mutexes;

	/* Event */
	const char *event_debug_script;

	/* Failover */
	bool failover_disabled;

	/* Legacy */
	bool realtime_scheduling;
	bool recmaster_capability;
	bool lmaster_capability;
	bool start_as_stopped;
	bool start_as_disabled;
	const char *script_log_level;
};

extern struct ctdb_config ctdb_config;

int ctdbd_config_load(TALLOC_CTX *mem_ctx, struct conf_context **conf);

#endif /* __CTDB_CONFIG_H__ */
