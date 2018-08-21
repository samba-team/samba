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

#include "replace.h"

#include "lib/util/debug.h"

#include "common/conf.h"
#include "common/logging_conf.h"
#include "common/path.h"

#include "cluster/cluster_conf.h"
#include "database/database_conf.h"
#include "event/event_conf.h"
#include "failover/failover_conf.h"
#include "legacy_conf.h"

#include "ctdb_config.h"

struct ctdb_config ctdb_config;

static void setup_config_pointers(struct conf_context *conf)
{
	/*
	 * Cluster
	 */

	conf_assign_string_pointer(conf,
				   CLUSTER_CONF_SECTION,
				   CLUSTER_CONF_TRANSPORT,
				   &ctdb_config.transport);
	conf_assign_string_pointer(conf,
				   CLUSTER_CONF_SECTION,
				   CLUSTER_CONF_NODE_ADDRESS,
				   &ctdb_config.node_address);
	conf_assign_string_pointer(conf,
				   CLUSTER_CONF_SECTION,
				   CLUSTER_CONF_RECOVERY_LOCK,
				   &ctdb_config.recovery_lock);

	/*
	 * Database
	 */

	conf_assign_string_pointer(conf,
				   DATABASE_CONF_SECTION,
				   DATABASE_CONF_VOLATILE_DB_DIR,
				   &ctdb_config.dbdir_volatile);
       conf_assign_string_pointer(conf,
				   DATABASE_CONF_SECTION,
				   DATABASE_CONF_PERSISTENT_DB_DIR,
				   &ctdb_config.dbdir_persistent);
	conf_assign_string_pointer(conf,
				   DATABASE_CONF_SECTION,
				   DATABASE_CONF_STATE_DB_DIR,
				   &ctdb_config.dbdir_state);
	conf_assign_string_pointer(conf,
				   DATABASE_CONF_SECTION,
				   DATABASE_CONF_LOCK_DEBUG_SCRIPT,
				   &ctdb_config.lock_debug_script);
	conf_assign_boolean_pointer(conf,
				    DATABASE_CONF_SECTION,
				    DATABASE_CONF_TDB_MUTEXES,
				    &ctdb_config.tdb_mutexes);

	/*
	 * Event
	 */
	conf_assign_string_pointer(conf,
				   EVENT_CONF_SECTION,
				   EVENT_CONF_DEBUG_SCRIPT,
				   &ctdb_config.event_debug_script);

	/*
	 * Failover
	 */
	conf_assign_boolean_pointer(conf,
				    FAILOVER_CONF_SECTION,
				    FAILOVER_CONF_DISABLED,
				    &ctdb_config.failover_disabled);

	/*
	 * Legacy
	 */

	conf_assign_boolean_pointer(conf,
				    LEGACY_CONF_SECTION,
				    LEGACY_CONF_REALTIME_SCHEDULING,
				    &ctdb_config.realtime_scheduling);
	conf_assign_boolean_pointer(conf,
				    LEGACY_CONF_SECTION,
				    LEGACY_CONF_RECMASTER_CAPABILITY,
				    &ctdb_config.recmaster_capability);
	conf_assign_boolean_pointer(conf,
				    LEGACY_CONF_SECTION,
				    LEGACY_CONF_LMASTER_CAPABILITY,
				    &ctdb_config.lmaster_capability);
	conf_assign_boolean_pointer(conf,
				    LEGACY_CONF_SECTION,
				    LEGACY_CONF_START_AS_STOPPED,
				    &ctdb_config.start_as_stopped);
	conf_assign_boolean_pointer(conf,
				    LEGACY_CONF_SECTION,
				    LEGACY_CONF_START_AS_DISABLED,
				    &ctdb_config.start_as_disabled);
	conf_assign_string_pointer(conf,
				   LEGACY_CONF_SECTION,
				   LEGACY_CONF_SCRIPT_LOG_LEVEL,
				   &ctdb_config.script_log_level);
}

int ctdbd_config_load(TALLOC_CTX *mem_ctx,
		      struct conf_context **result)
{
	struct conf_context *conf = NULL;
	int ret = 0;
	char *conf_file =  NULL;

	ret = conf_init(mem_ctx, &conf);
	if (ret != 0) {
		return ret;
	}

	logging_conf_init(conf, "NOTICE");
	cluster_conf_init(conf);
	database_conf_init(conf);
	event_conf_init(conf);
	failover_conf_init(conf);
	legacy_conf_init(conf);

	setup_config_pointers(conf);

	if (! conf_valid(conf)) {
		ret = EINVAL;
		goto fail;
	}

	conf_file = path_config(conf);
	if (conf_file == NULL) {
		D_ERR("Memory allocation error\n");
		ret = ENOMEM;
		goto fail;
	}
	ret = conf_load(conf, conf_file, true);
	/* Configuration file does not need to exist */
	if (ret != 0 && ret != ENOENT) {
		D_ERR("Failed to load configuration file %s\n", conf_file);
		goto fail;
	}

	talloc_free(conf_file);
	*result = conf;

	return 0;

fail:
	talloc_free(conf);
	return ret;
}
