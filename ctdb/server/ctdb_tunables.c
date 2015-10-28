/* 
   ctdb tunables code

   Copyright (C) Andrew Tridgell  2007

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
#include "system/network.h"

#include <talloc.h>
#include <tdb.h>

#include "lib/util/debug.h"

#include "ctdb_private.h"

#include "common/common.h"
#include "common/logging.h"

static const struct {
	const char *name;
	uint32_t default_v;
	size_t offset;
	bool obsolete;
} tunable_map[] = {
	{ "MaxRedirectCount",     3,  offsetof(struct ctdb_tunable_list, max_redirect_count), false },
	{ "SeqnumInterval",      1000,  offsetof(struct ctdb_tunable_list, seqnum_interval), false },
	{ "ControlTimeout",      60, offsetof(struct ctdb_tunable_list, control_timeout), false },
	{ "TraverseTimeout",     20, offsetof(struct ctdb_tunable_list, traverse_timeout), false },
	{ "KeepaliveInterval",    5,  offsetof(struct ctdb_tunable_list, keepalive_interval), false },
	{ "KeepaliveLimit",       5,  offsetof(struct ctdb_tunable_list, keepalive_limit), false },
	{ "RecoverTimeout",     120,  offsetof(struct ctdb_tunable_list, recover_timeout), false },
	{ "RecoverInterval",      1,  offsetof(struct ctdb_tunable_list, recover_interval), false },
	{ "ElectionTimeout",      3,  offsetof(struct ctdb_tunable_list, election_timeout), false },
	{ "TakeoverTimeout",      9,  offsetof(struct ctdb_tunable_list, takeover_timeout), false },
	{ "MonitorInterval",     15,  offsetof(struct ctdb_tunable_list, monitor_interval), false },
	{ "TickleUpdateInterval",20,  offsetof(struct ctdb_tunable_list, tickle_update_interval), false },
	{ "EventScriptTimeout",  30,  offsetof(struct ctdb_tunable_list, script_timeout), false },
	{ "MonitorTimeoutCount", 20,  offsetof(struct ctdb_tunable_list, monitor_timeout_count), false },
	{ "EventScriptUnhealthyOnTimeout", 0, offsetof(struct ctdb_tunable_list, script_unhealthy_on_timeout), true },
	{ "RecoveryGracePeriod", 120,  offsetof(struct ctdb_tunable_list, recovery_grace_period), false },
	{ "RecoveryBanPeriod",  300,  offsetof(struct ctdb_tunable_list, recovery_ban_period), false },
	{ "DatabaseHashSize", 100001, offsetof(struct ctdb_tunable_list, database_hash_size), false },
	{ "DatabaseMaxDead",      5,  offsetof(struct ctdb_tunable_list, database_max_dead), false },
	{ "RerecoveryTimeout",   10,  offsetof(struct ctdb_tunable_list, rerecovery_timeout), false },
	{ "EnableBans",           1,  offsetof(struct ctdb_tunable_list, enable_bans), false },
	{ "DeterministicIPs",     0,  offsetof(struct ctdb_tunable_list, deterministic_public_ips), false },
	{ "LCP2PublicIPs",        1,  offsetof(struct ctdb_tunable_list, lcp2_public_ip_assignment), false },
	{ "ReclockPingPeriod",   60,  offsetof(struct ctdb_tunable_list,  reclock_ping_period), false },
	{ "NoIPFailback",         0,  offsetof(struct ctdb_tunable_list, no_ip_failback), false },
	{ "DisableIPFailover",    0,  offsetof(struct ctdb_tunable_list, disable_ip_failover), false },
	{ "VerboseMemoryNames",   0,  offsetof(struct ctdb_tunable_list, verbose_memory_names), false },
	{ "RecdPingTimeout",	 60,  offsetof(struct ctdb_tunable_list, recd_ping_timeout), false },
	{ "RecdFailCount",	 10,  offsetof(struct ctdb_tunable_list, recd_ping_failcount), false },
	{ "LogLatencyMs",         0,  offsetof(struct ctdb_tunable_list, log_latency_ms), false },
	{ "RecLockLatencyMs",  1000,  offsetof(struct ctdb_tunable_list, reclock_latency_ms), false },
	{ "RecoveryDropAllIPs", 120,  offsetof(struct ctdb_tunable_list, recovery_drop_all_ips), false },
	{ "VerifyRecoveryLock",   1,  offsetof(struct ctdb_tunable_list, verify_recovery_lock), true },
	{ "VacuumInterval",   10,  offsetof(struct ctdb_tunable_list, vacuum_interval), false },
	{ "VacuumMaxRunTime",     120,  offsetof(struct ctdb_tunable_list, vacuum_max_run_time), false },
	{ "RepackLimit",      10000,  offsetof(struct ctdb_tunable_list, repack_limit), false },
	{ "VacuumLimit",       5000,  offsetof(struct ctdb_tunable_list, vacuum_limit), false },
	{ "VacuumFastPathCount", 60, offsetof(struct ctdb_tunable_list, vacuum_fast_path_count), false },
	{ "MaxQueueDropMsg",  1000000, offsetof(struct ctdb_tunable_list, max_queue_depth_drop_msg), false },
	{ "AllowUnhealthyDBRead", 0,  offsetof(struct ctdb_tunable_list, allow_unhealthy_db_read), false },
	{ "StatHistoryInterval",  1,  offsetof(struct ctdb_tunable_list, stat_history_interval), false },
	{ "DeferredAttachTO",  120,  offsetof(struct ctdb_tunable_list, deferred_attach_timeout), false },
	{ "AllowClientDBAttach", 1, offsetof(struct ctdb_tunable_list, allow_client_db_attach), false },
	{ "RecoverPDBBySeqNum",  1, offsetof(struct ctdb_tunable_list, recover_pdb_by_seqnum), false },
	{ "DeferredRebalanceOnNodeAdd", 300, offsetof(struct ctdb_tunable_list, deferred_rebalance_on_node_add) },
	{ "FetchCollapse",       1, offsetof(struct ctdb_tunable_list, fetch_collapse) },
	{ "HopcountMakeSticky",   50,  offsetof(struct ctdb_tunable_list, hopcount_make_sticky) },
	{ "StickyDuration",      600,  offsetof(struct ctdb_tunable_list, sticky_duration) },
	{ "StickyPindown",       200,  offsetof(struct ctdb_tunable_list, sticky_pindown) },
	{ "NoIPTakeover",         0,  offsetof(struct ctdb_tunable_list, no_ip_takeover), false },
	{ "DBRecordCountWarn",    100000,  offsetof(struct ctdb_tunable_list, db_record_count_warn), false },
	{ "DBRecordSizeWarn",   10000000,  offsetof(struct ctdb_tunable_list, db_record_size_warn), false },
	{ "DBSizeWarn",        100000000,  offsetof(struct ctdb_tunable_list, db_size_warn), false },
	{ "PullDBPreallocation", 10*1024*1024,  offsetof(struct ctdb_tunable_list, pulldb_preallocation_size), false },
	{ "NoIPHostOnAllDisabled",    0,  offsetof(struct ctdb_tunable_list, no_ip_host_on_all_disabled), false },
	{ "Samba3AvoidDeadlocks", 0, offsetof(struct ctdb_tunable_list, samba3_hack), false },
	{ "TDBMutexEnabled", 0, offsetof(struct ctdb_tunable_list, mutex_enabled), false },
	{ "LockProcessesPerDB", 200, offsetof(struct ctdb_tunable_list, lock_processes_per_db), false },
};

/*
  set all tunables to defaults
 */
void ctdb_tunables_set_defaults(struct ctdb_context *ctdb)
{
	int i;
	for (i=0;i<ARRAY_SIZE(tunable_map);i++) {
		*(uint32_t *)(tunable_map[i].offset + (uint8_t*)&ctdb->tunable) = tunable_map[i].default_v;
	}
}


/*
  get a tunable
 */
int32_t ctdb_control_get_tunable(struct ctdb_context *ctdb, TDB_DATA indata, 
				 TDB_DATA *outdata)
{
	struct ctdb_control_get_tunable *t = 
		(struct ctdb_control_get_tunable *)indata.dptr;
	char *name;
	uint32_t val;
	int i;

	if (indata.dsize < sizeof(*t) ||
	    t->length > indata.dsize - offsetof(struct ctdb_control_get_tunable, name)) {
		DEBUG(DEBUG_ERR,("Bad indata in ctdb_control_get_tunable\n"));
		return -1;
	}

	name = talloc_strndup(ctdb, (char*)t->name, t->length);
	CTDB_NO_MEMORY(ctdb, name);

	for (i=0;i<ARRAY_SIZE(tunable_map);i++) {
		if (strcasecmp(name, tunable_map[i].name) == 0) break;
	}
	talloc_free(name);
	
	if (i == ARRAY_SIZE(tunable_map)) {
		return -EINVAL;
	}

	val = *(uint32_t *)(tunable_map[i].offset + (uint8_t*)&ctdb->tunable);

	outdata->dptr = (uint8_t *)talloc(outdata, uint32_t);
	CTDB_NO_MEMORY(ctdb, outdata->dptr);

	*(uint32_t *)outdata->dptr = val;
	outdata->dsize = sizeof(uint32_t);

	return 0;
}


/*
  set a tunable
 */
int32_t ctdb_control_set_tunable(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_tunable_old *t =
		(struct ctdb_tunable_old *)indata.dptr;
	char *name;
	int i;

	if (indata.dsize < sizeof(*t) ||
	    t->length > indata.dsize - offsetof(struct ctdb_tunable_old, name)) {
		DEBUG(DEBUG_ERR,("Bad indata in ctdb_control_set_tunable\n"));
		return -1;
	}

	name = talloc_strndup(ctdb, (char *)t->name, t->length);
	CTDB_NO_MEMORY(ctdb, name);

	for (i=0;i<ARRAY_SIZE(tunable_map);i++) {
		if (strcasecmp(name, tunable_map[i].name) == 0) break;
	}

	talloc_free(name);

	if (i == ARRAY_SIZE(tunable_map)) {
		return -1;
	}

	*(uint32_t *)(tunable_map[i].offset + (uint8_t*)&ctdb->tunable) = t->value;

	if (tunable_map[i].obsolete) {
		DEBUG(DEBUG_WARNING,
		      ("Setting obsolete tunable \"%s\"\n",
		       tunable_map[i].name));
		return 1;
	}

	return 0;
}

/*
  list tunables
 */
int32_t ctdb_control_list_tunables(struct ctdb_context *ctdb, TDB_DATA *outdata)
{
	char *list = NULL;
	int i;
	struct ctdb_control_list_tunable *t;

	list = talloc_strdup(outdata, tunable_map[0].name);
	CTDB_NO_MEMORY(ctdb, list);

	for (i=1;i<ARRAY_SIZE(tunable_map);i++) {
		if (tunable_map[i].obsolete) {
			continue;
		}
		list = talloc_asprintf_append(list, ":%s", tunable_map[i].name);
		CTDB_NO_MEMORY(ctdb, list);		
	}

	outdata->dsize = offsetof(struct ctdb_control_list_tunable, data) + 
		strlen(list) + 1;
	outdata->dptr = talloc_size(outdata, outdata->dsize);
	CTDB_NO_MEMORY(ctdb, outdata->dptr);

	t = (struct ctdb_control_list_tunable *)outdata->dptr;
	t->length = strlen(list)+1;

	memcpy(t->data, list, t->length);
	talloc_free(list);

	return 0;	
}
