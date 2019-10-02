/*
   Tunables utilities

   Copyright (C) Amitay Isaacs  2016

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
#include "system/locale.h"
#include "system/network.h"

#include <talloc.h>

#include "protocol/protocol.h"

#include "common/tunable.h"

static struct {
	const char *label;
	uint32_t value;
	bool obsolete;
	size_t offset;
} tunable_map[] = {
	{ "MaxRedirectCount", 3, true,
		offsetof(struct ctdb_tunable_list, max_redirect_count) },
	{ "SeqnumInterval", 1000, false,
		offsetof(struct ctdb_tunable_list, seqnum_interval) },
	{ "ControlTimeout", 60, false,
		offsetof(struct ctdb_tunable_list, control_timeout) },
	{ "TraverseTimeout", 20, false,
		offsetof(struct ctdb_tunable_list, traverse_timeout) },
	{ "KeepaliveInterval", 5, false,
		offsetof(struct ctdb_tunable_list, keepalive_interval) },
	{ "KeepaliveLimit", 5, false,
		offsetof(struct ctdb_tunable_list, keepalive_limit) },
	{ "RecoverTimeout", 30, false,
		offsetof(struct ctdb_tunable_list, recover_timeout) },
	{ "RecoverInterval", 1, false,
		offsetof(struct ctdb_tunable_list, recover_interval) },
	{ "ElectionTimeout", 3, false,
		offsetof(struct ctdb_tunable_list, election_timeout) },
	{ "TakeoverTimeout", 9, false,
		offsetof(struct ctdb_tunable_list, takeover_timeout) },
	{ "MonitorInterval", 15, false,
		offsetof(struct ctdb_tunable_list, monitor_interval) },
	{ "TickleUpdateInterval", 20, false,
		offsetof(struct ctdb_tunable_list, tickle_update_interval) },
	{ "EventScriptTimeout", 30, false,
		offsetof(struct ctdb_tunable_list, script_timeout) },
	{ "MonitorTimeoutCount", 20, false,
		offsetof(struct ctdb_tunable_list, monitor_timeout_count) },
	{ "EventScriptUnhealthyOnTimeout", 0, true,
		offsetof(struct ctdb_tunable_list, script_unhealthy_on_timeout) },
	{ "RecoveryGracePeriod", 120, false,
		offsetof(struct ctdb_tunable_list, recovery_grace_period) },
	{ "RecoveryBanPeriod", 300, false,
		offsetof(struct ctdb_tunable_list, recovery_ban_period) },
	{ "DatabaseHashSize", 100001, false,
		offsetof(struct ctdb_tunable_list, database_hash_size) },
	{ "DatabaseMaxDead", 5, false,
		offsetof(struct ctdb_tunable_list, database_max_dead) },
	{ "RerecoveryTimeout", 10, false,
		offsetof(struct ctdb_tunable_list, rerecovery_timeout) },
	{ "EnableBans", 1, false,
		offsetof(struct ctdb_tunable_list, enable_bans) },
	{ "DeterministicIPs", 0, true,
		offsetof(struct ctdb_tunable_list, deterministic_public_ips) },
	{ "LCP2PublicIPs", 1, true,
		offsetof(struct ctdb_tunable_list, lcp2_public_ip_assignment) },
	{ "ReclockPingPeriod", 60, true,
		offsetof(struct ctdb_tunable_list,  reclock_ping_period) },
	{ "NoIPFailback", 0, false,
		offsetof(struct ctdb_tunable_list, no_ip_failback) },
	{ "DisableIPFailover", 0, true,
		offsetof(struct ctdb_tunable_list, disable_ip_failover) },
	{ "VerboseMemoryNames", 0, false,
		offsetof(struct ctdb_tunable_list, verbose_memory_names) },
	{ "RecdPingTimeout", 60, false,
		offsetof(struct ctdb_tunable_list, recd_ping_timeout) },
	{ "RecdFailCount", 10, false,
		offsetof(struct ctdb_tunable_list, recd_ping_failcount) },
	{ "LogLatencyMs", 0, false,
		offsetof(struct ctdb_tunable_list, log_latency_ms) },
	{ "RecLockLatencyMs", 1000, false,
		offsetof(struct ctdb_tunable_list, reclock_latency_ms) },
	{ "RecoveryDropAllIPs", 120, false,
		offsetof(struct ctdb_tunable_list, recovery_drop_all_ips) },
	{ "VerifyRecoveryLock", 1, true,
		offsetof(struct ctdb_tunable_list, verify_recovery_lock) },
	{ "VacuumInterval", 10, false,
		offsetof(struct ctdb_tunable_list, vacuum_interval) },
	{ "VacuumMaxRunTime", 120, false,
		offsetof(struct ctdb_tunable_list, vacuum_max_run_time) },
	{ "RepackLimit", 10*1000, false,
		offsetof(struct ctdb_tunable_list, repack_limit) },
	{ "VacuumLimit", 5*1000, true,
		offsetof(struct ctdb_tunable_list, vacuum_limit) },
	{ "VacuumFastPathCount", 60, false,
		offsetof(struct ctdb_tunable_list, vacuum_fast_path_count) },
	{ "MaxQueueDropMsg", 1000*1000, false,
		offsetof(struct ctdb_tunable_list, max_queue_depth_drop_msg) },
	{ "AllowUnhealthyDBRead", 0, false,
		offsetof(struct ctdb_tunable_list, allow_unhealthy_db_read) },
	{ "StatHistoryInterval", 1, false,
		offsetof(struct ctdb_tunable_list, stat_history_interval) },
	{ "DeferredAttachTO", 120, false,
		offsetof(struct ctdb_tunable_list, deferred_attach_timeout) },
	{ "AllowClientDBAttach", 1, false,
		offsetof(struct ctdb_tunable_list, allow_client_db_attach) },
	{ "RecoverPDBBySeqNum", 1, true,
		offsetof(struct ctdb_tunable_list, recover_pdb_by_seqnum) },
	{ "DeferredRebalanceOnNodeAdd", 300, true,
		offsetof(struct ctdb_tunable_list, deferred_rebalance_on_node_add) },
	{ "FetchCollapse", 1, false,
		offsetof(struct ctdb_tunable_list, fetch_collapse) },
	{ "HopcountMakeSticky", 50, false,
		offsetof(struct ctdb_tunable_list, hopcount_make_sticky) },
	{ "StickyDuration", 600, false,
		offsetof(struct ctdb_tunable_list, sticky_duration) },
	{ "StickyPindown", 200, false,
		offsetof(struct ctdb_tunable_list, sticky_pindown) },
	{ "NoIPTakeover", 0, false,
		offsetof(struct ctdb_tunable_list, no_ip_takeover) },
	{ "DBRecordCountWarn", 100*1000, false,
		offsetof(struct ctdb_tunable_list, db_record_count_warn) },
	{ "DBRecordSizeWarn", 10*1000*1000, false,
		offsetof(struct ctdb_tunable_list, db_record_size_warn) },
	{ "DBSizeWarn", 100*1000*1000, false,
		offsetof(struct ctdb_tunable_list, db_size_warn) },
	{ "PullDBPreallocation", 10*1024*1024, false,
		offsetof(struct ctdb_tunable_list, pulldb_preallocation_size) },
	{ "NoIPHostOnAllDisabled", 1, true,
		offsetof(struct ctdb_tunable_list, no_ip_host_on_all_disabled) },
	{ "Samba3AvoidDeadlocks", 0, true,
		offsetof(struct ctdb_tunable_list, samba3_hack) },
	{ "TDBMutexEnabled", 1, true,
		offsetof(struct ctdb_tunable_list, mutex_enabled) },
	{ "LockProcessesPerDB", 200, false,
		offsetof(struct ctdb_tunable_list, lock_processes_per_db) },
	{ "RecBufferSizeLimit", 1000*1000, false,
		offsetof(struct ctdb_tunable_list, rec_buffer_size_limit) },
	{ "QueueBufferSize", 1024, false,
		offsetof(struct ctdb_tunable_list, queue_buffer_size) },
	{ "IPAllocAlgorithm", 2, false,
		offsetof(struct ctdb_tunable_list, ip_alloc_algorithm) },
	{ "AllowMixedVersions", 0, false,
		offsetof(struct ctdb_tunable_list, allow_mixed_versions) },
	{ .obsolete = true, }
};

void ctdb_tunable_set_defaults(struct ctdb_tunable_list *tun_list)
{
	int i;

	for (i=0; tunable_map[i].label != NULL; i++) {
		size_t offset = tunable_map[i].offset;
		uint32_t value = tunable_map[i].value;
		uint32_t *value_ptr;

		value_ptr = (uint32_t *)((uint8_t *)tun_list + offset);
		*value_ptr = value;
	}
}

bool ctdb_tunable_get_value(struct ctdb_tunable_list *tun_list,
			    const char *tunable_str, uint32_t *value)
{
	int i;

	for (i=0; tunable_map[i].label != NULL; i++) {
		if (strcasecmp(tunable_map[i].label, tunable_str) == 0) {
			uint32_t *value_ptr;

			value_ptr = (uint32_t *)((uint8_t *)tun_list +
						 tunable_map[i].offset);
			*value = *value_ptr;
			return true;
		}
	}

	return false;
}

bool ctdb_tunable_set_value(struct ctdb_tunable_list *tun_list,
			    const char *tunable_str, uint32_t value,
			    bool *obsolete)
{
	int i;

	for (i=0; tunable_map[i].label != NULL; i++) {
		if (strcasecmp(tunable_map[i].label, tunable_str) == 0) {
			uint32_t *value_ptr;

			value_ptr = (uint32_t *)((uint8_t *)tun_list +
						 tunable_map[i].offset);
			*value_ptr = value;
			if (obsolete != NULL) {
				*obsolete = tunable_map[i].obsolete;
			}
			return true;
		}
	}

	return false;
}

struct ctdb_var_list *ctdb_tunable_names(TALLOC_CTX *mem_ctx)
{
	struct ctdb_var_list *list;
	int i;

	list = talloc_zero(mem_ctx, struct ctdb_var_list);
	if (list == NULL) {
		return NULL;
	}

	for (i=0; tunable_map[i].label != NULL; i++) {
		if (tunable_map[i].obsolete) {
			continue;
		}

		list->var = talloc_realloc(list, list->var, const char *,
					   list->count + 1);
		if (list->var == NULL) {
			goto fail;
		}

		list->var[list->count] = talloc_strdup(list,
						       tunable_map[i].label);
		if (list->var[list->count] == NULL) {
			goto fail;
		}

		list->count += 1;
	}

	return list;

fail:
	TALLOC_FREE(list);
	return NULL;
}

char *ctdb_tunable_names_to_string(TALLOC_CTX *mem_ctx)
{
	char *str = NULL;
	int i;

	str = talloc_strdup(mem_ctx, ":");
	if (str == NULL) {
		return NULL;
	}

	for (i=0; tunable_map[i].label != NULL; i++) {
		if (tunable_map[i].obsolete) {
			continue;
		}

		str = talloc_asprintf_append(str, "%s:",
					     tunable_map[i].label);
		if (str == NULL) {
			return NULL;
		}
	}

	/* Remove the last ':' */
	str[strlen(str)-1] = '\0';

	return str;
}
