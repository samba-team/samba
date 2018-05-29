/* 
   Unix SMB/CIFS mplementation.

   KCC service
   
   Copyright (C) Andrew Tridgell 2009
   based on drepl service code
    
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

#ifndef _DSDB_REPL_KCC_SERVICE_H_
#define _DSDB_REPL_KCC_SERVICE_H_

#include "librpc/gen_ndr/ndr_drsuapi_c.h"
#include "dsdb/common/util.h"

struct kccsrv_service {
	/* the whole kcc service is in one task */
	struct task_server *task;

	/* the time the service was started */
	struct timeval startup_time;

	/* dn of our configuration partition */
	struct ldb_dn *config_dn;

	/* 
	 * system session info
	 * with machine account credentials
	 */
	struct auth_session_info *system_session_info;

	/* list of local partitions */
	struct dsdb_ldb_dn_list_node *partitions;

	/*
	 * a connection to the local samdb
	 */
	struct ldb_context *samdb;

	/* the guid of our NTDS Settings object, which never changes! */
	struct GUID ntds_guid;

	/* some stuff for periodic processing */
	struct {
		/*
		 * the interval between to periodic runs
		 */
		uint32_t interval;

		/*
		 * the timestamp for the next event,
		 * this is the timstamp passed to event_add_timed()
		 */
		struct timeval next_event;

		/* here we have a reference to the timed event the schedules the periodic stuff */
		struct tevent_timer *te;

		/* samba_runcmd_send service for samba_kcc */
		struct tevent_req *subreq;

		/* return status of samba_kcc */
		NTSTATUS status;

	} periodic;

	time_t last_deleted_check;

	time_t last_dns_scavenge;

	time_t last_dns_tombstone_collection;

	time_t last_full_scan_deleted_check;

	bool am_rodc;

	/* run new samba_kcc topology generator code */
	bool samba_kcc_code;
};

struct kcc_connection_list;

#include "dsdb/kcc/garbage_collect_tombstones.h"
#include "dsdb/kcc/scavenge_dns_records.h"
#include "dsdb/kcc/kcc_service_proto.h"

#endif /* _DSDB_REPL_KCC_SERVICE_H_ */
