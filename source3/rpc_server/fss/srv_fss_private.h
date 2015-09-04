/*
 * File Server Remote VSS Protocol (FSRVP) server state
 *
 * Copyright (C) David Disseldorp	2012-2015
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _SRV_FSS_PRIVATE_H_
#define _SRV_FSS_PRIVATE_H_

#define FSS_DB_NAME "srv_fss.tdb"

struct fss_sc_smap {
	struct fss_sc_smap *next, *prev;
	char *share_name;		/* name of the base file share */
	char *sc_share_name;		/* share exposing the shadow copy */
	char *sc_share_comment;
	bool is_exposed;		/* whether shadow copy is exposed */
};

struct fss_sc {
	struct fss_sc *next, *prev;
	struct GUID id;			/* GUID of the shadow copy */
	char *id_str;
	char *volume_name;		/* name uniquely identifying on the
					 * server object store on which this
					 * shadow copy is created. */
	char *sc_path;			/* path exposing the shadow copy */
	time_t create_ts;		/* timestamp of client initiation */
	struct fss_sc_smap *smaps;	/* shares mapped to this shadow copy */
	uint32_t smaps_count;
	struct fss_sc_set *sc_set;	/* parent shadow copy set */
};

/*
 * 3.1.1.2: Per ShadowCopySet
 * The status of the shadow copy set. This MUST be one of "Started", "Added",
 * "CreationInProgress", "Committed", "Exposed", or "Recovered".
 */
enum fss_sc_state {
	FSS_SC_STARTED,
	FSS_SC_ADDED,
	FSS_SC_CREATING,
	FSS_SC_COMMITED,
	FSS_SC_EXPOSED,
	FSS_SC_RECOVERED,
};
struct fss_sc_set {
	struct fss_sc_set *next, *prev;
	struct GUID id;			/* GUID of the shadow copy set. */
	char *id_str;
	enum fss_sc_state state;	/* status of the shadow copy set */
	uint32_t context;		/* attributes used for set creation */
	struct fss_sc *scs;		/* list of ShadowCopy objects */
	uint32_t scs_count;
};

struct fss_global {
	TALLOC_CTX *mem_ctx;		/* parent mem ctx for sc sets */
	char *db_path;
	uint32_t min_vers;
	uint32_t max_vers;
	bool ctx_set;			/* whether client has set context */
	uint32_t cur_ctx;
	struct fss_sc_set *sc_sets;
	uint32_t sc_sets_count;
	struct tevent_timer *seq_tmr;	/* time to wait between client reqs */
};

NTSTATUS fss_state_store(TALLOC_CTX *mem_ctx,
			 struct fss_sc_set *sc_sets,
			 uint32_t sc_sets_count,
			 const char *db_path);

NTSTATUS fss_state_retrieve(TALLOC_CTX *mem_ctx,
			    struct fss_sc_set **sc_sets,
			    uint32_t *sc_sets_count,
			    const char *db_path);

#endif /*_SRV_FSS_PRIVATE_H_ */
