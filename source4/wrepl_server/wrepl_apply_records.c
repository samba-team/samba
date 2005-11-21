/* 
   Unix SMB/CIFS implementation.
   
   WINS Replication server
   
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
#include "dlinklist.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "smbd/service_task.h"
#include "smbd/service_stream.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_winsrepl.h"
#include "wrepl_server/wrepl_server.h"
#include "wrepl_server/wrepl_out_helpers.h"
#include "nbt_server/wins/winsdb.h"
#include "ldb/include/ldb.h"
#include "libcli/composite/composite.h"
#include "libcli/wrepl/winsrepl.h"

enum _R_ACTION {
	R_DO_ADD		= 1,
	R_DO_REPLACE		= 2,
	R_NOT_REPLACE		= 3,
	R_DO_MHOMED_MERGE	= 4,
	R_DO_RELEASE_DEMAND	= 5,
	R_DO_SGROUP_MERGE	= 6
};

static const char *_R_ACTION_enum_string(enum _R_ACTION action)
{
	switch (action) {
	case R_DO_ADD:			return "ADD";
	case R_DO_REPLACE:		return "REPLACE";
	case R_NOT_REPLACE:		return "NOT_REPLACE";
	case R_DO_MHOMED_MERGE:		return "MHOMED_MERGE";
	case R_DO_RELEASE_DEMAND:	return "RELEASE_DEMAND";
	case R_DO_SGROUP_MERGE:		return "SGROUP_MERGE";
	}

	return "enum _R_ACTION unknown";
}

#define R_IS_ACTIVE(r) ((r)->state == WREPL_STATE_ACTIVE)
#define R_IS_RELEASED(r) ((r)->state == WREPL_STATE_RELEASED)
#define R_IS_TOMBSTONE(r) ((r)->state == WREPL_STATE_TOMBSTONE)

#define R_IS_UNIQUE(r) ((r)->type == WREPL_TYPE_UNIQUE)
#define R_IS_GROUP(r) ((r)->type == WREPL_TYPE_GROUP)
#define R_IS_SGROUP(r) ((r)->type == WREPL_TYPE_SGROUP)
#define R_IS_MHOMED(r) ((r)->type == WREPL_TYPE_MHOMED)

/* blindly overwrite records from the same owner in all cases */
static enum _R_ACTION replace_same_owner(struct winsdb_record *r1, struct wrepl_name *r2)
{
	/* REPLACE */
	return R_DO_REPLACE;
}

/*
UNIQUE,ACTIVE vs. UNIQUE,ACTIVE with different ip(s) => REPLACE
UNIQUE,ACTIVE vs. UNIQUE,TOMBSTONE with different ip(s) => NOT REPLACE
UNIQUE,RELEASED vs. UNIQUE,ACTIVE with different ip(s) => REPLACE
UNIQUE,RELEASED vs. UNIQUE,TOMBSTONE with different ip(s) => REPLACE
UNIQUE,TOMBSTONE vs. UNIQUE,ACTIVE with different ip(s) => REPLACE
UNIQUE,TOMBSTONE vs. UNIQUE,TOMBSTONE with different ip(s) => REPLACE
UNIQUE,ACTIVE vs. GROUP,ACTIVE with different ip(s) => REPLACE
UNIQUE,ACTIVE vs. GROUP,TOMBSTONE with same ip(s) => NOT REPLACE
UNIQUE,RELEASED vs. GROUP,ACTIVE with different ip(s) => REPLACE
UNIQUE,RELEASED vs. GROUP,TOMBSTONE with different ip(s) => REPLACE
UNIQUE,TOMBSTONE vs. GROUP,ACTIVE with different ip(s) => REPLACE
UNIQUE,TOMBSTONE vs. GROUP,TOMBSTONE with different ip(s) => REPLACE
UNIQUE,ACTIVE vs. SGROUP,ACTIVE with same ip(s) => NOT REPLACE
UNIQUE,ACTIVE vs. SGROUP,TOMBSTONE with same ip(s) => NOT REPLACE
UNIQUE,RELEASED vs. SGROUP,ACTIVE with different ip(s) => REPLACE
UNIQUE,RELEASED vs. SGROUP,TOMBSTONE with different ip(s) => REPLACE
UNIQUE,TOMBSTONE vs. SGROUP,ACTIVE with different ip(s) => REPLACE
UNIQUE,TOMBSTONE vs. SGROUP,TOMBSTONE with different ip(s) => REPLACE
UNIQUE,ACTIVE vs. MHOMED,ACTIVE with different ip(s) => REPLACE
UNIQUE,ACTIVE vs. MHOMED,TOMBSTONE with same ip(s) => NOT REPLACE
UNIQUE,RELEASED vs. MHOMED,ACTIVE with different ip(s) => REPLACE
UNIQUE,RELEASED vs. MHOMED,TOMBSTONE with different ip(s) => REPLACE
UNIQUE,TOMBSTONE vs. MHOMED,ACTIVE with different ip(s) => REPLACE
UNIQUE,TOMBSTONE vs. MHOMED,TOMBSTONE with different ip(s) => REPLACE
*/
static enum _R_ACTION replace_unique_replica_vs_X_replica(struct winsdb_record *r1, struct wrepl_name *r2)
{
	if (!R_IS_ACTIVE(r1)) {
		/* REPLACE */
		return R_DO_REPLACE;
	}

	if (!R_IS_SGROUP(r2) && R_IS_ACTIVE(r2)) {
		/* REPLACE */
		return R_DO_REPLACE;
	}

	/* NOT REPLACE */
	return R_NOT_REPLACE;
}

/*
GROUP,ACTIVE vs. UNIQUE,ACTIVE with same ip(s) => NOT REPLACE
GROUP,ACTIVE vs. UNIQUE,TOMBSTONE with same ip(s) => NOT REPLACE
GROUP,RELEASED vs. UNIQUE,ACTIVE with same ip(s) => NOT REPLACE
GROUP,RELEASED vs. UNIQUE,TOMBSTONE with same ip(s) => NOT REPLACE
GROUP,TOMBSTONE vs. UNIQUE,ACTIVE with same ip(s) => NOT REPLACE
GROUP,TOMBSTONE vs. UNIQUE,TOMBSTONE with same ip(s) => NOT REPLACE
GROUP,ACTIVE vs. GROUP,ACTIVE with same ip(s) => NOT REPLACE
GROUP,ACTIVE vs. GROUP,TOMBSTONE with same ip(s) => NOT REPLACE
GROUP,RELEASED vs. GROUP,ACTIVE with different ip(s) => REPLACE
GROUP,RELEASED vs. GROUP,TOMBSTONE with different ip(s) => REPLACE
GROUP,TOMBSTONE vs. GROUP,ACTIVE with different ip(s) => REPLACE
GROUP,TOMBSTONE vs. GROUP,TOMBSTONE with different ip(s) => REPLACE
GROUP,ACTIVE vs. SGROUP,ACTIVE with same ip(s) => NOT REPLACE
GROUP,ACTIVE vs. SGROUP,TOMBSTONE with same ip(s) => NOT REPLACE
GROUP,RELEASED vs. SGROUP,ACTIVE with different ip(s) => REPLACE
GROUP,RELEASED vs. SGROUP,TOMBSTONE with same ip(s) => NOT REPLACE
GROUP,TOMBSTONE vs. SGROUP,ACTIVE with different ip(s) => REPLACE
GROUP,TOMBSTONE vs. SGROUP,TOMBSTONE with different ip(s) => REPLACE
GROUP,ACTIVE vs. MHOMED,ACTIVE with same ip(s) => NOT REPLACE
GROUP,ACTIVE vs. MHOMED,TOMBSTONE with same ip(s) => NOT REPLACE
GROUP,RELEASED vs. MHOMED,ACTIVE with same ip(s) => NOT REPLACE
GROUP,RELEASED vs. MHOMED,TOMBSTONE with same ip(s) => NOT REPLACE
GROUP,TOMBSTONE vs. MHOMED,ACTIVE with different ip(s) => REPLACE
GROUP,TOMBSTONE vs. MHOMED,TOMBSTONE with different ip(s) => REPLACE
*/
static enum _R_ACTION replace_group_replica_vs_X_replica(struct winsdb_record *r1, struct wrepl_name *r2)
{
	if (!R_IS_ACTIVE(r1) && R_IS_GROUP(r2)) {
		/* REPLACE */
		return R_DO_REPLACE;
	}

	if (R_IS_TOMBSTONE(r1) && !R_IS_UNIQUE(r2)) {
		/* REPLACE */
		return R_DO_REPLACE;
	}

	/* NOT REPLACE */
	return R_NOT_REPLACE;
}

/*
SGROUP,ACTIVE vs. UNIQUE,ACTIVE with same ip(s) => NOT REPLACE
SGROUP,ACTIVE vs. UNIQUE,TOMBSTONE with same ip(s) => NOT REPLACE
SGROUP,RELEASED vs. UNIQUE,ACTIVE with different ip(s) => REPLACE
SGROUP,RELEASED vs. UNIQUE,TOMBSTONE with different ip(s) => REPLACE
SGROUP,TOMBSTONE vs. UNIQUE,ACTIVE with different ip(s) => REPLACE
SGROUP,TOMBSTONE vs. UNIQUE,TOMBSTONE with different ip(s) => REPLACE
SGROUP,ACTIVE vs. GROUP,ACTIVE with same ip(s) => NOT REPLACE
SGROUP,ACTIVE vs. GROUP,TOMBSTONE with same ip(s) => NOT REPLACE
SGROUP,RELEASED vs. GROUP,ACTIVE with different ip(s) => REPLACE
SGROUP,RELEASED vs. GROUP,TOMBSTONE with different ip(s) => REPLACE
SGROUP,TOMBSTONE vs. GROUP,ACTIVE with different ip(s) => REPLACE
SGROUP,TOMBSTONE vs. GROUP,TOMBSTONE with different ip(s) => REPLACE
SGROUP,RELEASED vs. SGROUP,ACTIVE with different ip(s) => REPLACE
SGROUP,RELEASED vs. SGROUP,TOMBSTONE with different ip(s) => REPLACE
SGROUP,TOMBSTONE vs. SGROUP,ACTIVE with different ip(s) => REPLACE
SGROUP,TOMBSTONE vs. SGROUP,TOMBSTONE with different ip(s) => REPLACE
SGROUP,ACTIVE vs. MHOMED,ACTIVE with same ip(s) => NOT REPLACE
SGROUP,ACTIVE vs. MHOMED,TOMBSTONE with same ip(s) => NOT REPLACE
SGROUP,RELEASED vs. MHOMED,ACTIVE with different ip(s) => REPLACE
SGROUP,RELEASED vs. MHOMED,TOMBSTONE with different ip(s) => REPLACE
SGROUP,TOMBSTONE vs. MHOMED,ACTIVE with different ip(s) => REPLACE
SGROUP,TOMBSTONE vs. MHOMED,TOMBSTONE with different ip(s) => REPLACE

SGROUP,ACTIVE vs. SGROUP,* is not handled here!

*/
static enum _R_ACTION replace_sgroup_replica_vs_X_replica(struct winsdb_record *r1, struct wrepl_name *r2)
{
	if (!R_IS_ACTIVE(r1)) {
		/* REPLACE */
		return R_DO_REPLACE;
	}

	if (R_IS_SGROUP(r2)) {
		/* not handled here: MERGE */
		return R_DO_SGROUP_MERGE;
	}

	/* NOT REPLACE */
	return R_NOT_REPLACE;
}

/*
MHOMED,ACTIVE vs. UNIQUE,ACTIVE with different ip(s) => REPLACE
MHOMED,ACTIVE vs. UNIQUE,TOMBSTONE with same ip(s) => NOT REPLACE
MHOMED,RELEASED vs. UNIQUE,ACTIVE with different ip(s) => REPLACE
MHOMED,RELEASED vs. UNIQUE,TOMBSTONE with different ip(s) => REPLACE
MHOMED,TOMBSTONE vs. UNIQUE,ACTIVE with different ip(s) => REPLACE
MHOMED,TOMBSTONE vs. UNIQUE,TOMBSTONE with different ip(s) => REPLACE
MHOMED,ACTIVE vs. GROUP,ACTIVE with different ip(s) => REPLACE
MHOMED,ACTIVE vs. GROUP,TOMBSTONE with same ip(s) => NOT REPLACE
MHOMED,RELEASED vs. GROUP,ACTIVE with different ip(s) => REPLACE
MHOMED,RELEASED vs. GROUP,TOMBSTONE with different ip(s) => REPLACE
MHOMED,TOMBSTONE vs. GROUP,ACTIVE with different ip(s) => REPLACE
MHOMED,TOMBSTONE vs. GROUP,TOMBSTONE with different ip(s) => REPLACE
MHOMED,ACTIVE vs. SGROUP,ACTIVE with same ip(s) => NOT REPLACE
MHOMED,ACTIVE vs. SGROUP,TOMBSTONE with same ip(s) => NOT REPLACE
MHOMED,RELEASED vs. SGROUP,ACTIVE with different ip(s) => REPLACE
MHOMED,RELEASED vs. SGROUP,TOMBSTONE with different ip(s) => REPLACE
MHOMED,TOMBSTONE vs. SGROUP,ACTIVE with different ip(s) => REPLACE
MHOMED,TOMBSTONE vs. SGROUP,TOMBSTONE with different ip(s) => REPLACE
MHOMED,ACTIVE vs. MHOMED,ACTIVE with different ip(s) => REPLACE
MHOMED,ACTIVE vs. MHOMED,TOMBSTONE with same ip(s) => NOT REPLACE
MHOMED,RELEASED vs. MHOMED,ACTIVE with different ip(s) => REPLACE
MHOMED,RELEASED vs. MHOMED,TOMBSTONE with different ip(s) => REPLACE
MHOMED,TOMBSTONE vs. MHOMED,ACTIVE with different ip(s) => REPLACE
MHOMED,TOMBSTONE vs. MHOMED,TOMBSTONE with different ip(s) => REPLACE
*/
static enum _R_ACTION replace_mhomed_replica_vs_X_replica(struct winsdb_record *r1, struct wrepl_name *r2)
{
	if (!R_IS_ACTIVE(r1)) {
		/* REPLACE */
		return R_DO_REPLACE;
	}

	if (!R_IS_SGROUP(r2) && R_IS_ACTIVE(r2)) {
		/* REPLACE */
		return R_DO_REPLACE;
	}

	/* NOT REPLACE */
	return R_NOT_REPLACE;
}

/*
active:
_UA_UA_SI_U<00> => REPLACE
_UA_UA_DI_P<00> => NOT REPLACE
_UA_UA_DI_N<00> => REPLACE
_UA_UT_SI_U<00> => NOT REPLACE
_UA_UT_DI_U<00> => NOT REPLACE
_UA_GA_SI_R<00> => REPLACE
_UA_GA_DI_R<00> => REPLACE
_UA_GT_SI_U<00> => NOT REPLACE
_UA_GT_DI_U<00> => NOT REPLACE
_UA_SA_SI_R<00> => REPLACE
_UA_SA_DI_R<00> => REPLACE
_UA_ST_SI_U<00> => NOT REPLACE
_UA_ST_DI_U<00> => NOT REPLACE
_UA_MA_SI_U<00> => REPLACE
_UA_MA_DI_P<00> => NOT REPLACE
_UA_MA_DI_N<00> => REPLACE
_UA_MT_SI_U<00> => NOT REPLACE
_UA_MT_DI_U<00> => NOT REPLACE
Test Replica vs. owned active: some more UNIQUE,MHOMED combinations
_UA_UA_DI_A<00> => MHOMED_MERGE
_UA_MA_DI_A<00> => MHOMED_MERGE

released:
_UR_UA_SI<00> => REPLACE
_UR_UA_DI<00> => REPLACE
_UR_UT_SI<00> => REPLACE
_UR_UT_DI<00> => REPLACE
_UR_GA_SI<00> => REPLACE
_UR_GA_DI<00> => REPLACE
_UR_GT_SI<00> => REPLACE
_UR_GT_DI<00> => REPLACE
_UR_SA_SI<00> => REPLACE
_UR_SA_DI<00> => REPLACE
_UR_ST_SI<00> => REPLACE
_UR_ST_DI<00> => REPLACE
_UR_MA_SI<00> => REPLACE
_UR_MA_DI<00> => REPLACE
_UR_MT_SI<00> => REPLACE
_UR_MT_DI<00> => REPLACE
*/
static enum _R_ACTION replace_unique_owned_vs_X_replica(struct winsdb_record *r1, struct wrepl_name *r2)
{
	if (!R_IS_ACTIVE(r1)) {
		/* REPLACE */
		return R_DO_REPLACE;
	}

	if (!R_IS_ACTIVE(r2)) {
		/* NOT REPLACE */
		return R_NOT_REPLACE;
	}

	/* TODO: handle MHOMED merging and release damands */

	/* NOT REPLACE */
	return R_NOT_REPLACE;
}

/*
active:
_GA_UA_SI_U<00> => NOT REPLACE
_GA_UA_DI_U<00> => NOT REPLACE
_GA_UT_SI_U<00> => NOT REPLACE
_GA_UT_DI_U<00> => NOT REPLACE
_GA_GA_SI_U<00> => REPLACE
_GA_GA_DI_U<00> => REPLACE
_GA_GT_SI_U<00> => NOT REPLACE
_GA_GT_DI_U<00> => NOT REPLACE
_GA_SA_SI_U<00> => NOT REPLACE
_GA_SA_DI_U<00> => NOT REPLACE
_GA_ST_SI_U<00> => NOT REPLACE
_GA_ST_DI_U<00> => NOT REPLACE
_GA_MA_SI_U<00> => NOT REPLACE
_GA_MA_DI_U<00> => NOT REPLACE
_GA_MT_SI_U<00> => NOT REPLACE
_GA_MT_DI_U<00> => NOT REPLACE

released:
_GR_UA_SI<00> => NOT REPLACE
_GR_UA_DI<00> => NOT REPLACE
_GR_UT_SI<00> => NOT REPLACE
_GR_UT_DI<00> => NOT REPLACE
_GR_GA_SI<00> => REPLACE
_GR_GA_DI<00> => REPLACE
_GR_GT_SI<00> => REPLACE
_GR_GT_DI<00> => REPLACE
_GR_SA_SI<00> => NOT REPLACE
_GR_SA_DI<00> => NOT REPLACE
_GR_ST_SI<00> => NOT REPLACE
_GR_ST_DI<00> => NOT REPLACE
_GR_MA_SI<00> => NOT REPLACE
_GR_MA_DI<00> => NOT REPLACE
_GR_MT_SI<00> => NOT REPLACE
_GR_MT_DI<00> => NOT REPLACE
*/
static enum _R_ACTION replace_group_owned_vs_X_replica(struct winsdb_record *r1, struct wrepl_name *r2)
{
	if (R_IS_GROUP(r1) && R_IS_GROUP(r2)) {
		if (!R_IS_ACTIVE(r1) || R_IS_ACTIVE(r2)) {
			/* REPLACE */
			return R_DO_REPLACE;
		}
	}

	/* NOT REPLACE */
	return R_NOT_REPLACE;
}

/*
active (not sgroup vs. sgroup yet!):
_SA_UA_SI_U<1c> => NOT REPLACE
_SA_UA_DI_U<1c> => NOT REPLACE
_SA_UT_SI_U<1c> => NOT REPLACE
_SA_UT_DI_U<1c> => NOT REPLACE
_SA_GA_SI_U<1c> => NOT REPLACE
_SA_GA_DI_U<1c> => NOT REPLACE
_SA_GT_SI_U<1c> => NOT REPLACE
_SA_GT_DI_U<1c> => NOT REPLACE
_SA_MA_SI_U<1c> => NOT REPLACE
_SA_MA_DI_U<1c> => NOT REPLACE
_SA_MT_SI_U<1c> => NOT REPLACE
_SA_MT_DI_U<1c> => NOT REPLACE

SGROUP,ACTIVE vs. SGROUP,* is not handled here!

released:
_SR_UA_SI<1c> => REPLACE
_SR_UA_DI<1c> => REPLACE
_SR_UT_SI<1c> => REPLACE
_SR_UT_DI<1c> => REPLACE
_SR_GA_SI<1c> => REPLACE
_SR_GA_DI<1c> => REPLACE
_SR_GT_SI<1c> => REPLACE
_SR_GT_DI<1c> => REPLACE
_SR_SA_SI<1c> => REPLACE
_SR_SA_DI<1c> => REPLACE
_SR_ST_SI<1c> => REPLACE
_SR_ST_DI<1c> => REPLACE
_SR_MA_SI<1c> => REPLACE
_SR_MA_DI<1c> => REPLACE
_SR_MT_SI<1c> => REPLACE
_SR_MT_DI<1c> => REPLACE
*/
static enum _R_ACTION replace_sgroup_owned_vs_X_replica(struct winsdb_record *r1, struct wrepl_name *r2)
{
	if (!R_IS_ACTIVE(r1)) {
		/* REPLACE */
		return R_DO_REPLACE;
	}

	if (R_IS_SGROUP(r2)) {
		/* not handled here: MERGE */
		return R_DO_SGROUP_MERGE;
	}

	/* NOT REPLACE */
	return R_NOT_REPLACE;
}

/*
active:
_MA_UA_SI_U<00> => REPLACE
_MA_UA_DI_P<00> => NOT REPLACE
_MA_UA_DI_O<00> => NOT REPLACE
_MA_UA_DI_N<00> => REPLACE
_MA_UT_SI_U<00> => NOT REPLACE
_MA_UT_DI_U<00> => NOT REPLACE
_MA_GA_SI_R<00> => REPLACE
_MA_GA_DI_R<00> => REPLACE
_MA_GT_SI_U<00> => NOT REPLACE
_MA_GT_DI_U<00> => NOT REPLACE
_MA_SA_SI_R<00> => REPLACE
_MA_SA_DI_R<00> => REPLACE
_MA_ST_SI_U<00> => NOT REPLACE
_MA_ST_DI_U<00> => NOT REPLACE
_MA_MA_SI_U<00> => REPLACE
_MA_MA_SP_U<00> => REPLACE
_MA_MA_DI_P<00> => NOT REPLACE
_MA_MA_DI_O<00> => NOT REPLACE
_MA_MA_DI_N<00> => REPLACE
_MA_MT_SI_U<00> => NOT REPLACE
_MA_MT_DI_U<00> => NOT REPLACE
Test Replica vs. owned active: some more MHOMED combinations
_MA_MA_SP_U<00> => REPLACE
_MA_MA_SM_U<00> => REPLACE
_MA_MA_SB_P<00> => MHOMED_MERGE
_MA_MA_SB_A<00> => MHOMED_MERGE
_MA_MA_SB_C<00> => NOT REPLACE
_MA_MA_SB_O<00> => NOT REPLACE
_MA_MA_SB_N<00> => REPLACE
Test Replica vs. owned active: some more UNIQUE,MHOMED combinations
_MA_UA_SB_A<00> => MHOMED_MERGE

released:
_MR_UA_SI<00> => REPLACE
_MR_UA_DI<00> => REPLACE
_MR_UT_SI<00> => REPLACE
_MR_UT_DI<00> => REPLACE
_MR_GA_SI<00> => REPLACE
_MR_GA_DI<00> => REPLACE
_MR_GT_SI<00> => REPLACE
_MR_GT_DI<00> => REPLACE
_MR_SA_SI<00> => REPLACE
_MR_SA_DI<00> => REPLACE
_MR_ST_SI<00> => REPLACE
_MR_ST_DI<00> => REPLACE
_MR_MA_SI<00> => REPLACE
_MR_MA_DI<00> => REPLACE
_MR_MT_SI<00> => REPLACE
_MR_MT_DI<00> => REPLACE
*/
static enum _R_ACTION replace_mhomed_owned_vs_X_replica(struct winsdb_record *r1, struct wrepl_name *r2)
{
	if (!R_IS_ACTIVE(r1)) {
		/* REPLACE */
		return R_DO_REPLACE;
	}

	if (!R_IS_ACTIVE(r2)) {
		/* NOT REPLACE */
		return R_NOT_REPLACE;
	}

	/* TODO: handle MHOMED merging and release demands */

	/* NOT REPLACE */
	return R_NOT_REPLACE;
}


static NTSTATUS wreplsrv_apply_one_record(struct wreplsrv_partner *partner,
					  TALLOC_CTX *mem_ctx,
					  struct wrepl_wins_owner *owner,
					  struct wrepl_name *name)
{
	NTSTATUS status;
	struct winsdb_record *rec = NULL;
	enum _R_ACTION action = R_NOT_REPLACE;
	BOOL same_owner = False;
	BOOL replica_vs_replica = False;
	BOOL local_vs_replica = False;

	status = winsdb_lookup(partner->service->wins_db,
			       &name->name, mem_ctx, &rec);
	if (NT_STATUS_EQUAL(NT_STATUS_OBJECT_NAME_NOT_FOUND, status)) {
		rec = NULL;
		action = R_DO_ADD;
		status = NT_STATUS_OK;
	}
	NT_STATUS_NOT_OK_RETURN(status);

	if (rec) {
		if (strcmp(rec->wins_owner, WINSDB_OWNER_LOCAL)==0) {
			local_vs_replica = True;
		} else if (strcmp(rec->wins_owner, owner->address)==0) {
			same_owner = True;
		} else {
			replica_vs_replica = True;
		}
	}

	if (rec && same_owner) {
		action = replace_same_owner(rec, name);
	} else if (rec && replica_vs_replica) {
		switch (rec->type) {
		case WREPL_TYPE_UNIQUE:
			action = replace_unique_replica_vs_X_replica(rec, name);
			break;
		case WREPL_TYPE_GROUP:
			action = replace_group_replica_vs_X_replica(rec, name);
			break;
		case WREPL_TYPE_SGROUP:
			action = replace_sgroup_replica_vs_X_replica(rec, name);
			break;
		case WREPL_TYPE_MHOMED:
			action = replace_mhomed_replica_vs_X_replica(rec, name);
			break;
		}
	} else if (rec && local_vs_replica) {
		switch (rec->type) {
		case WREPL_TYPE_UNIQUE:
			action = replace_unique_owned_vs_X_replica(rec, name);
			break;
		case WREPL_TYPE_GROUP:
			action = replace_group_owned_vs_X_replica(rec, name);
			break;
		case WREPL_TYPE_SGROUP:
			action = replace_sgroup_owned_vs_X_replica(rec, name);
			break;
		case WREPL_TYPE_MHOMED:
			action = replace_mhomed_owned_vs_X_replica(rec, name);
			break;
		}
	}

	/* TODO: !!! */
	DEBUG(0,("TODO: apply record %s: %s\n",
		 nbt_name_string(mem_ctx, &name->name), _R_ACTION_enum_string(action)));

	return NT_STATUS_OK;
}

NTSTATUS wreplsrv_apply_records(struct wreplsrv_partner *partner, struct wreplsrv_pull_names_io *names_io)
{
	TALLOC_CTX *tmp_mem = talloc_new(partner);
	NTSTATUS status;
	uint32_t i;

	/* TODO: ! */
	DEBUG(0,("TODO: apply records count[%u]:owner[%s]:min[%llu]:max[%llu]:partner[%s]\n",
		names_io->out.num_names, names_io->in.owner.address,
		names_io->in.owner.min_version, names_io->in.owner.max_version,
		partner->address));

	for (i=0; i < names_io->out.num_names; i++) {
		status = wreplsrv_apply_one_record(partner, tmp_mem,
						   &names_io->in.owner,
						   &names_io->out.names[i]);
		NT_STATUS_NOT_OK_RETURN(status);
	}

	status = wreplsrv_add_table(partner->service,
				    partner->service,
				    &partner->service->table,
				    names_io->in.owner.address,
				    names_io->in.owner.max_version);
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
}
