/*
 *  idmap_autorid_tdb: This file contains common code used by
 *  idmap_autorid and net idmap autorid utilities. The common
 *  code provides functions for performing various operations
 *  on autorid.tdb
 *
 *  Copyright (C) Christian Ambach, 2010-2012
 *  Copyright (C) Atul Kulkarni, 2013
 *  Copyright (C) Michael Adam, 2012-2013
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "idmap_autorid_tdb.h"
#include "../libcli/security/dom_sid.h"

/**
 * Build the database keystring for getting a range
 * belonging to a domain sid and a range index.
 */
static void idmap_autorid_build_keystr(const char *domsid,
				       uint32_t domain_range_index,
				       fstring keystr)
{
	if (domain_range_index > 0) {
		fstr_sprintf(keystr, "%s#%"PRIu32,
			     domsid, domain_range_index);
	} else {
		fstrcpy(keystr, domsid);
	}
}

static char *idmap_autorid_build_keystr_talloc(TALLOC_CTX *mem_ctx,
					      const char *domsid,
					      uint32_t domain_range_index)
{
	char *keystr;

	if (domain_range_index > 0) {
		keystr = talloc_asprintf(mem_ctx, "%s#%"PRIu32, domsid,
					 domain_range_index);
	} else {
		keystr = talloc_strdup(mem_ctx, domsid);
	}

	return keystr;
}


static bool idmap_autorid_validate_sid(const char *sid)
{
	struct dom_sid ignore;
	if (sid == NULL) {
		return false;
	}

	if (strcmp(sid, ALLOC_RANGE) == 0) {
		return true;
	}

	return dom_sid_parse(sid, &ignore);
}

struct idmap_autorid_addrange_ctx {
	struct autorid_range_config *range;
	bool acquire;
};

static NTSTATUS idmap_autorid_addrange_action(struct db_context *db,
					      void *private_data)
{
	struct idmap_autorid_addrange_ctx *ctx;
	uint32_t requested_rangenum, stored_rangenum;
	struct autorid_range_config *range;
	bool acquire;
	NTSTATUS ret;
	uint32_t hwm;
	char *numstr;
	struct autorid_global_config *globalcfg;
	fstring keystr;
	uint32_t increment;
	TALLOC_CTX *mem_ctx = NULL;

	ctx = (struct idmap_autorid_addrange_ctx *)private_data;
	range = ctx->range;
	acquire = ctx->acquire;
	requested_rangenum = range->rangenum;

	if (db == NULL) {
		DEBUG(3, ("Invalid database argument: NULL"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (range == NULL) {
		DEBUG(3, ("Invalid range argument: NULL"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(10, ("Adding new range for domain %s "
		   "(domain_range_index=%"PRIu32")\n",
		   range->domsid, range->domain_range_index));

	if (!idmap_autorid_validate_sid(range->domsid)) {
		DEBUG(3, ("Invalid SID: %s\n", range->domsid));
		return NT_STATUS_INVALID_PARAMETER;
	}

	idmap_autorid_build_keystr(range->domsid, range->domain_range_index,
				   keystr);

	ret = dbwrap_fetch_uint32_bystring(db, keystr, &stored_rangenum);

	if (NT_STATUS_IS_OK(ret)) {
		/* entry is already present*/
		if (acquire) {
			DEBUG(10, ("domain range already allocated - "
				   "Not adding!\n"));
			return NT_STATUS_OK;
		}

		if (stored_rangenum != requested_rangenum) {
			DEBUG(1, ("Error: requested rangenumber (%u) differs "
				  "from stored one (%u).\n",
				  requested_rangenum, stored_rangenum));
			return NT_STATUS_UNSUCCESSFUL;
		}

		DEBUG(10, ("Note: stored range agrees with requested "
			   "one - ok\n"));
		return NT_STATUS_OK;
	}

	/* fetch the current HWM */
	ret = dbwrap_fetch_uint32_bystring(db, HWM, &hwm);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1, ("Fatal error while fetching current "
			  "HWM value: %s\n", nt_errstr(ret)));
		return NT_STATUS_INTERNAL_ERROR;
	}

	mem_ctx = talloc_stackframe();

	ret = idmap_autorid_loadconfig(db, mem_ctx, &globalcfg);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1, ("Fatal error while fetching configuration: %s\n",
			  nt_errstr(ret)));
		goto error;
	}

	if (acquire) {
		/*
		 * automatically acquire the next range
		 */
		requested_rangenum = hwm;
	}

	if (requested_rangenum >= globalcfg->maxranges) {
		DEBUG(1, ("Not enough ranges available: New range %u must be "
			  "smaller than configured maximum number of ranges "
			  "(%u).\n",
			  requested_rangenum, globalcfg->maxranges));
		ret = NT_STATUS_NO_MEMORY;
		goto error;
	}

	/*
	 * Check that it is not yet taken.
	 * If the range is requested and < HWM, we need
	 * to check anyways, and otherwise, we also better
	 * check in order to prevent further corruption
	 * in case the db has been externally modified.
	 */

	numstr = talloc_asprintf(mem_ctx, "%u", requested_rangenum);
	if (!numstr) {
		DEBUG(1, ("Talloc failed!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto error;
	}

	if (dbwrap_exists(db, string_term_tdb_data(numstr))) {
		DEBUG(1, ("Requested range '%s' is already in use.\n", numstr));

		if (requested_rangenum < hwm) {
			ret = NT_STATUS_INVALID_PARAMETER;
		} else {
			ret = NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		goto error;
	}

	if (requested_rangenum >= hwm) {
		/*
		 * requested or automatic range >= HWM:
		 * increment the HWM.
		 */

		/* HWM always contains current max range + 1 */
		increment = requested_rangenum + 1 - hwm;

		/* increase the HWM */
		ret = dbwrap_change_uint32_atomic_bystring(db, HWM, &hwm,
							   increment);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1, ("Fatal error while incrementing the HWM "
				  "value in the database: %s\n",
				  nt_errstr(ret)));
			goto error;
		}
	}

	/*
	 * store away the new mapping in both directions
	 */

	ret = dbwrap_store_uint32_bystring(db, keystr, requested_rangenum);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1, ("Fatal error while storing new "
			  "domain->range assignment: %s\n", nt_errstr(ret)));
		goto error;
	}

	numstr = talloc_asprintf(mem_ctx, "%u", requested_rangenum);
	if (!numstr) {
		ret = NT_STATUS_NO_MEMORY;
		goto error;
	}

	ret = dbwrap_store_bystring(db, numstr,
			string_term_tdb_data(keystr), TDB_INSERT);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1, ("Fatal error while storing new "
			  "domain->range assignment: %s\n", nt_errstr(ret)));
		goto error;
	}

	DEBUG(5, ("%s new range #%d for domain %s "
		  "(domain_range_index=%"PRIu32")\n",
		  (acquire?"Acquired":"Stored"),
		  requested_rangenum, keystr,
		  range->domain_range_index));

	range->rangenum = requested_rangenum;

	range->low_id = globalcfg->minvalue
		      + range->rangenum * globalcfg->rangesize;
	range->high_id = range->low_id  + globalcfg->rangesize - 1;

	ret = NT_STATUS_OK;

error:
	talloc_free(mem_ctx);
	return ret;
}

static NTSTATUS idmap_autorid_addrange(struct db_context *db,
				       struct autorid_range_config *range,
				       bool acquire)
{
	NTSTATUS status;
	struct idmap_autorid_addrange_ctx ctx;

	ctx.acquire = acquire;
	ctx.range = range;

	status = dbwrap_trans_do(db, idmap_autorid_addrange_action, &ctx);
	return status;
}

NTSTATUS idmap_autorid_setrange(struct db_context *db,
				const char *domsid,
				uint32_t domain_range_index,
				uint32_t rangenum)
{
	NTSTATUS status;
	struct autorid_range_config range;

	ZERO_STRUCT(range);
	fstrcpy(range.domsid, domsid);
	range.domain_range_index = domain_range_index;
	range.rangenum = rangenum;

	status = idmap_autorid_addrange(db, &range, false);
	return status;
}

static NTSTATUS idmap_autorid_acquire_range(struct db_context *db,
					    struct autorid_range_config *range)
{
	return idmap_autorid_addrange(db, range, true);
}

static NTSTATUS idmap_autorid_getrange_int(struct db_context *db,
					   struct autorid_range_config *range)
{
	NTSTATUS status = NT_STATUS_INVALID_PARAMETER;
	struct autorid_global_config *globalcfg = NULL;
	fstring keystr;

	if (db == NULL || range == NULL) {
		DEBUG(3, ("Invalid arguments received\n"));
		goto done;
	}

	if (!idmap_autorid_validate_sid(range->domsid)) {
		DEBUG(3, ("Invalid SID: '%s'\n", range->domsid));
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	idmap_autorid_build_keystr(range->domsid, range->domain_range_index,
				   keystr);

	DEBUG(10, ("reading domain range for key %s\n", keystr));
	status = dbwrap_fetch_uint32_bystring(db, keystr, &(range->rangenum));
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to read database record for key '%s': %s\n",
			  keystr, nt_errstr(status)));
		goto done;
	}

	status = idmap_autorid_loadconfig(db, talloc_tos(), &globalcfg);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to read global configuration"));
		goto done;
	}
	range->low_id = globalcfg->minvalue
		      + range->rangenum * globalcfg->rangesize;
	range->high_id = range->low_id  + globalcfg->rangesize - 1;

	TALLOC_FREE(globalcfg);
done:
	return status;
}

NTSTATUS idmap_autorid_getrange(struct db_context *db,
				const char *domsid,
				uint32_t domain_range_index,
				uint32_t *rangenum,
				uint32_t *low_id)
{
	NTSTATUS status;
	struct autorid_range_config range;

	if (rangenum == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ZERO_STRUCT(range);
	fstrcpy(range.domsid, domsid);
	range.domain_range_index = domain_range_index;

	status = idmap_autorid_getrange_int(db, &range);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*rangenum = range.rangenum;

	if (low_id != NULL) {
		*low_id = range.low_id;
	}

	return NT_STATUS_OK;
}

NTSTATUS idmap_autorid_get_domainrange(struct db_context *db,
				       struct autorid_range_config *range,
				       bool read_only)
{
	NTSTATUS ret;

	ret = idmap_autorid_getrange_int(db, range);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(10, ("Failed to read range config for '%s': %s\n",
			   range->domsid, nt_errstr(ret)));
		if (read_only) {
			DEBUG(10, ("Not allocating new range for '%s' because "
				   "read-only is enabled.\n", range->domsid));
			return NT_STATUS_NOT_FOUND;
		}

		ret = idmap_autorid_acquire_range(db, range);
	}

	DEBUG(10, ("Using range #%d for domain %s "
		   "(domain_range_index=%"PRIu32", low_id=%"PRIu32")\n",
		   range->rangenum, range->domsid, range->domain_range_index,
		   range->low_id));

	return ret;
}

/* initialize the given HWM to 0 if it does not exist yet */
static NTSTATUS idmap_autorid_init_hwm_action(struct db_context *db,
					      void *private_data)
{
	NTSTATUS status;
	uint32_t hwmval;
	const char *hwm;

	hwm = (char *)private_data;

	status = dbwrap_fetch_uint32_bystring(db, hwm, &hwmval);
	if (NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("HWM (%s) already initialized in autorid database "
			  "(value %"PRIu32").\n", hwm, hwmval));
		return NT_STATUS_OK;
	}
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		DEBUG(0, ("Error fetching HWM (%s) from autorid "
			  "database: %s\n", hwm, nt_errstr(status)));
		return status;
	}

	status = dbwrap_trans_store_uint32_bystring(db, hwm, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Error storing HWM (%s) in autorid database: %s\n",
			  hwm, nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS idmap_autorid_init_hwm(struct db_context *db, const char *hwm)
{
	NTSTATUS status;
	uint32_t hwmval;

	status = dbwrap_fetch_uint32_bystring(db, hwm, &hwmval);
	if (NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("HWM (%s) already initialized in autorid database "
			  "(value %"PRIu32").\n", hwm, hwmval));
		return NT_STATUS_OK;
	}
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		DEBUG(0, ("unable to fetch HWM (%s) from autorid "
			  "database: %s\n", hwm,  nt_errstr(status)));
		return status;
	}

	status = dbwrap_trans_do(db, idmap_autorid_init_hwm_action,
				 discard_const(hwm));
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Error initializing HWM (%s) in autorid database: "
			  "%s\n", hwm, nt_errstr(status)));
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	DEBUG(1, ("Initialized HWM (%s) in autorid database.\n", hwm));

	return NT_STATUS_OK;
}

/*
 * Delete a domain#index <-> range mapping from the database.
 * The mapping is specified by the sid and index.
 * If force == true, invalid mapping records are deleted as far
 * as possible, otherwise they are left untouched.
 */

struct idmap_autorid_delete_range_by_sid_ctx {
	const char *domsid;
	uint32_t domain_range_index;
	bool force;
};

static NTSTATUS idmap_autorid_delete_range_by_sid_action(struct db_context *db,
							 void *private_data)
{
	struct idmap_autorid_delete_range_by_sid_ctx *ctx =
		(struct idmap_autorid_delete_range_by_sid_ctx *)private_data;
	const char *domsid;
	uint32_t domain_range_index;
	uint32_t rangenum;
	char *keystr;
	char *range_keystr;
	TDB_DATA data;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	bool is_valid_range_mapping = true;
	bool force;

	domsid = ctx->domsid;
	domain_range_index = ctx->domain_range_index;
	force = ctx->force;

	keystr = idmap_autorid_build_keystr_talloc(frame, domsid,
						   domain_range_index);
	if (keystr == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	status = dbwrap_fetch_uint32_bystring(db, keystr, &rangenum);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	range_keystr = talloc_asprintf(frame, "%"PRIu32, rangenum);
	if (range_keystr == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	status = dbwrap_fetch_bystring(db, frame, range_keystr, &data);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		DEBUG(1, ("Incomplete mapping %s -> %s: no backward mapping\n",
			  keystr, range_keystr));
		is_valid_range_mapping = false;
	} else if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Error fetching reverse mapping for %s -> %s:  %s\n",
			  keystr, range_keystr, nt_errstr(status)));
		goto done;
	} else if (strncmp((const char *)data.dptr, keystr, strlen(keystr))
		   != 0)
	{
		DEBUG(1, ("Invalid mapping: %s -> %s -> %s\n",
			  keystr, range_keystr, (const char *)data.dptr));
		is_valid_range_mapping = false;
	}

	if (!is_valid_range_mapping && !force) {
		DEBUG(10, ("Not deleting invalid mapping, since not in force "
			   "mode.\n"));
		status = NT_STATUS_FILE_INVALID;
		goto done;
	}

	status = dbwrap_delete_bystring(db, keystr);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Deletion of '%s' failed: %s\n",
			  keystr, nt_errstr(status)));
		goto done;
	}

	if (!is_valid_range_mapping) {
		goto done;
	}

	status = dbwrap_delete_bystring(db, range_keystr);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Deletion of '%s' failed: %s\n",
			  range_keystr, nt_errstr(status)));
		goto done;
	}

	DEBUG(10, ("Deleted range mapping %s <--> %s\n", keystr,
		   range_keystr));

done:
	TALLOC_FREE(frame);
	return status;
}

NTSTATUS idmap_autorid_delete_range_by_sid(struct db_context *db,
					   const char *domsid,
					   uint32_t domain_range_index,
					   bool force)
{
	NTSTATUS status;
	struct idmap_autorid_delete_range_by_sid_ctx ctx;

	ctx.domain_range_index = domain_range_index;
	ctx.domsid = domsid;
	ctx.force = force;

	status = dbwrap_trans_do(db, idmap_autorid_delete_range_by_sid_action,
				 &ctx);
	return status;
}

/*
 * Delete a domain#index <-> range mapping from the database.
 * The mapping is specified by the range number.
 * If force == true, invalid mapping records are deleted as far
 * as possible, otherwise they are left untouched.
 */
struct idmap_autorid_delete_range_by_num_ctx {
	uint32_t rangenum;
	bool force;
};

static NTSTATUS idmap_autorid_delete_range_by_num_action(struct db_context *db,
							   void *private_data)
{
	struct idmap_autorid_delete_range_by_num_ctx *ctx =
		(struct idmap_autorid_delete_range_by_num_ctx *)private_data;
	uint32_t rangenum;
	char *keystr;
	char *range_keystr;
	TDB_DATA val;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	bool is_valid_range_mapping = true;
	bool force;

	rangenum = ctx->rangenum;
	force = ctx->force;

	range_keystr = talloc_asprintf(frame, "%"PRIu32, rangenum);
	if (range_keystr == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	ZERO_STRUCT(val);

	status = dbwrap_fetch_bystring(db, frame, range_keystr, &val);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		DEBUG(10, ("Did not find range '%s' in database.\n",
			   range_keystr));
		goto done;
	} else if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("Error fetching rang key: %s\n", nt_errstr(status)));
		goto done;
	}

	if (val.dptr == NULL) {
		DEBUG(1, ("Invalid mapping: %s -> empty value\n",
			  range_keystr));
		is_valid_range_mapping = false;
	} else {
		uint32_t reverse_rangenum = 0;

		keystr = (char *)val.dptr;

		status = dbwrap_fetch_uint32_bystring(db, keystr,
						      &reverse_rangenum);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
			DEBUG(1, ("Incomplete mapping %s -> %s: "
				  "no backward mapping\n",
				  range_keystr, keystr));
			is_valid_range_mapping = false;
		} else if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Error fetching reverse mapping for "
				  "%s -> %s: %s\n",
				  range_keystr, keystr, nt_errstr(status)));
			goto done;
		} else if (rangenum != reverse_rangenum) {
			is_valid_range_mapping = false;
		}
	}

	if (!is_valid_range_mapping && !force) {
		DEBUG(10, ("Not deleting invalid mapping, since not in force "
			   "mode.\n"));
		status = NT_STATUS_FILE_INVALID;
		goto done;
	}

	status = dbwrap_delete_bystring(db, range_keystr);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Deletion of '%s' failed: %s\n",
			  range_keystr, nt_errstr(status)));
		goto done;
	}

	if (!is_valid_range_mapping) {
		goto done;
	}

	status = dbwrap_delete_bystring(db, keystr);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Deletion of '%s' failed: %s\n",
			  keystr, nt_errstr(status)));
		goto done;
	}

	DEBUG(10, ("Deleted range mapping %s <--> %s\n", range_keystr,
		   keystr));

done:
	talloc_free(frame);
	return status;
}

NTSTATUS idmap_autorid_delete_range_by_num(struct db_context *db,
					   uint32_t rangenum,
					   bool force)
{
	NTSTATUS status;
	struct idmap_autorid_delete_range_by_num_ctx ctx;

	ctx.rangenum = rangenum;
	ctx.force = force;

	status = dbwrap_trans_do(db, idmap_autorid_delete_range_by_num_action,
				 &ctx);
	return status;
}

/**
 * Open and possibly create the database.
 */
NTSTATUS idmap_autorid_db_open(const char *path,
			       TALLOC_CTX *mem_ctx,
			       struct db_context **db)
{
	if (*db != NULL) {
		/* its already open */
		return NT_STATUS_OK;
	}

	/* Open idmap repository */
	*db = db_open(mem_ctx, path, 0, TDB_DEFAULT, O_RDWR | O_CREAT, 0644,
		      DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);

	if (*db == NULL) {
		DEBUG(0, ("Unable to open idmap_autorid database '%s'\n", path));
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

/**
 * Initialize the high watermark records in the database.
 */
NTSTATUS idmap_autorid_init_hwms(struct db_context *db)
{
	NTSTATUS status;

	status = idmap_autorid_init_hwm(db, HWM);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = idmap_autorid_init_hwm(db, ALLOC_HWM_UID);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = idmap_autorid_init_hwm(db, ALLOC_HWM_GID);

	return status;
}

NTSTATUS idmap_autorid_db_init(const char *path,
			       TALLOC_CTX *mem_ctx,
			       struct db_context **db)
{
	NTSTATUS status;

	status = idmap_autorid_db_open(path, mem_ctx, db);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = idmap_autorid_init_hwms(*db);
	return status;
}



struct idmap_autorid_fetch_config_state {
	TALLOC_CTX *mem_ctx;
	char *configstr;
};

static void idmap_autorid_config_parser(TDB_DATA key, TDB_DATA value,
					void *private_data)
{
	struct idmap_autorid_fetch_config_state *state;

	state = (struct idmap_autorid_fetch_config_state *)private_data;

	/*
	 * strndup because we have non-nullterminated strings in the db
	 */
	state->configstr = talloc_strndup(
		state->mem_ctx, (const char *)value.dptr, value.dsize);
}

NTSTATUS idmap_autorid_getconfigstr(struct db_context *db, TALLOC_CTX *mem_ctx,
				    char **result)
{
	TDB_DATA key;
	NTSTATUS status;
	struct idmap_autorid_fetch_config_state state;

	if (result == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	key = string_term_tdb_data(CONFIGKEY);

	state.mem_ctx = mem_ctx;
	state.configstr = NULL;

	status = dbwrap_parse_record(db, key, idmap_autorid_config_parser,
				     &state);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Error while retrieving config: %s\n",
			  nt_errstr(status)));
		return status;
	}

	if (state.configstr == NULL) {
		DEBUG(1, ("Error while retrieving config\n"));
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(5, ("found CONFIG: %s\n", state.configstr));

	*result = state.configstr;
	return NT_STATUS_OK;
}

bool idmap_autorid_parse_configstr(const char *configstr,
				   struct autorid_global_config *cfg)
{
	unsigned long minvalue, rangesize, maxranges;

	if (sscanf(configstr,
		   "minvalue:%lu rangesize:%lu maxranges:%lu",
		   &minvalue, &rangesize, &maxranges) != 3) {
		DEBUG(1,
		      ("Found invalid configuration data. "
		       "Creating new config\n"));
		return false;
	}

	cfg->minvalue = minvalue;
	cfg->rangesize = rangesize;
	cfg->maxranges = maxranges;

	return true;
}

NTSTATUS idmap_autorid_loadconfig(struct db_context *db,
				  TALLOC_CTX *mem_ctx,
				  struct autorid_global_config **result)
{
	struct autorid_global_config *cfg;
	NTSTATUS status;
	bool ok;
	char *configstr = NULL;

	if (result == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = idmap_autorid_getconfigstr(db, mem_ctx, &configstr);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	cfg = talloc_zero(mem_ctx, struct autorid_global_config);
	if (cfg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ok = idmap_autorid_parse_configstr(configstr, cfg);
	if (!ok) {
		talloc_free(cfg);
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(10, ("Loaded previously stored configuration "
		   "minvalue:%d rangesize:%d\n",
		   cfg->minvalue, cfg->rangesize));

	*result = cfg;

	return NT_STATUS_OK;
}

NTSTATUS idmap_autorid_saveconfig(struct db_context *db,
				  struct autorid_global_config *cfg)
{

	struct autorid_global_config *storedconfig = NULL;
	NTSTATUS status = NT_STATUS_INVALID_PARAMETER;
	TDB_DATA data;
	char *cfgstr;
	uint32_t hwm;
	TALLOC_CTX *frame = talloc_stackframe();

	DEBUG(10, ("New configuration provided for storing is "
		   "minvalue:%d rangesize:%d maxranges:%d\n",
		   cfg->minvalue, cfg->rangesize, cfg->maxranges));

	if (cfg->rangesize < 2000) {
		DEBUG(1, ("autorid rangesize must be at least 2000\n"));
		goto done;
	}

	if (cfg->maxranges == 0) {
		DEBUG(1, ("An autorid maxranges value of 0 is invalid. "
			  "Must have at least one range available.\n"));
		goto done;
	}

	status = idmap_autorid_loadconfig(db, frame, &storedconfig);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		DEBUG(5, ("No configuration found. Storing initial "
			  "configuration.\n"));
	} else if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Error loading configuration: %s\n",
			  nt_errstr(status)));
		goto done;
	}

	/* did the minimum value or rangesize change? */
	if (storedconfig &&
	    ((storedconfig->minvalue != cfg->minvalue) ||
	     (storedconfig->rangesize != cfg->rangesize)))
	{
		DEBUG(1, ("New configuration values for rangesize or "
			  "minimum uid value conflict with previously "
			  "used values! Not storing new config.\n"));
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	status = dbwrap_fetch_uint32_bystring(db, HWM, &hwm);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Fatal error while fetching current "
			  "HWM value: %s\n", nt_errstr(status)));
		status = NT_STATUS_INTERNAL_ERROR;
		goto done;
	}

	/*
	 * has the highest uid value been reduced to setting that is not
	 * sufficient any more for already existing ranges?
	 */
	if (hwm > cfg->maxranges) {
		DEBUG(1, ("New upper uid limit is too low to cover "
			  "existing mappings! Not storing new config.\n"));
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	cfgstr =
	    talloc_asprintf(frame,
			    "minvalue:%u rangesize:%u maxranges:%u",
			    cfg->minvalue, cfg->rangesize, cfg->maxranges);

	if (cfgstr == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	data = string_tdb_data(cfgstr);

	status = dbwrap_trans_store_bystring(db, CONFIGKEY, data, TDB_REPLACE);

done:
	TALLOC_FREE(frame);
	return status;
}

NTSTATUS idmap_autorid_saveconfigstr(struct db_context *db,
				     const char *configstr)
{
	bool ok;
	NTSTATUS status;
	struct autorid_global_config cfg;

	ok = idmap_autorid_parse_configstr(configstr, &cfg);
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = idmap_autorid_saveconfig(db, &cfg);
	return status;
}


/*
 * iteration: Work on all range mappings for a given domain
 */

struct domain_range_visitor_ctx {
	const char *domsid;
	NTSTATUS (*fn)(struct db_context *db,
		       const char *domsid,
		       uint32_t index,
		       uint32_t rangenum,
		       void *private_data);
	void *private_data;
	int count; /* number of records worked on */
};

static int idmap_autorid_visit_domain_range(struct db_record *rec,
					    void *private_data)
{
	struct domain_range_visitor_ctx *vi;
	char *domsid;
	char *sep;
	uint32_t range_index = 0;
	uint32_t rangenum = 0;
	TDB_DATA key, value;
	NTSTATUS status;
	int ret = 0;
	struct db_context *db;

	vi = talloc_get_type_abort(private_data,
				   struct domain_range_visitor_ctx);

	key = dbwrap_record_get_key(rec);

	/*
	 * split string "<sid>[#<index>]" into sid string and index number
	 */

	domsid = (char *)key.dptr;

	DEBUG(10, ("idmap_autorid_visit_domain_range: visiting key '%s'\n",
		   domsid));

	sep = strrchr(domsid, '#');
	if (sep != NULL) {
		char *index_str;
		*sep = '\0';
		index_str = sep+1;
		if (sscanf(index_str, "%"SCNu32, &range_index) != 1) {
			DEBUG(10, ("Found separator '#' but '%s' is not a "
				   "valid range index. Skipping record\n",
				   index_str));
			goto done;
		}
	}

	if (!idmap_autorid_validate_sid(domsid)) {
		DEBUG(10, ("String '%s' is not a valid sid. "
			   "Skipping record.\n", domsid));
		goto done;
	}

	if ((vi->domsid != NULL) && (strcmp(domsid, vi->domsid) != 0)) {
		DEBUG(10, ("key sid '%s' does not match requested sid '%s'.\n",
			   domsid, vi->domsid));
		goto done;
	}

	value = dbwrap_record_get_value(rec);

	if (value.dsize != sizeof(uint32_t)) {
		/* it might be a mapping of a well known sid */
		DEBUG(10, ("value size %u != sizeof(uint32_t) for sid '%s', "
			   "skipping.\n", (unsigned)value.dsize, vi->domsid));
		goto done;
	}

	rangenum = IVAL(value.dptr, 0);

	db = dbwrap_record_get_db(rec);

	status = vi->fn(db, domsid, range_index, rangenum, vi->private_data);
	if (!NT_STATUS_IS_OK(status)) {
		ret = -1;
		goto done;
	}

	vi->count++;
	ret = 0;

done:
	return ret;
}

static NTSTATUS idmap_autorid_iterate_domain_ranges_int(struct db_context *db,
				const char *domsid,
				NTSTATUS (*fn)(struct db_context *db,
					       const char *domsid,
					       uint32_t index,
					       uint32_t rangnum,
					       void *private_data),
				void *private_data,
				int *count,
				NTSTATUS (*traverse)(struct db_context *db,
					  int (*f)(struct db_record *, void *),
					  void *private_data,
					  int *count))
{
	NTSTATUS status;
	struct domain_range_visitor_ctx *vi;
	TALLOC_CTX *frame = talloc_stackframe();

	if (domsid == NULL) {
		DEBUG(10, ("No sid provided, operating on all ranges\n"));
	}

	if (fn == NULL) {
		DEBUG(1, ("Error: missing visitor callback\n"));
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	vi = talloc_zero(frame, struct domain_range_visitor_ctx);
	if (vi == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	vi->domsid = domsid;
	vi->fn = fn;
	vi->private_data = private_data;

	status = traverse(db, idmap_autorid_visit_domain_range, vi, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (count != NULL) {
		*count = vi->count;
	}

done:
	talloc_free(frame);
	return status;
}

NTSTATUS idmap_autorid_iterate_domain_ranges(struct db_context *db,
					const char *domsid,
					NTSTATUS (*fn)(struct db_context *db,
						       const char *domsid,
						       uint32_t index,
						       uint32_t rangenum,
						       void *private_data),
					void *private_data,
					int *count)
{
	NTSTATUS status;

	status = idmap_autorid_iterate_domain_ranges_int(db,
							 domsid,
							 fn,
							 private_data,
							 count,
							 dbwrap_traverse);

	return status;
}


NTSTATUS idmap_autorid_iterate_domain_ranges_read(struct db_context *db,
					const char *domsid,
					NTSTATUS (*fn)(struct db_context *db,
						       const char *domsid,
						       uint32_t index,
						       uint32_t rangenum,
						       void *count),
					void *private_data,
					int *count)
{
	NTSTATUS status;

	status = idmap_autorid_iterate_domain_ranges_int(db,
							 domsid,
							 fn,
							 private_data,
							 count,
							 dbwrap_traverse_read);

	return status;
}


/*
 * Delete all ranges configured for a given domain
 */

struct delete_domain_ranges_visitor_ctx {
	bool force;
};

static NTSTATUS idmap_autorid_delete_domain_ranges_visitor(
						struct db_context *db,
						const char *domsid,
						uint32_t domain_range_index,
						uint32_t rangenum,
						void *private_data)
{
	struct delete_domain_ranges_visitor_ctx *ctx;
	NTSTATUS status;

	ctx = (struct delete_domain_ranges_visitor_ctx *)private_data;

	status = idmap_autorid_delete_range_by_sid(
				db, domsid, domain_range_index, ctx->force);
	return status;
}

struct idmap_autorid_delete_domain_ranges_ctx {
	const char *domsid;
	bool force;
	int count; /* output: count records operated on */
};

static NTSTATUS idmap_autorid_delete_domain_ranges_action(struct db_context *db,
							  void *private_data)
{
	struct idmap_autorid_delete_domain_ranges_ctx *ctx;
	struct delete_domain_ranges_visitor_ctx visitor_ctx;
	int count;
	NTSTATUS status;

	ctx = (struct idmap_autorid_delete_domain_ranges_ctx *)private_data;

	ZERO_STRUCT(visitor_ctx);
	visitor_ctx.force = ctx->force;

	status = idmap_autorid_iterate_domain_ranges(db,
				ctx->domsid,
				idmap_autorid_delete_domain_ranges_visitor,
				&visitor_ctx,
				&count);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ctx->count = count;

	return NT_STATUS_OK;
}

NTSTATUS idmap_autorid_delete_domain_ranges(struct db_context *db,
					    const char *domsid,
					    bool force,
					    int *count)
{
	NTSTATUS status;
	struct idmap_autorid_delete_domain_ranges_ctx ctx;

	ZERO_STRUCT(ctx);
	ctx.domsid = domsid;
	ctx.force = force;

	status = dbwrap_trans_do(db, idmap_autorid_delete_domain_ranges_action,
				 &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*count = ctx.count;

	return NT_STATUS_OK;
}
