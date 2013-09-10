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

static NTSTATUS idmap_autorid_get_domainrange_action(struct db_context *db,
					      void *private_data)
{
	NTSTATUS ret;
	uint32_t rangenum, hwm;
	char *numstr;
	struct autorid_range_config *range;

	range = (struct autorid_range_config *)private_data;

	ret = dbwrap_fetch_uint32_bystring(db, range->keystr,
					   &(range->rangenum));

	if (NT_STATUS_IS_OK(ret)) {
		/* entry is already present*/
		return ret;
	}

	DEBUG(10, ("Acquiring new range for domain %s "
		   "(domain_range_index=%"PRIu32")\n",
		   range->domsid, range->domain_range_index));

	/* fetch the current HWM */
	ret = dbwrap_fetch_uint32_bystring(db, HWM, &hwm);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1, ("Fatal error while fetching current "
			  "HWM value: %s\n", nt_errstr(ret)));
		ret = NT_STATUS_INTERNAL_ERROR;
		goto error;
	}

	/* do we have a range left? */
	if (hwm >= range->globalcfg->maxranges) {
		DEBUG(1, ("No more domain ranges available!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto error;
	}

	/* increase the HWM */
	ret = dbwrap_change_uint32_atomic_bystring(db, HWM, &rangenum, 1);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1, ("Fatal error while fetching a new "
			  "domain range value!\n"));
		goto error;
	}

	/* store away the new mapping in both directions */
	ret = dbwrap_store_uint32_bystring(db, range->keystr, rangenum);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1, ("Fatal error while storing new "
			  "domain->range assignment!\n"));
		goto error;
	}

	numstr = talloc_asprintf(db, "%u", rangenum);
	if (!numstr) {
		ret = NT_STATUS_NO_MEMORY;
		goto error;
	}

	ret = dbwrap_store_bystring(db, numstr,
			string_term_tdb_data(range->keystr), TDB_INSERT);

	talloc_free(numstr);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1, ("Fatal error while storing "
			  "new domain->range assignment!\n"));
		goto error;
	}
	DEBUG(5, ("Acquired new range #%d for domain %s "
		  "(domain_range_index=%"PRIu32")\n", rangenum, range->keystr,
		  range->domain_range_index));

	range->rangenum = rangenum;

	return NT_STATUS_OK;

error:
	return ret;

}

NTSTATUS idmap_autorid_get_domainrange(struct db_context *db,
				       struct autorid_range_config *range,
				       bool read_only)
{
	NTSTATUS ret;

	/*
	 * try to find mapping without locking the database,
	 * if it is not found create a mapping in a transaction unless
	 * read-only mode has been set
	 */
	if (range->domain_range_index > 0) {
		snprintf(range->keystr, FSTRING_LEN, "%s#%"PRIu32,
			 range->domsid, range->domain_range_index);
	} else {
		fstrcpy(range->keystr, range->domsid);
	}

	ret = dbwrap_fetch_uint32_bystring(db, range->keystr,
					   &(range->rangenum));

	if (!NT_STATUS_IS_OK(ret)) {
		if (read_only) {
			return NT_STATUS_NOT_FOUND;
		}
		ret = dbwrap_trans_do(db,
			      idmap_autorid_get_domainrange_action, range);
	}

	range->low_id = range->globalcfg->minvalue
		      + range->rangenum * range->globalcfg->rangesize;

	DEBUG(10, ("Using range #%d for domain %s "
		   "(domain_range_index=%"PRIu32", low_id=%"PRIu32")\n",
		   range->rangenum, range->domsid, range->domain_range_index,
		   range->low_id));

	return ret;
}

/* initialize the given HWM to 0 if it does not exist yet */
NTSTATUS idmap_autorid_init_hwm(struct db_context *db, const char *hwm)
{
	NTSTATUS status;
	uint32_t hwmval;

	status = dbwrap_fetch_uint32_bystring(db, hwm, &hwmval);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND))  {
		status = dbwrap_trans_store_int32_bystring(db, hwm, 0);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,
			      ("Unable to initialise HWM (%s) in autorid "
			       "database: %s\n", hwm, nt_errstr(status)));
			return NT_STATUS_INTERNAL_DB_ERROR;
		}
	} else if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("unable to fetch HWM (%s) from autorid "
			  "database: %s\n", hwm,  nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

/*
 * open and initialize the database which stores the ranges for the domains
 */
NTSTATUS idmap_autorid_db_init(const char *path,
			       TALLOC_CTX *mem_ctx,
			       struct db_context **db)
{
	NTSTATUS status;

	if (*db != NULL) {
		/* its already open */
		return NT_STATUS_OK;
	}

	/* Open idmap repository */
	*db = db_open(mem_ctx, path, 0, TDB_DEFAULT, O_RDWR | O_CREAT, 0644,
		      DBWRAP_LOCK_ORDER_1);

	if (*db == NULL) {
		DEBUG(0, ("Unable to open idmap_autorid database '%s'\n", path));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Initialize high water mark for the currently used range to 0 */

	status = idmap_autorid_init_hwm(*db, HWM);
	NT_STATUS_NOT_OK_RETURN(status);

	status = idmap_autorid_init_hwm(*db, ALLOC_HWM_UID);
	NT_STATUS_NOT_OK_RETURN(status);

	status = idmap_autorid_init_hwm(*db, ALLOC_HWM_GID);

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
		      ("Found invalid configuration data"
		       "creating new config\n"));
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
