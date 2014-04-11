/*
 *  idmap_autorid: static map between Active Directory/NT RIDs
 *  and RFC 2307 accounts. This file contains common functions
 *  and structures used by idmap_autorid and net idmap autorid utilities
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

#ifndef _IDMAP_AUTORID_H_
#define _IDMAP_AUTORID_H_

#include "includes.h"
#include "system/filesys.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "../lib/util/util_tdb.h"
#include "winbindd/idmap_tdb_common.h"

#define HWM "NEXT RANGE"
#define ALLOC_HWM_UID "NEXT ALLOC UID"
#define ALLOC_HWM_GID "NEXT ALLOC GID"
#define ALLOC_RANGE "ALLOC"
#define CONFIGKEY "CONFIG"

struct autorid_global_config {
	uint32_t minvalue;
	uint32_t rangesize;
	uint32_t maxranges;
};

struct autorid_range_config {
	fstring domsid;
	uint32_t rangenum;
	uint32_t domain_range_index;
	uint32_t low_id;
	uint32_t high_id;
};

/**
 * Get the range for a pair consisting of the domain sid
 * and a domain range. If there is no stored range for
 * this pair and read_only == false, a new range is
 * acquired by incrementing that range HWM counter in the
 * database.
 */
NTSTATUS idmap_autorid_get_domainrange(struct db_context *db,
				       struct autorid_range_config *range,
				       bool read_only);

/**
 * get the domain range and low_id for the domain
 * identified by domsid and domain_range_index
 */
NTSTATUS idmap_autorid_getrange(struct db_context *db,
				const char *domsid,
				uint32_t domain_range_index,
				uint32_t *rangenum,
				uint32_t *low_id);

/**
 * Set a range for a domain#index pair to a given
 * number. Fail if a different range was already stored.
 */
NTSTATUS idmap_autorid_setrange(struct db_context *db,
				const char *domsid,
				uint32_t domain_range_index,
				uint32_t rangenum);

/**
 * Delete a domain#index <-> range maping from the database.
 * The mapping is specified by the sid and index.
 * If force == true, invalid mapping records are deleted as far
 * as possible, otherwise they are left untouched.
 */
NTSTATUS idmap_autorid_delete_range_by_sid(struct db_context *db,
					   const char *domsid,
					   uint32_t domain_range_index,
					   bool force);

/**
 * Delete a domain#index <-> range maping from the database.
 * The mapping is specified by the range number.
 * If force == true, invalid mapping records are deleted as far
 * as possible, otherwise they are left untouched.
 */
NTSTATUS idmap_autorid_delete_range_by_num(struct db_context *db,
					   uint32_t rangenum,
					   bool force);

/**
 * Initialize a specified HWM value to 0 if it is not
 * yet present in the database.
 */
NTSTATUS idmap_autorid_init_hwm(struct db_context *db, const char *hwm);

/**
 * Open and possibly create the autorid database.
 */
NTSTATUS idmap_autorid_db_open(const char *path,
			       TALLOC_CTX *mem_ctx,
			       struct db_context **db);

/**
 * Initialize the high watermark records in the database.
 */
NTSTATUS idmap_autorid_init_hwms(struct db_context *db);

/**
 * Initialize an idmap_autorid database.
 * After this function has successfully completed, the following are true:
 * - the database exists
 * - the required HWM keys exist (range, alloc-uid, alloc-gid)
 */
NTSTATUS idmap_autorid_db_init(const char *path,
			       TALLOC_CTX *mem_ctx,
			       struct db_context **db);

/**
 * Load the configuration stored in the autorid database.
 */
NTSTATUS idmap_autorid_loadconfig(struct db_context *db,
				  TALLOC_CTX *ctx,
				  struct autorid_global_config **result);

/**
 * Save the global autorid configuration into the autorid database.
 * The stored configuration consists of:
 * - the low value of the idmap range
 * - the rangesize
 * - the maximum number of ranges
 */
NTSTATUS idmap_autorid_saveconfig(struct db_context *db,
				  struct autorid_global_config *cfg);

/**
 * get the range config string stored in the database
 */
NTSTATUS idmap_autorid_getconfigstr(struct db_context *db, TALLOC_CTX *mem_ctx,
				    char **result);

/**
 * parse the handed in config string and fill the provided config structure.
 * return false if the string could not be parsed.
 */
bool idmap_autorid_parse_configstr(const char *configstr,
				   struct autorid_global_config *cfg);


/**
 * Save the global autorid configuration into the autorid database
 * as provided in the config string.
 * First parse the configstr and validate it.
 */
NTSTATUS idmap_autorid_saveconfigstr(struct db_context *db,
				     const char *configstr);


/**
 * idmap_autorid_iterate_domain_ranges:
 * perform an action on all domain range mappings for a given domain
 * specified by domain sid.
 */
NTSTATUS idmap_autorid_iterate_domain_ranges(struct db_context *db,
					const char *domsid,
					NTSTATUS (*fn)(struct db_context *db,
						       const char *domsid,
						       uint32_t index,
						       uint32_t rangenum,
						       void *private_data),
					void *private_data,
					int *count);

/**
 * idmap_autorid_iterate_domain_ranges_read:
 * perform a read only action on all domain range mappings for a given domain
 * specified by domain sid.
 */
NTSTATUS idmap_autorid_iterate_domain_ranges_read(struct db_context *db,
					const char *domsid,
					NTSTATUS (*fn)(struct db_context *db,
						       const char *domsid,
						       uint32_t index,
						       uint32_t rangenum,
						       void *private_data),
					void *private_data,
					int *count);

/**
 * delete all range mappings for a given domain
 */
NTSTATUS idmap_autorid_delete_domain_ranges(struct db_context *db,
					    const char *domsid,
					    bool force,
					    int *count);

#endif /* _IDMAP_AUTORID_H_ */
