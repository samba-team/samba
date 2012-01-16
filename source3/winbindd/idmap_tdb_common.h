/*
   Unix SMB/CIFS implementation.

   common functions for TDB based idmapping backends

   Copyright (C) Christian Ambach 2012

   These functions were initially copied over from idmap_tdb.c and idmap_tdb2.c
   which are:

   Copyright (C) Tim Potter 2000
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Jeremy Allison 2006
   Copyright (C) Simo Sorce 2003-2006
   Copyright (C) Michael Adam 2009-2010
   Copyright (C) Andrew Tridgell 2007

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

#ifndef _IDMAP_TDB_COMMON_H_
#define _IDMAP_TDB_COMMON_H_

#include "includes.h"
#include "idmap.h"
#include "dbwrap/dbwrap.h"

/*
 * this must be stored in idmap_domain->private_data
 * when using idmap_tdb_common_get_new_id and the
 * mapping functions idmap_tdb_common_unixid(s)_to_sids
 *
 * private_data can be used for backend specific
 * configuration data (e.g. idmap script in idmap_tdb2)
 *
 */
struct idmap_tdb_common_context {
	struct db_context *db;
	struct idmap_rw_ops *rw_ops;
	/*
	 * what is the maximum xid to be allocated
	 * this is typically just dom->high_id
	 */
	uint32_t max_id;
	const char *hwmkey_uid;
	const char *hwmkey_gid;
	/**
	 * if not set, idmap_tdb_common_unixids_to_sid will be used by
	 * idmap_tdb_common_unixids_to_sids
	 */
	NTSTATUS(*unixid_to_sid_fn) (struct idmap_domain *dom,
				     struct id_map * map);
	/*
	 * if not set, idmap_tdb_common_sid_to_id will be used by
	 * idmap_tdb_common_sids_to_unixids
	 */
	NTSTATUS(*sid_to_unixid_fn) (struct idmap_domain *dom,
				     struct id_map * map);
	void *private_data;
};

/**
 * Allocate a new unix-ID.
 * For now this is for the default idmap domain only.
 * Should be extended later on.
 */
NTSTATUS idmap_tdb_common_get_new_id(struct idmap_domain *dom,
				     struct unixid *id);

/*
 * store a mapping into the idmap database
 *
 * the entries that will be stored are
 * UID map->xid.id => map->sid and map->sid => UID map->xid.id
 * or
 * GID map->xid.id => map->sid and map->sid => GID map->xid.id
 *
 * for example
 * UID 12345 = S-1-5-21-297746067-1479432880-4056370663
 * S-1-5-21-297746067-1479432880-4056370663 = UID 12345
 *
 */
NTSTATUS idmap_tdb_common_set_mapping(struct idmap_domain *dom,
				      const struct id_map *map);

/*
 * Create a new mapping for an unmapped SID, also allocating a new ID.
 * This should be run inside a transaction.
 *
 * TODO:
 *  Properly integrate this with multi domain idmap config:
 *  Currently, the allocator is default-config only.
 */
NTSTATUS idmap_tdb_common_new_mapping(struct idmap_domain *dom,
				      struct id_map *map);

/*
 * default multiple id to sid lookup function
 *
 * will call idmap_tdb_common_unixid_to_sid for each mapping
 * if no other function to lookup unixid_to_sid was given in
 * idmap_tdb_common_context
 */
NTSTATUS idmap_tdb_common_unixids_to_sids(struct idmap_domain *dom,
					  struct id_map **ids);

/*
 * default single id to sid lookup function
 *
 * will read the entries written by idmap_tdb_common_set_mapping
 */
NTSTATUS idmap_tdb_common_unixid_to_sid(struct idmap_domain *dom,
					struct id_map *map);

/**********************************
 Single sid to id lookup function.
**********************************/

NTSTATUS idmap_tdb_common_sid_to_unixid(struct idmap_domain *dom,
					struct id_map *map);

NTSTATUS idmap_tdb_common_sids_to_unixids(struct idmap_domain *dom,
					  struct id_map **ids);

#endif				/* _IDMAP_TDB_COMMON_H_ */
