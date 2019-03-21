/*
 *  idmap_autorid: static map between Active Directory/NT RIDs
 *  and RFC 2307 accounts
 *
 *  based on the idmap_rid module, but this module defines the ranges
 *  for the domains by automatically allocating a range for each domain
 *
 *  Copyright (C) Christian Ambach, 2010-2012
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

/*
 * This module allocates ranges for domains to be used in a
 * algorithmic mode like idmap_rid. Multiple ranges are supported
 * for a single domain: If a rid exceeds the range size, a matching
 * range is allocated to hold the rid's id.
 *
 * Here are the formulas applied:
 *
 *
 * For a sid of the form domain_sid-rid, we have
 *
 *   rid = reduced_rid + domain_range_index * range_size
 *
 * with
 *   reduced_rid := rid % range_size
 *   domain_range_index := rid / range_size
 *
 * And reduced_rid fits into a range.
 *
 * In the database, we associate a range_number to
 * the pair domain_sid,domain_range_index.
 *
 * Now the unix id for the given sid calculates as:
 *
 *   id = reduced_rid + range_low_id
 *
 * with
 *
 *   range_low_id = low_id + range_number * range_size
 *
 *
 * The inverse calculation goes like this:
 *
 * Given a unix id, let
 *
 *   normalized_id := id - low_id
 *   reduced_rid := normalized_id % range_size
 *   range_number = normalized_id / range_size
 *
 * Then we have
 *
 *   id = reduced_rid + low_id + range_number * range_size
 *
 * From the database, get the domain_sid,domain_range_index pair
 * belonging to the range_number (if there is already one).
 *
 * Then the rid for the unix id calculates as:
 *
 *   rid = reduced_rid + domain_range_index * range_size
 */

#include "idmap_autorid_tdb.h"
#include "winbindd.h"
#include "idmap.h"
#include "idmap_rw.h"
#include "../libcli/security/dom_sid.h"
#include "libsmb/samlogon_cache.h"
#include "passdb/machine_sid.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

#define IDMAP_AUTORID_ALLOC_RESERVED 500

/* handle to the tdb storing domain <-> range assignments */
static struct db_context *autorid_db;

static bool ignore_builtin = false;

static NTSTATUS idmap_autorid_get_alloc_range(struct idmap_domain *dom,
					struct autorid_range_config *range)
{
	NTSTATUS status;

	ZERO_STRUCT(*range);

	fstrcpy(range->domsid, ALLOC_RANGE);

	status = idmap_autorid_get_domainrange(autorid_db,
					       range,
					       dom->read_only);

	return status;
}

static NTSTATUS idmap_autorid_allocate_id(struct idmap_domain *dom,
					  struct unixid *xid) {

	NTSTATUS ret;
	struct autorid_range_config range;

	if (dom->read_only) {
		DEBUG(3, ("Backend is read-only, refusing "
			  "new allocation request\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* fetch the range for the allocation pool */

	ret = idmap_autorid_get_alloc_range(dom, &range);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(3, ("Could not determine range for allocation pool, "
			  "check previous messages for reason\n"));
		return ret;
	}

	ret = idmap_tdb_common_get_new_id(dom, xid);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1, ("Fatal error while allocating new ID!\n"));
		return ret;
	}

	xid->id = xid->id + range.low_id;

	DEBUG(10, ("Returned new %s %d from allocation range\n",
		   (xid->type==ID_TYPE_UID)?"uid":"gid", xid->id));

	return ret;
}

/*
 * map a xid to SID using the idmap_tdb like pool
 */
static NTSTATUS idmap_autorid_id_to_sid_alloc(struct idmap_domain *dom,
					      struct id_map *map)
{
	NTSTATUS ret;

	/* look out for the mapping */
	ret = idmap_tdb_common_unixid_to_sid(dom, map);

	if (NT_STATUS_IS_OK(ret)) {
		map->status = ID_MAPPED;
		return ret;
	}

	map->status = ID_UNKNOWN;

	DEBUG(10, ("no ID->SID mapping for %d could be found\n", map->xid.id));

	return ret;
}

static NTSTATUS idmap_autorid_id_to_sid(struct autorid_global_config *cfg,
					struct idmap_domain *dom,
					struct id_map *map)
{
	uint32_t range_number;
	uint32_t domain_range_index;
	uint32_t normalized_id;
	uint32_t reduced_rid;
	uint32_t rid;
	TDB_DATA data = tdb_null;
	char *keystr;
	struct dom_sid domsid;
	NTSTATUS status;
	bool ok;
	const char *q = NULL;

	/* can this be one of our ids? */
	if (map->xid.id < cfg->minvalue) {
		DEBUG(10, ("id %d is lower than minimum value, "
			   "ignoring mapping request\n", map->xid.id));
		map->status = ID_UNKNOWN;
		return NT_STATUS_OK;
	}

	if (map->xid.id > (cfg->minvalue + cfg->rangesize * cfg->maxranges)) {
		DEBUG(10, ("id %d is outside of maximum id value, "
			   "ignoring mapping request\n", map->xid.id));
		map->status = ID_UNKNOWN;
		return NT_STATUS_OK;
	}

	/* determine the range of this uid */

	normalized_id = map->xid.id - cfg->minvalue;
	range_number = normalized_id / cfg->rangesize;

	keystr = talloc_asprintf(talloc_tos(), "%u", range_number);
	if (!keystr) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dbwrap_fetch_bystring(autorid_db, talloc_tos(), keystr, &data);
	TALLOC_FREE(keystr);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(4, ("id %d belongs to range %d which does not have "
			  "domain mapping, ignoring mapping request\n",
			  map->xid.id, range_number));
		TALLOC_FREE(data.dptr);
		map->status = ID_UNKNOWN;
		return NT_STATUS_OK;
	}

	if ((data.dsize == 0) || (data.dptr[data.dsize-1] != '\0')) {
		DBG_WARNING("Invalid range %"PRIu32"\n", range_number);
		TALLOC_FREE(data.dptr);
		map->status = ID_UNKNOWN;
		return NT_STATUS_OK;
	}

	if (strncmp((const char *)data.dptr,
		    ALLOC_RANGE,
		    strlen(ALLOC_RANGE)) == 0) {
		/*
		 * this is from the alloc range, check if there is a mapping
		 */
		DEBUG(5, ("id %d belongs to allocation range, "
			  "checking for mapping\n",
			  map->xid.id));
		TALLOC_FREE(data.dptr);
		return idmap_autorid_id_to_sid_alloc(dom, map);
	}

	ok = dom_sid_parse_endp((const char *)data.dptr, &domsid, &q);
	if (!ok) {
		TALLOC_FREE(data.dptr);
		map->status = ID_UNKNOWN;
		return NT_STATUS_OK;
	}

	/*
	 * Allow for sid#range_index, just sid is range index 0
	 */

	switch (*q) {
	    case '\0':
		    domain_range_index = 0;
		    break;
	    case '#':
		    if (sscanf(q+1, "%"SCNu32, &domain_range_index) == 1) {
			    break;
		    }
		    /* If we end up here, something weird is in the record. */

		    FALL_THROUGH;
	    default:
		    DBG_DEBUG("SID/domain range: %s\n",
			      (const char *)data.dptr);
		    TALLOC_FREE(data.dptr);
		    map->status = ID_UNKNOWN;
		    return NT_STATUS_OK;
	}

	TALLOC_FREE(data.dptr);

	reduced_rid = normalized_id % cfg->rangesize;
	rid = reduced_rid + domain_range_index * cfg->rangesize;

	sid_compose(map->sid, &domsid, rid);

	/* We **really** should have some way of validating
	   the SID exists and is the correct type here.  But
	   that is a deficiency in the idmap_rid design. */

	map->status = ID_MAPPED;
	map->xid.type = ID_TYPE_BOTH;

	return NT_STATUS_OK;
}

/**********************************
 Single sid to id lookup function.
**********************************/

static NTSTATUS idmap_autorid_sid_to_id_rid(
					uint32_t rangesize,
					uint32_t low_id,
					struct id_map *map)
{
	uint32_t rid;
	uint32_t reduced_rid;

	sid_peek_rid(map->sid, &rid);

	reduced_rid = rid % rangesize;

	map->xid.id = reduced_rid + low_id;
	map->xid.type = ID_TYPE_BOTH;
	map->status = ID_MAPPED;

	return NT_STATUS_OK;
}

/**********************************
 lookup a set of unix ids.
**********************************/

static NTSTATUS idmap_autorid_unixids_to_sids(struct idmap_domain *dom,
					      struct id_map **ids)
{
	struct idmap_tdb_common_context *commoncfg;
	struct autorid_global_config *globalcfg;
	NTSTATUS ret;
	int i;
	int num_tomap = 0;
	int num_mapped = 0;

	/* initialize the status to avoid surprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
		num_tomap++;
	}

	commoncfg =
	    talloc_get_type_abort(dom->private_data,
				  struct idmap_tdb_common_context);

	globalcfg = talloc_get_type(commoncfg->private_data,
				    struct autorid_global_config);

	for (i = 0; ids[i]; i++) {

		ret = idmap_autorid_id_to_sid(globalcfg, dom, ids[i]);

		if ((!NT_STATUS_IS_OK(ret)) &&
		    (!NT_STATUS_EQUAL(ret, NT_STATUS_NONE_MAPPED))) {
			/* some fatal error occurred, log it */
			DBG_NOTICE("Unexpected error resolving an ID "
				   "(%d): %s\n", ids[i]->xid.id,
				   nt_errstr(ret));
			goto failure;
		}

		if (NT_STATUS_IS_OK(ret) && ids[i]->status == ID_MAPPED) {
			num_mapped++;
		}

	}

	if (num_tomap == num_mapped) {
		return NT_STATUS_OK;
	}
	if (num_mapped == 0) {
		return NT_STATUS_NONE_MAPPED;
	}

	return STATUS_SOME_UNMAPPED;


      failure:
	return ret;
}

static bool idmap_autorid_sid_is_special(struct dom_sid *sid)
{
	bool match;

	match = sid_check_is_in_wellknown_domain(sid);
	if (match) {
		return true;
	}

	return false;
}

static NTSTATUS idmap_autorid_sid_to_id_special(struct idmap_domain *dom,
						struct id_map *map)
{
	struct idmap_tdb_common_context *common =
		talloc_get_type_abort(dom->private_data,
				      struct idmap_tdb_common_context);
	uint32_t count;
	struct autorid_range_config range;
	NTSTATUS status;
	uint32_t free_id;

	status = idmap_autorid_get_alloc_range(dom, &range);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Take the next free ID, counting from the top */
	free_id = 0;
	for (count = 0; count < IDMAP_AUTORID_ALLOC_RESERVED; count++) {
		struct id_map test_map;
		struct dom_sid sid;

		test_map.sid = &sid;
		test_map.xid.type = map->xid.type;
		test_map.xid.id = range.high_id - count;
		test_map.status = ID_UNKNOWN;

		status = idmap_tdb_common_unixid_to_sid(dom, &test_map);
		if (NT_STATUS_EQUAL(NT_STATUS_NONE_MAPPED, status)) {
			free_id = test_map.xid.id;
			break;
		}

		if (!NT_STATUS_IS_OK(status)) {
			/* error - get out */
			return status;
		}

		/* mapping exists - try next ID */
	}

	if (free_id == 0) {
		return NT_STATUS_NONE_MAPPED;
	}

	map->status = ID_MAPPED;
	map->xid.id = free_id;

	status = common->rw_ops->set_mapping(dom, map);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("Error storing new mapping: %s\n",
			  nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

struct idmap_autorid_sid_to_id_alloc_ctx {
	struct idmap_domain *dom;
	struct id_map *map;
};

static NTSTATUS idmap_autorid_sid_to_id_alloc_action(
				struct db_context *db,
				void *private_data)
{
	struct idmap_autorid_sid_to_id_alloc_ctx *ctx;

	ctx = (struct idmap_autorid_sid_to_id_alloc_ctx *)private_data;

	if (idmap_autorid_sid_is_special(ctx->map->sid)) {
		struct dom_sid_buf buf;
		NTSTATUS ret;

		ret = idmap_autorid_sid_to_id_special(ctx->dom, ctx->map);
		if (NT_STATUS_IS_OK(ret)) {
			return NT_STATUS_OK;
		}
		if (!NT_STATUS_EQUAL(NT_STATUS_NONE_MAPPED, ret)) {
			return ret;
		}

		DEBUG(10, ("Special sid %s not mapped. falling back to "
			   "regular allocation\n",
			   dom_sid_str_buf(ctx->map->sid, &buf)));
	}

	return idmap_tdb_common_new_mapping(ctx->dom, ctx->map);
}

/*
 * map a SID to xid using the idmap_tdb like pool
 */
static NTSTATUS idmap_autorid_sid_to_id_alloc(
					struct idmap_tdb_common_context *ctx,
					struct idmap_domain *dom,
					struct id_map *map)
{
	NTSTATUS ret;
	struct idmap_autorid_sid_to_id_alloc_ctx alloc_ctx;
	struct dom_sid_buf buf;

	map->status = ID_UNKNOWN;

	/* see if we already have a mapping */
	ret = idmap_tdb_common_sid_to_unixid(dom, map);

	if (NT_STATUS_IS_OK(ret)) {
		map->status = ID_MAPPED;
		return ret;
	}

	/* bad things happened */
	if (!NT_STATUS_EQUAL(ret, NT_STATUS_NONE_MAPPED)) {
		DEBUG(1, ("Looking up SID->ID mapping for %s failed: %s\n",
			  dom_sid_str_buf(map->sid, &buf),
			  nt_errstr(ret)));
		return ret;
	}

	if (dom->read_only) {
		DEBUG(3, ("Not allocating new mapping for %s, because backend "
			  "is read-only\n",
			  dom_sid_str_buf(map->sid, &buf)));
		map->status = ID_UNMAPPED;
		return NT_STATUS_NONE_MAPPED;
	}

	DEBUG(10, ("Creating new mapping in pool for %s\n",
		   dom_sid_str_buf(map->sid, &buf)));

	alloc_ctx.dom = dom;
	alloc_ctx.map = map;

	ret = dbwrap_trans_do(ctx->db, idmap_autorid_sid_to_id_alloc_action,
			      &alloc_ctx);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(1, ("Failed to create a new mapping in alloc range: %s\n",
			  nt_errstr(ret)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	map->status = ID_MAPPED;
	return NT_STATUS_OK;
}

static bool idmap_autorid_domsid_is_for_alloc(struct dom_sid *sid)
{
	bool match;

	match = sid_check_is_wellknown_domain(sid, NULL);
	if (match) {
		return true;
	}

	return false;
}

static NTSTATUS idmap_autorid_sid_to_id(struct idmap_tdb_common_context *common,
					struct idmap_domain *dom,
					struct id_map *map)
{
	struct autorid_global_config *global =
		talloc_get_type_abort(common->private_data,
				      struct autorid_global_config);
	struct autorid_range_config range;
	uint32_t rid;
	struct dom_sid domainsid;
	struct dom_sid_buf buf;
	NTSTATUS ret;

	ZERO_STRUCT(range);
	map->status = ID_UNKNOWN;

	DEBUG(10, ("Trying to map %s\n", dom_sid_str_buf(map->sid, &buf)));

	sid_copy(&domainsid, map->sid);
	if (!sid_split_rid(&domainsid, &rid)) {
		DEBUG(4, ("Could not determine domain SID from %s, "
			  "ignoring mapping request\n",
			  dom_sid_str_buf(map->sid, &buf)));
		map->status = ID_UNMAPPED;
		return NT_STATUS_NONE_MAPPED;
	}

	if (idmap_autorid_domsid_is_for_alloc(&domainsid)) {
		DEBUG(10, ("SID %s is for ALLOC range.\n",
			   dom_sid_str_buf(map->sid, &buf)));

		return idmap_autorid_sid_to_id_alloc(common, dom, map);
	}

	if (dom_sid_equal(&domainsid, &global_sid_Builtin) && ignore_builtin) {
		DEBUG(10, ("Ignoring request for BUILTIN domain\n"));
		map->status = ID_UNMAPPED;
		return NT_STATUS_NONE_MAPPED;
	}

	sid_to_fstring(range.domsid, &domainsid);

	range.domain_range_index = rid / (global->rangesize);

	ret = idmap_autorid_getrange(autorid_db, range.domsid,
				     range.domain_range_index,
				     &range.rangenum, &range.low_id);
	if (NT_STATUS_IS_OK(ret)) {
		return idmap_autorid_sid_to_id_rid(
			global->rangesize, range.low_id, map);
	}

	if (dom->read_only) {
		DBG_DEBUG("read-only is enabled, did not allocate "
			  "new range for domain %s\n", range.domsid);
		map->status = ID_UNMAPPED;
		return NT_STATUS_NONE_MAPPED;
	}

	/*
	 * Check if we should allocate a domain range. We need to
	 * protect against unknown domains to not fill our ranges
	 * needlessly.
	 */

	if (sid_check_is_builtin(&domainsid) ||
	    sid_check_is_our_sam(&domainsid)) {
		goto allocate;
	}

	{
		struct winbindd_domain *domain;

		/*
		 * Deterministic check for domain members: We can be
		 * sure that the domain we are member of is worth to
		 * add a mapping for.
		 */

		domain = find_our_domain();
		if ((domain != NULL) &&
		    dom_sid_equal(&domain->sid, &domainsid)) {
			goto allocate;
		}
	}

	/*
	 * If we have already allocated range index 0, this domain is
	 * worth allocating for in higher ranges.
	 */
	if (range.domain_range_index != 0) {
		uint32_t zero_rangenum, zero_low_id;

		ret = idmap_autorid_getrange(autorid_db, range.domsid, 0,
					     &zero_rangenum, &zero_low_id);
		if (NT_STATUS_IS_OK(ret)) {
			goto allocate;
		}
	}

	/*
	 * If the caller already did a lookup sid and made sure the
	 * domain sid is valid, we can allocate a new range.
	 *
	 * Currently the winbindd parent already does a lookup sids
	 * first, but hopefully changes in future. If the
	 * caller knows the domain sid, ID_TYPE_BOTH should be
	 * passed instead of ID_TYPE_NOT_SPECIFIED.
	 */
	if (map->xid.type != ID_TYPE_NOT_SPECIFIED) {
		goto allocate;
	}

	/*
	 * Check of last resort: A domain is valid if a user from that
	 * domain has recently logged in. The samlogon_cache these
	 * days also stores the domain sid.
	 *
	 * We used to check the list of trusted domains we received
	 * from "our" dc, but this is not reliable enough.
	 */
	if (netsamlogon_cache_have(&domainsid)) {
		goto allocate;
	}

	/*
	 * Nobody knows this domain, so refuse to allocate a fresh
	 * range.
	 */

	DBG_NOTICE("Allocating range for domain %s refused\n", range.domsid);
	map->status = ID_UNMAPPED;
	return NT_STATUS_NONE_MAPPED;

allocate:
	ret = idmap_autorid_acquire_range(autorid_db, &range);
	if (!NT_STATUS_IS_OK(ret)) {
		DBG_NOTICE("Could not determine range for domain: %s, "
			   "check previous messages for reason\n",
			   nt_errstr(ret));
		return ret;
	}

	return idmap_autorid_sid_to_id_rid(global->rangesize, range.low_id,
					   map);
}

/**********************************
 lookup a set of sids.
**********************************/

static NTSTATUS idmap_autorid_sids_to_unixids(struct idmap_domain *dom,
					      struct id_map **ids)
{
	struct idmap_tdb_common_context *commoncfg;
	NTSTATUS ret;
	int i;
	int num_tomap = 0;
	int num_mapped = 0;

	/* initialize the status to avoid surprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
		num_tomap++;
	}

	commoncfg =
	    talloc_get_type_abort(dom->private_data,
				  struct idmap_tdb_common_context);

	for (i = 0; ids[i]; i++) {
		ret = idmap_autorid_sid_to_id(commoncfg, dom, ids[i]);
		if ((!NT_STATUS_IS_OK(ret)) &&
		    (!NT_STATUS_EQUAL(ret, NT_STATUS_NONE_MAPPED))) {
			struct dom_sid_buf buf;
			/* some fatal error occurred, log it */
			DEBUG(3, ("Unexpected error resolving a SID (%s)\n",
				  dom_sid_str_buf(ids[i]->sid, &buf)));
			return ret;
		}

		if (NT_STATUS_IS_OK(ret) && ids[i]->status == ID_MAPPED) {
			num_mapped++;
		}
	}

	if (num_tomap == num_mapped) {
		return NT_STATUS_OK;
	} else if (num_mapped == 0) {
		return NT_STATUS_NONE_MAPPED;
	}

	return STATUS_SOME_UNMAPPED;
}

static NTSTATUS idmap_autorid_preallocate_wellknown(struct idmap_domain *dom)
{
	const char *groups[] = { "S-1-1-0", "S-1-2-0", "S-1-2-1",
		"S-1-3-0", "S-1-3-1", "S-1-3-2", "S-1-3-3", "S-1-3-4",
		"S-1-5-1", "S-1-5-2", "S-1-5-3", "S-1-5-4", "S-1-5-6",
		"S-1-5-7", "S-1-5-8", "S-1-5-9", "S-1-5-10", "S-1-5-11",
		"S-1-5-12", "S-1-5-13", "S-1-5-14", "S-1-5-15",
		"S-1-5-17", "S-1-5-18", "S-1-5-19", "S-1-5-20"
	};

	struct id_map **maps;
	int i, num;
	NTSTATUS status;

	if (dom->read_only) {
		return NT_STATUS_OK;
	}

	num = ARRAY_SIZE(groups);

	maps = talloc_array(talloc_tos(), struct id_map*, num+1);
	if (!maps) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num; i++) {
		maps[i] = talloc(maps, struct id_map);
		if (maps[i] == NULL) {
			talloc_free(maps);
			return NT_STATUS_NO_MEMORY;
		}
		maps[i]->xid.type = ID_TYPE_GID;
		maps[i]->sid = dom_sid_parse_talloc(maps, groups[i]);
	}

	maps[num] = NULL;

	status = idmap_autorid_sids_to_unixids(dom, maps);

	DEBUG(10,("Preallocation run finished with status %s\n",
		  nt_errstr(status)));

	talloc_free(maps);

	return NT_STATUS_IS_OK(status)?NT_STATUS_OK:NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS idmap_autorid_initialize_action(struct db_context *db,
						void *private_data)
{
	struct idmap_domain *dom;
	struct idmap_tdb_common_context *common;
	struct autorid_global_config *config;
	NTSTATUS status;

	dom = (struct idmap_domain *)private_data;
	common = (struct idmap_tdb_common_context *)dom->private_data;
	config = (struct autorid_global_config *)common->private_data;

	status = idmap_autorid_init_hwms(db);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = idmap_autorid_saveconfig(db, config);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to store configuration data!\n"));
		return status;
	}

	status = idmap_autorid_preallocate_wellknown(dom);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to preallocate wellknown sids: %s\n",
			  nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS idmap_autorid_initialize(struct idmap_domain *dom)
{
	struct idmap_tdb_common_context *commonconfig;
	struct autorid_global_config *config;
	NTSTATUS status;
	char *db_path;

	if (!strequal(dom->name, "*")) {
		DEBUG(0, ("idmap_autorid_initialize: Error: autorid configured "
			  "for domain '%s'. But autorid can only be used for "
			  "the default idmap configuration.\n", dom->name));
		return NT_STATUS_INVALID_PARAMETER;
	}

	commonconfig = talloc_zero(dom, struct idmap_tdb_common_context);
	if (!commonconfig) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}
	dom->private_data = commonconfig;

	commonconfig->rw_ops = talloc_zero(commonconfig, struct idmap_rw_ops);
	if (commonconfig->rw_ops == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	config = talloc_zero(commonconfig, struct autorid_global_config);
	if (!config) {
		DEBUG(0, ("Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}
	commonconfig->private_data = config;

	config->minvalue = dom->low_id;
	config->rangesize = idmap_config_int("*", "rangesize", 100000);

	config->maxranges = (dom->high_id - dom->low_id + 1) /
	    config->rangesize;

	if (config->maxranges == 0) {
		DEBUG(1, ("Allowed uid range is smaller than rangesize. "
			  "Increase uid range or decrease rangesize.\n"));
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	/* check if the high-low limit is a multiple of the rangesize */
	if ((dom->high_id - dom->low_id + 1) % config->rangesize != 0) {
		DEBUG(5, ("High uid-low uid difference of %d "
			  "is not a multiple of the rangesize %d, "
			  "limiting ranges to lower boundary number of %d\n",
			  (dom->high_id - dom->low_id + 1), config->rangesize,
			  config->maxranges));
	}

	DEBUG(5, ("%d domain ranges with a size of %d are available\n",
		  config->maxranges, config->rangesize));

	ignore_builtin = idmap_config_bool("*", "ignore builtin", false);

	/* fill the TDB common configuration */

	commonconfig->max_id = config->rangesize - 1
			     - IDMAP_AUTORID_ALLOC_RESERVED;
	commonconfig->hwmkey_uid = ALLOC_HWM_UID;
	commonconfig->hwmkey_gid = ALLOC_HWM_GID;
	commonconfig->rw_ops->get_new_id = idmap_autorid_allocate_id;
	commonconfig->rw_ops->set_mapping = idmap_tdb_common_set_mapping;

	db_path = state_path(talloc_tos(), "autorid.tdb");
	if (db_path == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto error;
	}

	status = idmap_autorid_db_open(db_path,
				       NULL, /* TALLOC_CTX */
				       &autorid_db);
	TALLOC_FREE(db_path);
	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}

	commonconfig->db = autorid_db;

	status = dbwrap_trans_do(autorid_db,
				 idmap_autorid_initialize_action,
				 dom);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to init the idmap database: %s\n",
			  nt_errstr(status)));
		goto error;
	}

	goto done;

error:
	talloc_free(config);

done:
	return status;
}

static const struct idmap_methods autorid_methods = {
	.init = idmap_autorid_initialize,
	.unixids_to_sids = idmap_autorid_unixids_to_sids,
	.sids_to_unixids = idmap_autorid_sids_to_unixids,
	.allocate_id	 = idmap_autorid_allocate_id
};

static_decl_idmap;
NTSTATUS idmap_autorid_init(TALLOC_CTX *ctx)
{
	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION,
				  "autorid", &autorid_methods);
}
