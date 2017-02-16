/*
   Unix SMB/CIFS implementation.

   handle removal of deleted objects

   Copyright (C) 2009 Andrew Tridgell
   Copyright (C) 2016 Andrew Bartlett
   Copyright (C) 2016 Catalyst.NET Ltd

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

#include "includes.h"
#include <ldb_errors.h>
#include "../lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"
#include "lib/util/dlinklist.h"
#include "ldb.h"
#include "dsdb/kcc/garbage_collect_tombstones.h"
#include "lib/ldb-samba/ldb_matching_rules.h"
#include "lib/util/time.h"

static NTSTATUS garbage_collect_tombstones_part(TALLOC_CTX *mem_ctx,
						struct ldb_context *samdb,
						struct dsdb_ldb_dn_list_node *part,
						char *filter,
						unsigned int *num_links_removed,
						unsigned int *num_objects_removed,
						struct dsdb_schema *schema,
						const char **attrs,
						char **error_string,
						NTTIME expunge_time_nttime)
{
	int ret;
	struct ldb_dn *do_dn;
	struct ldb_result *res;
	unsigned int i, j, k;
	uint32_t flags;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = dsdb_get_deleted_objects_dn(samdb, tmp_ctx, part->dn, &do_dn);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(tmp_ctx);
		/* some partitions have no Deleted Objects
		   container */
		return NT_STATUS_OK;
	}

	DEBUG(1, ("Doing a full scan on %s and looking for deleted objects\n",
		  ldb_dn_get_linearized(part->dn)));

	flags = DSDB_SEARCH_SHOW_RECYCLED |
		DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT |
		DSDB_SEARCH_REVEAL_INTERNALS;
	ret = dsdb_search(samdb, tmp_ctx, &res, part->dn, LDB_SCOPE_SUBTREE,
			  attrs, flags, "%s", filter);

	if (ret != LDB_SUCCESS) {
		*error_string = talloc_asprintf(mem_ctx,
						"Failed to search for deleted "
						"objects in %s: %s",
						ldb_dn_get_linearized(do_dn),
						ldb_errstring(samdb));
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	for (i=0; i<res->count; i++) {
		struct ldb_message *cleanup_msg = NULL;
		unsigned int num_modified = 0;

		bool isDeleted = ldb_msg_find_attr_as_bool(res->msgs[i],
							   "isDeleted", false);
		if (isDeleted) {
			if (ldb_dn_compare(do_dn, res->msgs[i]->dn) == 0) {
				/* Skip the Deleted Object Container */
				continue;
			}

			ret = dsdb_delete(samdb, res->msgs[i]->dn,
					  DSDB_SEARCH_SHOW_RECYCLED
					  |DSDB_MODIFY_RELAX);
			if (ret != LDB_SUCCESS) {
				DEBUG(1,(__location__ ": Failed to remove "
					 "deleted object %s\n",
					 ldb_dn_get_linearized(res->
							       msgs[i]->dn)));
			} else {
				DEBUG(4,("Removed deleted object %s\n",
					 ldb_dn_get_linearized(res->
							       msgs[i]->dn)));
				(*num_objects_removed)++;
			}
			continue;
		}

		/* This must have a linked attribute */

		/*
		 * From MS-ADTS 3.1.1.1.9 DCs, usn Counters, and
		 * the Originating Update Stamp
		 *
		 * "A link value r is deleted, but exists as a
		 *  tombstone, if r.stamp.timeDeleted ≠ 0. When
		 *  the current time minus r.stamp.timeDeleted
		 *  exceeds the tombstone lifetime, the link
		 *  value r is garbage-collected; that is,
		 *  removed from its containing forward link
		 *  attribute. "
		 */

		for (j=0; j < res->msgs[i]->num_elements; j++) {
			struct ldb_message_element *element = NULL;
			/* TODO this is O(log n) per attribute with deleted values */
			const struct dsdb_attribute *attrib = NULL;

			element = &res->msgs[i]->elements[j];
			attrib = dsdb_attribute_by_lDAPDisplayName(schema,
								   element->name);

			/* This avoids parsing isDeleted as a link */
			if (attrib == NULL ||
			    attrib->linkID == 0 ||
			    ((attrib->linkID & 1) == 1)) {
				continue;
			}

			for (k = 0; k < element->num_values; k++) {
				struct ldb_val *value = &element->values[k];
				uint64_t whenChanged = 0;
				NTSTATUS status;
				struct dsdb_dn *dn;
				struct ldb_message_element *cleanup_elem = NULL;
				char *guid_search_str = NULL;
				char *guid_buf_str = NULL;
				struct ldb_val cleanup_val;
				struct GUID_txt_buf buf_guid;
				struct GUID guid;
				const struct ldb_val *guid_blob;

				if (dsdb_dn_is_deleted_val(value) == false) {
					continue;
				}

				dn = dsdb_dn_parse(tmp_ctx, samdb,
						   &element->values[k],
						   attrib->syntax->ldap_oid);
				if (dn == NULL) {
					DEBUG(1, ("Failed to parse linked attribute blob of "
						  "%s on %s while expunging expired links\n",
						  element->name,
						  ldb_dn_get_linearized(res->msgs[i]->dn)));
					continue;
				}

				status = dsdb_get_extended_dn_uint64(dn->dn,
								     &whenChanged,
								     "RMD_CHANGETIME");
				if (!NT_STATUS_IS_OK(status)) {
					DEBUG(1, ("Error: RMD_CHANGETIME is missing on a forward link.\n"));
					talloc_free(dn);
					continue;
				}

				if (whenChanged >= expunge_time_nttime) {
					talloc_free(dn);
					continue;
				}

				guid_blob = ldb_dn_get_extended_component(dn->dn, "GUID");
				status = GUID_from_ndr_blob(guid_blob, &guid);
				if (!NT_STATUS_IS_OK(status)) {
					DEBUG(1, ("Error: Invalid GUID on link target.\n"));
					talloc_free(dn);
					continue;
				}

				guid_buf_str = GUID_buf_string(&guid, &buf_guid);
				guid_search_str = talloc_asprintf(mem_ctx,
								  "<GUID=%s>;%s",
								  guid_buf_str,
								  dsdb_dn_get_linearized(mem_ctx, dn));
				cleanup_val = data_blob_string_const(guid_search_str);

				talloc_free(dn);

				if (cleanup_msg == NULL) {
					cleanup_msg = ldb_msg_new(mem_ctx);
					if (cleanup_msg == NULL) {
						return NT_STATUS_NO_MEMORY;
					}
					cleanup_msg->dn = res->msgs[i]->dn;
				}

				ret = ldb_msg_add_value(cleanup_msg,
							element->name,
							&cleanup_val,
							&cleanup_elem);
				if (ret != LDB_SUCCESS) {
					return NT_STATUS_NO_MEMORY;
				}
				cleanup_elem->flags = LDB_FLAG_MOD_DELETE;
				num_modified++;
			}
		}

		if (num_modified > 0) {
			ret = dsdb_modify(samdb, cleanup_msg,
					  DSDB_REPLMD_VANISH_LINKS);
			if (ret != LDB_SUCCESS) {
				DEBUG(1,(__location__ ": Failed to remove deleted object %s\n",
					 ldb_dn_get_linearized(res->msgs[i]->dn)));
			} else {
				DEBUG(4,("Removed deleted object %s\n",
					 ldb_dn_get_linearized(res->msgs[i]->dn)));
				*num_links_removed = *num_links_removed + num_modified;
			}

		}
	}

	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}

/*
 * Per MS-ADTS 3.1.1.5.5 Delete Operation
 *
 * "Tombstones are a type of deleted object distinguished from
 *  existing-objects by the presence of the isDeleted attribute with the
 *  value true."
 *
 * "After a time period at least as large as a tombstone lifetime, the
 *  tombstone is removed from the directory."
 *
 * The purpose of this routine is to remove such objects.  It is
 * called from a timed event in the KCC, and from samba-tool domain
 * expunge tombstones.
 *
 * Additionally, linked attributes have similar properties.
 */
NTSTATUS dsdb_garbage_collect_tombstones(TALLOC_CTX *mem_ctx,
					 struct ldb_context *samdb,
					 struct dsdb_ldb_dn_list_node *part,
					 time_t current_time,
					 uint32_t tombstoneLifetime,
					 unsigned int *num_objects_removed,
					 unsigned int *num_links_removed,
					 char **error_string)
{
	const char **attrs = NULL;
	char *filter = NULL;
	NTSTATUS status;
	unsigned int i;
	struct dsdb_attribute *next_attr;
	unsigned int num_link_attrs;
	struct dsdb_schema *schema = dsdb_get_schema(samdb, mem_ctx);
	unsigned long long expunge_time = current_time - tombstoneLifetime*60*60*24;
	char *expunge_time_string = ldb_timestring_utc(mem_ctx, expunge_time);
	NTTIME expunge_time_nttime;
	unix_to_nt_time(&expunge_time_nttime, expunge_time);

	*num_objects_removed = 0;
	*num_links_removed = 0;
	*error_string = NULL;
	num_link_attrs = 0;

	/*
	 * This filter is a bit strange, but the idea is to filter for
	 * objects that need to have tombstones expunged without
	 * bringing a potentially large databse all into memory.  To
	 * do that, we could use callbacks, but instead we use a
	 * custom match rule to triage the objects during the search,
	 * and ideally avoid memory allocation for most of the
	 * un-matched objects.
	 *
	 * The parameter to DSDB_MATCH_FOR_EXPUNGE is the NTTIME, we
	 * return records with deleted links deleted before this time.
	 *
	 * We use a date comparison on whenChanged to avoid returning
	 * all isDeleted records
	 */

	filter = talloc_asprintf(mem_ctx, "(|");
	for (next_attr = schema->attributes; next_attr != NULL; next_attr = next_attr->next) {
		if (next_attr->linkID != 0 && ((next_attr->linkID & 1) == 0)) {
			num_link_attrs++;
			filter = talloc_asprintf_append(filter,
							"(%s:" DSDB_MATCH_FOR_EXPUNGE ":=%llu)",
							next_attr->lDAPDisplayName,
							(unsigned long long)expunge_time_nttime);
			if (filter == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		}
	}

	attrs = talloc_array(mem_ctx, const char *, num_link_attrs + 2);
	i = 0;
	for (next_attr = schema->attributes; next_attr != NULL; next_attr = next_attr->next) {
		if (next_attr->linkID != 0 && ((next_attr->linkID & 1) == 0)) {
			attrs[i++] = next_attr->lDAPDisplayName;
		}
	}
	attrs[i] = "isDeleted";
	attrs[i+1] = NULL;

	filter = talloc_asprintf_append(filter,
					"(&(isDeleted=TRUE)(whenChanged<=%s)))",
					expunge_time_string);
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (; part != NULL; part = part->next) {
		status = garbage_collect_tombstones_part(mem_ctx, samdb, part,
							 filter,
							 num_links_removed,
							 num_objects_removed,
							 schema, attrs,
							 error_string,
							 expunge_time_nttime);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}
