/*
   Unix SMB/CIFS implementation.

   Helpers to search for links in the DB

   Copyright (C) Catalyst.Net Ltd 2017

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
#include "dsdb/samdb/samdb.h"
#include "lib/util/binsearch.h"
#include "librpc/gen_ndr/ndr_misc.h"

/*
 * We choose, as the sort order, the same order as is used in DRS replication,
 * which is the memcmp() order of the NDR GUID, not that obtained from
 * GUID_compare().
 *
 * This means that sorted links will be in the same order as a new DC would
 * see them.
 */
int ndr_guid_compare(const struct GUID *guid1, const struct GUID *guid2)
{
	uint8_t v1_data[16];
	struct ldb_val v1 = data_blob_const(v1_data, sizeof(v1_data));
	uint8_t v2_data[16];
	struct ldb_val v2 = data_blob_const(v2_data, sizeof(v2_data));

	/* This can't fail */
	ndr_push_struct_into_fixed_blob(&v1, guid1,
					(ndr_push_flags_fn_t)ndr_push_GUID);
	/* This can't fail */
	ndr_push_struct_into_fixed_blob(&v2, guid2,
					(ndr_push_flags_fn_t)ndr_push_GUID);
	return data_blob_cmp(&v1, &v2);
}


static int la_guid_compare_with_trusted_dn(struct compare_ctx *ctx,
					   struct parsed_dn *p)
{
	int cmp = 0;
	/*
	 * This works like a standard compare function in its return values,
	 * but has an extra trick to deal with errors: zero is returned and
	 * ctx->err is set to the ldb error code.
	 *
	 * That is, if (as is expected in most cases) you get a non-zero
	 * result, you don't need to check for errors.
	 *
	 * We assume the second argument refers to a DN is from the database
	 * and has a GUID -- but this GUID might not have been parsed out yet.
	 */
	if (p->dsdb_dn == NULL) {
		int ret = really_parse_trusted_dn(ctx->mem_ctx, ctx->ldb, p,
						  ctx->ldap_oid);
		if (ret != LDB_SUCCESS) {
			ctx->err = ret;
			return 0;
		}
	}
	cmp = ndr_guid_compare(ctx->guid, &p->guid);
	if (cmp == 0 && ctx->compare_extra_part) {
		if (ctx->partial_extra_part_length != 0) {
			/* Allow a prefix match on the blob. */
			return memcmp(ctx->extra_part.data,
				      p->dsdb_dn->extra_part.data,
				      MIN(ctx->partial_extra_part_length,
					  p->dsdb_dn->extra_part.length));
		} else {
			return data_blob_cmp(&ctx->extra_part,
					     &p->dsdb_dn->extra_part);
		}
	}

	return cmp;
}

/* When a parsed_dn comes from the database, sometimes it is not really parsed. */

int really_parse_trusted_dn(TALLOC_CTX *mem_ctx, struct ldb_context *ldb,
				   struct parsed_dn *pdn, const char *ldap_oid)
{
	NTSTATUS status;
	struct dsdb_dn *dsdb_dn = dsdb_dn_parse_trusted(mem_ctx, ldb, pdn->v,
							ldap_oid);
	if (dsdb_dn == NULL) {
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	status = dsdb_get_extended_dn_guid(dsdb_dn->dn, &pdn->guid, "GUID");
	if (!NT_STATUS_IS_OK(status)) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	pdn->dsdb_dn = dsdb_dn;
	return LDB_SUCCESS;
}


int get_parsed_dns_trusted(TALLOC_CTX *mem_ctx, struct ldb_message_element *el,
				  struct parsed_dn **pdn)
{
	/* Here we get a list of 'struct parsed_dns' without the parsing */
	unsigned int i;
	*pdn = talloc_zero_array(mem_ctx, struct parsed_dn,
				 el->num_values);
	if (!*pdn) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	for (i = 0; i < el->num_values; i++) {
		(*pdn)[i].v = &el->values[i];
	}

	return LDB_SUCCESS;
}


int parsed_dn_find(struct ldb_context *ldb, struct parsed_dn *pdn,
		   unsigned int count,
		   const struct GUID *guid,
		   struct ldb_dn *target_dn,
		   DATA_BLOB extra_part,
		   size_t partial_extra_part_length,
		   struct parsed_dn **exact,
		   struct parsed_dn **next,
		   const char *ldap_oid,
		   bool compare_extra_part)
{
	unsigned int i;
	struct compare_ctx ctx;
	if (pdn == NULL) {
		*exact = NULL;
		*next = NULL;
		return LDB_SUCCESS;
	}

	if (unlikely(GUID_all_zero(guid))) {
		/*
		 * When updating a link using DRS, we sometimes get a NULL
		 * GUID when a forward link has been deleted and its GUID has
		 * for some reason been forgotten. The best we can do is try
		 * and match by DN via a linear search. Note that this
		 * probably only happens in the ADD case, in which we only
		 * allow modification of link if it is already deleted, so
		 * this seems very close to an elaborate NO-OP, but we are not
		 * quite prepared to declare it so.
		 *
		 * If the DN is not in our list, we have to add it to the
		 * beginning of the list, where it would naturally sort.
		 */
		struct parsed_dn *p;
		if (target_dn == NULL) {
			/* We don't know the target DN, so we can't search for DN */
			DEBUG(1, ("parsed_dn_find has a NULL GUID for a linked "
				  "attribute but we don't have a DN to compare "
				  "it with\n"));
			return LDB_ERR_OPERATIONS_ERROR;
		}
		*exact = NULL;
		*next = NULL;

		DEBUG(3, ("parsed_dn_find has a NULL GUID for a link to DN "
			  "%s; searching through links for it",
			  ldb_dn_get_linearized(target_dn)));

		for (i = 0; i < count; i++) {
			int cmp;
			p = &pdn[i];
			if (p->dsdb_dn == NULL) {
				int ret = really_parse_trusted_dn(pdn, ldb, p, ldap_oid);
				if (ret != LDB_SUCCESS) {
					return LDB_ERR_OPERATIONS_ERROR;
				}
			}

			cmp = ldb_dn_compare(p->dsdb_dn->dn, target_dn);
			if (cmp == 0) {
				*exact = p;
				return LDB_SUCCESS;
			}
		}
		/*
		 * Here we have a null guid which doesn't match any existing
		 * link. This is a bit unexpected because null guids occur
		 * when a forward link has been deleted and we are replicating
		 * that deletion.
		 *
		 * The best thing to do is weep into the logs and add the
		 * offending link to the beginning of the list which is
		 * at least the correct sort position.
		 */
		DEBUG(1, ("parsed_dn_find has been given a NULL GUID for a "
			  "link to unknown DN %s\n",
			  ldb_dn_get_linearized(target_dn)));
		*next = pdn;
		return LDB_SUCCESS;
	}

	ctx.guid = guid;
	ctx.ldb = ldb;
	ctx.mem_ctx = pdn;
	ctx.ldap_oid = ldap_oid;
	ctx.extra_part = extra_part;
	ctx.partial_extra_part_length = partial_extra_part_length;
	ctx.compare_extra_part = compare_extra_part;
	ctx.err = 0;

	BINARY_ARRAY_SEARCH_GTE(pdn, count, &ctx, la_guid_compare_with_trusted_dn,
				*exact, *next);

	if (ctx.err != 0) {
		return ctx.err;
	}
	return LDB_SUCCESS;
}
