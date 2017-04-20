/*
   Unix SMB/CIFS implementation.

   common sid helper functions

   Copyright (C) Catalyst.NET Ltd 2017

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
#include "rpc_server/dcerpc_server.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "source4/dsdb/samdb/samdb.h"
#include "rpc_server/common/sid_helper.h"
#include "libcli/security/security.h"

/*
  see if any SIDs in list1 are in list2
 */
bool sid_list_match(const struct dom_sid **list1, const struct dom_sid **list2)
{
	unsigned int i, j;
	/* do we ever have enough SIDs here to worry about O(n^2) ? */
	for (i=0; list1[i]; i++) {
		for (j=0; list2[j]; j++) {
			if (dom_sid_equal(list1[i], list2[j])) {
				return true;
			}
		}
	}
	return false;
}

/*
 * Return an array of SIDs from a ldb_message given an attribute name assumes
 * the SIDs are in NDR form (with additional sids applied on the end).
 */
WERROR samdb_result_sid_array_ndr(struct ldb_context *sam_ctx,
				  struct ldb_message *msg,
				  TALLOC_CTX *mem_ctx,
				  const char *attr,
					 const struct dom_sid ***sids,
					 const struct dom_sid **additional_sids,
					 unsigned int num_additional)
{
	struct ldb_message_element *el;
	unsigned int i, j;

	el = ldb_msg_find_element(msg, attr);
	if (!el) {
		*sids = NULL;
		return WERR_OK;
	}

	/* Make array long enough for NULL and additional SID */
	(*sids) = talloc_array(mem_ctx, const struct dom_sid *,
			       el->num_values + num_additional + 1);
	W_ERROR_HAVE_NO_MEMORY(*sids);

	for (i=0; i<el->num_values; i++) {
		enum ndr_err_code ndr_err;
		struct dom_sid *sid;

		sid = talloc(*sids, struct dom_sid);
		W_ERROR_HAVE_NO_MEMORY(sid);

		ndr_err = ndr_pull_struct_blob(&el->values[i], sid, sid,
					       (ndr_pull_flags_fn_t)ndr_pull_dom_sid);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return WERR_INTERNAL_DB_CORRUPTION;
		}
		(*sids)[i] = sid;
	}

	for (j = 0; j < num_additional; j++) {
		(*sids)[i++] = additional_sids[j];
	}

	(*sids)[i] = NULL;

	return WERR_OK;
}

/*
  return an array of SIDs from a ldb_message given an attribute name
  assumes the SIDs are in extended DN format
 */
WERROR samdb_result_sid_array_dn(struct ldb_context *sam_ctx,
				 struct ldb_message *msg,
				 TALLOC_CTX *mem_ctx,
				 const char *attr,
				 const struct dom_sid ***sids)
{
	struct ldb_message_element *el;
	unsigned int i;

	el = ldb_msg_find_element(msg, attr);
	if (!el) {
		*sids = NULL;
		return WERR_OK;
	}

	(*sids) = talloc_array(mem_ctx, const struct dom_sid *, el->num_values + 1);
	W_ERROR_HAVE_NO_MEMORY(*sids);

	for (i=0; i<el->num_values; i++) {
		struct ldb_dn *dn = ldb_dn_from_ldb_val(mem_ctx, sam_ctx, &el->values[i]);
		NTSTATUS status;
		struct dom_sid *sid;

		sid = talloc(*sids, struct dom_sid);
		W_ERROR_HAVE_NO_MEMORY(sid);
		status = dsdb_get_extended_dn_sid(dn, sid, "SID");
		if (!NT_STATUS_IS_OK(status)) {
			return WERR_INTERNAL_DB_CORRUPTION;
		}
		(*sids)[i] = sid;
	}
	(*sids)[i] = NULL;

	return WERR_OK;
}
