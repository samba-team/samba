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
#include "libcli/security/security.h"

/*
  see if any SIDs in list1 are in list2
 */
bool sid_list_match(uint32_t num_sids1,
		    const struct dom_sid *list1,
		    uint32_t num_sids2,
		    const struct dom_sid *list2)
{
	unsigned int i, j;
	/* do we ever have enough SIDs here to worry about O(n^2) ? */
	for (i=0; i < num_sids1; i++) {
		for (j=0; j < num_sids2; j++) {
			if (dom_sid_equal(&list1[i], &list2[j])) {
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
				  uint32_t *num_sids,
				  struct dom_sid **sids,
				  const struct dom_sid *additional_sids,
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
	(*sids) = talloc_array(mem_ctx, struct dom_sid,
			       el->num_values + num_additional);
	W_ERROR_HAVE_NO_MEMORY(*sids);

	for (i=0; i<el->num_values; i++) {
		enum ndr_err_code ndr_err;

		ndr_err = ndr_pull_struct_blob_all_noalloc(&el->values[i], &(*sids)[i],
					       (ndr_pull_flags_fn_t)ndr_pull_dom_sid);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return WERR_INTERNAL_DB_CORRUPTION;
		}
	}

	for (j = 0; j < num_additional; j++) {
		(*sids)[i++] = additional_sids[j];
	}

	*num_sids = i;

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
				 uint32_t *num_sids,
				 struct dom_sid **sids)
{
	struct ldb_message_element *el;
	unsigned int i;

	el = ldb_msg_find_element(msg, attr);
	if (!el) {
		*sids = NULL;
		return WERR_OK;
	}

	(*sids) = talloc_array(mem_ctx, struct dom_sid, el->num_values + 1);
	W_ERROR_HAVE_NO_MEMORY(*sids);

	for (i=0; i<el->num_values; i++) {
		struct ldb_dn *dn = ldb_dn_from_ldb_val(mem_ctx, sam_ctx, &el->values[i]);
		NTSTATUS status;
		struct dom_sid sid = { 0, };

		status = dsdb_get_extended_dn_sid(dn, &sid, "SID");
		if (!NT_STATUS_IS_OK(status)) {
			return WERR_INTERNAL_DB_CORRUPTION;
		}
		(*sids)[i] = sid;
	}
	*num_sids = i;

	return WERR_OK;
}

WERROR samdb_confirm_rodc_allowed_to_repl_to_sid_list(struct ldb_context *sam_ctx,
						      struct ldb_message *rodc_msg,
						      struct ldb_message *obj_msg,
						      uint32_t num_token_sids,
						      struct dom_sid *token_sids)
{
	uint32_t num_never_reveal_sids, num_reveal_sids;
	struct dom_sid *never_reveal_sids, *reveal_sids;
	TALLOC_CTX *frame = talloc_stackframe();
	WERROR werr;
	uint32_t rodc_uac;
	
	/*
	 * We are not allowed to get anyone elses krbtgt secrets (and
	 * in callers that don't shortcut before this, the RODC should
	 * not deal with any krbtgt)
	 */
	if (samdb_result_dn(sam_ctx, frame,
			    obj_msg, "msDS-KrbTgtLinkBL", NULL)) {
		TALLOC_FREE(frame);
		DBG_INFO("Denied attempt to replicate to/act as a RODC krbtgt trust account %s using RODC: %s\n",
			 ldb_dn_get_linearized(obj_msg->dn),
			 ldb_dn_get_linearized(rodc_msg->dn));
		return WERR_DS_DRA_SECRETS_DENIED;
	}

	if (ldb_msg_find_attr_as_uint(obj_msg,
				      "userAccountControl", 0) &
	    UF_INTERDOMAIN_TRUST_ACCOUNT) {
		DBG_INFO("Denied attempt to replicate to/act as a inter-domain trust account %s using RODC: %s\n",
			 ldb_dn_get_linearized(obj_msg->dn),
			 ldb_dn_get_linearized(rodc_msg->dn));
		TALLOC_FREE(frame);
		return WERR_DS_DRA_SECRETS_DENIED;
	}

	/* Be very sure the RODC is really an RODC */
	rodc_uac = ldb_msg_find_attr_as_uint(rodc_msg,
					     "userAccountControl",
					     0);
	if ((rodc_uac & UF_PARTIAL_SECRETS_ACCOUNT)
	    != UF_PARTIAL_SECRETS_ACCOUNT) {
		DBG_ERR("Attempt to use an RODC account that is not an RODC: %s\n",
			ldb_dn_get_linearized(rodc_msg->dn));
		TALLOC_FREE(frame);
		return WERR_DS_DRA_SECRETS_DENIED;
	}

	werr = samdb_result_sid_array_dn(sam_ctx, rodc_msg,
					 frame, "msDS-NeverRevealGroup",
					 &num_never_reveal_sids,
					 &never_reveal_sids);
	if (!W_ERROR_IS_OK(werr)) {
		DBG_ERR("Failed to parse msDS-NeverRevealGroup on %s: %s\n",
			ldb_dn_get_linearized(rodc_msg->dn),
			win_errstr(werr));
		TALLOC_FREE(frame);
		return WERR_DS_DRA_SECRETS_DENIED;
	}

	werr = samdb_result_sid_array_dn(sam_ctx, rodc_msg,
					 frame, "msDS-RevealOnDemandGroup",
					 &num_reveal_sids,
					 &reveal_sids);
	if (!W_ERROR_IS_OK(werr)) {
		DBG_ERR("Failed to parse msDS-RevealOnDemandGroup on %s: %s\n",
			ldb_dn_get_linearized(rodc_msg->dn),
			win_errstr(werr));
		TALLOC_FREE(frame);
		return WERR_DS_DRA_SECRETS_DENIED;
	}

	if (never_reveal_sids &&
	    sid_list_match(num_token_sids,
			   token_sids,
			   num_never_reveal_sids,
			   never_reveal_sids)) {
		TALLOC_FREE(frame);
		return WERR_DS_DRA_SECRETS_DENIED;
	}

	if (reveal_sids &&
	    sid_list_match(num_token_sids,
			   token_sids,
			   num_reveal_sids,
			   reveal_sids)) {
		TALLOC_FREE(frame);
		return WERR_OK;
	}

	TALLOC_FREE(frame);
	return WERR_DS_DRA_SECRETS_DENIED;

}

/*
 * This is a wrapper for the above that pulls in the tokenGroups
 * rather than relying on the caller providing those
 */
WERROR samdb_confirm_rodc_allowed_to_repl_to(struct ldb_context *sam_ctx,
					     struct ldb_message *rodc_msg,
					     struct ldb_message *obj_msg)
{
	TALLOC_CTX *frame = talloc_stackframe();
	WERROR werr;
	uint32_t num_token_sids;
	struct dom_sid *token_sids;
	const struct dom_sid *object_sid = NULL;

	object_sid = samdb_result_dom_sid(frame,
					  obj_msg,
					  "objectSid");
	if (object_sid == NULL) {
		return WERR_DS_DRA_BAD_DN;
	}
	
	/*
	 * The SID list needs to include itself as well as the tokenGroups.
	 *
	 * TODO determine if sIDHistory is required for this check
	 */
	werr = samdb_result_sid_array_ndr(sam_ctx,
					  obj_msg,
					  frame, "tokenGroups",
					  &num_token_sids,
					  &token_sids,
					  object_sid, 1);
	if (!W_ERROR_IS_OK(werr) || token_sids==NULL) {
		DBG_ERR("Failed to get tokenGroups on %s to confirm access via RODC %s: %s\n",
			ldb_dn_get_linearized(obj_msg->dn),
			ldb_dn_get_linearized(rodc_msg->dn),
			win_errstr(werr));
		return WERR_DS_DRA_SECRETS_DENIED;
	}

	werr = samdb_confirm_rodc_allowed_to_repl_to_sid_list(sam_ctx,
							      rodc_msg,
							      obj_msg,
							      num_token_sids,
							      token_sids);
	TALLOC_FREE(frame);
	return werr;
}
