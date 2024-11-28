/*
 *  Unix SMB implementation.
 *  Utility functions for converting between claims formats.
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
 */

#include "replace.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/ndr_conditional_ace.h"
#include "libcli/security/claims-conversions.h"
#include "lib/util/debug.h"
#include "lib/util/stable_sort.h"
#include "libcli/security/dom_sid.h"

#include "librpc/gen_ndr/conditional_ace.h"
#include "librpc/gen_ndr/claims.h"

/*
 * We support three formats for claims, all slightly different.
 *
 * 1. MS-ADTS 2.2.18.* claims sets, blobs, arrays, or whatever, which
 *    are used in the PAC.
 *
 * 2. MS-DTYP 2.4.10.1 CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1
 *    structures, used in security tokens and resource SACL ACEs.
 *
 * 3. MS-DTYP 2.4.4.17 Conditional ACE tokens.
 *
 * The types don't map perfectly onto each other -- in particular,
 * Conditional ACEs don't have unsigned integer or boolean types, but
 * do have short integer types which the other forms don't.
 *
 * We don't support the format used by the Win32 API function
 * AddResourceAttributeAce(), which is called CLAIM_SECURITY_ATTRIBUTE_V1.
 * Nobody has ever used that function in public, and the format is not used
 * on the wire.
 */


static bool claim_v1_string_to_ace_string(
	TALLOC_CTX *mem_ctx,
	const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
	size_t offset,
	struct ace_condition_token *result)
{
	char *s = talloc_strdup(mem_ctx,
				claim->values[offset].string_value);
	if (s == NULL) {
		return false;
	}

	result->type = CONDITIONAL_ACE_TOKEN_UNICODE;
	result->data.unicode.value = s;
	return true;
}


static bool claim_v1_octet_string_to_ace_octet_string(
	TALLOC_CTX *mem_ctx,
	const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
	size_t offset,
	struct ace_condition_token *result)
{
	DATA_BLOB *v = NULL;
	DATA_BLOB w = data_blob_null;

	v = claim->values[offset].octet_value;

	if (v->length > CONDITIONAL_ACE_MAX_LENGTH) {
		DBG_WARNING("claim has octet string of unexpected length %zu "
			    "(expected range 1 - %u)\n",
			    v->length, CONDITIONAL_ACE_MAX_LENGTH);
		return false;
	}
	if (v->length != 0) {
		w = data_blob_talloc(mem_ctx, v->data, v->length);
		if (w.data == NULL) {
			return false;
		}
	}

	result->type = CONDITIONAL_ACE_TOKEN_OCTET_STRING;
	result->data.bytes = w;
	return true;
}


static bool blob_string_sid_to_sid(DATA_BLOB *blob,
				   struct dom_sid *sid)
{
	/*
	 * Resource ACE claim SIDs are stored as SID strings in
	 * CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_RELATIVE blobs. These are in
	 * ACEs, which means we don't quite know who wrote them, and it is
	 * unspecified whether the blob should contain a terminating NUL byte.
	 * Therefore we accept either form, copying into a temporary buffer if
	 * there is no '\0'. Apart from this special case, we don't accept
	 * SIDs that are shorter than the blob.
	 *
	 * It doesn't seem like SDDL short SIDs ("WD") are accepted here. This
	 * isn't SDDL.
	 */
	bool ok;
	size_t len = blob->length;
	char buf[DOM_SID_STR_BUFLEN + 1];   /* 191 + 1 */
	const char *end = NULL;
	char *str = NULL;

	if (len < 5 || len >= DOM_SID_STR_BUFLEN) {
		return false;
	}
	if (blob->data[len - 1] == '\0') {
		str = (char *)blob->data;
		len--;
	} else {
		memcpy(buf, blob->data, len);
		buf[len] = 0;
		str = buf;
	}

	ok = dom_sid_parse_endp(str, sid, &end);
	if (!ok) {
		return false;
	}

	if (str + len != end) {
		return false;
	}
	return true;
}


static bool claim_v1_sid_to_ace_sid(
	const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
	size_t offset,
	struct ace_condition_token *result)
{
	/*
	 * In the _V1 struct, SIDs are stored as octet string blobs,
	 * as *SID strings*.
	 *
	 * In the conditional ACE they are stored as struct dom_sid.
	 *
	 * There are no SIDs in ADTS claims, but there can be in
	 * resource ACEs.
	 */
	DATA_BLOB *v = NULL;
	bool ok;

	v = claim->values[offset].sid_value;

	ok = blob_string_sid_to_sid(v, &result->data.sid.sid);
	if (! ok) {
		DBG_WARNING("claim has invalid SID string of length %zu.\n",
			    v->length);
		return false;
	}

	result->type = CONDITIONAL_ACE_TOKEN_SID;
	return true;
}


static bool claim_v1_int_to_ace_int(
	const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
	size_t offset,
	struct ace_condition_token *result)
{
	int64_t v = *claim->values[offset].int_value;
	result->type = CONDITIONAL_ACE_TOKEN_INT64;
	result->data.int64.base = CONDITIONAL_ACE_INT_BASE_10;
	result->data.int64.value = v;

	/*
	 * The sign flag (and the base flag above) determines how the
	 * ACE token will be displayed if converted to SDDL. These
	 * values are not likely to end up as SDDL, but we might as
	 * well get it right. A negative flag means it will be
	 * displayed with a minus sign, and a positive flag means a
	 * plus sign is shown. The none flag means no + or -.
	 */
	if (v < 0) {
		result->data.int64.sign = CONDITIONAL_ACE_INT_SIGN_NEGATIVE;
	} else {
		result->data.int64.sign = CONDITIONAL_ACE_INT_SIGN_NONE;
	}

	return true;
}


static bool claim_v1_unsigned_int_to_ace_int(
	const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
	size_t offset,
	struct ace_condition_token *result)
{
	uint64_t v = *claim->values[offset].uint_value;
	if (v > INT64_MAX) {
		/*
		 * The unsigned value can't be represented in a
		 * conditional ACE type.
		 *
                 * XXX or can it? does the positive flag make it
                 * unsigned?
		 */
		return false;
	}
	result->type = CONDITIONAL_ACE_TOKEN_INT64;
	result->data.int64.base = CONDITIONAL_ACE_INT_BASE_10;
	result->data.int64.sign = CONDITIONAL_ACE_INT_SIGN_POSITIVE;
	result->data.int64.value = v;
	return true;
}


static bool claim_v1_bool_to_ace_int(
	const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
	size_t offset,
	struct ace_condition_token *result)
{
	uint64_t v = *claim->values[offset].uint_value;
	result->type = CONDITIONAL_ACE_TOKEN_INT64;
	result->data.int64.base = CONDITIONAL_ACE_INT_BASE_10;
	result->data.int64.sign = CONDITIONAL_ACE_INT_SIGN_NONE;
	result->data.int64.value = v ? 1 : 0;
	return true;
}


static bool claim_v1_offset_to_ace_token(
	TALLOC_CTX *mem_ctx,
	const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
	size_t offset,
	struct ace_condition_token *result)
{
	/*
	 * A claim structure has an array of claims of a certain type,
	 * and this converts a single one into a conditional ACE token.
	 *
	 * For example, if offset is 3, claim->values[3] will be
	 * turned into *result.
	 *
	 * conditional ace token will have flags to indicate that it
	 * comes from a claim attribute, and whether or not that
	 * attribute should be compared case-sensitively (only
	 * affecting unicode strings).
	 *
	 * The CLAIM_SECURITY_ATTRIBUTE_CASE_SENSITIVE (from the
	 * claim_flags enum in security.idl) is used for both.
	 */
	uint8_t f = claim->flags & CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;
	result->flags = f | CONDITIONAL_ACE_FLAG_TOKEN_FROM_ATTR;

	if (claim->values[offset].int_value == NULL) {
		return false;
	}
	switch (claim->value_type) {
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
		return claim_v1_int_to_ace_int(claim, offset, result);
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
		return claim_v1_unsigned_int_to_ace_int(claim, offset, result);
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
		return claim_v1_string_to_ace_string(mem_ctx, claim, offset,
						     result);
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
		return claim_v1_sid_to_ace_sid(claim, offset, result);
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN:
		return claim_v1_bool_to_ace_int(claim, offset, result);
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
		return claim_v1_octet_string_to_ace_octet_string(mem_ctx,
								 claim,
								 offset,
								 result);
	default:
		return false;
	}
}


static bool claim_v1_copy(
	TALLOC_CTX *mem_ctx,
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *dest,
	const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *src);



bool claim_v1_to_ace_composite_unchecked(
	TALLOC_CTX *mem_ctx,
	const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
	struct ace_condition_token *result)
{
	/*
	 * This converts a claim object into a conditional ACE
	 * composite without checking whether it is a valid and sorted
	 * claim. It is called in two places:
	 *
	 * 1. claim_v1_to_ace_token() below (which does do those
	 * checks, and is the function you want).
	 *
	 * 2. sddl_resource_attr_from_claim() in which a resource
	 * attribute claim needs to pass through a conditional ACE
	 * composite structure on its way to becoming SDDL. In that
	 * case we don't want to check validity.
	 */
	size_t i;
	struct ace_condition_token *tokens = NULL;
	bool ok;

	tokens = talloc_array(mem_ctx,
			      struct ace_condition_token,
			      claim->value_count);
	if (tokens == NULL) {
		return false;
	}

	for (i = 0; i < claim->value_count; i++) {
		ok = claim_v1_offset_to_ace_token(tokens,
						  claim,
						  i,
						  &tokens[i]);
		if (! ok) {
			TALLOC_FREE(tokens);
			return false;
		}
	}

	result->type = CONDITIONAL_ACE_TOKEN_COMPOSITE;
	result->data.composite.tokens = tokens;
	result->data.composite.n_members = claim->value_count;
	result->flags = claim->flags & CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;
	return true;
}


bool claim_v1_to_ace_token(TALLOC_CTX *mem_ctx,
			   const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
			   struct ace_condition_token *result)
{
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim_copy = NULL;
	const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *sorted_claim = NULL;
	NTSTATUS status;
	bool ok;
	bool case_sensitive = claim->flags &			\
		CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;

	if (claim->value_count < 1 ||
	    claim->value_count >= CONDITIONAL_ACE_MAX_TOKENS) {
		DBG_WARNING("rejecting claim with %"PRIu32" tokens\n",
			    claim->value_count);
		return false;
	}
	/*
	 * if there is one, we return a single thing of that type; if
	 * there are many, we return a composite.
	 */

	if (claim->value_count == 1) {
		return claim_v1_offset_to_ace_token(mem_ctx,
						    claim,
						    0,
						    result);
	}

	if (claim->flags & CLAIM_SECURITY_ATTRIBUTE_UNIQUE_AND_SORTED) {
		/*
		 * We can avoid making a sorted copy.
		 *
		 * This is normal case for wire claims, where the
		 * sorting and duplicate checking happens earlier in
		 * token_claims_to_claims_v1().
		*/
		sorted_claim = claim;
	} else {
		/*
		 * This is presumably a resource attribute ACE, which
		 * is stored in the ACE as struct
		 * CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1, and we don't
		 * really want to mutate that copy -- even if there
		 * aren't currently realistic pathways that read an
		 * ACE, trigger this, and write it back (outside of
		 * tests).
		 */
		claim_copy = talloc(mem_ctx, struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1);
		if (claim_copy == NULL) {
			return false;
		}

		ok = claim_v1_copy(claim_copy, claim_copy, claim);
		if (!ok) {
			TALLOC_FREE(claim_copy);
			return false;
		}

		status = claim_v1_check_and_sort(claim_copy, claim_copy,
						 case_sensitive);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("resource attribute claim sort failed with %s\n",
				    nt_errstr(status));
			TALLOC_FREE(claim_copy);
			return false;
		}
		sorted_claim = claim_copy;
	}
	ok = claim_v1_to_ace_composite_unchecked(mem_ctx, sorted_claim, result);
	if (! ok) {
		TALLOC_FREE(claim_copy);
		return false;
	}

	/*
	 * The multiple values will get turned into a composite
	 * literal in the conditional ACE. Each element of the
	 * composite will have flags set by
	 * claim_v1_offset_to_ace_token(), but they also need to be
	 * set here (at least the _FROM_ATTR flag) or the child values
	 * will not be reached.
	 */
	result->flags |= (
		CONDITIONAL_ACE_FLAG_TOKEN_FROM_ATTR |
		CLAIM_SECURITY_ATTRIBUTE_UNIQUE_AND_SORTED);

	return true;
}



static bool ace_int_to_claim_v1_int(TALLOC_CTX *mem_ctx,
				    const struct ace_condition_token *tok,
				    struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
				    size_t offset)
{
	int64_t *v = talloc(mem_ctx, int64_t);
	if (v == NULL) {
		return false;
	}
	*v = tok->data.int64.value;
	claim->values[offset].int_value = v;
	return true;
}


static bool ace_string_to_claim_v1_string(TALLOC_CTX *mem_ctx,
					  const struct ace_condition_token *tok,
					  struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
					  size_t offset)
{
	const char *s = talloc_strdup(mem_ctx,
				      tok->data.unicode.value);
	if (s == NULL) {
		return false;
	}
	claim->values[offset].string_value = s;
	return true;

}


static bool ace_sid_to_claim_v1_sid(TALLOC_CTX *mem_ctx,
				    const struct ace_condition_token *tok,
				    struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
				    size_t offset)
{
	/* claim_v1 sid is an "S-1-*" string data blob, not struct dom_sid. */
	char *s = NULL;

	DATA_BLOB *blob = NULL;
	blob = talloc(mem_ctx, DATA_BLOB);
	if (blob == NULL) {
		return false;
	}
	s = dom_sid_string(blob, &tok->data.sid.sid);
	if (s == NULL) {
		TALLOC_FREE(blob);
		return false;
	}
	*blob = data_blob_string_const(s);
	claim->values[offset].sid_value = blob;
	return true;
}

static bool ace_octet_string_to_claim_v1_octet_string(
	TALLOC_CTX *mem_ctx,
	const struct ace_condition_token *tok,
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
	size_t offset)
{
	DATA_BLOB *v = talloc(mem_ctx, DATA_BLOB);
	if (v == NULL) {
		return false;
	}

	*v = data_blob_talloc(v,
			      tok->data.bytes.data,
			      tok->data.bytes.length);
	if (v->data == NULL) {
		return false;
	}

	claim->values[offset].octet_value = v;
	return true;
}



static bool ace_token_to_claim_v1_offset(TALLOC_CTX *mem_ctx,
					 const struct ace_condition_token *tok,
					 struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
					 size_t offset)
{
	/*
	 * A claim structure has an array of claims of a certain type,
	 * and this converts a single one into a conditional ACE token.
	 *
	 * For example, if offset is 3, claim->values[3] will be
	 * turned into *result.
	 */
	if (offset >= claim->value_count) {
		return false;
	}
	switch (claim->value_type) {
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
		return ace_int_to_claim_v1_int(mem_ctx, tok, claim, offset);
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
		return ace_string_to_claim_v1_string(mem_ctx, tok, claim, offset);
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
		return ace_sid_to_claim_v1_sid(mem_ctx, tok, claim, offset);
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
		return ace_octet_string_to_claim_v1_octet_string(mem_ctx,
								 tok,
								 claim,
								 offset);
	default:
		/*bool unimplemented, because unreachable */
		return false;
	}
}


bool ace_token_to_claim_v1(TALLOC_CTX *mem_ctx,
			   const char *name,
			   const struct ace_condition_token *tok,
			   struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 **claim,
			   uint32_t flags)
{
	size_t i;
	bool ok;
	bool is_comp = false;
	int claim_type = -1;
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *_claim = NULL;
	uint32_t value_count;

	if (name == NULL || claim == NULL || tok == NULL) {
		return false;
	}
	*claim = NULL;

	if (tok->type == CONDITIONAL_ACE_TOKEN_COMPOSITE) {
		is_comp = true;
		/* there must be values, all of the same type */
		if (tok->data.composite.n_members == 0) {
			DBG_WARNING("Empty ACE composite list\n");
			return false;
		}
		if (tok->data.composite.n_members > 1) {
			for (i = 1; i < tok->data.composite.n_members; i++) {
				if (tok->data.composite.tokens[i].type !=
				    tok->data.composite.tokens[0].type) {
					DBG_WARNING(
						"ACE composite list has varying "
						"types (at least %u and %u)\n",
						tok->data.composite.tokens[i].type,
						tok->data.composite.tokens[0].type);
					return false;
				}
			}
		}
		value_count = tok->data.composite.n_members;

		switch (tok->data.composite.tokens[0].type) {
		case CONDITIONAL_ACE_TOKEN_INT8:
		case CONDITIONAL_ACE_TOKEN_INT16:
		case CONDITIONAL_ACE_TOKEN_INT32:
		case CONDITIONAL_ACE_TOKEN_INT64:
			claim_type = CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64;
			break;
		case CONDITIONAL_ACE_TOKEN_UNICODE:
			claim_type = CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING;
			break;
		case CONDITIONAL_ACE_TOKEN_OCTET_STRING:
			claim_type = CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING;
			break;
		case CONDITIONAL_ACE_TOKEN_SID:
			claim_type = CLAIM_SECURITY_ATTRIBUTE_TYPE_SID;
			break;
		default:
			/* reject nested composites, no uint or bool. */
			DBG_WARNING("ACE composite list has invalid type %u\n",
				    tok->data.composite.tokens[0].type);
			return false;
		}
	} else {
		value_count = 1;
		switch(tok->type) {
		case CONDITIONAL_ACE_TOKEN_INT8:
		case CONDITIONAL_ACE_TOKEN_INT16:
		case CONDITIONAL_ACE_TOKEN_INT32:
		case CONDITIONAL_ACE_TOKEN_INT64:
			claim_type = CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64;
			break;
		case CONDITIONAL_ACE_TOKEN_UNICODE:
			claim_type = CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING;
			break;
		case CONDITIONAL_ACE_TOKEN_OCTET_STRING:
			claim_type = CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING;
			break;
		case CONDITIONAL_ACE_TOKEN_SID:
			claim_type = CLAIM_SECURITY_ATTRIBUTE_TYPE_SID;
			break;
		default:
			/*
			 * no way of creating bool or uint values,
			 * composite is handled above.
			 */
			DBG_WARNING("ACE token has invalid type %u\n",
				    tok->data.composite.tokens[0].type);
			return false;
		}
	}

	_claim = talloc(mem_ctx, struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1);
	if (_claim == NULL) {
		return false;
	}

	_claim->value_count = value_count;
	_claim->value_type = claim_type;
	_claim->flags = flags;
	_claim->name = talloc_strdup(mem_ctx, name);
	if (_claim->name == NULL) {
		TALLOC_FREE(_claim);
		return false;
	}
	/*
	 * The values array is actually an array of pointers to
	 * values, even when the values are ints or bools.
	 */
	_claim->values = talloc_array(_claim, union claim_values, value_count);
	if (_claim->values == NULL) {
		TALLOC_FREE(_claim);
		return false;
	}
	if (! is_comp) {
		/* there is one value, not a list */
		ok = ace_token_to_claim_v1_offset(_claim,
						  tok,
						  _claim,
						  0);
		if (! ok) {
			TALLOC_FREE(_claim);
			return false;
		}
	} else {
		/* a composite list of values */
		for (i = 0; i < value_count; i++) {
			struct ace_condition_token *t = &tok->data.composite.tokens[i];
			ok = ace_token_to_claim_v1_offset(mem_ctx,
							  t,
							  _claim,
							  i);
			if (! ok) {
				TALLOC_FREE(_claim);
				return false;
			}
		}
	}


	if (_claim->value_type == CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64) {
		/*
		 * Conditional ACE tokens don't have a UINT type but
		 * claims do. Windows tends to use UINT types in
		 * claims when it can, so so do we.
		 */
		bool could_be_uint = true;
		for (i = 0; i < value_count; i++) {
			if (*_claim->values[i].int_value < 0) {
				could_be_uint = false;
				break;
			}
		}
		if (could_be_uint) {
			_claim->value_type = CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64;
		}
	}

	*claim = _claim;
	return true;
}



static bool claim_v1_copy(
	TALLOC_CTX *mem_ctx,
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *dest,
	const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *src)
{
	DATA_BLOB blob = {0};
	enum ndr_err_code ndr_err;

	/*
	 * FIXME, could be more efficient! but copying these
	 * structures is fiddly, and it might be worth coming up
	 * with a better API for adding claims.
	 */

	ndr_err = ndr_push_struct_blob(
		&blob, mem_ctx, src,
		(ndr_push_flags_fn_t)ndr_push_CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}

	ndr_err = ndr_pull_struct_blob(
		&blob, mem_ctx, dest,
		(ndr_pull_flags_fn_t)ndr_pull_CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(blob.data);
		return false;
	}
	TALLOC_FREE(blob.data);
	return true;
}



bool add_claim_to_token(TALLOC_CTX *mem_ctx,
			struct security_token *token,
			const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
			const char *claim_type)
{
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *tmp = NULL;
	NTSTATUS status;
	uint32_t *n = NULL;
	bool ok;
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 **list = NULL;
	if (strcmp(claim_type, "device") == 0) {
		n = &token->num_device_claims;
		list = &token->device_claims;
	} else if (strcmp(claim_type, "local") == 0) {
		n = &token->num_local_claims;
		list = &token->local_claims;
	} else if (strcmp(claim_type, "user") == 0) {
		n = &token->num_user_claims;
		list = &token->user_claims;
	} else {
		return false;
	}
	if ((*n) == UINT32_MAX) {
		return false;
	}

	tmp = talloc_realloc(mem_ctx,
			     *list,
			     struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1,
			     (*n) + 1);
	if (tmp == NULL) {
		return false;
	}

	ok = claim_v1_copy(mem_ctx, &tmp[*n], claim);
	if (! ok ) {
		TALLOC_FREE(tmp);
		return false;
	}

	status = claim_v1_check_and_sort(tmp, &tmp[*n],
					 claim->flags & CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("resource attribute claim sort failed with %s\n",
			    nt_errstr(status));
		TALLOC_FREE(tmp);
		return false;
	}

	(*n)++;
	*list = tmp;
	return true;
}


static NTSTATUS claim_v1_check_and_sort_boolean(
	TALLOC_CTX *mem_ctx,
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim)
{
	/*
	 * There are so few valid orders in a boolean claim that we can
	 * enumerate them all.
	 */
	switch (claim->value_count) {
	case 0:
		return NT_STATUS_OK;
	case 1:
		if (*claim->values[0].uint_value == 0 ||
		    *claim->values[0].uint_value == 1) {
			return NT_STATUS_OK;
		}
		break;
	case 2:
		if (*claim->values[0].uint_value == 1) {
			/* switch the order. */
			*claim->values[0].uint_value = *claim->values[1].uint_value;
			*claim->values[1].uint_value = 1;
		}
		if (*claim->values[0].uint_value == 0 &&
		    *claim->values[1].uint_value == 1) {
			return NT_STATUS_OK;
		}
		break;
	default:
		/* 3 or more must have duplicates. */
		break;
	}
	return NT_STATUS_INVALID_PARAMETER;
}


struct claim_sort_context {
	uint16_t value_type;
	bool failed;
	bool case_sensitive;
};

static int claim_sort_cmp(const union claim_values *lhs,
			  const union claim_values *rhs,
			  struct claim_sort_context *ctx)
{
	/*
	 * These comparisons have to match those used in
	 * conditional_ace.c.
	 */
	int cmp;

	switch (ctx->value_type) {
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
	{
		/*
		 * We sort as signed integers, even for uint64,
		 * because a) we don't actually care about the true
		 * order, just uniqueness, and b) the conditional ACEs
		 * only know of signed values.
		 */
		int64_t a, b;
		if (ctx->value_type == CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64) {
			a = *lhs->int_value;
			b = *rhs->int_value;
		} else {
			a = (int64_t)*lhs->uint_value;
			b = (int64_t)*rhs->uint_value;
		}
		if (a < b) {
			return -1;
		}
		if (a == b) {
			return 0;
		}
		return 1;
	}
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
	{
		const char *a = lhs->string_value;
		const char *b = rhs->string_value;
		if (ctx->case_sensitive) {
			return strcmp(a, b);
		}
		return strcasecmp_m(a, b);
	}

	case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
	{
		/*
		 * The blobs in a claim are "S-1-.." strings, not struct
		 * dom_sid as used in conditional ACEs, and to sort them the
		 * same as ACEs we need to make temporary structs.
		 *
		 * We don't accept SID claims over the wire -- these
		 * are resource attribute ACEs only.
		 */
		struct dom_sid a, b;
		bool lhs_ok, rhs_ok;

		lhs_ok = blob_string_sid_to_sid(lhs->sid_value, &a);
		rhs_ok = blob_string_sid_to_sid(rhs->sid_value, &b);
		if (!(lhs_ok && rhs_ok)) {
			ctx->failed = true;
			return -1;
		}
		cmp = dom_sid_compare(&a, &b);
		return cmp;
	}
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING:
	{
		const DATA_BLOB *a = lhs->octet_value;
		const DATA_BLOB *b = rhs->octet_value;
		return data_blob_cmp(a, b);
	}
	default:
		ctx->failed = true;
		break;
	}
	return -1;
}


NTSTATUS claim_v1_check_and_sort(TALLOC_CTX *mem_ctx,
				 struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
				 bool case_sensitive)
{
	bool ok;
	uint32_t i;
	struct claim_sort_context sort_ctx = {
		.failed = false,
		.value_type = claim->value_type,
		.case_sensitive = case_sensitive
	};

	/*
	 * It could be that the values array contains a NULL pointer, in which
	 * case we don't need to worry about what type it is.
	 */
	for (i = 0; i < claim->value_count; i++) {
		if (claim->values[i].int_value == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	if (claim->value_type == CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN) {
		NTSTATUS status = claim_v1_check_and_sort_boolean(mem_ctx, claim);
		if (NT_STATUS_IS_OK(status)) {
			claim->flags |= CLAIM_SECURITY_ATTRIBUTE_UNIQUE_AND_SORTED;
		}
		return status;
	}

	ok =  stable_sort_talloc_r(mem_ctx,
				   claim->values,
				   claim->value_count,
				   sizeof(union claim_values),
				   (samba_compare_with_context_fn_t)claim_sort_cmp,
				   &sort_ctx);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	if (sort_ctx.failed) {
		/* this failure probably means a bad SID string */
		DBG_WARNING("claim sort of %"PRIu32" members, type %"PRIu16" failed\n",
			    claim->value_count,
			    claim->value_type);
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (i = 1; i < claim->value_count; i++) {
		int cmp = claim_sort_cmp(&claim->values[i - 1],
					 &claim->values[i],
					 &sort_ctx);
		if (cmp == 0) {
			DBG_WARNING("duplicate values in claim\n");
			return NT_STATUS_INVALID_PARAMETER;
		}
		if (cmp > 0) {
			DBG_ERR("claim sort failed!\n");
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	if (case_sensitive) {
		claim->flags |= CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;
	}
	claim->flags |= CLAIM_SECURITY_ATTRIBUTE_UNIQUE_AND_SORTED;
	return NT_STATUS_OK;
}


NTSTATUS token_claims_to_claims_v1(TALLOC_CTX *mem_ctx,
				   const struct CLAIMS_SET *claims_set,
				   struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 **out_claims,
				   uint32_t *out_n_claims)
{
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claims = NULL;
	uint32_t n_claims = 0;
	uint32_t expected_n_claims = 0;
	uint32_t i;
	NTSTATUS status;

	if (out_claims == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (out_n_claims == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	*out_claims = NULL;
	*out_n_claims = 0;

	if (claims_set == NULL) {
		return NT_STATUS_OK;
	}

	/*
	 * The outgoing number of claims is (at most) the sum of the
	 * claims_counts of each claims_array.
	 */
	for (i = 0; i < claims_set->claims_array_count; ++i) {
		uint32_t count = claims_set->claims_arrays[i].claims_count;
		expected_n_claims += count;
		if (expected_n_claims < count) {
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	claims = talloc_array(mem_ctx,
			      struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1,
			      expected_n_claims);
	if (claims == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < claims_set->claims_array_count; ++i) {
		const struct CLAIMS_ARRAY *claims_array = &claims_set->claims_arrays[i];
		uint32_t j;

		switch (claims_array->claims_source_type) {
		case CLAIMS_SOURCE_TYPE_AD:
		case CLAIMS_SOURCE_TYPE_CERTIFICATE:
			break;
		default:
			/* Ignore any claims of a type we don’t recognize. */
			continue;
		}

		for (j = 0; j < claims_array->claims_count; ++j) {
			const struct CLAIM_ENTRY *claim_entry = &claims_array->claim_entries[j];
			const char *name = NULL;
			union claim_values *claim_values = NULL;
			uint32_t n_values;
			enum security_claim_value_type value_type;

			switch (claim_entry->type) {
			case CLAIM_TYPE_INT64:
			{
				const struct CLAIM_INT64 *values = &claim_entry->values.claim_int64;
				uint32_t k;
				int64_t *claim_values_int64 = NULL;

				n_values = values->value_count;
				value_type = CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64;

				claim_values = talloc_array(claims,
							    union claim_values,
							    n_values);
				if (claim_values == NULL) {
					talloc_free(claims);
					return NT_STATUS_NO_MEMORY;
				}
				claim_values_int64 = talloc_array(claims,
								  int64_t,
								  n_values);
				if (claim_values_int64 == NULL) {
					talloc_free(claims);
					return NT_STATUS_NO_MEMORY;
				}

				for (k = 0; k < n_values; ++k) {
					claim_values_int64[k] = values->values[k];
					claim_values[k].int_value = &claim_values_int64[k];
				}

				break;
			}
			case CLAIM_TYPE_UINT64:
			case CLAIM_TYPE_BOOLEAN:
			{
				const struct CLAIM_UINT64 *values = &claim_entry->values.claim_uint64;
				uint32_t k;
				uint64_t *claim_values_uint64 = NULL;

				n_values = values->value_count;
				value_type = (claim_entry->type == CLAIM_TYPE_UINT64)
					? CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64
					: CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN;

				claim_values = talloc_array(claims,
							    union claim_values,
							    n_values);
				if (claim_values == NULL) {
					talloc_free(claims);
					return NT_STATUS_NO_MEMORY;
				}

				claim_values_uint64 = talloc_array(claims,
								   uint64_t,
								   n_values);
				if (claim_values_uint64 == NULL) {
					talloc_free(claims);
					return NT_STATUS_NO_MEMORY;
				}

				for (k = 0; k < n_values; ++k) {
					claim_values_uint64[k] = values->values[k];
					claim_values[k].uint_value = &claim_values_uint64[k];
				}

				break;
			}
			case CLAIM_TYPE_STRING:
			{
				const struct CLAIM_STRING *values = &claim_entry->values.claim_string;
				uint32_t k, m;
				bool seen_empty = false;
				n_values = values->value_count;
				value_type = CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING;

				claim_values = talloc_array(claims,
							    union claim_values,
							    n_values);
				if (claim_values == NULL) {
					talloc_free(claims);
					return NT_STATUS_NO_MEMORY;
				}

				m = 0;
				for (k = 0; k < n_values; ++k) {
					const char *string_value = NULL;

					if (values->values[k] != NULL) {
						string_value = talloc_strdup(claim_values, values->values[k]);
						if (string_value == NULL) {
							talloc_free(claims);
							return NT_STATUS_NO_MEMORY;
						}
						claim_values[m].string_value = string_value;
						m++;
					} else {
						/*
						 * We allow one NULL string
						 * per claim, but not two,
						 * because two would be a
						 * duplicate, and we don't
						 * want those (duplicates in
						 * actual values are checked
						 * later).
						 */
						if (seen_empty) {
							talloc_free(claims);
							return NT_STATUS_INVALID_PARAMETER;
						}
						seen_empty = true;
					}
				}
				n_values = m;
				break;
			}
			default:
				/*
				 * Other claim types are unsupported — just skip
				 * them.
				 */
				continue;
			}

			if (claim_entry->id != NULL) {
				name = talloc_strdup(claims, claim_entry->id);
				if (name == NULL) {
					talloc_free(claims);
					return NT_STATUS_NO_MEMORY;
				}
			}

			claims[n_claims] = (struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1) {
				.name = name,
				.value_type = value_type,
				.flags = 0,
				.value_count = n_values,
				.values = claim_values,
			};

			status = claim_v1_check_and_sort(claims, &claims[n_claims],
							 false);
			if (!NT_STATUS_IS_OK(status)) {
				talloc_free(claims);
				DBG_WARNING("claim sort and uniqueness test failed with %s\n",
					    nt_errstr(status));
				return status;
			}
			n_claims++;
		}
	}
	*out_claims = claims;
	*out_n_claims = n_claims;

	return NT_STATUS_OK;
}
