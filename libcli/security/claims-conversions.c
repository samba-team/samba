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
#include "libcli/security/security.h"
#include "libcli/security/conditional_ace.h"
#include "libcli/security/claims-conversions.h"
#include "lib/util/tsort.h"
#include "lib/util/debug.h"
#include "lib/util/bytearray.h"

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


static bool claim_v1_sid_to_ace_sid(
	TALLOC_CTX *mem_ctx,
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
	struct dom_sid *sid = NULL;
	DATA_BLOB *v = NULL;

	v = claim->values[offset].sid_value;

	if (v->length == 0 || v->length > CONDITIONAL_ACE_MAX_LENGTH) {
		DBG_WARNING("claim has SID string of unexpected length %zu, "
			    "(expected range 1 - %u)\n",
			    v->length, CONDITIONAL_ACE_MAX_LENGTH);
		return false;
	}

	sid = dom_sid_parse_length(mem_ctx, v);
	if (sid == NULL) {
		DBG_WARNING("claim has invalid SID string of length %zu.\n",
			    v->length);
		return false;
	}

	result->type = CONDITIONAL_ACE_TOKEN_SID;
	result->data.sid.sid = *sid;
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

	switch (claim->value_type) {
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64:
		return claim_v1_int_to_ace_int(claim, offset, result);
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64:
		return claim_v1_unsigned_int_to_ace_int(claim, offset, result);
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING:
		return claim_v1_string_to_ace_string(mem_ctx, claim, offset,
						     result);
	case CLAIM_SECURITY_ATTRIBUTE_TYPE_SID:
		return claim_v1_sid_to_ace_sid(mem_ctx, claim, offset, result);
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


bool claim_v1_to_ace_token(TALLOC_CTX *mem_ctx,
			   const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
			   struct ace_condition_token *result)
{
	size_t i;
	struct ace_condition_token *tokens = NULL;
	if (claim->value_count < 1 ||
	    claim->value_count >= CONDITIONAL_ACE_MAX_TOKENS) {
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
	/*
	 * The multiple values will get turned into a composite
	 * literal in the conditional ACE. Each element of the
	 * composite will have flags set by
	 * claim_v1_offset_to_ace_token(), but they also need to be
	 * set here (at least the _FROM_ATTR flag) or the child values
	 * will not be reached.
	 */

	result->flags = (
		CONDITIONAL_ACE_FLAG_TOKEN_FROM_ATTR |
		(claim->flags & CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE));

	tokens = talloc_array(mem_ctx,
			      struct ace_condition_token,
			      claim->value_count);
	if (tokens == NULL) {
		return false;
	}

	for (i = 0; i < claim->value_count; i++) {
		bool ok = claim_v1_offset_to_ace_token(tokens,
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
		return false;
	}
	(*n)++;
	*list = tmp;
	return true;
}

NTSTATUS token_claims_to_claims_v1(TALLOC_CTX *mem_ctx,
				   const struct CLAIMS_SET *claims_set,
				   struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 **out_claims,
				   uint32_t *out_n_claims)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claims = NULL;
	uint32_t n_claims = 0;
	uint32_t i;

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

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
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

				n_values = values->value_count;
				value_type = CLAIM_SECURITY_ATTRIBUTE_TYPE_INT64;

				claim_values = talloc_array(claims,
							    union claim_values,
							    n_values);
				if (claim_values == NULL) {
					talloc_free(tmp_ctx);
					return NT_STATUS_NO_MEMORY;
				}

				for (k = 0; k < n_values; ++k) {
					int64_t *value = NULL;
					uint32_t m;

					/*
					 * Ensure that there are no duplicate
					 * values (very inefficiently, in
					 * O(n²)).
					 */
					for (m = 0; m < k; ++m) {
						if (values->values[m] == values->values[k]) {
							talloc_free(tmp_ctx);
							return NT_STATUS_INVALID_PARAMETER;
						}
					}

					value = talloc(mem_ctx, int64_t);
					if (value == NULL) {
						talloc_free(tmp_ctx);
						return NT_STATUS_NO_MEMORY;
					}

					*value = values->values[k];
					claim_values[k].int_value = value;
				}

				break;
			}
			case CLAIM_TYPE_UINT64:
			case CLAIM_TYPE_BOOLEAN:
			{
				const struct CLAIM_UINT64 *values = &claim_entry->values.claim_uint64;
				uint32_t k;

				n_values = values->value_count;
				value_type = (claim_entry->type == CLAIM_TYPE_UINT64)
					? CLAIM_SECURITY_ATTRIBUTE_TYPE_UINT64
					: CLAIM_SECURITY_ATTRIBUTE_TYPE_BOOLEAN;

				claim_values = talloc_array(claims,
							    union claim_values,
							    n_values);
				if (claim_values == NULL) {
					talloc_free(tmp_ctx);
					return NT_STATUS_NO_MEMORY;
				}

				for (k = 0; k < n_values; ++k) {
					uint64_t *value = NULL;
					uint32_t m;

					/*
					 * Ensure that there are no duplicate
					 * values (very inefficiently, in
					 * O(n²)).
					 */
					for (m = 0; m < k; ++m) {
						if (values->values[m] == values->values[k]) {
							talloc_free(tmp_ctx);
							return NT_STATUS_INVALID_PARAMETER;
						}
					}

					value = talloc(mem_ctx, uint64_t);
					if (value == NULL) {
						talloc_free(tmp_ctx);
						return NT_STATUS_NO_MEMORY;
					}

					*value = values->values[k];
					claim_values[k].uint_value = value;
				}

				break;
			}
			case CLAIM_TYPE_STRING:
			{
				const struct CLAIM_STRING *values = &claim_entry->values.claim_string;
				uint32_t k;

				n_values = values->value_count;
				value_type = CLAIM_SECURITY_ATTRIBUTE_TYPE_STRING;

				claim_values = talloc_array(claims,
							    union claim_values,
							    n_values);
				if (claim_values == NULL) {
					talloc_free(tmp_ctx);
					return NT_STATUS_NO_MEMORY;
				}

				for (k = 0; k < n_values; ++k) {
					const char *string_value = NULL;
					uint32_t m;

					/*
					 * Ensure that there are no duplicate
					 * values (very inefficiently, in
					 * O(n²)).
					 */
					for (m = 0; m < k; ++m) {
						if (values->values[m] == NULL && values->values[k] == NULL) {
							talloc_free(tmp_ctx);
							return NT_STATUS_INVALID_PARAMETER;
						}

						if (values->values[m] != NULL &&
						    values->values[k] != NULL &&
						    strcasecmp_m(values->values[m], values->values[k]) == 0)
						{
							talloc_free(tmp_ctx);
							return NT_STATUS_INVALID_PARAMETER;
						}
					}

					if (values->values[k] != NULL) {
						string_value = talloc_strdup(claim_values, values->values[k]);
						if (string_value == NULL) {
							talloc_free(tmp_ctx);
							return NT_STATUS_NO_MEMORY;
						}
					}

					claim_values[k].string_value = string_value;
				}

				break;
			}
			default:
				/*
				 * Other claim types are unsupported — just skip
				 * them.
				 */
				continue;
			}

			claims = talloc_realloc(tmp_ctx,
						claims,
						struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1,
						++n_claims);
			if (claims == NULL) {
				talloc_free(tmp_ctx);
				return NT_STATUS_NO_MEMORY;
			}

			if (claim_entry->id != NULL) {
				name = talloc_strdup(claims, claim_entry->id);
				if (name == NULL) {
					talloc_free(tmp_ctx);
					return NT_STATUS_NO_MEMORY;
				}
			}

			claims[n_claims - 1] = (struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1) {
				.name = name,
				.value_type = value_type,
				.flags = 0,
				.value_count = n_values,
				.values = claim_values,
			};
		}
	}

	*out_claims = talloc_move(mem_ctx, &claims);
	*out_n_claims = n_claims;

	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}
