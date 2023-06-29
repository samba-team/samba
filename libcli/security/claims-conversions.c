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
 * Nobody has ever used that function in public, and it the format is not used
 * on the wire.
 */


static bool claim_v1_string_to_ace_string(
	TALLOC_CTX *mem_ctx,
	const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
	size_t offset,
	struct ace_condition_token *result)
{
	/*
	 * A _v1 name string is NUL-terminated, while a conditional
	 * ACE is length-deliminated. We choose to copy the \0.
	 */
	size_t len;
	char *s = talloc_strndup(mem_ctx,
				 claim->values[offset].string_value,
				 CONDITIONAL_ACE_MAX_LENGTH);
	if (s == NULL) {
		return false;
	}

	len = talloc_get_size(s) - 1;
	if (len >= CONDITIONAL_ACE_MAX_LENGTH) {
		DBG_WARNING("claim has string of unexpected length %zu or more\n",
			    len);
		TALLOC_FREE(s);
		return false;
	}
	result->type = CONDITIONAL_ACE_TOKEN_UNICODE;
	result->data.unicode.value = s;
	result->data.unicode.length = len;
	return true;
}


static bool claim_v1_octet_string_to_ace_octet_string(
	TALLOC_CTX *mem_ctx,
	const struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
	size_t offset,
	struct ace_condition_token *result)
{
	DATA_BLOB *v = NULL;
	struct ace_condition_bytes w = {0};

	v = claim->values[offset].octet_value;

	if (v->length > CONDITIONAL_ACE_MAX_LENGTH) {
		DBG_WARNING("claim has octet string of unexpected length %zu "
			    "(expected range 1 - %u)\n",
			    v->length, CONDITIONAL_ACE_MAX_LENGTH);
		return false;
	}
	if (v->length == 0) {
		w.bytes = NULL;
		w.length = 0;
	} else {
		w.bytes = talloc_memdup(mem_ctx, v->data, v->length);
		if (w.bytes == NULL) {
			return false;
		}

		w.length = v->length;
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
	result->data.sid.sid = sid;
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
	int64_t v = *claim->values[offset].int_value;
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
				    struct ace_condition_token *tok,
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
					  struct ace_condition_token *tok,
					  struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
					  size_t offset)
{
	const char *s = talloc_strndup(mem_ctx,
				       tok->data.unicode.value,
				       tok->data.unicode.length);
	if (s == NULL) {
		return false;
	}
	claim->values[offset].string_value = s;
	return true;

}


static bool ace_sid_to_claim_v1_sid(TALLOC_CTX *mem_ctx,
				    struct ace_condition_token *tok,
				    struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
				    size_t offset)
{
	/* claim_v1 sid is an "S-1-*" string data blob, not struct dom_sid. */
	DATA_BLOB *blob = NULL;
	char *s = dom_sid_string(mem_ctx, tok->data.sid.sid);
	if (s == NULL) {
		return false;
	}
	blob = talloc(mem_ctx, DATA_BLOB);
	if (blob == NULL) {
		TALLOC_FREE(s);
		return false;
	}
	*blob = data_blob_string_const(s);
	claim->values[offset].sid_value = blob;
	return true;
}

static bool ace_octet_string_to_claim_v1_octet_string(
	TALLOC_CTX *mem_ctx,
	struct ace_condition_token *tok,
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
	size_t offset)
{
	DATA_BLOB *v = talloc(mem_ctx, DATA_BLOB);
	if (v == NULL) {
		return false;
	}

	*v = data_blob_talloc(mem_ctx,
			      tok->data.bytes.bytes,
			      tok->data.bytes.length);
	if (v->data == NULL) {
		return false;
	}

	claim->values[offset].octet_value = v;
	return true;
}



static bool ace_token_to_claim_v1_offset(TALLOC_CTX *mem_ctx,
					 struct ace_condition_token *tok,
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
			   struct ace_condition_token *tok,
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
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *src)
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
			struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
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
