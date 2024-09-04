/*
 *  Unix SMB implementation.
 *  Functions for understanding conditional ACEs
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
#include "librpc/gen_ndr/conditional_ace.h"
#include "libcli/security/security.h"
#include "libcli/security/conditional_ace.h"
#include "libcli/security/claims-conversions.h"
#include "lib/util/tsort.h"
#include "lib/util/debug.h"
#include "lib/util/bytearray.h"
#include "lib/util/talloc_stack.h"
#include "util/discard.h"
#include "lib/util/stable_sort.h"
/*
 * Conditional ACE logic truth tables.
 *
 * Conditional ACES use a ternary logic, with "unknown" as well as true and
 * false. The ultimate meaning of unknown depends on the context; in a deny
 * ace, unknown means yes, in an allow ace, unknown means no. That is, we
 * treat unknown results with maximum suspicion.
 *
 *   AND   true   false  unknown
 *  true     T      F      ?
 *  false    F      F      F
 *  unknown  ?      F      ?
 *
 *   OR    true   false  unknown
 *  true     T      T      T
 *  false    T      F      ?
 *  unknown  T      ?      ?
 *
 *   NOT
 *  true     F
 *  false    T
 *  unknown  ?
 *
 * This can be summed up by saying unknown values taint the result except in
 * the cases where short circuit evaluation could apply (true OR anything,
 * false AND anything, which hold their value).
 *
 * What counts as unknown
 *
 * - NULL attributes.
 * - certain comparisons between incompatible types
 *
 * What counts as false
 *
 * - zero
 * - empty strings
 *
 * An error means the entire expression is unknown.
 */


static bool check_integer_range(const struct ace_condition_token *tok)
{
	int64_t val = tok->data.int64.value;
	switch (tok->type) {
	case CONDITIONAL_ACE_TOKEN_INT8:
		if (val < -128 || val > 127) {
			return false;
		}
		break;
	case CONDITIONAL_ACE_TOKEN_INT16:
		if (val < INT16_MIN || val > INT16_MAX) {
			return false;
		}
		break;
	case CONDITIONAL_ACE_TOKEN_INT32:
		if (val < INT32_MIN || val > INT32_MAX) {
			return false;
		}
		break;
	case CONDITIONAL_ACE_TOKEN_INT64:
		/* val has these limits naturally */
		break;
	default:
		return false;
	}

	if (tok->data.int64.base != CONDITIONAL_ACE_INT_BASE_8 &&
	    tok->data.int64.base != CONDITIONAL_ACE_INT_BASE_10 &&
	    tok->data.int64.base != CONDITIONAL_ACE_INT_BASE_16) {
		return false;
	}
	if (tok->data.int64.sign != CONDITIONAL_ACE_INT_SIGN_POSITIVE &&
	    tok->data.int64.sign != CONDITIONAL_ACE_INT_SIGN_NEGATIVE &&
	    tok->data.int64.sign != CONDITIONAL_ACE_INT_SIGN_NONE) {
		return false;
	}
	return true;
}


static ssize_t pull_integer(TALLOC_CTX *mem_ctx,
			uint8_t *data, size_t length,
			struct ace_condition_int *tok)
{
	ssize_t bytes_used;
	enum ndr_err_code ndr_err;
	DATA_BLOB v = data_blob_const(data, length);
	struct ndr_pull *ndr = ndr_pull_init_blob(&v, mem_ctx);
	if (ndr == NULL) {
		return -1;
	}
	ndr_err = ndr_pull_ace_condition_int(ndr, NDR_SCALARS|NDR_BUFFERS, tok);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(ndr);
		return -1;
	}
	bytes_used = ndr->offset;
	TALLOC_FREE(ndr);
	return bytes_used;
}

static ssize_t push_integer(uint8_t *data, size_t available,
			const struct ace_condition_int *tok)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB v;
	ndr_err = ndr_push_struct_blob(&v, NULL,
				       tok,
				       (ndr_push_flags_fn_t)ndr_push_ace_condition_int);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return -1;
	}
	if (available < v.length) {
		talloc_free(v.data);
		return -1;
	}
	memcpy(data, v.data, v.length);
	talloc_free(v.data);
	return v.length;
}


static ssize_t pull_unicode(TALLOC_CTX *mem_ctx,
			uint8_t *data, size_t length,
			struct ace_condition_unicode *tok)
{
	ssize_t bytes_used;
	enum ndr_err_code ndr_err;
	DATA_BLOB v = data_blob_const(data, length);
	struct ndr_pull *ndr = ndr_pull_init_blob(&v, mem_ctx);
	if (ndr == NULL) {
		return -1;
	}
	ndr_err = ndr_pull_ace_condition_unicode(ndr, NDR_SCALARS|NDR_BUFFERS, tok);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(ndr);
		return -1;
	}
	bytes_used = ndr->offset;
	TALLOC_FREE(ndr);
	return bytes_used;
}

static ssize_t push_unicode(uint8_t *data, size_t available,
			const struct ace_condition_unicode *tok)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB v;
	ndr_err = ndr_push_struct_blob(&v, NULL,
				       tok,
				       (ndr_push_flags_fn_t)ndr_push_ace_condition_unicode);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return -1;
	}
	if (available < v.length) {
		talloc_free(v.data);
		return -1;
	}
	memcpy(data, v.data, v.length);
	talloc_free(v.data);
	return v.length;
}


static ssize_t pull_bytes(TALLOC_CTX *mem_ctx,
			  uint8_t *data, size_t length,
			  DATA_BLOB *tok)
{
	ssize_t bytes_used;
	enum ndr_err_code ndr_err;
	DATA_BLOB v = data_blob_const(data, length);
	struct ndr_pull *ndr = ndr_pull_init_blob(&v, mem_ctx);
	if (ndr == NULL) {
		return -1;
	}
	ndr_err = ndr_pull_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, tok);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(ndr);
		return -1;
	}
	bytes_used = ndr->offset;
	talloc_free(ndr);
	return bytes_used;
}

static ssize_t push_bytes(uint8_t *data, size_t available,
			const DATA_BLOB *tok)
{
	size_t offset;
	enum ndr_err_code ndr_err;
	TALLOC_CTX *frame = talloc_stackframe();
	struct ndr_push *ndr = ndr_push_init_ctx(frame);
	if (ndr == NULL) {
		TALLOC_FREE(frame);
		return -1;
	}

	ndr_err = ndr_push_DATA_BLOB(ndr, NDR_SCALARS|NDR_BUFFERS, *tok);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return -1;
	}

	if (available < ndr->offset) {
		TALLOC_FREE(frame);
		return -1;
	}
	memcpy(data, ndr->data, ndr->offset);
	offset = ndr->offset;
	TALLOC_FREE(frame);
	return offset;
}

static ssize_t pull_sid(TALLOC_CTX *mem_ctx,
			uint8_t *data, size_t length,
			struct ace_condition_sid *tok)
{
	ssize_t bytes_used;
	enum ndr_err_code ndr_err;
	DATA_BLOB v = data_blob_const(data, length);
	struct ndr_pull *ndr = ndr_pull_init_blob(&v, mem_ctx);
	if (ndr == NULL) {
		return -1;
	}
	ndr->flags |= LIBNDR_FLAG_SUBCONTEXT_NO_UNREAD_BYTES;

	ndr_err = ndr_pull_ace_condition_sid(ndr, NDR_SCALARS|NDR_BUFFERS, tok);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(ndr);
		return -1;
	}
	bytes_used = ndr->offset;
	TALLOC_FREE(ndr);
	return bytes_used;
}

static ssize_t push_sid(uint8_t *data, size_t available,
			const struct ace_condition_sid *tok)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB v;
	ndr_err = ndr_push_struct_blob(&v, NULL,
				       tok,
				       (ndr_push_flags_fn_t)ndr_push_ace_condition_sid);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return -1;
	}
	if (available < v.length) {
		talloc_free(v.data);
		return -1;
	}
	memcpy(data, v.data, v.length);
	talloc_free(v.data);
	return v.length;
}


static ssize_t pull_composite(TALLOC_CTX *mem_ctx,
			      uint8_t *data, size_t length,
			      struct ace_condition_composite *tok)
{
	size_t i, j;
	size_t alloc_length;
	size_t byte_size;
	struct ace_condition_token *tokens = NULL;
	if (length < 4) {
		return -1;
	}
	byte_size = PULL_LE_U32(data, 0);
	if (byte_size > length - 4) {
		return -1;
	}
	/*
	 * There is a list of other literal tokens (possibly including nested
	 * composites), which we will store in an array.
	 *
	 * This array can *only* be literals.
	 */
	alloc_length = byte_size;
	tokens = talloc_array(mem_ctx,
			      struct ace_condition_token,
			      alloc_length);
	if (tokens == NULL) {
		return -1;
	}
	byte_size += 4;
	i = 4;
	j = 0;
	while (i < byte_size) {
		struct ace_condition_token *el = &tokens[j];
		ssize_t consumed;
		uint8_t *el_data = NULL;
		size_t available;
		bool ok;
		*el = (struct ace_condition_token) { .type = data[i] };
		i++;

		el_data = data + i;
		available = byte_size - i;

		switch (el->type) {
		case CONDITIONAL_ACE_TOKEN_INT8:
		case CONDITIONAL_ACE_TOKEN_INT16:
		case CONDITIONAL_ACE_TOKEN_INT32:
		case CONDITIONAL_ACE_TOKEN_INT64:
			consumed = pull_integer(mem_ctx,
						el_data,
						available,
						&el->data.int64);
			ok = check_integer_range(el);
			if (! ok) {
				goto error;
			}
			break;
		case CONDITIONAL_ACE_TOKEN_UNICODE:
			consumed = pull_unicode(mem_ctx,
						el_data,
						available,
						&el->data.unicode);
			break;

		case CONDITIONAL_ACE_TOKEN_OCTET_STRING:
			consumed = pull_bytes(mem_ctx,
					      el_data,
					      available,
					      &el->data.bytes);
			break;

		case CONDITIONAL_ACE_TOKEN_SID:
			consumed = pull_sid(mem_ctx,
					    el_data,
					    available,
					    &el->data.sid);
			break;

		case CONDITIONAL_ACE_TOKEN_COMPOSITE:
			DBG_ERR("recursive composite tokens in conditional "
				"ACEs are not currently supported\n");
			goto error;
		default:
			goto error;
		}

		if (consumed < 0 || consumed + i > length) {
			goto error;
		}
		i += consumed;
		j++;
		if (j == UINT16_MAX) {
			talloc_free(tokens);
			return -1;
		}
		if (j == alloc_length) {
			struct ace_condition_token *new_tokens = NULL;

			alloc_length += 5;
			new_tokens = talloc_realloc(mem_ctx,
						    tokens,
						    struct ace_condition_token,
						    alloc_length);

			if (new_tokens == NULL) {
				goto error;
			}
			tokens = new_tokens;
		}
	}
	tok->n_members = j;
	tok->tokens = tokens;
	return byte_size;
error:
	talloc_free(tokens);
	return -1;
}


static ssize_t push_composite(uint8_t *data, size_t length,
			      const struct ace_condition_composite *tok)
{
	size_t i;
	uint8_t *byte_length_ptr;
	size_t used = 0;
	if (length < 4) {
		return -1;
	}
	/*
	 * We have no idea what the eventual length will be, so we keep a
	 * pointer to write it in at the end.
	 */
	byte_length_ptr = data;
	PUSH_LE_U32(data, 0, 0);
	used = 4;

	for (i = 0; i < tok->n_members && used < length; i++) {
		struct ace_condition_token *el = &tok->tokens[i];
		ssize_t consumed;
		uint8_t *el_data = NULL;
		size_t available;
		bool ok;
		data[used] = el->type;
		used++;
		if (used == length) {
			/*
			 * used == length is not expected here; the token
			 * types that only have an opcode and no data are not
			 * literals that can be in composites.
			 */
			return -1;
		}
		el_data = data + used;
		available = length - used;

		switch (el->type) {
		case CONDITIONAL_ACE_TOKEN_INT8:
		case CONDITIONAL_ACE_TOKEN_INT16:
		case CONDITIONAL_ACE_TOKEN_INT32:
		case CONDITIONAL_ACE_TOKEN_INT64:
			ok = check_integer_range(el);
			if (! ok) {
				return -1;
			}
			consumed = push_integer(el_data,
						available,
						&el->data.int64);
			break;
		case CONDITIONAL_ACE_TOKEN_UNICODE:
			consumed = push_unicode(el_data,
						available,
						&el->data.unicode);
			break;

		case CONDITIONAL_ACE_TOKEN_OCTET_STRING:
			consumed = push_bytes(el_data,
					      available,
					      &el->data.bytes);
			break;

		case CONDITIONAL_ACE_TOKEN_SID:
			consumed = push_sid(el_data,
					    available,
					    &el->data.sid);
			break;

		case CONDITIONAL_ACE_TOKEN_COMPOSITE:
			consumed = push_composite(el_data,
						  available,
						  &el->data.composite);
			break;

		default:
			return -1;
		}

		if (consumed < 0) {
			return -1;
		}
		used += consumed;
	}
	if (used > length) {
		return -1;
	}

	PUSH_LE_U32(byte_length_ptr, 0, used - 4);
	return used;
}

static ssize_t pull_end_padding(uint8_t *data, size_t length)
{
	/*
	 * We just check that we have the right kind of number of zero
	 * bytes. The blob must end on a multiple of 4. One zero byte
	 * has already been swallowed as tok->type, which sends us
	 * here, so we expect 1 or two more -- total padding is 0, 1,
	 * 2, or 3.
	 *
	 * zero is also called CONDITIONAL_ACE_TOKEN_INVALID_OR_PADDING.
	 */
	ssize_t i;
	if (length > 2) {
		return -1;
	}
	for (i = 0; i < length; i++) {
		if (data[i] != 0) {
			return -1;
		}
	}
	return length;
}


struct ace_condition_script *parse_conditional_ace(TALLOC_CTX *mem_ctx,
						   DATA_BLOB data)
{
	size_t i, j;
	struct ace_condition_token *tokens = NULL;
	size_t alloc_length;
	struct ace_condition_script *program = NULL;

	if (data.length < 4 ||
	    data.data[0] != 'a' ||
	    data.data[1] != 'r' ||
	    data.data[2] != 't' ||
	    data.data[3] != 'x') {
		/*
		 * lacks the "artx" conditional ace identifier magic.
		 * NULL returns will deny access.
		 */
		return NULL;
	}
	if (data.length > CONDITIONAL_ACE_MAX_LENGTH ||
	    (data.length & 3) != 0) {
		/*
		 * >= 64k or non-multiples of 4 are not possible in the ACE
		 * wire format.
		 */
		return NULL;
	}

	program = talloc(mem_ctx, struct ace_condition_script);
	if (program == NULL) {
		return NULL;
	}

	/*
	 * We will normally end up with fewer than data.length tokens, as
	 * values are stored in multiple bytes (all integers are 10 bytes,
	 * strings and attributes are utf16 + length, SIDs are SID-size +
	 * length, etc). But operators are one byte, so something like
	 * !(!(!(!(!(!(x)))))) -- where each '!(..)' is one byte -- will bring
	 * the number of tokens close to the number of bytes.
	 *
	 * This is all to say we're guessing a token length that hopes to
	 * avoid reallocs without wasting too much up front.
	 */
	alloc_length = data.length / 2 + 1;
	tokens = talloc_array(program,
			      struct ace_condition_token,
			      alloc_length);
	if (tokens == NULL) {
		TALLOC_FREE(program);
		return NULL;
	}

	i = 4;
	j = 0;
	while(i < data.length) {
		struct ace_condition_token *tok = &tokens[j];
		ssize_t consumed = 0;
		uint8_t *tok_data = NULL;
		size_t available;
		bool ok;
		tok->type = data.data[i];
		tok->flags = 0;
		i++;
		tok_data = data.data + i;
		available = data.length - i;

		switch (tok->type) {
		case CONDITIONAL_ACE_TOKEN_INT8:
		case CONDITIONAL_ACE_TOKEN_INT16:
		case CONDITIONAL_ACE_TOKEN_INT32:
		case CONDITIONAL_ACE_TOKEN_INT64:
			consumed = pull_integer(program,
						tok_data,
						available,
						&tok->data.int64);
			ok = check_integer_range(tok);
			if (! ok) {
				goto fail;
			}
			break;
		case CONDITIONAL_ACE_TOKEN_UNICODE:
			/*
			 * The next four are pulled as unicode, but are
			 *  processed as user attribute look-ups.
			 */
		case CONDITIONAL_ACE_LOCAL_ATTRIBUTE:
		case CONDITIONAL_ACE_USER_ATTRIBUTE:
		case CONDITIONAL_ACE_RESOURCE_ATTRIBUTE:
		case CONDITIONAL_ACE_DEVICE_ATTRIBUTE:
			consumed = pull_unicode(program,
						tok_data,
						available,
						&tok->data.unicode);
			break;

		case CONDITIONAL_ACE_TOKEN_OCTET_STRING:
			consumed = pull_bytes(program,
					      tok_data,
					      available,
					      &tok->data.bytes);
			break;

		case CONDITIONAL_ACE_TOKEN_SID:
			consumed = pull_sid(program,
					    tok_data,
					    available,
					    &tok->data.sid);
			break;

		case CONDITIONAL_ACE_TOKEN_COMPOSITE:
			consumed = pull_composite(program,
						  tok_data,
						  available,
						  &tok->data.composite);
			break;

		case CONDITIONAL_ACE_TOKEN_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF_ANY:
			/*
			 * these require a SID or composite SID list operand,
			 * and we could check that now in most cases.
			 */
			break;
		/* binary relational operators */
		case CONDITIONAL_ACE_TOKEN_EQUAL:
		case CONDITIONAL_ACE_TOKEN_NOT_EQUAL:
		case CONDITIONAL_ACE_TOKEN_LESS_THAN:
		case CONDITIONAL_ACE_TOKEN_LESS_OR_EQUAL:
		case CONDITIONAL_ACE_TOKEN_GREATER_THAN:
		case CONDITIONAL_ACE_TOKEN_GREATER_OR_EQUAL:
		case CONDITIONAL_ACE_TOKEN_CONTAINS:
		case CONDITIONAL_ACE_TOKEN_ANY_OF:
		case CONDITIONAL_ACE_TOKEN_NOT_CONTAINS:
		case CONDITIONAL_ACE_TOKEN_NOT_ANY_OF:
		/* unary logical operators */
		case CONDITIONAL_ACE_TOKEN_EXISTS:
		case CONDITIONAL_ACE_TOKEN_NOT_EXISTS:
		case CONDITIONAL_ACE_TOKEN_NOT:
		/* binary logical operators */
		case CONDITIONAL_ACE_TOKEN_AND:
		case CONDITIONAL_ACE_TOKEN_OR:
			break;
		case CONDITIONAL_ACE_TOKEN_INVALID_OR_PADDING:
			/* this is only valid at the end */
			consumed = pull_end_padding(tok_data,
						    available);
			j--; /* don't add this token */
			break;
		default:
			goto fail;
		}

		if (consumed < 0) {
			goto fail;
		}
		if (consumed + i < i || consumed + i > data.length) {
			goto fail;
		}
		i += consumed;
		j++;
		if (j == alloc_length) {
			alloc_length *= 2;
			tokens = talloc_realloc(program,
						tokens,
						struct ace_condition_token,
						alloc_length);
			if (tokens == NULL) {
				goto fail;
			}
		}
	}
	program->length = j;
	program->tokens = talloc_realloc(program,
					 tokens,
					 struct ace_condition_token,
					 program->length + 1);
	if (program->tokens == NULL) {
		goto fail;
	}
	return program;
  fail:
	talloc_free(program);
	return NULL;
  }


static bool claim_lookup_internal(
	TALLOC_CTX *mem_ctx,
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claim,
	struct ace_condition_token *result)
{
	bool ok = claim_v1_to_ace_token(mem_ctx, claim, result);
	return ok;
}


static bool resource_claim_lookup(
	TALLOC_CTX *mem_ctx,
	const struct ace_condition_token *op,
	const struct security_descriptor *sd,
	struct ace_condition_token *result)
{
	/*
	 * For a @Resource.attr, the claims come from a resource ACE
	 * in the object's SACL. That's why we need a security descriptor.
	 *
	 * If there is no matching resource ACE, a NULL result is returned,
	 * which should compare UNKNOWN to anything. The NULL will have the
	 * CONDITIONAL_ACE_FLAG_NULL_MEANS_ERROR flag set if it seems failure
	 * is not simply due to the sought claim not existing. This is useful for
	 * the Exists and Not_Exists operators.
	 */
	size_t i;
	struct ace_condition_unicode name;

	result->type = CONDITIONAL_ACE_SAMBA_RESULT_NULL;

	if (op->type != CONDITIONAL_ACE_RESOURCE_ATTRIBUTE) {
		/* what are we even doing here? */
		result->type = CONDITIONAL_ACE_SAMBA_RESULT_ERROR;
		return false;
	}

	name = op->data.resource_attr;

	if (sd->sacl == NULL) {
		DBG_NOTICE("Resource attribute ACE '%s' not found, "
			   "because there is no SACL\n",
			   name.value);
		return true;
	}

	for (i = 0; i < sd->sacl->num_aces; i++) {
		struct security_ace *ace = &sd->sacl->aces[i];
		bool ok;

		if (ace->type != SEC_ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE) {
			continue;
		}
		if (strcasecmp_m(name.value,
				 ace->coda.claim.name) != 0) {
			continue;
		}
		/* this is the one */
		ok = claim_lookup_internal(mem_ctx, &ace->coda.claim, result);
		if (ok) {
			return true;
		}
	}
	DBG_NOTICE("Resource attribute ACE '%s' not found.\n",
		   name.value);
	return false;
}


static bool token_claim_lookup(
	TALLOC_CTX *mem_ctx,
	const struct security_token *token,
	const struct ace_condition_token *op,
	struct ace_condition_token *result)
{
	/*
	 * The operator has an attribute name; if there is a claim of
	 * the right type with that name, that is returned as the result.
	 *
	 * XXX what happens otherwise? NULL result?
	 */
	struct CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *claims = NULL;
	size_t num_claims;
	bool ok;
	const struct ace_condition_unicode *name = NULL;
	size_t i;

	result->type = CONDITIONAL_ACE_SAMBA_RESULT_NULL;

	switch (op->type) {
	case CONDITIONAL_ACE_LOCAL_ATTRIBUTE:
		claims = token->local_claims;
		num_claims = token->num_local_claims;
		name = &op->data.local_attr;
		break;
	case CONDITIONAL_ACE_USER_ATTRIBUTE:
		claims = token->user_claims;
		num_claims = token->num_user_claims;
		name = &op->data.user_attr;
		break;
	case CONDITIONAL_ACE_DEVICE_ATTRIBUTE:
		claims = token->device_claims;
		num_claims = token->num_device_claims;
		name = &op->data.device_attr;
		break;
	default:
		DBG_WARNING("Conditional ACE claim lookup got bad arg type %u\n",
			    op->type);
		result->type = CONDITIONAL_ACE_SAMBA_RESULT_ERROR;
		return false;
	}

	if (num_claims == 0) {
		DBG_NOTICE("There are no type %u claims\n", op->type);
		return false;
	}
	if (claims == NULL) {
		DBG_ERR("Type %u claim list unexpectedly NULL!\n", op->type);
		result->type = CONDITIONAL_ACE_SAMBA_RESULT_ERROR;
		return false;
	}
	/*
	 * Loop backwards: a later claim will override an earlier one with the
	 * same name.
	 */
	for (i = num_claims - 1; i < num_claims; i--) {
		if (claims[i].name == NULL) {
			DBG_ERR("claim %zu has no name!\n", i);
			continue;
		}
		if (strcasecmp_m(claims[i].name, name->value) == 0) {
			/* this is the one */
			ok = claim_lookup_internal(mem_ctx, &claims[i], result);
			return ok;
		}
	}
	DBG_NOTICE("Claim not found\n");
	return false;
}




static bool member_lookup(
	const struct security_token *token,
	const struct ace_condition_token *op,
	const struct ace_condition_token *arg,
	struct ace_condition_token *result)
{
	/*
	 * We need to compare the lists of SIDs in the token with the
	 * SID[s] in the argument. There are 8 combinations of
	 * operation, depending on whether we want to match all or any
	 * of the SIDs, whether we're using the device SIDs or user
	 * SIDs, and whether the operator name starts with "Not_".
	 *
	 * _MEMBER_OF               User has all operand SIDs
	 * _DEVICE_MEMBER_OF        Device has all operand SIDs
	 * _MEMBER_OF_ANY           User has one or more operand SIDs
	 * _DEVICE_MEMBER_OF_ANY    Device has one or more operand SIDs
	 *
	 * NOT_* has the effect of !(the operator without NOT_).
	 *
	 * The operand can either be a composite of SIDs or a single SID.
	 * This adds an additional branch.
	 */
	bool match = false;
	bool it_is_a_not_op;
	bool it_is_an_any_op;
	bool it_is_a_device_op;
	bool arg_is_a_single_sid;
	struct dom_sid *sid_array = NULL;
	size_t num_sids, i, j;
	const struct dom_sid *sid = NULL;

	result->type = CONDITIONAL_ACE_SAMBA_RESULT_BOOL;
	result->data.result.value = ACE_CONDITION_UNKNOWN;

	switch (arg->type) {
	case CONDITIONAL_ACE_TOKEN_SID:
		arg_is_a_single_sid = true;
		break;
	case CONDITIONAL_ACE_TOKEN_COMPOSITE:
		arg_is_a_single_sid = false;
		break;
	default:
		DBG_WARNING("Conditional ACE Member_Of got bad arg type %u\n",
			    arg->type);
		return false;
	}

	switch (op->type) {
	case CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF:
	case CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF_ANY:
		it_is_a_not_op = true;
		it_is_a_device_op = false;
		break;
	case CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF_ANY:
	case CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF:
		it_is_a_not_op = true;
		it_is_a_device_op = true;
		break;
	case CONDITIONAL_ACE_TOKEN_MEMBER_OF:
	case CONDITIONAL_ACE_TOKEN_MEMBER_OF_ANY:
		it_is_a_not_op = false;
		it_is_a_device_op = false;
		break;
	case CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF_ANY:
	case CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF:
		it_is_a_not_op = false;
		it_is_a_device_op = true;
		break;
	default:
		DBG_WARNING("Conditional ACE Member_Of got bad op type %u\n",
			    op->type);
		return false;
	}

	switch (op->type) {
	case CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF_ANY:
	case CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF_ANY:
	case CONDITIONAL_ACE_TOKEN_MEMBER_OF_ANY:
	case CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF_ANY:
		it_is_an_any_op = true;
		break;
	default:
		it_is_an_any_op = false;
	}

	if (it_is_a_device_op) {
		sid_array = token->device_sids;
		num_sids = token->num_device_sids;
	} else {
		sid_array = token->sids;
		num_sids = token->num_sids;
	}

	if (arg_is_a_single_sid) {
		/*
		 * In this case the any and all operations are the
		 * same.
		 */
		sid = &arg->data.sid.sid;
		match = false;
		for (i = 0; i < num_sids; i++) {
			match = dom_sid_equal(sid, &sid_array[i]);
			if (match) {
				break;
			}
		}
		if (it_is_a_not_op) {
			match = ! match;
		}
		if (match) {
			result->data.result.value = ACE_CONDITION_TRUE;
		} else {
			result->data.result.value = ACE_CONDITION_FALSE;
		}
		return true;
	}

	/* This is a composite list (hopefully of SIDs) */
	if (arg->data.composite.n_members == 0) {
		DBG_WARNING("Conditional ACE Member_Of argument is empty\n");
		return false;
	}

	for (j = 0; j < arg->data.composite.n_members; j++) {
		const struct ace_condition_token *member =
			&arg->data.composite.tokens[j];
		if (member->type != CONDITIONAL_ACE_TOKEN_SID) {
			DBG_WARNING("Conditional ACE Member_Of argument contains "
				    "non-sid element [%zu]: %u\n",
				    j, member->type);
			return false;
		}
		sid = &member->data.sid.sid;
		match = false;
		for (i = 0; i < num_sids; i++) {
			match = dom_sid_equal(sid, &sid_array[i]);
			if (match) {
				break;
			}
		}
		if (it_is_an_any_op) {
			if (match) {
				/* we have matched one SID, which is enough */
				goto apply_not;
			}
		} else { /* an all op */
			if (! match) {
				/* failing one is enough */
				goto apply_not;
			}
		}
	}
	/*
	 * Reaching the end of that loop means either:
	 * 1. it was an ALL op and we never failed to find one, or
	 * 2. it was an ANY op, and we didn't find one.
	 */
	match = !it_is_an_any_op;

  apply_not:
	if (it_is_a_not_op) {
		match = ! match;
	}
	if (match) {
		result->data.result.value = ACE_CONDITION_TRUE;
	} else {
		result->data.result.value = ACE_CONDITION_FALSE;
	}

	return true;
}


static bool ternary_value(
	const struct ace_condition_token *arg,
	struct ace_condition_token *result)
{
	/*
	 * Find the truth value of the argument, stored in the result token.
	 *
	 * A return value of false means the operation is invalid, and the
	 * result is undefined.
	 */
	if (arg->type == CONDITIONAL_ACE_SAMBA_RESULT_BOOL) {
		/* pass through */
		*result = *arg;
		return true;
	}

	result->type = CONDITIONAL_ACE_SAMBA_RESULT_BOOL;
	result->data.result.value = ACE_CONDITION_UNKNOWN;

	if (IS_INT_TOKEN(arg)) {
		/* zero is false */
		if (arg->data.int64.value == 0) {
			result->data.result.value = ACE_CONDITION_FALSE;
		} else {
			result->data.result.value = ACE_CONDITION_TRUE;
		}
		return true;
	}
	if (arg->type == CONDITIONAL_ACE_TOKEN_UNICODE) {
		/* empty is false */
		if (arg->data.unicode.value[0] == '\0') {
			result->data.result.value = ACE_CONDITION_FALSE;
		} else {
			result->data.result.value = ACE_CONDITION_TRUE;
		}
		return true;
	}

	/*
	 * everything else in UNKNOWN. This includes NULL values (i.e. an
	 * unsuccessful look-up).
	 */
	result->data.result.value = ACE_CONDITION_UNKNOWN;
	return true;
}

static bool not_operator(
	const struct ace_condition_token *arg,
	struct ace_condition_token *result)
{
	bool ok;
	if (IS_LITERAL_TOKEN(arg)) {
		/*
		 * Logic operators don't work on literals.
		 */
		return false;
	}

	ok = ternary_value(arg, result);
	if (! ok) {
		return false;
	}
	if (result->data.result.value == ACE_CONDITION_FALSE) {
		result->data.result.value = ACE_CONDITION_TRUE;
	} else if (result->data.result.value == ACE_CONDITION_TRUE) {
		result->data.result.value = ACE_CONDITION_FALSE;
	}
	/* unknown stays unknown */
	return true;
}


static bool unary_logic_operator(
	TALLOC_CTX *mem_ctx,
	const struct security_token *token,
	const struct ace_condition_token *op,
	const struct ace_condition_token *arg,
	const struct security_descriptor *sd,
	struct ace_condition_token *result)
{

	bool ok;
	bool found;
	struct ace_condition_token claim = {
		.type = CONDITIONAL_ACE_SAMBA_RESULT_ERROR
	};
	if (op->type == CONDITIONAL_ACE_TOKEN_NOT) {
		return not_operator(arg, result);
	}
	result->type = CONDITIONAL_ACE_SAMBA_RESULT_BOOL;
	result->data.result.value = ACE_CONDITION_UNKNOWN;

	/*
	 * Not_Exists and Exists require the same work, except we negate the
	 * answer in one case. From [MS-DTYP] 2.4.4.17.7:
	 *
	 *  If the type of the operand is "Local Attribute"
         *    If the value is non-null return TRUE
	 *    Else return FALSE
	 *  Else if the type of the operand is "Resource Attribute"
         *    Return TRUE if value is non-null; FALSE otherwise.
	 *  Else return Error
	 */
	switch (op->type) {
	case CONDITIONAL_ACE_LOCAL_ATTRIBUTE:
		ok = token_claim_lookup(mem_ctx, token, arg, &claim);
		/*
		 * "not ok" usually means a failure to find the attribute,
		 * which is the false condition and not an error.
		 *
		 * XXX or do we need an extra flag?
		 */
		break;
	case CONDITIONAL_ACE_RESOURCE_ATTRIBUTE:
		ok = resource_claim_lookup(mem_ctx, arg, sd, &claim);
		break;
	default:
		return false;
	}

	/*
	 *
	 */

	if (claim.type != CONDITIONAL_ACE_SAMBA_RESULT_NULL) {
		found = true;
	} else if (ok) {
		found = false;
	} else {
		return false;
	}



	if (op->type == CONDITIONAL_ACE_TOKEN_NOT_EXISTS) {
		found = ! found;
	} else if (op->type != CONDITIONAL_ACE_TOKEN_EXISTS) {
		/* should not get here */
		return false;
	}

	result->data.result.value = found ? ACE_CONDITION_TRUE: ACE_CONDITION_FALSE;
	return true;
}



static bool binary_logic_operator(
	const struct security_token *token,
	const struct ace_condition_token *op,
	const struct ace_condition_token *lhs,
	const struct ace_condition_token *rhs,
	struct ace_condition_token *result)
{
	struct ace_condition_token at, bt;
	int a, b;
	bool ok;

	result->type = CONDITIONAL_ACE_SAMBA_RESULT_BOOL;
	result->data.result.value = ACE_CONDITION_UNKNOWN;

	if (IS_LITERAL_TOKEN(lhs) || IS_LITERAL_TOKEN(rhs)) {
		/*
		 * Logic operators don't work on literals.
		 */
		return false;
	}

	ok = ternary_value(lhs, &at);
	if (! ok) {
		return false;
	}
	ok = ternary_value(rhs, &bt);
	if (! ok) {
		return false;
	}
	a = at.data.result.value;
	b = bt.data.result.value;

	if (op->type == CONDITIONAL_ACE_TOKEN_AND) {
		/*
		 *   AND   true   false  unknown
		 *  true     T      F      ?
		 *  false    F      F      F
		 *  unknown  ?      F      ?
		 *
		 * unknown unless BOTH true or EITHER false
		 */
		if (a == ACE_CONDITION_TRUE &&
		    b == ACE_CONDITION_TRUE) {
			result->data.result.value = ACE_CONDITION_TRUE;
			return true;
		}
		if (a == ACE_CONDITION_FALSE ||
		    b == ACE_CONDITION_FALSE) {
			result->data.result.value = ACE_CONDITION_FALSE;
			return true;
		}
		/*
		 * Neither value is False, so the result is Unknown,
		 * as set at the start of this function.
		 */
		return true;
	}
	/*
	 *   OR    true   false  unknown
	 *  true     T      T      T
	 *  false    T      F      ?
	 *  unknown  T      ?      ?
	 *
	 * unknown unless EITHER true or BOTH false
	 */
	if (a == ACE_CONDITION_TRUE ||
	    b == ACE_CONDITION_TRUE) {
			result->data.result.value = ACE_CONDITION_TRUE;
			return true;
	}
	if (a == ACE_CONDITION_FALSE &&
	    b == ACE_CONDITION_FALSE) {
		result->data.result.value = ACE_CONDITION_FALSE;
		return true;
	}
	return true;
}


static bool tokens_are_comparable(const struct ace_condition_token *op,
				  const struct ace_condition_token *lhs,
				  const struct ace_condition_token *rhs)
{
	uint64_t n;
	/*
	 * we can't compare different types *unless* they are both
	 * integers, or one is a bool and the other is an integer 0 or
	 * 1, and the operator is == or != (or NULL, which for convenience,
	 * is treated as ==).
	 */
	//XXX actually it says "literal integers", do we need to check flags?
	if (lhs->type == rhs->type) {
		return true;
	}

	if (IS_INT_TOKEN(lhs) && IS_INT_TOKEN(rhs)) {
		/* don't block e.g. comparing an int32 to an int64 */
		return true;
	}

	/* is it == or != */
	if (op != NULL &&
	    op->type != CONDITIONAL_ACE_TOKEN_EQUAL &&
	    op->type != CONDITIONAL_ACE_TOKEN_NOT_EQUAL) {
		return false;
	}
	/* is one a bool and the other an int? */
	if (IS_INT_TOKEN(lhs) && IS_BOOL_TOKEN(rhs)) {
		n = lhs->data.int64.value;
	} else if (IS_INT_TOKEN(rhs) && IS_BOOL_TOKEN(lhs)) {
		n = rhs->data.int64.value;
	} else {
		return false;
	}
	if (n == 0 || n == 1) {
		return true;
	}
	return false;
}


static bool cmp_to_result(const struct ace_condition_token *op,
			  struct ace_condition_token *result,
			  int cmp)
{
	bool answer;
	switch (op->type) {
	case CONDITIONAL_ACE_TOKEN_EQUAL:
		answer = cmp == 0;
		break;
	case CONDITIONAL_ACE_TOKEN_NOT_EQUAL:
		answer = cmp != 0;
		break;
	case CONDITIONAL_ACE_TOKEN_LESS_THAN:
		answer = cmp < 0;
		break;
	case CONDITIONAL_ACE_TOKEN_LESS_OR_EQUAL:
		answer = cmp <= 0;
		break;
	case CONDITIONAL_ACE_TOKEN_GREATER_THAN:
		answer = cmp > 0;
		break;
	case CONDITIONAL_ACE_TOKEN_GREATER_OR_EQUAL:
		answer = cmp >= 0;
		break;
	default:
		result->data.result.value = ACE_CONDITION_UNKNOWN;
		return false;
	}
	result->data.result.value = \
		answer ? ACE_CONDITION_TRUE : ACE_CONDITION_FALSE;
	return true;
}



static bool compare_unicode(const struct ace_condition_token *op,
			    const struct ace_condition_token *lhs,
			    const struct ace_condition_token *rhs,
			    int *cmp)
{
	struct ace_condition_unicode a = lhs->data.unicode;
	struct ace_condition_unicode b = rhs->data.unicode;
	/*
	 * Comparison is case-insensitive UNLESS the claim structure
	 * has the case-sensitive flag, which is passed through as a
	 * flag on the token. Usually only the LHS is a claim value,
	 * but in the event that they both are, we allow either to
	 * request case-sensitivity.
	 *
	 * For greater than and less than, the sort order is utf-8 order,
	 * which is not exactly what Windows does, but we don't sort like
	 * Windows does anywhere else either.
	 */
	uint8_t flags = lhs->flags | rhs->flags;
	if (flags & CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE) {
		*cmp = strcmp(a.value, b.value);
	} else {
		*cmp = strcasecmp_m(a.value, b.value);
	}
	return true;
}


static bool compare_bytes(const struct ace_condition_token *op,
			  const struct ace_condition_token *lhs,
			  const struct ace_condition_token *rhs,
			  int *cmp)
{
	DATA_BLOB a = lhs->data.bytes;
	DATA_BLOB b = rhs->data.bytes;
	*cmp = data_blob_cmp(&a, &b);
	return true;
}


static bool compare_sids(const struct ace_condition_token *op,
			 const struct ace_condition_token *lhs,
			 const struct ace_condition_token *rhs,
			 int *cmp)
{
	*cmp = dom_sid_compare(&lhs->data.sid.sid,
			       &rhs->data.sid.sid);
	return true;
}


static bool compare_ints(const struct ace_condition_token *op,
			 const struct ace_condition_token *lhs,
			 const struct ace_condition_token *rhs,
			 int *cmp)
{
	int64_t a = lhs->data.int64.value;
	int64_t b = rhs->data.int64.value;

	if (a < b) {
		*cmp = -1;
	} else if (a == b) {
		*cmp = 0;
	} else {
		*cmp = 1;
	}
	return true;
}


static bool compare_bools(const struct ace_condition_token *op,
			  const struct ace_condition_token *lhs,
			  const struct ace_condition_token *rhs,
			  int *cmp)
{
	bool ok;
	struct ace_condition_token a, b;
	*cmp = -1;

	if (IS_LITERAL_TOKEN(lhs)) {
		/*
		 * we can compare a boolean LHS to a literal RHS, but not
		 * vice versa
		 */
		return false;
	}
	ok = ternary_value(lhs, &a);
	if (! ok) {
		return false;
	}
	ok = ternary_value(rhs, &b);
	if (! ok) {
		return false;
	}
	if (a.data.result.value == ACE_CONDITION_UNKNOWN ||
	    b.data.result.value == ACE_CONDITION_UNKNOWN) {
		return false;
	}

	switch (op->type) {
	case CONDITIONAL_ACE_TOKEN_EQUAL:
	case CONDITIONAL_ACE_TOKEN_NOT_EQUAL:
		*cmp = a.data.result.value - b.data.result.value;
		break;
	default:
		/* we are not allowing non-equality comparisons with bools */
		return false;
	}
	return true;
}


static bool simple_relational_operator(const struct ace_condition_token *op,
				       const struct ace_condition_token *lhs,
				       const struct ace_condition_token *rhs,
				       int *cmp);


struct composite_sort_context {
	bool failed;
};

static int composite_sort_cmp(const struct ace_condition_token *lhs,
			      const struct ace_condition_token *rhs,
			      struct composite_sort_context *ctx)
{
	bool ok;
	int cmp = -1;
	/*
	 * simple_relational_operator uses the operator token only to
	 * decide whether the comparison is allowed for the type. In
	 * particular, boolean result and composite arguments can only
	 * be used with equality operators. We want those to fail (we
	 * should not see them here, remembering that claim booleans
	 * become composite integers), so we use a non-equality op.
	 */
	static const struct ace_condition_token op = {
		.type = CONDITIONAL_ACE_TOKEN_LESS_THAN
	};

	ok = simple_relational_operator(&op, lhs, rhs, &cmp);
	if (ok) {
		return cmp;
	}
	/*
	 * This sort isn't going to work out, but the sort function
	 * will only find out at the end.
	 */
	ctx->failed = true;
	return cmp;
}


/*
 * Return a sorted copy of the composite tokens array.
 *
 * The copy is shallow, so the actual string pointers are the same, which is
 * fine for the purposes of comparison.
 */

static struct ace_condition_token *composite_sorted_copy(
	TALLOC_CTX *mem_ctx,
	const struct ace_condition_composite *c,
	bool case_sensitive)
{
	struct ace_condition_token *copy = NULL;
	bool ok;
	size_t  i;
	struct composite_sort_context sort_ctx = {
		.failed = false
	};

	/*
	 * Case sensitivity is a bit tricky. Each token can have a flag saying
	 * it should be sorted case-sensitively and when comparing two tokens,
	 * we should respect this flag on either side. The flag can only come
	 * from claims (including resource attribute ACEs), and as there is only
	 * one flag per claim, it must apply the same to all members (in fact we
	 * don't set it on the members, only the composite). So to be sure we
	 * sort in the way we want, we might need to set the flag on all the
	 * members of the copy *before* sorting it.
	 *
	 * When it comes to comparing two composites, we want to be
	 * case-sensitive if either side has the flag. This can have odd
	 * effects. Think of these RA claims:
	 *
	 *   (RA;;;;;WD;("foo",TS,0,"a","A"))
	 *   (RA;;;;;WD;("bar",TS,2,"a","A"))    <-- 2 is the case-sensitive flag
	 *   (RA;;;;;WD;("baz",TS,0,"a"))
	 *
	 * (@Resource.foo == @Resource.bar) is true
	 * (@Resource.bar == @Resource.foo) is true
	 * (@Resource.bar == @Resource.bar) is true
	 * (@Resource.foo == @Resource.foo) is an error (duplicate values on LHS)
	 * (@Resource.baz == @Resource.foo) is true (RHS case-folds down)
	 * (@Resource.baz == @Resource.bar) is false
	 * (@Resource.bar == {"A", "a"})    is true
	 * (@Resource.baz == {"A", "a"})    is true
	 * (@Resource.foo == {"A", "a"})    is an error
	 */
	copy = talloc_array(mem_ctx, struct ace_condition_token, c->n_members);
	if (copy == NULL) {
		return NULL;
	}
	memcpy(copy, c->tokens, sizeof(struct ace_condition_token) * c->n_members);

	if (case_sensitive) {
		for (i = 0; i < c->n_members; i++) {
			c->tokens[i].flags |= CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;
		}
	}

	ok =  stable_sort_talloc_r(mem_ctx,
				   copy,
				   c->n_members,
				   sizeof(struct ace_condition_token),
				   (samba_compare_with_context_fn_t)composite_sort_cmp,
				   &sort_ctx);

	if (!ok || sort_ctx.failed) {
		DBG_NOTICE("composite sort of %"PRIu32" members failed\n",
			   c->n_members);
		TALLOC_FREE(copy);
		return NULL;
	}
	return copy;
}


/*
 * This is a helper for compare composites.
 */
static bool compare_composites_via_sort(const struct ace_condition_token *lhs,
					const struct ace_condition_token *rhs,
					int *cmp)
{
	const struct ace_condition_composite *lc = &lhs->data.composite;
	const struct ace_condition_composite *rc = &rhs->data.composite;
	size_t i;
	TALLOC_CTX *tmp_ctx = NULL;
	bool ok;
	int cmp_pair;
	bool case_sensitive, rhs_case_sensitive;
	bool rhs_sorted;
	struct ace_condition_token *ltok = lc->tokens;
	struct ace_condition_token *rtok = rc->tokens;
	static const struct ace_condition_token eq = {
		.type = CONDITIONAL_ACE_TOKEN_EQUAL
	};
	*cmp = -1;
	if (lc->n_members == 0 ||
	    rc->n_members < lc->n_members) {
		/* we should not have got this far */
		return false;
	}

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return false;
	}

	case_sensitive = lhs->flags & CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;
	rhs_case_sensitive = rhs->flags & CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE;
	rhs_sorted = rhs->flags & CLAIM_SECURITY_ATTRIBUTE_UNIQUE_AND_SORTED;

	if (lc->tokens[0].type != CONDITIONAL_ACE_TOKEN_UNICODE) {
		/*
		 * All LHS tokens are the same type (because it is a
		 * claim), and that type is not one that cares about
		 * case, so nor do we.
		 */
		case_sensitive = false;
	} else if (case_sensitive == rhs_case_sensitive) {
		/* phew, no extra work */
	} else if (case_sensitive) {
		/* trigger a sorted copy */
		rhs_sorted = false;
	} else if (rhs_case_sensitive) {
		/*
		 * Do we need to rescan for uniqueness, given the new
		 * comparison function? No! The strings were already
		 * unique in the looser comparison, and now they can
		 * only be more so. The number of unique values can't
		 * change, just their order.
		 */
		case_sensitive = true;
		ltok = composite_sorted_copy(tmp_ctx, lc, case_sensitive);
		if (ltok == NULL) {
			DBG_WARNING("sort of LHS failed\n");
			goto error;
		}
	}

	if (! rhs_sorted) {
		/*
		 * we need an RHS sorted copy (it's a literal, or
		 * there was a case sensitivity disagreement).
		 */
		rtok = composite_sorted_copy(tmp_ctx, rc, case_sensitive);
		if (rtok == NULL) {
			DBG_WARNING("sort of RHS failed\n");
			goto error;
		}
	}
	/*
	 * Each member of LHS must match one or more members of RHS.
	 * Each member of RHS must match at least one of LHS.
	 *
	 * If they are the same length we can compare directly, so let's get
	 * rid of duplicates in RHS. This can only happen with literal
	 * composites.
	 */
	if (rc->n_members > lc->n_members) {
		size_t gap = 0;
		for (i = 1; i < rc->n_members; i++) {
			ok = simple_relational_operator(&eq,
							&rtok[i - 1],
							&rtok[i],
							&cmp_pair);
			if (! ok) {
				goto error;
			}
			if (cmp_pair == 0) {
				gap++;
			}
			if (gap != 0) {
				rtok[i - gap] = rtok[i];
			}
		}
		if (rc->n_members - lc->n_members != gap) {
			/*
			 * There were too many or too few duplicates to account
			 * for the difference, and no further comparison is
			 * necessary.
			 */
			goto not_equal;
		}
	}
	/*
	 * OK, now we know LHS and RHS are the same length and sorted in the
	 * same way, so we can just iterate over them and check each pair.
	 */

	for (i = 0; i < lc->n_members; i++) {
		ok = simple_relational_operator(&eq,
						&ltok[i],
						&rtok[i],
						&cmp_pair);
		if (! ok){
			goto error;
		}
		if (cmp_pair != 0) {
			goto not_equal;
		}
	}

	*cmp = 0;

not_equal:
	TALLOC_FREE(tmp_ctx);
	return true;
error:
	TALLOC_FREE(tmp_ctx);
	return false;
}


static bool composite_is_comparable(const struct ace_condition_token *tok,
				    const struct ace_condition_token *comp)
{
	/*
	 * Are all members of the composite comparable to the token?
	 */
	size_t i;
	const struct ace_condition_composite *rc = &comp->data.composite;
	size_t n = rc->n_members;

	if ((comp->flags & CLAIM_SECURITY_ATTRIBUTE_UNIQUE_AND_SORTED) &&
	    n > 1) {
		/*
		 * all members are known to be the same type, so we
		 * can just check one.
		 */
		n = 1;
	}

	for (i = 0; i < n; i++) {
		if (! tokens_are_comparable(NULL,
					    tok,
					    &rc->tokens[i])) {
			DBG_NOTICE("token type %u !=  composite type %u\n",
				   tok->type, rc->tokens[i].type);
			return false;
		}
	}
	return true;
}


static bool compare_composites(const struct ace_condition_token *op,
			       const struct ace_condition_token *lhs,
			       const struct ace_condition_token *rhs,
			       int *cmp)
{
	/*
	 * This is for comparing multivalued sets, which includes
	 * conditional ACE composites and claim sets. Because these
	 * are sets, there are no < and > operations, just equality or
	 * otherwise.
	 *
	 * Claims are true sets, while composites are multisets --
	 * duplicate values are allowed -- but these are reduced to
	 * sets in evaluation, and the number of duplicates has no
	 * effect in comparisons. Resource attribute ACEs live in an
	 * intermediate state -- they can contain duplicates on the
	 * wire and as ACE structures, but as soon as they are
	 * evaluated as claims their values must be unique. Windows
	 * will treat RA ACEs with duplicate values as not existing,
	 * rather than as UNKNOWN (This is significant for the Exists
	 * operator). Claims can have a case-sensitive flags set,
	 * meaning they must be compared case-sensitively.
	 *
	 * Some good news is that the LHS of a comparison must always
	 * be a claim. That means we can assume it has unique values
	 * when it comes to pairwise comparisons. Using the magic of
	 * flags, we try to check this only once per claim.
	 *
	 * Conditional ACE composites, which can have duplicates (and
	 * mixed types), can only be on the RHS.
	 *
	 * To summarise:
	 *
	 * {a, b}    vs {a, b}        equal
	 * { }       vs { }           equal
	 * {a, b}    vs {b, a}        equal
	 * {a, b}    vs {a, c}        not equal
	 * {a, b}    vs {a, a, b}     equal
	 * {b, a}    vs {a, b, a}     equal
	 * {a, b}    vs {a, a, b, c}  not equal
	 * {a, b, a} vs {a, b}        should not happen, error
	 * {a, b, a} vs {a, b, a}     should not happen, error
	 *
	 * mixed types:
	 * {1, 2}    vs {1, "2"}      error
	 * {1, "2"}  vs {1, "2"}      should not happen, error
	 *
	 * case sensitivity (*{ }* indicates case-sensitive flag):
	 *
	 *  {"a", "b"}  vs  {"a", "B"}      equal
	 *  {"a", "b"}  vs *{"a", "B"}*     not equal
	 * *{"a", "b"}* vs  {"a", "B"}      not equal
	 * *{"a", "A"}* vs  {"a", "A"}      equal (if RHS is composite)
	 *  {"a", "A"}  vs *{"a", "A"}*     impossible (LHS is not unique)
	 * *{"a"}*      vs  {"a", "A"}      not equal
	 *
	 * The naive approach is of course O(n * m) with an additional O(n²)
	 * if the LHS values are not known to be unique (that is, in resource
	 * attribute claims). We want to avoid that with big sets.
	 */
	const struct ace_condition_composite *lc = &lhs->data.composite;
	const struct ace_condition_composite *rc = &rhs->data.composite;
	bool ok;

	if (!(lhs->flags & CLAIM_SECURITY_ATTRIBUTE_UNIQUE_AND_SORTED)) {
		/*
		 * The LHS needs to be a claim, and it should have gone
		 * through claim_v1_check_and_sort() to get here.
		 */
		*cmp = -1;
		return false;
	}

	/* if one or both are empty, the answer is easy */
	if (lc->n_members == 0) {
		if (rc->n_members == 0) {
			*cmp = 0;
			return true;
		}
		*cmp = -1;
		return true;
	}
	if (rc->n_members == 0) {
		*cmp = -1;
		return true;
	}

	/*
	 * LHS must be a claim, so it must be unique, so if there are
	 * fewer members on the RHS, we know they can't be equal.
	 *
	 * If you think about it too much, you might think this is
	 * affected by case sensitivity, but it isn't. One side can be
	 * infected by case-sensitivity by the other, but that can't
	 * shrink the number of elements on the RHS -- it can only
	 * make a literal {"a", "A"} have effective length 2 rather
	 * than 1.
	 *
	 * On the other hand, if the RHS is case sensitive, it must be
	 * a claim and unique in its own terms, and its finer-grained
	 * distinctions can't collapse members of the case sensitive
	 * LHS.
	 */
	if (lc->n_members > rc->n_members) {
		*cmp = -1;
		return composite_is_comparable(&lc->tokens[0], rhs);
	}

	/*
	 * It *could* be that RHS is also unique and we know it. In that
	 * case we can short circuit if RHS has more members. This is
	 * the case when both sides are claims.
	 *
	 * This is also not affected by case-senstivity.
	 */
	if (lc->n_members < rc->n_members &&
	    (rhs->flags & CLAIM_SECURITY_ATTRIBUTE_UNIQUE_AND_SORTED)) {
		*cmp = -1;
		return composite_is_comparable(&lc->tokens[0], rhs);
	}

	ok = compare_composites_via_sort(lhs, rhs, cmp);
	if (! ok) {
		return false;
	}
	return true;
}


static bool simple_relational_operator(const struct ace_condition_token *op,
				       const struct ace_condition_token *lhs,
				       const struct ace_condition_token *rhs,
				       int *cmp)

{
	if (lhs->type != rhs->type) {
		if (! tokens_are_comparable(op, lhs, rhs)) {
			return false;
		}
	}
	switch (lhs->type) {
	case CONDITIONAL_ACE_TOKEN_INT8:
	case CONDITIONAL_ACE_TOKEN_INT16:
	case CONDITIONAL_ACE_TOKEN_INT32:
	case CONDITIONAL_ACE_TOKEN_INT64:
		if (rhs->type == CONDITIONAL_ACE_SAMBA_RESULT_BOOL) {
			return compare_bools(op, lhs, rhs, cmp);
		}
		return compare_ints(op, lhs, rhs, cmp);
	case CONDITIONAL_ACE_SAMBA_RESULT_BOOL:
		return compare_bools(op, lhs, rhs, cmp);
	case CONDITIONAL_ACE_TOKEN_UNICODE:
		return compare_unicode(op, lhs, rhs, cmp);
	case CONDITIONAL_ACE_TOKEN_OCTET_STRING:
		return compare_bytes(op, lhs, rhs, cmp);
	case CONDITIONAL_ACE_TOKEN_SID:
		return compare_sids(op, lhs, rhs, cmp);
	case CONDITIONAL_ACE_TOKEN_COMPOSITE:
		return compare_composites(op, lhs, rhs, cmp);
	case CONDITIONAL_ACE_SAMBA_RESULT_NULL:
		/* leave the result unknown */
		return false;
	default:
		DBG_ERR("did not expect ace type %u\n", lhs->type);
		return false;
	}

	return false;
}


static bool find_in_composite(const struct ace_condition_token *tok,
			      struct ace_condition_composite candidates,
			      bool *answer)
{
	size_t i;
	int cmp;
	bool ok;
	const struct ace_condition_token equals = {
		.type = CONDITIONAL_ACE_TOKEN_EQUAL
	};

	*answer = false;

	for (i = 0; i < candidates.n_members; i++) {
		ok = simple_relational_operator(&equals,
						tok,
						&candidates.tokens[i],
						&cmp);
		if (! ok) {
			return false;
		}
		if (cmp == 0) {
			*answer = true;
			return true;
		}
	}
	return true;
}


static bool contains_operator(const struct ace_condition_token *lhs,
			      const struct ace_condition_token *rhs,
			      bool *answer)
{
	size_t i;
	bool ok;
	int cmp;
	const struct ace_condition_token equals = {
		.type = CONDITIONAL_ACE_TOKEN_EQUAL
	};

	/*
	 * All the required objects must be identical to something in
	 * candidates. But what do we mean by *identical*? We'll use
	 * the equality operator to decide that.
	 *
	 * Both the lhs or rhs can be solitary objects or composites.
	 * This makes it a bit fiddlier.
	 *
	 * NOTE: this operator does not take advantage of the
	 * CLAIM_SECURITY_ATTRIBUTE_UNIQUE_AND_SORTED flag. It could, but it
	 * doesn't.
	 */
	if (lhs->type == CONDITIONAL_ACE_TOKEN_COMPOSITE) {
		struct ace_condition_composite candidates = lhs->data.composite;
		struct ace_condition_composite required;
		if (rhs->type != CONDITIONAL_ACE_TOKEN_COMPOSITE) {
			return find_in_composite(rhs, candidates, answer);
		}
		required = rhs->data.composite;
		if (required.n_members == 0) {
			return false;
		}
		for (i = 0; i < required.n_members; i++) {
			const struct ace_condition_token *t = &required.tokens[i];
			ok = find_in_composite(t, candidates, answer);
			if (! ok) {
				return false;
			}
			if (! *answer) {
				/*
				 * one required item was not there,
				 * *answer is false
				 */
				return true;
			}
		}
		/* all required items are there, *answer will be true */
		return true;
	}
	/* LHS is a single item */
	if (rhs->type == CONDITIONAL_ACE_TOKEN_COMPOSITE) {
		/*
		 * There could be more than one RHS member that is
		 * equal to the single LHS value, so it doesn't help
		 * to compare lengths or anything.
		 */
		struct ace_condition_composite required = rhs->data.composite;
		if (required.n_members == 0) {
			return false;
		}
		for (i = 0; i < required.n_members; i++) {
			ok = simple_relational_operator(&equals,
							lhs,
							&required.tokens[i],
							&cmp);
			if (! ok) {
				return false;
			}
			if (cmp != 0) {
				/*
				 * one required item was not there,
				 * *answer is false
				 */
				*answer = false;
				return true;
			}
		}
		*answer = true;
		return true;
	}
	/* LHS and RHS are both single */
	ok = simple_relational_operator(&equals,
					lhs,
					rhs,
					&cmp);
	if (! ok) {
		return false;
	}
	*answer = (cmp == 0);
	return true;
}


static bool any_of_operator(const struct ace_condition_token *lhs,
			    const struct ace_condition_token *rhs,
			    bool *answer)
{
	size_t i;
	bool ok;
	int cmp;
	const struct ace_condition_token equals = {
		.type = CONDITIONAL_ACE_TOKEN_EQUAL
	};

	/*
	 * There has to be *some* overlap between the LHS and RHS.
	 * Both sides can be solitary objects or composites.
	 *
	 * We can exploit this symmetry.
	 */
	if (lhs->type != CONDITIONAL_ACE_TOKEN_COMPOSITE) {
		const struct ace_condition_token *tmp = lhs;
		lhs = rhs;
		rhs = tmp;
	}
	if (lhs->type != CONDITIONAL_ACE_TOKEN_COMPOSITE) {
		/* both singles */
		ok = simple_relational_operator(&equals,
						lhs,
						rhs,
						&cmp);
		if (! ok) {
			return false;
		}
		*answer = (cmp == 0);
		return true;
	}
	if (rhs->type != CONDITIONAL_ACE_TOKEN_COMPOSITE) {
		return find_in_composite(rhs, lhs->data.composite, answer);
	}
	/* both are composites */
	if (lhs->data.composite.n_members == 0) {
		return false;
	}
	for (i = 0; i < lhs->data.composite.n_members; i++) {
		ok = find_in_composite(&lhs->data.composite.tokens[i],
				       rhs->data.composite,
				       answer);
		if (! ok) {
			return false;
		}
		if (*answer) {
			/* We have found one match, which is enough. */
			return true;
		}
	}
	return true;
}


static bool composite_relational_operator(const struct ace_condition_token *op,
					  const struct ace_condition_token *lhs,
					  const struct ace_condition_token *rhs,
					  struct ace_condition_token *result)
{
	bool ok, answer;
	switch(op->type) {
	case CONDITIONAL_ACE_TOKEN_CONTAINS:
	case CONDITIONAL_ACE_TOKEN_NOT_CONTAINS:
		ok = contains_operator(lhs, rhs, &answer);
		break;
	case CONDITIONAL_ACE_TOKEN_ANY_OF:
	case CONDITIONAL_ACE_TOKEN_NOT_ANY_OF:
		ok = any_of_operator(lhs, rhs, &answer);
		break;
	default:
		return false;
	}
	if (!ok) {
		return false;
	}

	/* negate the NOTs */
	if (op->type == CONDITIONAL_ACE_TOKEN_NOT_CONTAINS ||
	    op->type == CONDITIONAL_ACE_TOKEN_NOT_ANY_OF)
	{
		answer = !answer;
	}

	if (answer) {
		result->data.result.value = ACE_CONDITION_TRUE;
	} else {
		result->data.result.value = ACE_CONDITION_FALSE;
	}
	return true;
}


static bool relational_operator(
	const struct security_token *token,
	const struct ace_condition_token *op,
	const struct ace_condition_token *lhs,
	const struct ace_condition_token *rhs,
	struct ace_condition_token *result)
{
	int cmp;
	bool ok;
	result->type = CONDITIONAL_ACE_SAMBA_RESULT_BOOL;
	result->data.result.value = ACE_CONDITION_UNKNOWN;

	if ((lhs->flags & CONDITIONAL_ACE_FLAG_TOKEN_FROM_ATTR) == 0) {
		/* LHS was not derived from an attribute */
		return false;
	}

	/*
	 * This first nested switch is ensuring that >, >=, <, <= are
	 * not being tried on tokens that are not numbers, strings, or
	 * octet strings. Equality operators are available for all types.
	 */
	switch (lhs->type) {
	case CONDITIONAL_ACE_TOKEN_INT8:
	case CONDITIONAL_ACE_TOKEN_INT16:
	case CONDITIONAL_ACE_TOKEN_INT32:
	case CONDITIONAL_ACE_TOKEN_INT64:
	case CONDITIONAL_ACE_TOKEN_UNICODE:
	case CONDITIONAL_ACE_TOKEN_OCTET_STRING:
		break;
	default:
		switch(op->type) {
		case CONDITIONAL_ACE_TOKEN_LESS_THAN:
		case CONDITIONAL_ACE_TOKEN_LESS_OR_EQUAL:
		case CONDITIONAL_ACE_TOKEN_GREATER_THAN:
		case CONDITIONAL_ACE_TOKEN_GREATER_OR_EQUAL:
			return false;
		default:
			break;
		}
	}

	/*
	 * Dispatch according to operator type.
	 */
	switch (op->type) {
	case CONDITIONAL_ACE_TOKEN_EQUAL:
	case CONDITIONAL_ACE_TOKEN_NOT_EQUAL:
	case CONDITIONAL_ACE_TOKEN_LESS_THAN:
	case CONDITIONAL_ACE_TOKEN_LESS_OR_EQUAL:
	case CONDITIONAL_ACE_TOKEN_GREATER_THAN:
	case CONDITIONAL_ACE_TOKEN_GREATER_OR_EQUAL:
		ok = simple_relational_operator(op,
						lhs,
						rhs,
						&cmp);
		if (ok) {
			ok = cmp_to_result(op, result, cmp);
		}
		return ok;

	case CONDITIONAL_ACE_TOKEN_CONTAINS:
	case CONDITIONAL_ACE_TOKEN_ANY_OF:
	case CONDITIONAL_ACE_TOKEN_NOT_CONTAINS:
	case CONDITIONAL_ACE_TOKEN_NOT_ANY_OF:
		return composite_relational_operator(op,
						     lhs,
						     rhs,
						     result);
	default:
		return false;
	}
}


int run_conditional_ace(TALLOC_CTX *mem_ctx,
			const struct security_token *token,
			struct ace_condition_script *program,
			const struct security_descriptor *sd)
{
	size_t i;
	size_t depth = 0;
	struct ace_condition_token *lhs = NULL;
	struct ace_condition_token *rhs = NULL;
	struct ace_condition_token result = {};
	struct ace_condition_token *stack = NULL;
	bool ok;

	/*
	 * When interpreting the program we will need a stack, which in the
	 * very worst case can be as deep as the program is long.
	 */
	stack = talloc_array(mem_ctx,
			     struct ace_condition_token,
			     program->length + 1);
	if (stack == NULL) {
		goto error;
	}

	for (i = 0; i < program->length; i++) {
		struct ace_condition_token *tok = &program->tokens[i];
		switch (tok->type) {
		case CONDITIONAL_ACE_TOKEN_INT8:
		case CONDITIONAL_ACE_TOKEN_INT16:
		case CONDITIONAL_ACE_TOKEN_INT32:
		case CONDITIONAL_ACE_TOKEN_INT64:
		case CONDITIONAL_ACE_TOKEN_UNICODE:
		case CONDITIONAL_ACE_TOKEN_OCTET_STRING:
		case CONDITIONAL_ACE_TOKEN_SID:
		case CONDITIONAL_ACE_TOKEN_COMPOSITE:
		/* just plonk these literals on the stack */
			stack[depth] = *tok;
			depth++;
			break;

		case CONDITIONAL_ACE_LOCAL_ATTRIBUTE:
		case CONDITIONAL_ACE_USER_ATTRIBUTE:
		case CONDITIONAL_ACE_DEVICE_ATTRIBUTE:
			ok = token_claim_lookup(mem_ctx, token, tok, &result);
			if (! ok) {
				goto error;
			}
			stack[depth] = result;
			depth++;
			break;

		case CONDITIONAL_ACE_RESOURCE_ATTRIBUTE:
			ok = resource_claim_lookup(mem_ctx,
						   tok,
						   sd,
						   &result);
			if (! ok) {
				goto error;
			}
			stack[depth] = result;
			depth++;
			break;

		case CONDITIONAL_ACE_TOKEN_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF_ANY:
			if (depth == 0) {
				goto error;
			}
			depth--;
			lhs = &stack[depth];
			ok = member_lookup(token, tok, lhs, &result);
			if (! ok) {
				goto error;
			}
			stack[depth] = result;
			depth++;
			break;
		/* binary relational operators */
		case CONDITIONAL_ACE_TOKEN_EQUAL:
		case CONDITIONAL_ACE_TOKEN_NOT_EQUAL:
		case CONDITIONAL_ACE_TOKEN_LESS_THAN:
		case CONDITIONAL_ACE_TOKEN_LESS_OR_EQUAL:
		case CONDITIONAL_ACE_TOKEN_GREATER_THAN:
		case CONDITIONAL_ACE_TOKEN_GREATER_OR_EQUAL:
		case CONDITIONAL_ACE_TOKEN_CONTAINS:
		case CONDITIONAL_ACE_TOKEN_ANY_OF:
		case CONDITIONAL_ACE_TOKEN_NOT_CONTAINS:
		case CONDITIONAL_ACE_TOKEN_NOT_ANY_OF:
			if (depth < 2) {
				goto error;
			}
			depth--;
			rhs = &stack[depth];
			depth--;
			lhs = &stack[depth];
			ok = relational_operator(token, tok, lhs, rhs, &result);
			if (! ok) {
				goto error;
			}
			stack[depth] = result;
			depth++;
			break;
		/* unary logical operators */
		case CONDITIONAL_ACE_TOKEN_EXISTS:
		case CONDITIONAL_ACE_TOKEN_NOT_EXISTS:
		case CONDITIONAL_ACE_TOKEN_NOT:
			if (depth == 0) {
				goto error;
			}
			depth--;
			lhs = &stack[depth];
			ok = unary_logic_operator(mem_ctx, token, tok, lhs, sd, &result);
			if (!ok) {
				goto error;
			}
			stack[depth] = result;
			depth++;
			break;
		/* binary logical operators */
		case CONDITIONAL_ACE_TOKEN_AND:
		case CONDITIONAL_ACE_TOKEN_OR:
			if (depth < 2) {
				goto error;
			}
			depth--;
			rhs = &stack[depth];
			depth--;
			lhs = &stack[depth];
			ok = binary_logic_operator(token, tok, lhs, rhs, &result);
			if (! ok) {
				goto error;
			}
			stack[depth] = result;
			depth++;
			break;
		default:
			goto error;
		}
	}
	/*
	 * The evaluation should have left a single result value (true, false,
	 * or unknown) on the stack. If not, the expression was malformed.
	 */
	if (depth != 1) {
		goto error;
	}
	result = stack[0];
	if (result.type != CONDITIONAL_ACE_SAMBA_RESULT_BOOL) {
		goto error;
	}
	TALLOC_FREE(stack);
	return result.data.result.value;

  error:
	/*
	 * the result of an error is always UNKNOWN, which should be
	 * interpreted pessimistically, not allowing access.
	 */
	TALLOC_FREE(stack);
	return ACE_CONDITION_UNKNOWN;
}


/** access_check_conditional_ace()
 *
 * Run the conditional ACE from the blob form. Return false if it is
 * not a valid conditional ACE, true if it is, even if there is some
 * other error in running it. The *result parameter is set to
 * ACE_CONDITION_FALSE, ACE_CONDITION_TRUE, or ACE_CONDITION_UNKNOWN.
 *
 * ACE_CONDITION_UNKNOWN should be treated pessimistically, as if it were
 * TRUE for deny ACEs, and FALSE for allow ACEs.
 *
 * @param[in] ace - the ACE being processed.
 * @param[in] token - the security token the ACE is processing.
 * @param[out] result - a ternary result value.
 *
 * @return true if it is a valid conditional ACE.
 */

bool access_check_conditional_ace(const struct security_ace *ace,
				  const struct security_token *token,
				  const struct security_descriptor *sd,
				  int *result)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	struct ace_condition_script *program = NULL;
	program = parse_conditional_ace(tmp_ctx, ace->coda.conditions);
	if (program == NULL) {
		*result = ACE_CONDITION_UNKNOWN;
		TALLOC_FREE(tmp_ctx);
		return false;
	}

	*result = run_conditional_ace(tmp_ctx, token, program, sd);

	TALLOC_FREE(tmp_ctx);
	return true;
}


bool conditional_ace_encode_binary(TALLOC_CTX *mem_ctx,
				   struct ace_condition_script *program,
				   DATA_BLOB *dest)
{
	size_t i, j, alloc_size, required_size;
	uint8_t *data = NULL;
	uint8_t *new_data = NULL;
	*dest = (DATA_BLOB){NULL, 0};

	alloc_size = CONDITIONAL_ACE_MAX_LENGTH;
	data = talloc_array(mem_ctx,
			    uint8_t,
			    alloc_size);
	if (data == NULL) {
		return false;
	}

	data[0] = 'a';
	data[1] = 'r';
	data[2] = 't';
	data[3] = 'x';

	j = 4;
	for (i = 0; i < program->length; i++) {
		struct ace_condition_token *tok = &program->tokens[i];
		ssize_t consumed;
		bool ok;
		/*
		 * In all cases we write the token type byte.
		 */
		data[j] = tok->type;
		j++;
		if (j >= alloc_size) {
			DBG_ERR("program exceeds %zu bytes\n", alloc_size);
			goto error;
		}

		switch (tok->type) {
		case CONDITIONAL_ACE_TOKEN_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_DEVICE_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF:
		case CONDITIONAL_ACE_TOKEN_NOT_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_NOT_DEVICE_MEMBER_OF_ANY:
		case CONDITIONAL_ACE_TOKEN_EQUAL:
		case CONDITIONAL_ACE_TOKEN_NOT_EQUAL:
		case CONDITIONAL_ACE_TOKEN_LESS_THAN:
		case CONDITIONAL_ACE_TOKEN_LESS_OR_EQUAL:
		case CONDITIONAL_ACE_TOKEN_GREATER_THAN:
		case CONDITIONAL_ACE_TOKEN_GREATER_OR_EQUAL:
		case CONDITIONAL_ACE_TOKEN_CONTAINS:
		case CONDITIONAL_ACE_TOKEN_ANY_OF:
		case CONDITIONAL_ACE_TOKEN_NOT_CONTAINS:
		case CONDITIONAL_ACE_TOKEN_NOT_ANY_OF:
		case CONDITIONAL_ACE_TOKEN_EXISTS:
		case CONDITIONAL_ACE_TOKEN_NOT_EXISTS:
		case CONDITIONAL_ACE_TOKEN_NOT:
		case CONDITIONAL_ACE_TOKEN_AND:
		case CONDITIONAL_ACE_TOKEN_OR:
			/*
			 * All of these are simple operators that operate on
			 * the stack. We have already added the tok->type and
			 * there's nothing else to do.
			 */
			continue;

		case CONDITIONAL_ACE_TOKEN_INT8:
		case CONDITIONAL_ACE_TOKEN_INT16:
		case CONDITIONAL_ACE_TOKEN_INT32:
		case CONDITIONAL_ACE_TOKEN_INT64:
			ok = check_integer_range(tok);
			if (! ok) {
				goto error;
			}
			consumed = push_integer(data + j,
						alloc_size - j,
						&tok->data.int64);
			break;
		case CONDITIONAL_ACE_LOCAL_ATTRIBUTE:
		case CONDITIONAL_ACE_USER_ATTRIBUTE:
		case CONDITIONAL_ACE_RESOURCE_ATTRIBUTE:
		case CONDITIONAL_ACE_DEVICE_ATTRIBUTE:
		case CONDITIONAL_ACE_TOKEN_UNICODE:
			consumed = push_unicode(data + j,
						alloc_size - j,
						&tok->data.unicode);
			break;
		case CONDITIONAL_ACE_TOKEN_OCTET_STRING:
			consumed = push_bytes(data + j,
					      alloc_size - j,
					      &tok->data.bytes);
			break;
		case CONDITIONAL_ACE_TOKEN_SID:
			consumed = push_sid(data + j,
					    alloc_size - j,
					    &tok->data.sid);
			break;
		case CONDITIONAL_ACE_TOKEN_COMPOSITE:
			consumed = push_composite(data + j,
						  alloc_size - j,
						  &tok->data.composite);
			break;

		default:
			DBG_ERR("unknown token 0x%02x at position %zu\n",
				tok->type, i);
			goto error;
		}
		if (consumed == -1) {
			DBG_ERR("program exceeds %zu bytes\n", alloc_size);
			goto error;
		}
		j += consumed;
		if (j >= alloc_size) {
			DBG_ERR("program exceeds %zu bytes\n", alloc_size);
			goto error;
		}
	}
	/* align to a 4 byte boundary */
	required_size = (j + 3) & ~((size_t)3);
	if (required_size > alloc_size) {
		DBG_ERR("program exceeds %zu bytes\n", alloc_size);
		goto error;
	}
	while (j < required_size) {
		data[j] = 0;
		j++;
	}
	new_data = talloc_realloc(mem_ctx,
				  data,
				  uint8_t,
				  required_size);
	if (new_data == NULL) {
		goto error;
	}
	data = new_data;

	(*dest).data = data;
	(*dest).length = j;
	return true;
  error:
	TALLOC_FREE(data);
	return false;
}
