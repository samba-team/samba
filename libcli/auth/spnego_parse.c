/*
   Unix SMB/CIFS implementation.

   RFC2478 Compliant SPNEGO implementation

   Copyright (C) Jim McDonough <jmcd@us.ibm.com>   2003

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
#include "../libcli/auth/spnego.h"
#include "../lib/util/asn1.h"

static bool read_negTokenInit(struct asn1_data *asn1, TALLOC_CTX *mem_ctx,
			      struct spnego_negTokenInit *token)
{
	ZERO_STRUCTP(token);

	if (!asn1_start_tag(asn1, ASN1_CONTEXT(0))) return false;
	if (!asn1_start_tag(asn1, ASN1_SEQUENCE(0))) return false;

	while (!asn1->has_error && 0 < asn1_tag_remaining(asn1)) {
		int i;
		uint8_t context;

		if (!asn1_peek_uint8(asn1, &context)) {
			asn1->has_error = true;
			break;
		}

		switch (context) {
		/* Read mechTypes */
		case ASN1_CONTEXT(0): {
			const char **mechTypes;

			if (!asn1_start_tag(asn1, ASN1_CONTEXT(0))) return false;
			if (!asn1_start_tag(asn1, ASN1_SEQUENCE(0))) return false;

			mechTypes = talloc(mem_ctx, const char *);
			if (mechTypes == NULL) {
				asn1->has_error = true;
				return false;
			}
			for (i = 0; !asn1->has_error &&
				     0 < asn1_tag_remaining(asn1); i++) {
				char *oid;
				const char **p;
				p = talloc_realloc(mem_ctx,
						   mechTypes,
						   const char *, i+2);
				if (p == NULL) {
					talloc_free(mechTypes);
					asn1->has_error = true;
					return false;
				}
				mechTypes = p;

				if (!asn1_read_OID(asn1, mechTypes, &oid)) return false;
				mechTypes[i] = oid;
			}
			mechTypes[i] = NULL;
			token->mechTypes = mechTypes;

			asn1_end_tag(asn1);
			asn1_end_tag(asn1);
			break;
		}
		/* Read reqFlags */
		case ASN1_CONTEXT(1):
			if (!asn1_start_tag(asn1, ASN1_CONTEXT(1))) return false;
			if (!asn1_read_BitString(asn1, mem_ctx, &token->reqFlags,
					    &token->reqFlagsPadding)) return false;
			if (!asn1_end_tag(asn1)) return false;
			break;
                /* Read mechToken */
		case ASN1_CONTEXT(2):
			if (!asn1_start_tag(asn1, ASN1_CONTEXT(2))) return false;
			if (!asn1_read_OctetString(asn1, mem_ctx, &token->mechToken)) return false;
			if (!asn1_end_tag(asn1)) return false;
			break;
		/* Read mecListMIC */
		case ASN1_CONTEXT(3):
		{
			uint8_t type_peek;
			if (!asn1_start_tag(asn1, ASN1_CONTEXT(3))) return false;
			if (!asn1_peek_uint8(asn1, &type_peek)) {
				asn1->has_error = true;
				break;
			}
			if (type_peek == ASN1_OCTET_STRING) {
				if (!asn1_read_OctetString(asn1, mem_ctx,
						      &token->mechListMIC)) return false;
			} else {
				/* RFC 2478 says we have an Octet String here,
				   but W2k sends something different... */
				char *mechListMIC;
				if (!asn1_start_tag(asn1, ASN1_SEQUENCE(0))) return false;
				if (!asn1_start_tag(asn1, ASN1_CONTEXT(0))) return false;
				if (!asn1_read_GeneralString(asn1, mem_ctx, &mechListMIC)) return false;
				if (!asn1_end_tag(asn1)) return false;
				if (!asn1_end_tag(asn1)) return false;

				token->targetPrincipal = mechListMIC;
			}
			if (!asn1_end_tag(asn1)) return false;
			break;
		}
		default:
			asn1->has_error = true;
			break;
		}
	}

	if (!asn1_end_tag(asn1)) return false;
	if (!asn1_end_tag(asn1)) return false;

	return !asn1->has_error;
}

static bool write_negTokenInit(struct asn1_data *asn1, struct spnego_negTokenInit *token)
{
	if (!asn1_push_tag(asn1, ASN1_CONTEXT(0))) return false;
	if (!asn1_push_tag(asn1, ASN1_SEQUENCE(0))) return false;

	/* Write mechTypes */
	if (token->mechTypes && *token->mechTypes) {
		int i;

		if (!asn1_push_tag(asn1, ASN1_CONTEXT(0))) return false;
		if (!asn1_push_tag(asn1, ASN1_SEQUENCE(0))) return false;
		for (i = 0; token->mechTypes[i]; i++) {
			if (!asn1_write_OID(asn1, token->mechTypes[i])) return false;
		}
		if (!asn1_pop_tag(asn1)) return false;
		if (!asn1_pop_tag(asn1)) return false;
	}

	/* write reqFlags */
	if (token->reqFlags.length > 0) {
		if (!asn1_push_tag(asn1, ASN1_CONTEXT(1))) return false;
		if (!asn1_write_BitString(asn1, token->reqFlags.data,
				     token->reqFlags.length,
				     token->reqFlagsPadding)) return false;
		if (!asn1_pop_tag(asn1)) return false;
	}

	/* write mechToken */
	if (token->mechToken.data) {
		if (!asn1_push_tag(asn1, ASN1_CONTEXT(2))) return false;
		if (!asn1_write_OctetString(asn1, token->mechToken.data,
				       token->mechToken.length)) return false;
		if (!asn1_pop_tag(asn1)) return false;
	}

	/* write mechListMIC */
	if (token->mechListMIC.data) {
		if (!asn1_push_tag(asn1, ASN1_CONTEXT(3))) return false;
#if 0
		/* This is what RFC 2478 says ... */
		asn1_write_OctetString(asn1, token->mechListMIC.data,
				       token->mechListMIC.length);
#else
		/* ... but unfortunately this is what Windows
		   sends/expects */
		if (!asn1_push_tag(asn1, ASN1_SEQUENCE(0))) return false;
		if (!asn1_push_tag(asn1, ASN1_CONTEXT(0))) return false;
		if (!asn1_push_tag(asn1, ASN1_GENERAL_STRING)) return false;
		if (!asn1_write(asn1, token->mechListMIC.data,
			   token->mechListMIC.length)) return false;
		if (!asn1_pop_tag(asn1)) return false;
		if (!asn1_pop_tag(asn1)) return false;
		if (!asn1_pop_tag(asn1)) return false;
#endif
		if (!asn1_pop_tag(asn1)) return false;
	}

	if (!asn1_pop_tag(asn1)) return false;
	if (!asn1_pop_tag(asn1)) return false;

	return !asn1->has_error;
}

static bool read_negTokenTarg(struct asn1_data *asn1, TALLOC_CTX *mem_ctx,
			      struct spnego_negTokenTarg *token)
{
	ZERO_STRUCTP(token);

	if (!asn1_start_tag(asn1, ASN1_CONTEXT(1))) return false;
	if (!asn1_start_tag(asn1, ASN1_SEQUENCE(0))) return false;

	while (!asn1->has_error && 0 < asn1_tag_remaining(asn1)) {
		uint8_t context;
		char *oid;
		if (!asn1_peek_uint8(asn1, &context)) {
			asn1->has_error = true;
			break;
		}

		switch (context) {
		case ASN1_CONTEXT(0):
			if (!asn1_start_tag(asn1, ASN1_CONTEXT(0))) return false;
			if (!asn1_start_tag(asn1, ASN1_ENUMERATED)) return false;
			if (!asn1_read_uint8(asn1, &token->negResult)) return false;
			if (!asn1_end_tag(asn1)) return false;
			if (!asn1_end_tag(asn1)) return false;
			break;
		case ASN1_CONTEXT(1):
			if (!asn1_start_tag(asn1, ASN1_CONTEXT(1))) return false;
			if (!asn1_read_OID(asn1, mem_ctx, &oid)) return false;
			token->supportedMech = oid;
			if (!asn1_end_tag(asn1)) return false;
			break;
		case ASN1_CONTEXT(2):
			if (!asn1_start_tag(asn1, ASN1_CONTEXT(2))) return false;
			if (!asn1_read_OctetString(asn1, mem_ctx, &token->responseToken)) return false;
			if (!asn1_end_tag(asn1)) return false;
			break;
		case ASN1_CONTEXT(3):
			if (!asn1_start_tag(asn1, ASN1_CONTEXT(3))) return false;
			if (!asn1_read_OctetString(asn1, mem_ctx, &token->mechListMIC)) return false;
			if (!asn1_end_tag(asn1)) return false;
			break;
		default:
			asn1->has_error = true;
			break;
		}
	}

	if (!asn1_end_tag(asn1)) return false;
	if (!asn1_end_tag(asn1)) return false;

	return !asn1->has_error;
}

static bool write_negTokenTarg(struct asn1_data *asn1, struct spnego_negTokenTarg *token)
{
	if (!asn1_push_tag(asn1, ASN1_CONTEXT(1))) return false;
	if (!asn1_push_tag(asn1, ASN1_SEQUENCE(0))) return false;

	if (token->negResult != SPNEGO_NONE_RESULT) {
		if (!asn1_push_tag(asn1, ASN1_CONTEXT(0))) return false;
		if (!asn1_write_enumerated(asn1, token->negResult)) return false;
		if (!asn1_pop_tag(asn1)) return false;
	}

	if (token->supportedMech) {
		if (!asn1_push_tag(asn1, ASN1_CONTEXT(1))) return false;
		if (!asn1_write_OID(asn1, token->supportedMech)) return false;
		if (!asn1_pop_tag(asn1)) return false;
	}

	if (token->responseToken.data) {
		if (!asn1_push_tag(asn1, ASN1_CONTEXT(2))) return false;
		if (!asn1_write_OctetString(asn1, token->responseToken.data,
				       token->responseToken.length)) return false;
		if (!asn1_pop_tag(asn1)) return false;
	}

	if (token->mechListMIC.data) {
		if (!asn1_push_tag(asn1, ASN1_CONTEXT(3))) return false;
		if (!asn1_write_OctetString(asn1, token->mechListMIC.data,
				      token->mechListMIC.length)) return false;
		if (!asn1_pop_tag(asn1)) return false;
	}

	if (!asn1_pop_tag(asn1)) return false;
	if (!asn1_pop_tag(asn1)) return false;

	return !asn1->has_error;
}

ssize_t spnego_read_data(TALLOC_CTX *mem_ctx, DATA_BLOB data, struct spnego_data *token)
{
	struct asn1_data *asn1;
	ssize_t ret = -1;
	uint8_t context;

	ZERO_STRUCTP(token);

	if (data.length == 0) {
		return ret;
	}

	asn1 = asn1_init(mem_ctx);
	if (asn1 == NULL) {
		return -1;
	}

	if (!asn1_load(asn1, data)) goto err;

	if (!asn1_peek_uint8(asn1, &context)) {
		asn1->has_error = true;
	} else {
		switch (context) {
		case ASN1_APPLICATION(0):
			if (!asn1_start_tag(asn1, ASN1_APPLICATION(0))) goto err;
			if (!asn1_check_OID(asn1, OID_SPNEGO)) goto err;
			if (read_negTokenInit(asn1, mem_ctx, &token->negTokenInit)) {
				token->type = SPNEGO_NEG_TOKEN_INIT;
			}
			if (!asn1_end_tag(asn1)) goto err;
			break;
		case ASN1_CONTEXT(1):
			if (read_negTokenTarg(asn1, mem_ctx, &token->negTokenTarg)) {
				token->type = SPNEGO_NEG_TOKEN_TARG;
			}
			break;
		default:
			asn1->has_error = true;
			break;
		}
	}

	if (!asn1->has_error) ret = asn1->ofs;

  err:

	asn1_free(asn1);

	return ret;
}

ssize_t spnego_write_data(TALLOC_CTX *mem_ctx, DATA_BLOB *blob, struct spnego_data *spnego)
{
	struct asn1_data *asn1 = asn1_init(mem_ctx);
	ssize_t ret = -1;

	if (asn1 == NULL) {
		return -1;
	}

	switch (spnego->type) {
	case SPNEGO_NEG_TOKEN_INIT:
		if (!asn1_push_tag(asn1, ASN1_APPLICATION(0))) goto err;
		if (!asn1_write_OID(asn1, OID_SPNEGO)) goto err;
		if (!write_negTokenInit(asn1, &spnego->negTokenInit)) goto err;
		if (!asn1_pop_tag(asn1)) goto err;
		break;
	case SPNEGO_NEG_TOKEN_TARG:
		write_negTokenTarg(asn1, &spnego->negTokenTarg);
		break;
	default:
		asn1->has_error = true;
		break;
	}

	if (!asn1->has_error) {
		*blob = data_blob_talloc(mem_ctx, asn1->data, asn1->length);
		ret = asn1->ofs;
	}

  err:

	asn1_free(asn1);

	return ret;
}

bool spnego_free_data(struct spnego_data *spnego)
{
	bool ret = true;

	if (!spnego) goto out;

	switch(spnego->type) {
	case SPNEGO_NEG_TOKEN_INIT:
		if (spnego->negTokenInit.mechTypes) {
			talloc_free(discard_const(spnego->negTokenInit.mechTypes));
		}
		data_blob_free(&spnego->negTokenInit.reqFlags);
		data_blob_free(&spnego->negTokenInit.mechToken);
		data_blob_free(&spnego->negTokenInit.mechListMIC);
		talloc_free(spnego->negTokenInit.targetPrincipal);
		break;
	case SPNEGO_NEG_TOKEN_TARG:
		if (spnego->negTokenTarg.supportedMech) {
			talloc_free(discard_const(spnego->negTokenTarg.supportedMech));
		}
		data_blob_free(&spnego->negTokenTarg.responseToken);
		data_blob_free(&spnego->negTokenTarg.mechListMIC);
		break;
	default:
		ret = false;
		break;
	}
	ZERO_STRUCTP(spnego);
out:
	return ret;
}

bool spnego_write_mech_types(TALLOC_CTX *mem_ctx,
			     const char * const *mech_types,
			     DATA_BLOB *blob)
{
	bool ret = false;
	struct asn1_data *asn1 = asn1_init(mem_ctx);

	if (asn1 == NULL) {
		return false;
	}

	/* Write mechTypes */
	if (mech_types && *mech_types) {
		int i;

		if (!asn1_push_tag(asn1, ASN1_SEQUENCE(0))) goto err;
		for (i = 0; mech_types[i]; i++) {
			if (!asn1_write_OID(asn1, mech_types[i])) goto err;
		}
		if (!asn1_pop_tag(asn1)) goto err;
	}

	if (asn1->has_error) {
		goto err;
	}

	*blob = data_blob_talloc(mem_ctx, asn1->data, asn1->length);
	if (blob->length != asn1->length) {
		goto err;
	}

	ret = true;

  err:

	asn1_free(asn1);

	return ret;
}
