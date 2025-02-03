#include "includes.h"
#include "librpc/gen_ndr/ndr_claims.h"
#include "librpc/ndr/ndr_claims.h"

#include "librpc/ndr/ndr_compression.h"
#include "lib/compression/lzxpress_huffman.h"

enum ndr_compression_alg ndr_claims_compression_alg(enum CLAIMS_COMPRESSION_FORMAT wire_alg)
{
	switch (wire_alg) {
	case CLAIMS_COMPRESSION_FORMAT_NONE:
		return NDR_COMPRESSION_NONE;

	case CLAIMS_COMPRESSION_FORMAT_LZNT1:
		return NDR_COMPRESSION_INVALID;

	case CLAIMS_COMPRESSION_FORMAT_XPRESS:
		return NDR_COMPRESSION_INVALID;

	case CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF:
		return NDR_COMPRESSION_XPRESS_HUFF_RAW;
	}
	return NDR_COMPRESSION_INVALID;
}


enum CLAIMS_COMPRESSION_FORMAT ndr_claims_actual_wire_compression_alg(enum CLAIMS_COMPRESSION_FORMAT specified_compression,
								      size_t uncompressed_claims_size) {
	if (uncompressed_claims_size < CLAIM_UPPER_COMPRESSION_THRESHOLD) {
		return CLAIMS_COMPRESSION_FORMAT_NONE;
	}

	return specified_compression;
}

size_t ndr_claims_compressed_size(struct CLAIMS_SET_NDR *claims_set,
				  enum CLAIMS_COMPRESSION_FORMAT wire_alg,
				  int flags)
{
	TALLOC_CTX *frame = NULL;
	DATA_BLOB tmp_blob;
	uint8_t * tmp_compressed;
	ssize_t compressed_size;
	enum ndr_err_code ndr_err;
	enum CLAIMS_COMPRESSION_FORMAT actual_wire_alg;

	if (claims_set == NULL) {
		return 0;
	}

	frame = talloc_stackframe();

	ndr_err = ndr_push_struct_blob(&tmp_blob,
				       frame,
				       claims_set,
				       (ndr_push_flags_fn_t)ndr_push_CLAIMS_SET_NDR);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("Failed to push claims while determining compressed size\n");
		TALLOC_FREE(frame);
		return 0;
	}

	actual_wire_alg = ndr_claims_actual_wire_compression_alg(wire_alg,
								 tmp_blob.length);

	switch (actual_wire_alg) {
	case CLAIMS_COMPRESSION_FORMAT_NONE:
		TALLOC_FREE(frame);
		return tmp_blob.length;

	case CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF:
		compressed_size = lzxpress_huffman_compress_talloc(frame,
								   tmp_blob.data,
								   tmp_blob.length,
								   &tmp_compressed);

		TALLOC_FREE(frame);

		if (compressed_size < 0) {
			DBG_ERR("Failed to compress claims (for determining compressed size)\n");
			return 0;
		}
		return compressed_size;

	default:
		TALLOC_FREE(frame);
		DBG_ERR("Invalid chosen compression algorithm while determining compressed claim size\n");
		return 0;
	}
}

_PUBLIC_ enum ndr_err_code ndr_push_claims_tf_rule_set(struct ndr_push *ndr, ndr_flags_type ndr_flags, const struct claims_tf_rule_set *r)
{
	return ndr_push_error(ndr, NDR_ERR_INVALID_POINTER,
			      "ndr_push_claims_tf_rule_set() not implemented");
}

_PUBLIC_ enum ndr_err_code ndr_pull_claims_tf_rule_set(struct ndr_pull *ndr, ndr_flags_type ndr_flags, struct claims_tf_rule_set *r)
{
	return ndr_pull_error(ndr, NDR_ERR_INVALID_POINTER,
			      "ndr_pull_claims_tf_rule_set() not implemented");
}
