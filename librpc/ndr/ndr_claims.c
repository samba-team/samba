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

static void ndr_claims_compressed_sizes(struct CLAIMS_SET_NDR *claims_set,
					enum CLAIMS_COMPRESSION_FORMAT wire_alg,
					int flags,
					ssize_t *_uncompressed_size,
					enum CLAIMS_COMPRESSION_FORMAT *_used_alg,
					ssize_t *_compressed_size)
{
	TALLOC_CTX *frame = NULL;
	DATA_BLOB tmp_blob;
	uint8_t * tmp_compressed;
	ssize_t compressed_size;
	enum ndr_err_code ndr_err;

	if (claims_set == NULL) {
		*_uncompressed_size = 0;
		*_used_alg = CLAIMS_COMPRESSION_FORMAT_NONE;
		*_compressed_size = 0;
		return;
	}

	frame = talloc_stackframe();

	ndr_err = ndr_push_struct_blob(&tmp_blob,
				       frame,
				       claims_set,
				       (ndr_push_flags_fn_t)ndr_push_CLAIMS_SET_NDR);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("Failed to push claims while determining compressed size\n");
		*_uncompressed_size = -1;
		*_used_alg = CLAIMS_COMPRESSION_FORMAT_NONE;
		*_compressed_size = -1;
		TALLOC_FREE(frame);
		return;
	}

	if (tmp_blob.length < CLAIM_UPPER_COMPRESSION_THRESHOLD) {
		*_uncompressed_size = tmp_blob.length;
		*_used_alg = CLAIMS_COMPRESSION_FORMAT_NONE;
		*_compressed_size = tmp_blob.length;
		TALLOC_FREE(frame);
		return;
	}

	switch (wire_alg) {
	case CLAIMS_COMPRESSION_FORMAT_NONE:
		*_uncompressed_size = tmp_blob.length;
		*_used_alg = CLAIMS_COMPRESSION_FORMAT_NONE;
		*_compressed_size = tmp_blob.length;
		TALLOC_FREE(frame);
		return;

	case CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF:
		compressed_size = lzxpress_huffman_compress_talloc(frame,
								   tmp_blob.data,
								   tmp_blob.length,
								   &tmp_compressed);

		if (compressed_size < 0) {
			DBG_ERR("Failed to compress claims (for determining compressed size)\n");
			*_uncompressed_size = -1;
			*_used_alg = CLAIMS_COMPRESSION_FORMAT_NONE;
			*_compressed_size = -1;
			TALLOC_FREE(frame);
			return;
		}
		if (compressed_size >= tmp_blob.length) {
			*_uncompressed_size = tmp_blob.length;
			*_used_alg = CLAIMS_COMPRESSION_FORMAT_NONE;
			*_compressed_size = tmp_blob.length;
			TALLOC_FREE(frame);
			return;
		}

		*_uncompressed_size = tmp_blob.length;
		*_used_alg = CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF;
		*_compressed_size = compressed_size;
		TALLOC_FREE(frame);
		return;

	default:
		DBG_ERR("Invalid chosen compression algorithm while determining compressed claim size\n");
		*_uncompressed_size = -1;
		*_used_alg = CLAIMS_COMPRESSION_FORMAT_NONE;
		*_compressed_size = -1;
		TALLOC_FREE(frame);
		return;
	}
}

enum CLAIMS_COMPRESSION_FORMAT ndr_claims_actual_wire_compression_alg(enum CLAIMS_COMPRESSION_FORMAT specified_compression,
								      struct CLAIMS_SET_NDR *claims_set,
								      int flags)
{
	ssize_t uncompressed_size = -1;
	enum CLAIMS_COMPRESSION_FORMAT used_alg = CLAIMS_COMPRESSION_FORMAT_NONE;
	ssize_t compressed_size = -1;

	ndr_claims_compressed_sizes(claims_set,
				    specified_compression,
				    flags,
				    &uncompressed_size,
				    &used_alg,
				    &compressed_size);

	return used_alg;
}

size_t ndr_claims_compressed_size(struct CLAIMS_SET_NDR *claims_set,
				  enum CLAIMS_COMPRESSION_FORMAT wire_alg,
				  int flags)
{
	ssize_t uncompressed_size = -1;
	enum CLAIMS_COMPRESSION_FORMAT used_alg = CLAIMS_COMPRESSION_FORMAT_NONE;
	ssize_t compressed_size = -1;

	ndr_claims_compressed_sizes(claims_set,
				    wire_alg,
				    flags,
				    &uncompressed_size,
				    &used_alg,
				    &compressed_size);
	if (uncompressed_size == -1) {
		DBG_ERR("Failed to push claims while determining compressed size\n");
		return 0;
	}

	return compressed_size;
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
