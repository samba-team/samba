/*
   Unix SMB/CIFS implementation.

   libndr compression support

   Copyright (C) Stefan Metzmacher 2005

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
#include "lib/compression/mszip.h"
#include "librpc/ndr/libndr.h"
#include "librpc/ndr/ndr_compression.h"

static enum ndr_err_code ndr_pull_compression_mszip_chunk(struct ndr_pull *ndrpull,
						 struct ndr_push *ndrpush,
						 struct decomp_state *decomp_state,
						 bool *last)
{
	DATA_BLOB comp_chunk;
	uint32_t comp_chunk_offset;
	uint32_t comp_chunk_size;
	DATA_BLOB plain_chunk;
	uint32_t plain_chunk_offset;
	uint32_t plain_chunk_size;
	int ret;

	NDR_CHECK(ndr_pull_uint32(ndrpull, NDR_SCALARS, &plain_chunk_size));
	if (plain_chunk_size > 0x00008000) {
		return ndr_pull_error(ndrpull, NDR_ERR_COMPRESSION, "Bad MSZIP plain chunk size %08X > 0x00008000 (PULL)",
				      plain_chunk_size);
	}

	NDR_CHECK(ndr_pull_uint32(ndrpull, NDR_SCALARS, &comp_chunk_size));

	DEBUG(10,("MSZIP plain_chunk_size: %08X (%u) comp_chunk_size: %08X (%u)\n",
		  plain_chunk_size, plain_chunk_size, comp_chunk_size, comp_chunk_size));

	comp_chunk_offset = ndrpull->offset;
	NDR_CHECK(ndr_pull_advance(ndrpull, comp_chunk_size));
	comp_chunk.length = comp_chunk_size;
	comp_chunk.data = ndrpull->data + comp_chunk_offset;

	plain_chunk_offset = ndrpush->offset;
	NDR_CHECK(ndr_push_zero(ndrpush, plain_chunk_size));
	plain_chunk.length = plain_chunk_size;
	plain_chunk.data = ndrpush->data + plain_chunk_offset;

	ret = ZIPdecompress(decomp_state, &comp_chunk, &plain_chunk);
	if (ret != DECR_OK) {
		return ndr_pull_error(ndrpull, NDR_ERR_COMPRESSION, "Bad ZIPdecompress() error %d (PULL)",
				      ret);
	}

	if ((plain_chunk_size < 0x00008000) || (ndrpull->offset+4 >= ndrpull->data_size)) {
		/* this is the last chunk */
		*last = true;
	}

	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_compression_mszip(struct ndr_pull *subndr,
					   struct ndr_pull **_comndr,
					   ssize_t decompressed_len)
{
	struct ndr_push *ndrpush;
	struct ndr_pull *comndr;
	DATA_BLOB uncompressed;
	uint32_t payload_header[4];
	uint32_t payload_size;
	uint32_t payload_offset;
	uint8_t *payload;
	struct decomp_state *decomp_state;
	bool last = false;

	ndrpush = ndr_push_init_ctx(subndr);
	NDR_ERR_HAVE_NO_MEMORY(ndrpush);

	decomp_state = ZIPdecomp_state(subndr);
	NDR_ERR_HAVE_NO_MEMORY(decomp_state);

	while (!last) {
		NDR_CHECK(ndr_pull_compression_mszip_chunk(subndr, ndrpush, decomp_state, &last));
	}

	uncompressed = ndr_push_blob(ndrpush);

	if (uncompressed.length != decompressed_len) {
		return ndr_pull_error(subndr, NDR_ERR_COMPRESSION, "Bad MSZIP uncompressed_len [%u] != [%d] (PULL)",
				      (int)uncompressed.length, (int)decompressed_len);
	}

	comndr = talloc_zero(subndr, struct ndr_pull);
	NDR_ERR_HAVE_NO_MEMORY(comndr);
	comndr->flags		= subndr->flags;
	comndr->current_mem_ctx	= subndr->current_mem_ctx;

	comndr->data		= uncompressed.data;
	comndr->data_size	= uncompressed.length;
	comndr->offset		= 0;

	NDR_CHECK(ndr_pull_uint32(comndr, NDR_SCALARS, &payload_header[0]));
	NDR_CHECK(ndr_pull_uint32(comndr, NDR_SCALARS, &payload_header[1]));
	NDR_CHECK(ndr_pull_uint32(comndr, NDR_SCALARS, &payload_header[2]));
	NDR_CHECK(ndr_pull_uint32(comndr, NDR_SCALARS, &payload_header[3]));

	if (payload_header[0] != 0x00081001) {
		return ndr_pull_error(subndr, NDR_ERR_COMPRESSION, "Bad MSZIP payload_header[0] [0x%08X] != [0x00081001] (PULL)",
				      payload_header[0]);
	}
	if (payload_header[1] != 0xCCCCCCCC) {
		return ndr_pull_error(subndr, NDR_ERR_COMPRESSION, "Bad MSZIP payload_header[1] [0x%08X] != [0xCCCCCCCC] (PULL)",
				      payload_header[1]);
	}

	payload_size = payload_header[2];

	if (payload_header[3] != 0x00000000) {
		return ndr_pull_error(subndr, NDR_ERR_COMPRESSION, "Bad MSZIP payload_header[3] [0x%08X] != [0x00000000] (PULL)",
				      payload_header[3]);
	}

	payload_offset = comndr->offset;
	NDR_CHECK(ndr_pull_advance(comndr, payload_size));
	payload = comndr->data + payload_offset;

	comndr->data		= payload;
	comndr->data_size	= payload_size;
	comndr->offset		= 0;

	*_comndr = comndr;
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_push_compression_mszip(struct ndr_push *subndr,
					   struct ndr_push *comndr)
{
	return ndr_push_error(subndr, NDR_ERR_COMPRESSION, "Sorry MSZIP compression is not supported yet (PUSH)");
}

static enum ndr_err_code ndr_pull_compression_xpress_chunk(struct ndr_pull *ndrpull,
						  struct ndr_push *ndrpush,
						  bool *last)
{
	DATA_BLOB comp_chunk;
	uint32_t comp_chunk_offset;
	uint32_t comp_chunk_size;
	uint32_t plain_chunk_size;

	comp_chunk_offset = ndrpull->offset;

	NDR_CHECK(ndr_pull_uint32(ndrpull, NDR_SCALARS, &plain_chunk_size));
	if (plain_chunk_size > 0x00010000) {
		return ndr_pull_error(ndrpull, NDR_ERR_COMPRESSION, "Bad XPRESS plain chunk size %08X > 0x00010000 (PULL)",
				      plain_chunk_size);
	}

	NDR_CHECK(ndr_pull_uint32(ndrpull, NDR_SCALARS, &comp_chunk_size));

	NDR_CHECK(ndr_pull_advance(ndrpull, comp_chunk_size));
	comp_chunk.length = comp_chunk_size + 8;
	comp_chunk.data = ndrpull->data + comp_chunk_offset;

	DEBUG(10,("XPRESS plain_chunk_size: %08X (%u) comp_chunk_size: %08X (%u)\n",
		  plain_chunk_size, plain_chunk_size, comp_chunk_size, comp_chunk_size));

	/* For now, we just copy over the compressed blob */
	NDR_CHECK(ndr_push_bytes(ndrpush, comp_chunk.data, comp_chunk.length));

	if ((plain_chunk_size < 0x00010000) || (ndrpull->offset+4 >= ndrpull->data_size)) {
		/* this is the last chunk */
		*last = true;
	}

	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_compression_xpress(struct ndr_pull *subndr,
					    struct ndr_pull **_comndr,
					    ssize_t decompressed_len)
{
	struct ndr_push *ndrpush;
	struct ndr_pull *comndr;
	DATA_BLOB uncompressed;
	bool last = false;

	ndrpush = ndr_push_init_ctx(subndr);
	NDR_ERR_HAVE_NO_MEMORY(ndrpush);

	while (!last) {
		NDR_CHECK(ndr_pull_compression_xpress_chunk(subndr, ndrpush, &last));
	}

	uncompressed = ndr_push_blob(ndrpush);

	comndr = talloc_zero(subndr, struct ndr_pull);
	NDR_ERR_HAVE_NO_MEMORY(comndr);
	comndr->flags		= subndr->flags;
	comndr->current_mem_ctx	= subndr->current_mem_ctx;

	comndr->data		= uncompressed.data;
	comndr->data_size	= uncompressed.length;
	comndr->offset		= 0;

	*_comndr = comndr;
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_push_compression_xpress(struct ndr_push *subndr,
					    struct ndr_push *comndr)
{
	return ndr_push_error(subndr, NDR_ERR_COMPRESSION, "XPRESS compression is not supported yet (PUSH)");
}

/*
  handle compressed subcontext buffers, which in midl land are user-marshalled, but
  we use magic in pidl to make them easier to cope with
*/
enum ndr_err_code ndr_pull_compression_start(struct ndr_pull *subndr,
				    struct ndr_pull **_comndr,
				    enum ndr_compression_alg compression_alg,
				    ssize_t decompressed_len)
{
	switch (compression_alg) {
	case NDR_COMPRESSION_MSZIP:
		return ndr_pull_compression_mszip(subndr, _comndr, decompressed_len);
	case NDR_COMPRESSION_XPRESS:
		return ndr_pull_compression_xpress(subndr, _comndr, decompressed_len);
	default:
		return ndr_pull_error(subndr, NDR_ERR_COMPRESSION, "Bad compression algorithm %d (PULL)",
				      compression_alg);
	}
	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_pull_compression_end(struct ndr_pull *subndr,
				  struct ndr_pull *comndr,
				  enum ndr_compression_alg compression_alg,
				  ssize_t decompressed_len)
{
	return NDR_ERR_SUCCESS;
}

/*
  push a compressed subcontext
*/
enum ndr_err_code ndr_push_compression_start(struct ndr_push *subndr,
				    struct ndr_push **_comndr,
				    enum ndr_compression_alg compression_alg,
				    ssize_t decompressed_len)
{
	struct ndr_push *comndr;

	comndr = ndr_push_init_ctx(subndr);
	NDR_ERR_HAVE_NO_MEMORY(comndr);
	comndr->flags	= subndr->flags;

	*_comndr = comndr;
	return NDR_ERR_SUCCESS;
}

/*
  push a compressed subcontext
*/
enum ndr_err_code ndr_push_compression_end(struct ndr_push *subndr,
				  struct ndr_push *comndr,
				  enum ndr_compression_alg compression_alg,
				  ssize_t decompressed_len)
{
	switch (compression_alg) {
	case NDR_COMPRESSION_MSZIP:
		return ndr_push_compression_mszip(subndr, comndr);
	case NDR_COMPRESSION_XPRESS:
		return ndr_push_compression_xpress(subndr, comndr);
	default:
		return ndr_push_error(subndr, NDR_ERR_COMPRESSION, "Bad compression algorithm %d (PUSH)",
				      compression_alg);
	}
	return NDR_ERR_SUCCESS;
}
