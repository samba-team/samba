/* 
   Unix SMB/CIFS implementation.

   libndr compression support

   Copyright (C) Stefan Metzmacher 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "lib/compression/mszip.h"

static NTSTATUS ndr_pull_compression_mszip_chunk(struct ndr_pull *ndrpull,
						 struct ndr_push *ndrpush,
						 struct decomp_state *decomp_state)
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
		return ndr_pull_error(ndrpull, NDR_ERR_COMPRESSION, "Bad ZLIB plain chunk size %08X > 0x00008000 (PULL)", 
				      plain_chunk_size);
	}

	NDR_CHECK(ndr_pull_uint32(ndrpull, NDR_SCALARS, &comp_chunk_size));

	DEBUG(10,("plain_chunk_size: %08X (%u) comp_chunk_size: %08X (%u)\n",
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
		return ndr_pull_error(ndrpull, NDR_ERR_COMPRESSION, "Bad ZIBdecompress() error %d (PULL)",
				      ret);
	}

	if ((plain_chunk_size < 0x00008000) || (ndrpull->offset+4 >= ndrpull->data_size)) {
		/* this is the last chunk */
		return NT_STATUS_OK;
	}

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS ndr_pull_compression_mszip(struct ndr_pull *subndr,
					   struct ndr_pull *comndr,
					   ssize_t decompressed_len)
{
	NTSTATUS status = NT_STATUS_MORE_PROCESSING_REQUIRED;
	struct ndr_push *ndrpush;
	DATA_BLOB uncompressed;
	uint32_t payload_header[4];
	uint32_t payload_size;
	uint32_t payload_offset;
	uint8_t *payload;
	struct decomp_state *decomp_state;

	ndrpush = ndr_push_init_ctx(subndr);
	NT_STATUS_HAVE_NO_MEMORY(ndrpush);

	decomp_state = ZIPdecomp_state(subndr);
	NT_STATUS_HAVE_NO_MEMORY(decomp_state);

	while (NT_STATUS_EQUAL(NT_STATUS_MORE_PROCESSING_REQUIRED, status)) {
		status = ndr_pull_compression_mszip_chunk(subndr, ndrpush, decomp_state);
	}
	NT_STATUS_NOT_OK_RETURN(status);

	uncompressed = ndr_push_blob(ndrpush);

	if (uncompressed.length != decompressed_len) {
		return ndr_pull_error(subndr, NDR_ERR_COMPRESSION, "Bad uncompressed_len [%u] != [%d] (PULL)",
				      uncompressed.length, decompressed_len);
	}

	*comndr = *subndr;
	comndr->data		= uncompressed.data;
	comndr->data_size	= uncompressed.length;
	comndr->offset		= 0;

	NDR_CHECK(ndr_pull_uint32(comndr, NDR_SCALARS, &payload_header[0]));
	NDR_CHECK(ndr_pull_uint32(comndr, NDR_SCALARS, &payload_header[1]));
	NDR_CHECK(ndr_pull_uint32(comndr, NDR_SCALARS, &payload_header[2]));
	NDR_CHECK(ndr_pull_uint32(comndr, NDR_SCALARS, &payload_header[3]));

	payload_size = payload_header[2];

	/* TODO: check the first 4 bytes of the header */
	if (payload_header[1] != 0xCCCCCCCC) {
		return ndr_pull_error(subndr, NDR_ERR_COMPRESSION, "Bad payload_header[1] [0x%08X] != [0xCCCCCCCC] (PULL)",
				      payload_header[1]);
	}

	payload_offset = comndr->offset;
	NDR_CHECK(ndr_pull_advance(comndr, payload_size));
	payload = comndr->data + payload_offset;

	comndr->data		= payload;
	comndr->data_size	= payload_size;
	comndr->offset		= 0;

	return NT_STATUS_OK;
}

static NTSTATUS ndr_push_compression_mszip(struct ndr_push *subndr,
					  struct ndr_push *comndr)
{
	return ndr_push_error(subndr, NDR_ERR_COMPRESSION, "Bad MSZIP compression is not supported yet (PUSH)");
}

/*
  handle compressed subcontext buffers, which in midl land are user-marshalled, but
  we use magic in pidl to make them easier to cope with
*/
NTSTATUS ndr_pull_compression(struct ndr_pull *subndr,
			      struct ndr_pull *comndr,
			      enum ndr_compression_alg compression_alg,
			      ssize_t decompressed_len)
{
	comndr->flags = subndr->flags;

	switch (compression_alg) {
	case NDR_COMPRESSION_MSZIP:
		return ndr_pull_compression_mszip(subndr, comndr, decompressed_len);
	default:
		return ndr_pull_error(subndr, NDR_ERR_COMPRESSION, "Bad compression algorithm %d (PULL)", 
				      compression_alg);
	}
	return NT_STATUS_OK;
}

/*
  push a compressed subcontext
*/
NTSTATUS ndr_push_compression(struct ndr_push *subndr,
			      struct ndr_push *comndr,
			      enum ndr_compression_alg compression_alg)
{
	comndr->flags = subndr->flags;

	switch (compression_alg) {
	case NDR_COMPRESSION_MSZIP:
		return ndr_push_compression_mszip(subndr, comndr);
	default:
		return ndr_push_error(subndr, NDR_ERR_COMPRESSION, "Bad compression algorithm %d (PUSH)", 
				      compression_alg);
	}
	return NT_STATUS_OK;
}
