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

#ifdef HAVE_ZLIB
#include <zlib.h>

static NTSTATUS ndr_pull_compression_zlib_chunk(struct ndr_pull *ndrpull,
						struct ndr_push *ndrpush,
						struct z_stream_s *zs, int i)
{
	uint8_t *comp_chunk;
	uint32_t comp_chunk_offset;
	uint32_t comp_chunk_size;
	uint8_t *plain_chunk;
	uint32_t plain_chunk_offset;
	uint32_t plain_chunk_size;
	uint16_t unknown_marker;
	int ret;

	/* I don't know why, this is needed... --metze */
	if (i == 5) ndrpull->offset -=4;

	NDR_CHECK(ndr_pull_uint32(ndrpull, NDR_SCALARS, &plain_chunk_size));
	if (plain_chunk_size > 0x00008000) {
		return ndr_pull_error(ndrpull, NDR_ERR_COMPRESSION, "Bad ZLIB plain chunk size %08X > 0x00008000 (PULL)", 
				      plain_chunk_size);	
	}

	NDR_CHECK(ndr_pull_uint32(ndrpull, NDR_SCALARS, &comp_chunk_size));

	NDR_CHECK(ndr_pull_uint16(ndrpull, NDR_SCALARS, &unknown_marker));

	DEBUG(10,("plain_chunk_size: %08X (%u) comp_chunk_size: %08X (%u) unknown_marker: %04X (%u)\n",
		  plain_chunk_size, plain_chunk_size, comp_chunk_size, comp_chunk_size, unknown_marker, unknown_marker));

	comp_chunk_offset = ndrpull->offset;
	NDR_CHECK(ndr_pull_advance(ndrpull, comp_chunk_size));
	comp_chunk = ndrpull->data + comp_chunk_offset;

	plain_chunk_offset = ndrpush->offset;
	NDR_CHECK(ndr_push_zero(ndrpush, plain_chunk_size));
	plain_chunk = ndrpush->data + plain_chunk_offset;

	zs->avail_in = comp_chunk_size;
	zs->next_in = comp_chunk;
	zs->next_out = plain_chunk;
	zs->avail_out = plain_chunk_size;

	while (True) {
		ret = inflate(zs, Z_BLOCK);
		if (ret == Z_STREAM_END) {
			DEBUG(0,("comp_chunk_size: %u avail_in: %d, plain_chunk_size: %u, avail_out: %d\n",
				comp_chunk_size, zs->avail_in, plain_chunk_size, zs->avail_out));
			break;
		}
		if (ret != Z_OK) {
			return ndr_pull_error(ndrpull, NDR_ERR_COMPRESSION, "Bad ZLIB (PULL) inflate error %d", 
				      ret);
		}
	}

	if ((plain_chunk_size < 0x00008000) || (ndrpull->offset+4 >= ndrpull->data_size)) {
		/* this is the last chunk */
		return NT_STATUS_OK;
	}

	return NT_STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS ndr_pull_compression_zlib(struct ndr_pull *subndr,
					  struct ndr_pull *comndr,
					  ssize_t decompressed_len)
{
	NTSTATUS status = NT_STATUS_MORE_PROCESSING_REQUIRED;
	struct ndr_push *ndrpush;
	DATA_BLOB uncompressed;
	struct z_stream_s zs;
	int ret;
	int i = 0;

	ZERO_STRUCT(zs);

	ndrpush = ndr_push_init_ctx(subndr);
	NT_STATUS_HAVE_NO_MEMORY(ndrpush);

	ret = inflateInit2(&zs, -15);
	if (ret != Z_OK) {
		return ndr_pull_error(subndr, NDR_ERR_COMPRESSION, "Bad ZLIB (PULL) inflateInit2 error %d", 
				      ret);
	}

	while (NT_STATUS_EQUAL(NT_STATUS_MORE_PROCESSING_REQUIRED, status)) {
		status = ndr_pull_compression_zlib_chunk(subndr, ndrpush, &zs, i++);
	}
	inflateEnd(&zs);
	NT_STATUS_NOT_OK_RETURN(status);

	uncompressed = ndr_push_blob(ndrpush);

	*comndr = *subndr;
	comndr->data		= uncompressed.data;
	comndr->data_size	= uncompressed.length;
	comndr->offset		= 0;

	return NT_STATUS_OK;
}

static NTSTATUS ndr_push_compression_zlib(struct ndr_push *subndr,
					  struct ndr_push *comndr)
{
	DATA_BLOB inbuf;
	DATA_BLOB outbuf = data_blob_talloc(comndr, NULL, comndr->offset + 10);
	struct z_stream_s zs;
	int ret;

	ZERO_STRUCT(zs);

	inbuf = ndr_push_blob(comndr);

	zs.avail_in = inbuf.length;
	zs.next_in = inbuf.data;
	zs.next_out = outbuf.data+10;
	zs.avail_out = outbuf.length-10;

	ret = deflateInit(&zs, Z_DEFAULT_COMPRESSION);
	if (ret != Z_OK) {
		return ndr_push_error(subndr, NDR_ERR_COMPRESSION, "Bad ZLIB (PUSH) deflateInit2 error %d", 
				      ret);
	}

	ret = deflate(&zs, Z_SYNC_FLUSH);

	if (ret != Z_OK && ret != Z_STREAM_END) {
		return ndr_push_error(subndr, NDR_ERR_COMPRESSION, "Bad ZLIB (PULL) deflate error %d", 
				      ret);
	}

	deflateEnd(&zs);

	/* TODO: push the header here */


	NDR_CHECK(ndr_push_bytes(subndr, outbuf.data, outbuf.length));

	return NT_STATUS_OK;
}
#endif

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
#ifdef HAVE_ZLIB
	case NDR_COMPRESSION_ZLIB:
		return ndr_pull_compression_zlib(subndr, comndr, decompressed_len);
#endif
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
#ifdef HAVE_ZLIB
	case NDR_COMPRESSION_ZLIB:
		return ndr_push_compression_zlib(subndr, comndr);
#endif
	default:
		return ndr_push_error(subndr, NDR_ERR_COMPRESSION, "Bad compression algorithm %d (PUSH)", 
				      compression_alg);
	}
	return NT_STATUS_OK;
}
