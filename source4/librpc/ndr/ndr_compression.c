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

static NTSTATUS ndr_pull_compression_zlib(struct ndr_pull *subndr,
					  struct ndr_pull *comndr,
					  ssize_t decompressed_len)
{
	DATA_BLOB inbuf;
	DATA_BLOB outbuf = data_blob_talloc(comndr, NULL, decompressed_len);
	uint32_t outbuf_len = outbuf.length;
	struct z_stream_s zs;
	int ret;

	ZERO_STRUCT(zs);

	if (subndr->data_size < 10) {
		return ndr_pull_error(subndr, NDR_ERR_COMPRESSION, "Bad ZLIB compressed header (PULL) subcontext size %d", 
				      subndr->data_size);
	}

	inbuf.data = subndr->data+10;
	inbuf.length = subndr->data_size-10;

	zs.avail_in = inbuf.length;
	zs.next_in = inbuf.data;
	zs.next_out = outbuf.data;
	zs.avail_out = outbuf.length;

	ret = inflateInit2(&zs, 15);
	if (ret != Z_OK) {
		return ndr_pull_error(subndr, NDR_ERR_COMPRESSION, "Bad ZLIB (PULL) inflateInit2 error %d", 
				      ret);
	}

	while(1) {
		ret = inflate(&zs, Z_SYNC_FLUSH);
		if (ret == Z_STREAM_END) {
			
			DEBUG(0,("inbuf.length: %d avail_in: %d, avail_out: %d\n", inbuf.length, zs.avail_in, zs.avail_out));
			break;
		}
		if (ret != Z_OK) {
			return ndr_pull_error(subndr, NDR_ERR_COMPRESSION, "Bad ZLIB (PULL) inflate error %d", 
				      ret);
		}
	}

	inflateEnd(&zs);

	/* TODO: check if the decompressed_len == outbuf_len */
	outbuf.length = outbuf_len - zs.avail_out;

	if (outbuf.length < 16) {
		return ndr_pull_error(subndr, NDR_ERR_COMPRESSION, "Bad ZLIB uncompressed header (PULL) uncompressed size %d", 
				      outbuf.length);
	}

	outbuf.data	+= 16;
	outbuf.length	-= 16;

	/* TODO: really decompress the data here */
	*comndr = *subndr;
	comndr->data		= outbuf.data;
	comndr->data_size	= outbuf.length;
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
