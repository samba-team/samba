/*
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling cab structures

   Copyright (C) Guenther Deschner 2016

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
#include "librpc/gen_ndr/ndr_cab.h"
#include "librpc/ndr/ndr_compression.h"

#define OFFSET_OF_FOLDER_COFFCABSTART(folder) (36 /* cfheader size */ + (size_t)(folder)*8)

_PUBLIC_ void ndr_print_cf_time(struct ndr_print *ndr, const char *name, const struct cf_time *r)
{
	uint8_t hour = 0, minute = 0, seconds = 0;
	char *s;
	if (r == NULL) { ndr_print_null(ndr); return; }
	hour = r->time >> 11;
	minute = (r->time >> 5) & 0x3f;
	seconds = (r->time << 1) & 0x3e;
	s = talloc_asprintf(ndr, "%02d:%02d:%02d", hour, minute, seconds);
	if (s == NULL) { return; }
	ndr_print_string(ndr, "time", s);
	talloc_free(s);
}

_PUBLIC_ void ndr_print_cf_date(struct ndr_print *ndr, const char *name, const struct cf_date *r)
{
	uint16_t year = 0;
	uint8_t month = 0, day = 0;
	char *s;
	if (r == NULL) { ndr_print_null(ndr); return; }
	year = (r->date >> 9);
	year += 1980;
	month = (r->date >> 5 & 0xf);
	day = (r->date & 0x1f);
	s = talloc_asprintf(ndr, "%02d/%02d/%04d", day, month, year);
	if (s == NULL) { return; }
	ndr_print_string(ndr, "date", s);
	talloc_free(s);
}

uint32_t ndr_count_cfdata(const struct cab_file *r)
{
	uint32_t count = 0, i;

	for (i = 0; i < r->cfheader.cFolders; i++) {
		if (count + r->cffolders[i].cCFData < count) {
			/* Integer wrap. */
			return 0;
		}
		count += r->cffolders[i].cCFData;
	}

	return count;
}

static uint32_t ndr_cab_compute_checksum(uint8_t *data, uint32_t length, uint32_t seed)
{
	int num_ulong;
	uint32_t checksum;
	uint8_t *pb;
	uint32_t ul;

	num_ulong = length / 4;
	checksum = seed;
	pb = data;

	while (num_ulong-- > 0) {
		ul = (uint32_t)(*pb++);
		ul |= (((uint32_t)(*pb++)) <<  8);
		ul |= (((uint32_t)(*pb++)) << 16);
		ul |= (((uint32_t)(*pb++)) << 24);

		checksum ^= ul;
	}

	ul = 0;

	switch (length % 4) {
	case 3:
		ul |= (((uint32_t)(*pb++)) << 16);
		FALL_THROUGH;
	case 2:
		ul |= (((uint32_t)(*pb++)) <<  8);
		FALL_THROUGH;
	case 1:
		ul |= (uint32_t)(*pb++);
		FALL_THROUGH;
	default:
		break;
	}

	checksum ^= ul;

	return checksum;
}

/* Push all CFDATA of a folder.
 *
 * This works on a folder level because compression type is set per
 * folder, and a compression state can be shared between CFDATA of the
 * same folder.
 *
 * This is not a regular NDR func as we pass the compression type and
 * the number of CFDATA as extra arguments
 */
static enum ndr_err_code ndr_push_folder_cfdata(struct ndr_push *ndr,
						const struct CFDATA *r,
						enum cf_compress_type cab_ctype,
						size_t num_cfdata)
{
	size_t i;
	enum ndr_compression_alg ndr_ctype = 0;

	ndr_set_flags(&ndr->flags, LIBNDR_PRINT_ARRAY_HEX|LIBNDR_FLAG_LITTLE_ENDIAN|LIBNDR_FLAG_NOALIGN);

	if (cab_ctype == CF_COMPRESS_MSZIP) {
		ndr_ctype = NDR_COMPRESSION_MSZIP_CAB;
		NDR_CHECK(ndr_push_compression_state_init(ndr, ndr_ctype, &ndr->cstate));
	}

	for (i = 0; i < num_cfdata; i++, r++) {
		uint32_t compressed_length = 0;
		uint32_t csum, csumPartial;
		size_t compressed_offset, csum_offset, data_offset;

		if (!r->ab.data) {
			return ndr_push_error(ndr, NDR_ERR_LENGTH,
					      "NULL uncompressed data blob");
		}
		if (r->ab.length != r->cbUncomp) {
			return ndr_push_error(ndr, NDR_ERR_LENGTH,
					      "Uncompressed data blob size != uncompressed data size field");
		}

		/*
		 * checksum is a function of the size fields
		 * and the potentially compressed data bytes,
		 * which haven't been compressed yet so
		 * remember offset, write zeroes, fill out
		 * later
		 */
		csum_offset = ndr->offset;
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));

		/*
		 * similarly, we don't know the compressed
		 * size yet, remember offset, write zeros,
		 * fill out later
		 */
		compressed_offset = ndr->offset;
		NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, 0));
		NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, r->cbUncomp));

		data_offset = ndr->offset;

		switch (cab_ctype) {
		case CF_COMPRESS_NONE:
			/* just copy the data */
			NDR_PUSH_NEED_BYTES(ndr, r->ab.length);
			NDR_CHECK(ndr_push_bytes(ndr, r->ab.data, r->ab.length));
			compressed_length = r->ab.length;
			break;
		case CF_COMPRESS_LZX:
			/*
			 * we have not yet worked out the details of LZX
			 * compression
			 */
			return NDR_ERR_COMPRESSION;

		case CF_COMPRESS_MSZIP: {
			struct ndr_push *push_sub, *push_compress;

			/* compress via subcontext */
			NDR_CHECK(ndr_push_subcontext_start(ndr, &push_sub, 0, -1));
			push_sub->cstate = ndr->cstate;
			NDR_CHECK(ndr_push_compression_start(push_sub, &push_compress, ndr_ctype, -1));
			ndr_set_flags(&push_compress->flags, LIBNDR_FLAG_REMAINING);
			NDR_CHECK(ndr_push_DATA_BLOB(push_compress, NDR_SCALARS, r->ab));
			NDR_CHECK(ndr_push_compression_end(push_sub, push_compress, ndr_ctype, -1));
			NDR_CHECK(ndr_push_subcontext_end(ndr, push_sub, 0, -1));
			compressed_length = push_sub->offset;

			break;
			}
		default:
			return NDR_ERR_BAD_SWITCH;
		}

		/* we can now write the compressed size and the checksum */
		SSVAL(ndr->data, compressed_offset, compressed_length);

		/*
		 * Create checksum over compressed data.
		 *
		 * The 8 bytes are the header size.
		 *
		 * We have already have written the checksum and set it to zero,
		 * earlier. So we know that after the checksum end the value
		 * for the compressed length comes the blob data.
		 *
		 * NDR already did all the checks for integer wraps.
		 */
		csumPartial = ndr_cab_compute_checksum(&ndr->data[data_offset],
						       compressed_length, 0);

		/*
		 * Checksum over header (compressed and uncompressed length).
		 *
		 * The first 4 bytes are the checksum size.
		 * The second 4 bytes are the size of the compressed and
		 * uncompressed length fields.
		 *
		 * NDR already did all the checks for integer wraps.
		 */
		csum = ndr_cab_compute_checksum(&ndr->data[compressed_offset],
						data_offset - compressed_offset,
						csumPartial);

		SIVAL(ndr->data, csum_offset, csum);
	}

	ndr_push_compression_state_free(ndr->cstate);
	ndr->cstate = NULL;

	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_push_cab_file(struct ndr_push *ndr, int ndr_flags, const struct cab_file *r)
{
	uint32_t cntr_cffolders_0;
	uint32_t cntr_cffiles_0;
	size_t processed_cfdata = 0;
	{
		uint32_t _flags_save_STRUCT = ndr->flags;
		ndr_set_flags(&ndr->flags, LIBNDR_PRINT_ARRAY_HEX|LIBNDR_FLAG_LITTLE_ENDIAN|LIBNDR_FLAG_NOALIGN);
		NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);

		if (ndr_flags & NDR_SCALARS) {
			uint32_t i;
			NDR_CHECK(ndr_push_align(ndr, 4));
			NDR_CHECK(ndr_push_CFHEADER(ndr, NDR_SCALARS, &r->cfheader));
			for (cntr_cffolders_0 = 0; cntr_cffolders_0 < (r->cfheader.cFolders); cntr_cffolders_0++) {
				NDR_CHECK(ndr_push_CFFOLDER(ndr, NDR_SCALARS, &r->cffolders[cntr_cffolders_0]));
			}
			for (cntr_cffiles_0 = 0; cntr_cffiles_0 < (r->cfheader.cFiles); cntr_cffiles_0++) {
				NDR_CHECK(ndr_push_CFFILE(ndr, NDR_SCALARS, &r->cffiles[cntr_cffiles_0]));
			}
#if 0
			NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ndr_count_cfdata(r)));
#endif

			/* write in the folder header the offset of its first data block */
			for (i = 0; i < r->cfheader.cFolders; i++) {
				size_t off = OFFSET_OF_FOLDER_COFFCABSTART(i);
				/* check that the offset we want to
				 * write to is always inside our
				 * current push buffer
				 */
				if (off >= ndr->offset) {
					return ndr_push_error(ndr, NDR_ERR_OFFSET,
							      "trying to write past current push buffer size");
				}
				SIVAL(ndr->data, off, ndr->offset);
				NDR_CHECK(ndr_push_folder_cfdata(ndr, r->cfdata + processed_cfdata, r->cffolders[i].typeCompress, r->cffolders[i].cCFData));
				processed_cfdata += r->cffolders[i].cCFData;
			}
			NDR_CHECK(ndr_push_trailer_align(ndr, 4));
		}
		if (ndr_flags & NDR_BUFFERS) {
		}
		ndr->flags = _flags_save_STRUCT;
	}


	/* write total file size in header */
	SIVAL(ndr->data, 8, ndr->offset);

	return NDR_ERR_SUCCESS;
}


/* Pull all CFDATA of a folder.
 *
 * This works on a folder level because compression type is set per
 * folder, and a compression state can be shared between CFDATA of the
 * same folder.
 *
 * This is not a regular NDR func as we pass the compression type and
 * the number of CFDATA as extra arguments
 */
static enum ndr_err_code ndr_pull_folder_cfdata(struct ndr_pull *ndr,
						struct CFDATA *r,
						enum cf_compress_type cab_ctype,
						size_t num_cfdata)
{
	size_t i;
	enum ndr_compression_alg ndr_ctype = 0;

	if (cab_ctype == CF_COMPRESS_MSZIP) {
		ndr_ctype = NDR_COMPRESSION_MSZIP_CAB;
		NDR_CHECK(ndr_pull_compression_state_init(ndr, NDR_COMPRESSION_MSZIP_CAB, &ndr->cstate));
	}

	for (i = 0; i < num_cfdata; i++, r++) {
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->csum));
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->cbData));
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->cbUncomp));

		switch (cab_ctype) {
		case CF_COMPRESS_NONE:
			/* just copy the data */
			NDR_PULL_NEED_BYTES(ndr, r->cbUncomp);
			r->ab = data_blob_talloc(ndr->current_mem_ctx,
						 ndr->data+ndr->offset,
						 r->cbUncomp);
			if (r->ab.data == NULL) {
				return ndr_pull_error(ndr, NDR_ERR_ALLOC,
						      "failed to allocate buffer for uncompressed CFDATA block");
			}
			ndr->offset += r->cbUncomp;
			break;

		case CF_COMPRESS_LZX:
			/* just copy the data (LZX decompression not implemented yet) */
			NDR_PULL_NEED_BYTES(ndr, r->cbData);
			r->ab = data_blob_talloc(ndr->current_mem_ctx,
						 ndr->data+ndr->offset,
						 r->cbData);
			if (r->ab.data == NULL) {
				return ndr_pull_error(ndr, NDR_ERR_ALLOC,
						      "failed to allocate buffer for LZX-compressed CFDATA block");
			}
			ndr->offset += r->cbData;
			break;

		case CF_COMPRESS_MSZIP: {
			struct ndr_pull *pull_sub, *pull_compress;
			NDR_PULL_NEED_BYTES(ndr, r->cbData);
			/* decompress via subcontext */
			NDR_CHECK(ndr_pull_subcontext_start(ndr, &pull_sub, 0, r->cbData));
			pull_sub->cstate = ndr->cstate;
			NDR_CHECK(ndr_pull_compression_start(pull_sub, &pull_compress,
							     ndr_ctype, r->cbUncomp, r->cbData));
			ndr_set_flags(&pull_compress->flags, LIBNDR_FLAG_REMAINING);
			NDR_CHECK(ndr_pull_DATA_BLOB(pull_compress, NDR_SCALARS, &r->ab));
			NDR_CHECK(ndr_pull_compression_end(pull_sub, pull_compress, ndr_ctype, r->cbUncomp));
			NDR_CHECK(ndr_pull_subcontext_end(ndr, pull_sub, 0, r->cbData));

			break;
		}
		default:
			return NDR_ERR_BAD_SWITCH;
		}
	}

	ndr_pull_compression_state_free(ndr->cstate);
	ndr->cstate = NULL;

	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_cab_file(struct ndr_pull *ndr, int ndr_flags, struct cab_file *r)
{
	uint32_t size_cffolders_0 = 0;
	uint32_t cntr_cffolders_0;
	TALLOC_CTX *_mem_save_cffolders_0 = NULL;
	uint32_t size_cffiles_0 = 0;
	uint32_t cntr_cffiles_0;
	TALLOC_CTX *_mem_save_cffiles_0 = NULL;
	uint32_t size_cfdata_0 = 0;
	size_t processed_cfdata = 0;
	TALLOC_CTX *_mem_save_cfdata_0 = NULL;
	{
		uint32_t _flags_save_STRUCT = ndr->flags;
		ndr_set_flags(&ndr->flags, LIBNDR_PRINT_ARRAY_HEX|LIBNDR_FLAG_LITTLE_ENDIAN|LIBNDR_FLAG_NOALIGN);
		NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
		if (ndr_flags & NDR_SCALARS) {
			NDR_CHECK(ndr_pull_align(ndr, 4));
			NDR_CHECK(ndr_pull_CFHEADER(ndr, NDR_SCALARS, &r->cfheader));
			size_cffolders_0 = r->cfheader.cFolders;
			NDR_PULL_ALLOC_N(ndr, r->cffolders, size_cffolders_0);
			_mem_save_cffolders_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->cffolders, 0);
			for (cntr_cffolders_0 = 0; cntr_cffolders_0 < (size_cffolders_0); cntr_cffolders_0++) {
				NDR_CHECK(ndr_pull_CFFOLDER(ndr, NDR_SCALARS, &r->cffolders[cntr_cffolders_0]));
			}
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_cffolders_0, 0);
			size_cffiles_0 = r->cfheader.cFiles;
			NDR_PULL_ALLOC_N(ndr, r->cffiles, size_cffiles_0);
			_mem_save_cffiles_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->cffiles, 0);
			for (cntr_cffiles_0 = 0; cntr_cffiles_0 < (size_cffiles_0); cntr_cffiles_0++) {
				NDR_CHECK(ndr_pull_CFFILE(ndr, NDR_SCALARS, &r->cffiles[cntr_cffiles_0]));
			}
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_cffiles_0, 0);
#if 0
			NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->cfdata_count));
#else
			r->cfdata_count = ndr_count_cfdata(r);
#endif
			size_cfdata_0 = r->cfdata_count;
			NDR_PULL_ALLOC_N(ndr, r->cfdata, size_cfdata_0);
			_mem_save_cfdata_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->cfdata, 0);
			for (cntr_cffolders_0 = 0; cntr_cffolders_0 < (size_cffolders_0); cntr_cffolders_0++) {
				NDR_CHECK(ndr_pull_folder_cfdata(ndr,
								 r->cfdata + processed_cfdata,
								 r->cffolders[cntr_cffolders_0].typeCompress,
								 r->cffolders[cntr_cffolders_0].cCFData));
				processed_cfdata += r->cffolders[cntr_cffolders_0].cCFData;
			}
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_cfdata_0, 0);
			NDR_CHECK(ndr_pull_trailer_align(ndr, 4));
		}
		if (ndr_flags & NDR_BUFFERS) {
		}
		ndr->flags = _flags_save_STRUCT;
	}
	return NDR_ERR_SUCCESS;
}
