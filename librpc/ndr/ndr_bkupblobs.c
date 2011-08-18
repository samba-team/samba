/*
   Unix SMB/CIFS implementation.

   helper routines for BKUP Blobs marshalling

   Copyright (C) Matthieu Patou <mat@matws.net> 2011

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
#include "librpc/gen_ndr/ndr_bkupblobs.h"


_PUBLIC_ enum ndr_err_code ndr_push_bkup_NTBackupFile(struct ndr_push *ndr, int ndr_flags, const struct bkup_NTBackupFile *r)
{
	uint32_t cntr_streams_0;
	{
		uint32_t _flags_save_STRUCT = ndr->flags;
		ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
		if (ndr_flags & NDR_SCALARS) {
			NDR_CHECK(ndr_push_align(ndr, 2));
			for (cntr_streams_0 = 0; cntr_streams_0 < r->num_stream; cntr_streams_0++) {
				NDR_CHECK(ndr_push_bkup_Win32StreamId(ndr, NDR_SCALARS, &r->streams[cntr_streams_0]));
			}
			NDR_CHECK(ndr_push_trailer_align(ndr, 8));
		}
		if (ndr_flags & NDR_BUFFERS) {
		}
		ndr->flags = _flags_save_STRUCT;
	}
	return NDR_ERR_SUCCESS;
}

#define _TMP_PULL_REALLOC_N(ndr, s, t, n) do { \
	_NDR_PULL_FIX_CURRENT_MEM_CTX(ndr);\
	(s) = talloc_realloc(ndr->current_mem_ctx, (s), t, n); \
	if (!(s)) { \
		return ndr_pull_error(ndr, NDR_ERR_ALLOC, \
				      "Alloc %u * %s failed: %s\n", \
				      (unsigned)n, # s, __location__); \
	} \
} while (0)

_PUBLIC_ enum ndr_err_code ndr_pull_bkup_NTBackupFile(struct ndr_pull *ndr, int ndr_flags, struct bkup_NTBackupFile *r)
{
	uint32_t cntr_streams_0;
	{
		uint32_t _flags_save_STRUCT = ndr->flags;
		ndr_set_flags(&ndr->flags, LIBNDR_FLAG_NOALIGN);
		if (ndr_flags & NDR_SCALARS) {
			uint32_t remaining = ndr->data_size - ndr->offset;
			r->num_stream = 0;
			r->streams = NULL;
			for (cntr_streams_0 = 0; remaining > 0; cntr_streams_0++) {
				r->num_stream += 1;
				_TMP_PULL_REALLOC_N(ndr, r->streams,
						    struct bkup_Win32StreamId,
						    r->num_stream);
				NDR_CHECK(ndr_pull_bkup_Win32StreamId(ndr,
						NDR_SCALARS,
						&r->streams[cntr_streams_0]));
				remaining = ndr->data_size - ndr->offset;
			}
		}
		if (ndr_flags & NDR_BUFFERS) {
		}
		ndr->flags = _flags_save_STRUCT;
	}
	return NDR_ERR_SUCCESS;
}
