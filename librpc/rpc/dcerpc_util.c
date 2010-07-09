/*
   Unix SMB/CIFS implementation.
   raw dcerpc operations

   Copyright (C) Andrew Tridgell 2003-2005
   Copyright (C) Jelmer Vernooij 2004-2005

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
#include "librpc/rpc/dcerpc.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"

/* we need to be able to get/set the fragment length without doing a full
   decode */
void dcerpc_set_frag_length(DATA_BLOB *blob, uint16_t v)
{
	if (CVAL(blob->data,DCERPC_DREP_OFFSET) & DCERPC_DREP_LE) {
		SSVAL(blob->data, DCERPC_FRAG_LEN_OFFSET, v);
	} else {
		RSSVAL(blob->data, DCERPC_FRAG_LEN_OFFSET, v);
	}
}

uint16_t dcerpc_get_frag_length(const DATA_BLOB *blob)
{
	if (CVAL(blob->data,DCERPC_DREP_OFFSET) & DCERPC_DREP_LE) {
		return SVAL(blob->data, DCERPC_FRAG_LEN_OFFSET);
	} else {
		return RSVAL(blob->data, DCERPC_FRAG_LEN_OFFSET);
	}
}

void dcerpc_set_auth_length(DATA_BLOB *blob, uint16_t v)
{
	if (CVAL(blob->data,DCERPC_DREP_OFFSET) & DCERPC_DREP_LE) {
		SSVAL(blob->data, DCERPC_AUTH_LEN_OFFSET, v);
	} else {
		RSSVAL(blob->data, DCERPC_AUTH_LEN_OFFSET, v);
	}
}

/*
  pull an dcerpc_auth structure, taking account of any auth padding in
  the blob at the end of the structure
 */
NTSTATUS dcerpc_pull_auth_trailer(struct ncacn_packet *pkt,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *pkt_auth_blob,
				  struct dcerpc_auth *auth,
				  uint32_t *auth_length,
				  bool check_pad)
{
	struct ndr_pull *ndr;
	enum ndr_err_code ndr_err;
	uint32_t pad;

	pad = pkt_auth_blob->length - (DCERPC_AUTH_TRAILER_LENGTH + pkt->auth_length);

	/* paranoia check for pad size. This would be caught anyway by
	   the ndr_pull_advance() a few lines down, but it scared
	   Jeremy enough for him to call me, so we might as well check
	   it now, just to prevent someone posting a bogus YouTube
	   video in the future.
	*/
	if (pad > pkt_auth_blob->length) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}

	*auth_length = pkt_auth_blob->length - pad;

	ndr = ndr_pull_init_blob(pkt_auth_blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!(pkt->drep[0] & DCERPC_DREP_LE)) {
		ndr->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	ndr_err = ndr_pull_advance(ndr, pad);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(ndr);
		return ndr_map_error2ntstatus(ndr_err);
	}

	ndr_err = ndr_pull_dcerpc_auth(ndr, NDR_SCALARS|NDR_BUFFERS, auth);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(ndr);
		return ndr_map_error2ntstatus(ndr_err);
	}

	if (check_pad && pad != auth->auth_pad_length) {
		DEBUG(1,(__location__ ": WARNING: pad length mismatch. Calculated %u  got %u\n",
			 (unsigned)pad, (unsigned)auth->auth_pad_length));
	}

	DEBUG(6,(__location__ ": auth_pad_length %u\n",
		 (unsigned)auth->auth_pad_length));

	talloc_steal(mem_ctx, auth->credentials.data);
	talloc_free(ndr);

	return NT_STATUS_OK;
}
