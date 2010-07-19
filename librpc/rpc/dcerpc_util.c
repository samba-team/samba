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

uint8_t dcerpc_get_endian_flag(DATA_BLOB *blob)
{
	return blob->data[DCERPC_DREP_OFFSET];
}


/**
* @brief	Pull a dcerpc_auth structure, taking account of any auth
*		padding in the blob. For request/response packets we pass
*		the whole data blob, so auth_data_only must be set to false
*		as the blob contains data+pad+auth and no just pad+auth.
*
* @param pkt		- The ncacn_packet strcuture
* @param mem_ctx	- The mem_ctx used to allocate dcerpc_auth elements
* @param pkt_trailer	- The packet trailer data, usually the trailing
*			  auth_info blob, but in the request/response case
*			  this is the stub_and_verifier blob.
* @param auth		- A preallocated dcerpc_auth *empty* structure
* @param auth_length	- The length of the auth trail, sum of auth header
*			  lenght and pkt->auth_length
* @param auth_data_only	- Whether the pkt_trailer includes only the auth_blob
*			  (+ padding) or also other data.
*
* @return		- A NTSTATUS error code.
*/
NTSTATUS dcerpc_pull_auth_trailer(struct ncacn_packet *pkt,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *pkt_trailer,
				  struct dcerpc_auth *auth,
				  uint32_t *auth_length,
				  bool auth_data_only)
{
	struct ndr_pull *ndr;
	enum ndr_err_code ndr_err;
	uint32_t data_and_pad;

	data_and_pad = pkt_trailer->length
			- (DCERPC_AUTH_TRAILER_LENGTH + pkt->auth_length);

	/* paranoia check for pad size. This would be caught anyway by
	   the ndr_pull_advance() a few lines down, but it scared
	   Jeremy enough for him to call me, so we might as well check
	   it now, just to prevent someone posting a bogus YouTube
	   video in the future.
	*/
	if (data_and_pad > pkt_trailer->length) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}

	*auth_length = pkt_trailer->length - data_and_pad;

	ndr = ndr_pull_init_blob(pkt_trailer, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!(pkt->drep[0] & DCERPC_DREP_LE)) {
		ndr->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	ndr_err = ndr_pull_advance(ndr, data_and_pad);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(ndr);
		return ndr_map_error2ntstatus(ndr_err);
	}

	ndr_err = ndr_pull_dcerpc_auth(ndr, NDR_SCALARS|NDR_BUFFERS, auth);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(ndr);
		return ndr_map_error2ntstatus(ndr_err);
	}

	if (auth_data_only && data_and_pad != auth->auth_pad_length) {
		DEBUG(1, (__location__ ": WARNING: pad length mismatch. "
			  "Calculated %u  got %u\n",
			  (unsigned)data_and_pad,
			  (unsigned)auth->auth_pad_length));
	}

	DEBUG(6,(__location__ ": auth_pad_length %u\n",
		 (unsigned)auth->auth_pad_length));

	talloc_steal(mem_ctx, auth->credentials.data);
	talloc_free(ndr);

	return NT_STATUS_OK;
}
