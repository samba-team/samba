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
#include "system/network.h"
#include <tevent.h>
#include "lib/tsocket/tsocket.h"
#include "lib/util/tevent_ntstatus.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "rpc_common.h"
#include "lib/util/bitmap.h"
#include "auth/gensec/gensec.h"
#include "lib/util/mkdir_p.h"
#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/crypto.h>

/* we need to be able to get/set the fragment length without doing a full
   decode */
void dcerpc_set_frag_length(DATA_BLOB *blob, uint16_t v)
{
	SMB_ASSERT(blob->length >= DCERPC_NCACN_PAYLOAD_OFFSET);

	if (CVAL(blob->data,DCERPC_DREP_OFFSET) & DCERPC_DREP_LE) {
		SSVAL(blob->data, DCERPC_FRAG_LEN_OFFSET, v);
	} else {
		RSSVAL(blob->data, DCERPC_FRAG_LEN_OFFSET, v);
	}
}

uint16_t dcerpc_get_frag_length(const DATA_BLOB *blob)
{
	SMB_ASSERT(blob->length >= DCERPC_NCACN_PAYLOAD_OFFSET);

	if (CVAL(blob->data,DCERPC_DREP_OFFSET) & DCERPC_DREP_LE) {
		return SVAL(blob->data, DCERPC_FRAG_LEN_OFFSET);
	} else {
		return RSVAL(blob->data, DCERPC_FRAG_LEN_OFFSET);
	}
}

void dcerpc_set_auth_length(DATA_BLOB *blob, uint16_t v)
{
	SMB_ASSERT(blob->length >= DCERPC_NCACN_PAYLOAD_OFFSET);

	if (CVAL(blob->data,DCERPC_DREP_OFFSET) & DCERPC_DREP_LE) {
		SSVAL(blob->data, DCERPC_AUTH_LEN_OFFSET, v);
	} else {
		RSSVAL(blob->data, DCERPC_AUTH_LEN_OFFSET, v);
	}
}

uint16_t dcerpc_get_auth_length(const DATA_BLOB *blob)
{
	SMB_ASSERT(blob->length >= DCERPC_NCACN_PAYLOAD_OFFSET);

	if (CVAL(blob->data,DCERPC_DREP_OFFSET) & DCERPC_DREP_LE) {
		return SVAL(blob->data, DCERPC_AUTH_LEN_OFFSET);
	} else {
		return RSVAL(blob->data, DCERPC_AUTH_LEN_OFFSET);
	}
}

uint8_t dcerpc_get_endian_flag(DATA_BLOB *blob)
{
	SMB_ASSERT(blob->length >= DCERPC_NCACN_PAYLOAD_OFFSET);

	return blob->data[DCERPC_DREP_OFFSET];
}

static uint16_t dcerpc_get_auth_context_offset(const DATA_BLOB *blob)
{
	uint16_t frag_len = dcerpc_get_frag_length(blob);
	uint16_t auth_len = dcerpc_get_auth_length(blob);
	uint16_t min_offset;
	uint16_t offset;

	if (auth_len == 0) {
		return 0;
	}

	if (frag_len > blob->length) {
		return 0;
	}

	if (auth_len > frag_len) {
		return 0;
	}

	min_offset = DCERPC_NCACN_PAYLOAD_OFFSET + DCERPC_AUTH_TRAILER_LENGTH;
	offset = frag_len - auth_len;
	if (offset < min_offset) {
		return 0;
	}
	offset -= DCERPC_AUTH_TRAILER_LENGTH;

	return offset;
}

uint8_t dcerpc_get_auth_type(const DATA_BLOB *blob)
{
	uint16_t offset;

	offset = dcerpc_get_auth_context_offset(blob);
	if (offset == 0) {
		return 0;
	}

	/*
	 * auth_typw is in the 1st byte
	 * of the auth trailer
	 */
	offset += 0;

	return blob->data[offset];
}

uint8_t dcerpc_get_auth_level(const DATA_BLOB *blob)
{
	uint16_t offset;

	offset = dcerpc_get_auth_context_offset(blob);
	if (offset == 0) {
		return 0;
	}

	/*
	 * auth_level is in 2nd byte
	 * of the auth trailer
	 */
	offset += 1;

	return blob->data[offset];
}

uint32_t dcerpc_get_auth_context_id(const DATA_BLOB *blob)
{
	uint16_t offset;

	offset = dcerpc_get_auth_context_offset(blob);
	if (offset == 0) {
		return 0;
	}

	/*
	 * auth_context_id is in the last 4 byte
	 * of the auth trailer
	 */
	offset += 4;

	if (CVAL(blob->data,DCERPC_DREP_OFFSET) & DCERPC_DREP_LE) {
		return IVAL(blob->data, offset);
	} else {
		return RIVAL(blob->data, offset);
	}
}

/**
* @brief Decodes a ncacn_packet
*
* @param mem_ctx	The memory context on which to allocate the packet
*			elements
* @param blob		The blob of data to decode
* @param r		An empty ncacn_packet, must not be NULL
*
* @return a NTSTATUS error code
*/
NTSTATUS dcerpc_pull_ncacn_packet(TALLOC_CTX *mem_ctx,
				  const DATA_BLOB *blob,
				  struct ncacn_packet *r)
{
	enum ndr_err_code ndr_err;
	struct ndr_pull *ndr;

	ndr = ndr_pull_init_blob(blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}

	ndr_err = ndr_pull_ncacn_packet(ndr, NDR_SCALARS|NDR_BUFFERS, r);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(ndr);
		return ndr_map_error2ntstatus(ndr_err);
	}
	talloc_free(ndr);

	if (r->frag_length != blob->length) {
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	return NT_STATUS_OK;
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
NTSTATUS dcerpc_pull_auth_trailer(const struct ncacn_packet *pkt,
				  TALLOC_CTX *mem_ctx,
				  const DATA_BLOB *pkt_trailer,
				  struct dcerpc_auth *auth,
				  uint32_t *_auth_length,
				  bool auth_data_only)
{
	struct ndr_pull *ndr;
	enum ndr_err_code ndr_err;
	uint16_t data_and_pad;
	uint16_t auth_length;
	uint32_t tmp_length;
	uint32_t max_pad_len = 0;

	ZERO_STRUCTP(auth);
	if (_auth_length != NULL) {
		*_auth_length = 0;

		if (auth_data_only) {
			return NT_STATUS_INTERNAL_ERROR;
		}
	} else {
		if (!auth_data_only) {
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	/* Paranoia checks for auth_length. The caller should check this... */
	if (pkt->auth_length == 0) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	/* Paranoia checks for auth_length. The caller should check this... */
	if (pkt->auth_length > pkt->frag_length) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	tmp_length = DCERPC_NCACN_PAYLOAD_OFFSET;
	tmp_length += DCERPC_AUTH_TRAILER_LENGTH;
	tmp_length += pkt->auth_length;
	if (tmp_length > pkt->frag_length) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	if (pkt_trailer->length > UINT16_MAX) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	auth_length = DCERPC_AUTH_TRAILER_LENGTH + pkt->auth_length;
	if (pkt_trailer->length < auth_length) {
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	data_and_pad = pkt_trailer->length - auth_length;

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
		ZERO_STRUCTP(auth);
		return ndr_map_error2ntstatus(ndr_err);
	}

	/*
	 * Make sure the padding would not exceed
	 * the frag_length.
	 *
	 * Here we assume at least 24 bytes for the
	 * payload specific header the value of
	 * DCERPC_{REQUEST,RESPONSE}_LENGTH.
	 *
	 * We use this also for BIND_*, ALTER_* and AUTH3 pdus.
	 *
	 * We need this check before we ignore possible
	 * invalid values. See also bug #11982.
	 *
	 * This check is mainly used to generate the correct
	 * error for BIND_*, ALTER_* and AUTH3 pdus.
	 *
	 * We always have the 'if (data_and_pad < auth->auth_pad_length)'
	 * protection for REQUEST and RESPONSE pdus, where the
	 * auth_pad_length field is actually used by the caller.
	 */
	tmp_length = DCERPC_REQUEST_LENGTH;
	tmp_length += DCERPC_AUTH_TRAILER_LENGTH;
	tmp_length += pkt->auth_length;
	if (tmp_length < pkt->frag_length) {
		max_pad_len = pkt->frag_length - tmp_length;
	}
	if (max_pad_len < auth->auth_pad_length) {
		DEBUG(1, (__location__ ": ERROR: pad length to large. "
			  "max %u got %u\n",
			  (unsigned)max_pad_len,
			  (unsigned)auth->auth_pad_length));
		talloc_free(ndr);
		ZERO_STRUCTP(auth);
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	/*
	 * This is a workarround for a bug in old
	 * Samba releases. For BIND_ACK <= 3.5.x
	 * and for ALTER_RESP <= 4.2.x (see bug #11061)
	 *
	 * See also bug #11982.
	 */
	if (auth_data_only && data_and_pad == 0 &&
	    auth->auth_pad_length > 0) {
		/*
		 * we need to ignore invalid auth_pad_length
		 * values for BIND_*, ALTER_* and AUTH3 pdus.
		 */
		auth->auth_pad_length = 0;
	}

	if (data_and_pad < auth->auth_pad_length) {
		DBG_WARNING(__location__ ": ERROR: pad length too long. "
			    "Calculated %u (pkt_trailer->length=%u - auth_length=%u) "
			    "was less than auth_pad_length=%u\n",
			    (unsigned)data_and_pad,
			    (unsigned)pkt_trailer->length,
			    (unsigned)auth_length,
			    (unsigned)auth->auth_pad_length);
		talloc_free(ndr);
		ZERO_STRUCTP(auth);
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	if (auth_data_only && data_and_pad > auth->auth_pad_length) {
		DBG_WARNING(__location__ ": ERROR: auth_data_only pad length mismatch. "
			    "Client sent a longer BIND packet than expected by %u bytes "
			    "(pkt_trailer->length=%u - auth_length=%u) "
			    "= %u auth_pad_length=%u\n",
			    (unsigned)data_and_pad - (unsigned)auth->auth_pad_length,
			    (unsigned)pkt_trailer->length,
			    (unsigned)auth_length,
			    (unsigned)data_and_pad,
			    (unsigned)auth->auth_pad_length);
		talloc_free(ndr);
		ZERO_STRUCTP(auth);
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	if (auth_data_only && data_and_pad != auth->auth_pad_length) {
		DBG_WARNING(__location__ ": ERROR: auth_data_only pad length mismatch. "
			    "Calculated %u (pkt_trailer->length=%u - auth_length=%u) "
			    "but auth_pad_length=%u\n",
			    (unsigned)data_and_pad,
			    (unsigned)pkt_trailer->length,
			    (unsigned)auth_length,
			    (unsigned)auth->auth_pad_length);
		talloc_free(ndr);
		ZERO_STRUCTP(auth);
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	DBG_DEBUG("auth_pad_length %u\n",
		  (unsigned)auth->auth_pad_length);

	talloc_steal(mem_ctx, auth->credentials.data);
	talloc_free(ndr);

	if (_auth_length != NULL) {
		*_auth_length = auth_length;
	}

	return NT_STATUS_OK;
}

/**
* @brief	Verify the fields in ncacn_packet header.
*
* @param pkt		- The ncacn_packet strcuture
* @param ptype		- The expected PDU type
* @param max_auth_info	- The maximum size of a possible auth trailer
* @param required_flags	- The required flags for the pdu.
* @param optional_flags	- The possible optional flags for the pdu.
*
* @return		- A NTSTATUS error code.
*/
NTSTATUS dcerpc_verify_ncacn_packet_header(const struct ncacn_packet *pkt,
					   enum dcerpc_pkt_type ptype,
					   size_t max_auth_info,
					   uint8_t required_flags,
					   uint8_t optional_flags)
{
	if (pkt->rpc_vers != 5) {
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	if (pkt->rpc_vers_minor != 0) {
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	if (pkt->auth_length > pkt->frag_length) {
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	if (pkt->ptype != ptype) {
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	if (max_auth_info > UINT16_MAX) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (pkt->auth_length > 0) {
		size_t max_auth_length;

		if (max_auth_info <= DCERPC_AUTH_TRAILER_LENGTH) {
			return NT_STATUS_RPC_PROTOCOL_ERROR;
		}
		max_auth_length = max_auth_info - DCERPC_AUTH_TRAILER_LENGTH;

		if (pkt->auth_length > max_auth_length) {
			return NT_STATUS_RPC_PROTOCOL_ERROR;
		}
	}

	if ((pkt->pfc_flags & required_flags) != required_flags) {
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}
	if (pkt->pfc_flags & ~(optional_flags|required_flags)) {
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	if (pkt->drep[0] & ~DCERPC_DREP_LE) {
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}
	if (pkt->drep[1] != 0) {
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}
	if (pkt->drep[2] != 0) {
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}
	if (pkt->drep[3] != 0) {
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	return NT_STATUS_OK;
}

NTSTATUS dcerpc_ncacn_pull_pkt_auth(const struct dcerpc_auth *auth_state,
				    struct gensec_security *gensec,
				    TALLOC_CTX *mem_ctx,
				    enum dcerpc_pkt_type ptype,
				    uint8_t required_flags,
				    uint8_t optional_flags,
				    uint8_t payload_offset,
				    DATA_BLOB *payload_and_verifier,
				    DATA_BLOB *raw_packet,
				    const struct ncacn_packet *pkt)
{
	NTSTATUS status;
	struct dcerpc_auth auth;
	uint32_t auth_length;

	if (auth_state == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = dcerpc_verify_ncacn_packet_header(pkt, ptype,
					payload_and_verifier->length,
					required_flags, optional_flags);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	switch (auth_state->auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
	case DCERPC_AUTH_LEVEL_INTEGRITY:
	case DCERPC_AUTH_LEVEL_PACKET:
		break;

	case DCERPC_AUTH_LEVEL_CONNECT:
		if (pkt->auth_length != 0) {
			break;
		}
		return NT_STATUS_OK;
	case DCERPC_AUTH_LEVEL_NONE:
		if (pkt->auth_length != 0) {
			return NT_STATUS_ACCESS_DENIED;
		}
		return NT_STATUS_OK;

	default:
		return NT_STATUS_RPC_UNSUPPORTED_AUTHN_LEVEL;
	}

	if (pkt->auth_length == 0) {
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	if (gensec == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = dcerpc_pull_auth_trailer(pkt, mem_ctx,
					  payload_and_verifier,
					  &auth, &auth_length, false);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (payload_and_verifier->length < auth_length) {
		/*
		 * should be checked in dcerpc_pull_auth_trailer()
		 */
		return NT_STATUS_INTERNAL_ERROR;
	}

	payload_and_verifier->length -= auth_length;

	if (payload_and_verifier->length < auth.auth_pad_length) {
		/*
		 * should be checked in dcerpc_pull_auth_trailer()
		 */
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (auth.auth_type != auth_state->auth_type) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (auth.auth_level != auth_state->auth_level) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (auth.auth_context_id != auth_state->auth_context_id) {
		return NT_STATUS_ACCESS_DENIED;
	}

	/* check signature or unseal the packet */
	switch (auth_state->auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		status = gensec_unseal_packet(gensec,
					      raw_packet->data + payload_offset,
					      payload_and_verifier->length,
					      raw_packet->data,
					      raw_packet->length -
					      auth.credentials.length,
					      &auth.credentials);
		if (!NT_STATUS_IS_OK(status)) {
			return NT_STATUS_RPC_SEC_PKG_ERROR;
		}
		memcpy(payload_and_verifier->data,
		       raw_packet->data + payload_offset,
		       payload_and_verifier->length);
		break;

	case DCERPC_AUTH_LEVEL_INTEGRITY:
	case DCERPC_AUTH_LEVEL_PACKET:
		status = gensec_check_packet(gensec,
					     payload_and_verifier->data,
					     payload_and_verifier->length,
					     raw_packet->data,
					     raw_packet->length -
					     auth.credentials.length,
					     &auth.credentials);
		if (!NT_STATUS_IS_OK(status)) {
			return NT_STATUS_RPC_SEC_PKG_ERROR;
		}
		break;

	case DCERPC_AUTH_LEVEL_CONNECT:
		/* for now we ignore possible signatures here */
		break;

	default:
		return NT_STATUS_RPC_UNSUPPORTED_AUTHN_LEVEL;
	}

	/*
	 * remove the indicated amount of padding
	 *
	 * A possible overflow is checked above.
	 */
	payload_and_verifier->length -= auth.auth_pad_length;

	return NT_STATUS_OK;
}

NTSTATUS dcerpc_ncacn_push_pkt_auth(const struct dcerpc_auth *auth_state,
				    struct gensec_security *gensec,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *raw_packet,
				    size_t sig_size,
				    uint8_t payload_offset,
				    const DATA_BLOB *payload,
				    const struct ncacn_packet *pkt)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	struct ndr_push *ndr = NULL;
	uint32_t payload_length;
	uint32_t whole_length;
	DATA_BLOB blob = data_blob_null;
	DATA_BLOB sig = data_blob_null;
	struct dcerpc_auth _out_auth_info;
	struct dcerpc_auth *out_auth_info = NULL;

	*raw_packet = data_blob_null;

	if (auth_state == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}

	switch (auth_state->auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
	case DCERPC_AUTH_LEVEL_INTEGRITY:
	case DCERPC_AUTH_LEVEL_PACKET:
		if (sig_size == 0) {
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_ERROR;
		}

		if (gensec == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_ERROR;
		}

		_out_auth_info = (struct dcerpc_auth) {
			.auth_type = auth_state->auth_type,
			.auth_level = auth_state->auth_level,
			.auth_context_id = auth_state->auth_context_id,
		};
		out_auth_info = &_out_auth_info;
		break;

	case DCERPC_AUTH_LEVEL_CONNECT:
		/*
		 * TODO: let the gensec mech decide if it wants to generate a
		 *       signature that might be needed for schannel...
		 */
		if (sig_size != 0) {
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_ERROR;
		}

		if (gensec == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_ERROR;
		}
		break;

	case DCERPC_AUTH_LEVEL_NONE:
		if (sig_size != 0) {
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_ERROR;
		}
		break;

	default:
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}

	ndr = ndr_push_init_ctx(frame);
	if (ndr == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	ndr_err = ndr_push_ncacn_packet(ndr, NDR_SCALARS|NDR_BUFFERS, pkt);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	if (out_auth_info != NULL) {
		/*
		 * pad to 16 byte multiple in the payload portion of the
		 * packet. This matches what w2k3 does. Note that we can't use
		 * ndr_push_align() as that is relative to the start of the
		 * whole packet, whereas w2k8 wants it relative to the start
		 * of the stub.
		 */
		out_auth_info->auth_pad_length =
			DCERPC_AUTH_PAD_LENGTH(payload->length);
		ndr_err = ndr_push_zero(ndr, out_auth_info->auth_pad_length);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			TALLOC_FREE(frame);
			return ndr_map_error2ntstatus(ndr_err);
		}

		payload_length = payload->length +
			out_auth_info->auth_pad_length;

		ndr_err = ndr_push_dcerpc_auth(ndr, NDR_SCALARS|NDR_BUFFERS,
					       out_auth_info);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			TALLOC_FREE(frame);
			return ndr_map_error2ntstatus(ndr_err);
		}

		whole_length = ndr->offset;

		ndr_err = ndr_push_zero(ndr, sig_size);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			TALLOC_FREE(frame);
			return ndr_map_error2ntstatus(ndr_err);
		}
	} else {
		payload_length = payload->length;
		whole_length = ndr->offset;
	}

	/* extract the whole packet as a blob */
	blob = ndr_push_blob(ndr);

	/*
	 * Setup the frag and auth length in the packet buffer.
	 * This is needed if the GENSEC mech does AEAD signing
	 * of the packet headers. The signature itself will be
	 * appended later.
	 */
	dcerpc_set_frag_length(&blob, blob.length);
	dcerpc_set_auth_length(&blob, sig_size);

	/* sign or seal the packet */
	switch (auth_state->auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		status = gensec_seal_packet(gensec,
					    frame,
					    blob.data + payload_offset,
					    payload_length,
					    blob.data,
					    whole_length,
					    &sig);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}
		break;

	case DCERPC_AUTH_LEVEL_INTEGRITY:
	case DCERPC_AUTH_LEVEL_PACKET:
		status = gensec_sign_packet(gensec,
					    frame,
					    blob.data + payload_offset,
					    payload_length,
					    blob.data,
					    whole_length,
					    &sig);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}
		break;

	case DCERPC_AUTH_LEVEL_CONNECT:
	case DCERPC_AUTH_LEVEL_NONE:
		break;

	default:
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (sig.length != sig_size) {
		TALLOC_FREE(frame);
		return NT_STATUS_RPC_SEC_PKG_ERROR;
	}

	if (sig_size != 0) {
		memcpy(blob.data + whole_length, sig.data, sig_size);
	}

	*raw_packet = blob;
	talloc_steal(mem_ctx, raw_packet->data);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

struct dcerpc_read_ncacn_packet_state {
#if 0
	struct {
	} caller;
#endif
	DATA_BLOB buffer;
	struct ncacn_packet *pkt;
};

static int dcerpc_read_ncacn_packet_next_vector(struct tstream_context *stream,
						void *private_data,
						TALLOC_CTX *mem_ctx,
						struct iovec **_vector,
						size_t *_count);
static void dcerpc_read_ncacn_packet_done(struct tevent_req *subreq);

struct tevent_req *dcerpc_read_ncacn_packet_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct tstream_context *stream)
{
	struct tevent_req *req;
	struct dcerpc_read_ncacn_packet_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct dcerpc_read_ncacn_packet_state);
	if (req == NULL) {
		return NULL;
	}

	state->pkt = talloc_zero(state, struct ncacn_packet);
	if (tevent_req_nomem(state->pkt, req)) {
		goto post;
	}

	subreq = tstream_readv_pdu_send(state, ev,
					stream,
					dcerpc_read_ncacn_packet_next_vector,
					state);
	if (tevent_req_nomem(subreq, req)) {
		goto post;
	}
	tevent_req_set_callback(subreq, dcerpc_read_ncacn_packet_done, req);

	return req;
 post:
	tevent_req_post(req, ev);
	return req;
}

static int dcerpc_read_ncacn_packet_next_vector(struct tstream_context *stream,
						void *private_data,
						TALLOC_CTX *mem_ctx,
						struct iovec **_vector,
						size_t *_count)
{
	struct dcerpc_read_ncacn_packet_state *state =
		talloc_get_type_abort(private_data,
		struct dcerpc_read_ncacn_packet_state);
	struct iovec *vector;
	off_t ofs = 0;

	if (state->buffer.length == 0) {
		/*
		 * first get enough to read the fragment length
		 *
		 * We read the full fixed ncacn_packet header
		 * in order to make wireshark happy with
		 * pcap files from socket_wrapper.
		 */
		ofs = 0;
		state->buffer.length = DCERPC_NCACN_PAYLOAD_OFFSET;
		state->buffer.data = talloc_array(state, uint8_t,
						  state->buffer.length);
		if (!state->buffer.data) {
			return -1;
		}
	} else if (state->buffer.length == DCERPC_NCACN_PAYLOAD_OFFSET) {
		/* now read the fragment length and allocate the full buffer */
		size_t frag_len = dcerpc_get_frag_length(&state->buffer);

		ofs = state->buffer.length;

		if (frag_len < ofs) {
			/*
			 * something is wrong, let the caller deal with it
			 */
			*_vector = NULL;
			*_count = 0;
			return 0;
		}

		state->buffer.data = talloc_realloc(state,
						    state->buffer.data,
						    uint8_t, frag_len);
		if (!state->buffer.data) {
			return -1;
		}
		state->buffer.length = frag_len;
	} else {
		/* if we reach this we have a full fragment */
		*_vector = NULL;
		*_count = 0;
		return 0;
	}

	/* now create the vector that we want to be filled */
	vector = talloc_array(mem_ctx, struct iovec, 1);
	if (!vector) {
		return -1;
	}

	vector[0].iov_base = (void *) (state->buffer.data + ofs);
	vector[0].iov_len = state->buffer.length - ofs;

	*_vector = vector;
	*_count = 1;
	return 0;
}

static void dcerpc_read_ncacn_packet_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct dcerpc_read_ncacn_packet_state *state = tevent_req_data(req,
					struct dcerpc_read_ncacn_packet_state);
	int ret;
	int sys_errno;
	NTSTATUS status;

	ret = tstream_readv_pdu_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		status = map_nt_error_from_unix_common(sys_errno);
		tevent_req_nterror(req, status);
		return;
	}

	status = dcerpc_pull_ncacn_packet(state->pkt,
					  &state->buffer,
					  state->pkt);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS dcerpc_read_ncacn_packet_recv(struct tevent_req *req,
				       TALLOC_CTX *mem_ctx,
				       struct ncacn_packet **pkt,
				       DATA_BLOB *buffer)
{
	struct dcerpc_read_ncacn_packet_state *state = tevent_req_data(req,
					struct dcerpc_read_ncacn_packet_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*pkt = talloc_move(mem_ctx, &state->pkt);
	if (buffer) {
		buffer->data = talloc_move(mem_ctx, &state->buffer.data);
		buffer->length = state->buffer.length;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

const char *dcerpc_default_transport_endpoint(TALLOC_CTX *mem_ctx,
					      enum dcerpc_transport_t transport,
					      const struct ndr_interface_table *table)
{
	NTSTATUS status;
	const char *p = NULL;
	const char *endpoint = NULL;
	uint32_t i;
	struct dcerpc_binding *default_binding = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	/* Find one of the default pipes for this interface */

	for (i = 0; i < table->endpoints->count; i++) {
		enum dcerpc_transport_t dtransport;
		const char *dendpoint;

		status = dcerpc_parse_binding(frame, table->endpoints->names[i],
					      &default_binding);
		if (!NT_STATUS_IS_OK(status)) {
			continue;
		}

		dtransport = dcerpc_binding_get_transport(default_binding);
		dendpoint = dcerpc_binding_get_string_option(default_binding,
							     "endpoint");
		if (dendpoint == NULL) {
			TALLOC_FREE(default_binding);
			continue;
		}

		if (transport == NCA_UNKNOWN) {
			transport = dtransport;
		}

		if (transport != dtransport) {
			TALLOC_FREE(default_binding);
			continue;
		}

		p = dendpoint;
		break;
	}

	if (p == NULL) {
		goto done;
	}

	/*
	 * extract the pipe name without \\pipe from for example
	 * ncacn_np:[\\pipe\\epmapper]
	 */
	if (transport == NCACN_NP) {
		if (strncasecmp(p, "\\pipe\\", 6) == 0) {
			p += 6;
		}
		if (strncmp(p, "\\", 1) == 0) {
			p += 1;
		}
	}

	endpoint = talloc_strdup(mem_ctx, p);

 done:
	talloc_free(frame);
	return endpoint;
}

struct dcerpc_sec_vt_header2 dcerpc_sec_vt_header2_from_ncacn_packet(const struct ncacn_packet *pkt)
{
	struct dcerpc_sec_vt_header2 ret;

	ZERO_STRUCT(ret);
	ret.ptype = pkt->ptype;
	memcpy(&ret.drep, pkt->drep, sizeof(ret.drep));
	ret.call_id = pkt->call_id;

	switch (pkt->ptype) {
	case DCERPC_PKT_REQUEST:
		ret.context_id = pkt->u.request.context_id;
		ret.opnum      = pkt->u.request.opnum;
		break;

	case DCERPC_PKT_RESPONSE:
		ret.context_id = pkt->u.response.context_id;
		break;

	case DCERPC_PKT_FAULT:
		ret.context_id = pkt->u.fault.context_id;
		break;

	default:
		break;
	}

	return ret;
}

bool dcerpc_sec_vt_header2_equal(const struct dcerpc_sec_vt_header2 *v1,
				 const struct dcerpc_sec_vt_header2 *v2)
{
	if (v1->ptype != v2->ptype) {
		return false;
	}

	if (memcmp(v1->drep, v2->drep, sizeof(v1->drep)) != 0) {
		return false;
	}

	if (v1->call_id != v2->call_id) {
		return false;
	}

	if (v1->context_id != v2->context_id) {
		return false;
	}

	if (v1->opnum != v2->opnum) {
		return false;
	}

	return true;
}

static bool dcerpc_sec_vt_is_valid(const struct dcerpc_sec_verification_trailer *r)
{
	bool ret = false;
	TALLOC_CTX *frame = talloc_stackframe();
	struct bitmap *commands_seen;
	int i;

	if (r->count.count == 0) {
		ret = true;
		goto done;
	}

	if (memcmp(r->magic, DCERPC_SEC_VT_MAGIC, sizeof(r->magic)) != 0) {
		goto done;
	}

	commands_seen = bitmap_talloc(frame, DCERPC_SEC_VT_COMMAND_ENUM + 1);
	if (commands_seen == NULL) {
		goto done;
	}

	for (i=0; i < r->count.count; i++) {
		enum dcerpc_sec_vt_command_enum cmd =
			r->commands[i].command & DCERPC_SEC_VT_COMMAND_ENUM;

		if (bitmap_query(commands_seen, cmd)) {
			/* Each command must appear at most once. */
			goto done;
		}
		bitmap_set(commands_seen, cmd);

		switch (cmd) {
		case DCERPC_SEC_VT_COMMAND_BITMASK1:
		case DCERPC_SEC_VT_COMMAND_PCONTEXT:
		case DCERPC_SEC_VT_COMMAND_HEADER2:
			break;
		default:
			if ((r->commands[i].u._unknown.length % 4) != 0) {
				goto done;
			}
			break;
		}
	}
	ret = true;
done:
	TALLOC_FREE(frame);
	return ret;
}

static bool dcerpc_sec_vt_bitmask_check(const uint32_t *bitmask1,
					struct dcerpc_sec_vt *c)
{
	if (bitmask1 == NULL) {
		if (c->command & DCERPC_SEC_VT_MUST_PROCESS) {
			DEBUG(10, ("SEC_VT check Bitmask1 must_process_command "
				   "failed\n"));
			return false;
		}

		return true;
	}

	if ((c->u.bitmask1 & DCERPC_SEC_VT_CLIENT_SUPPORTS_HEADER_SIGNING)
	 && (!(*bitmask1 & DCERPC_SEC_VT_CLIENT_SUPPORTS_HEADER_SIGNING))) {
		DEBUG(10, ("SEC_VT check Bitmask1 client_header_signing "
			   "failed\n"));
		return false;
	}
	return true;
}

static bool dcerpc_sec_vt_pctx_check(const struct dcerpc_sec_vt_pcontext *pcontext,
				     struct dcerpc_sec_vt *c)
{
	TALLOC_CTX *mem_ctx;
	bool ok;

	if (pcontext == NULL) {
		if (c->command & DCERPC_SEC_VT_MUST_PROCESS) {
			DEBUG(10, ("SEC_VT check Pcontext must_process_command "
				   "failed\n"));
			return false;
		}

		return true;
	}

	mem_ctx = talloc_stackframe();
	ok = ndr_syntax_id_equal(&pcontext->abstract_syntax,
				 &c->u.pcontext.abstract_syntax);
	if (!ok) {
		DEBUG(10, ("SEC_VT check pcontext abstract_syntax failed: "
			   "%s vs. %s\n",
			   ndr_syntax_id_to_string(mem_ctx,
					&pcontext->abstract_syntax),
			   ndr_syntax_id_to_string(mem_ctx,
					&c->u.pcontext.abstract_syntax)));
		goto err_ctx_free;
	}
	ok = ndr_syntax_id_equal(&pcontext->transfer_syntax,
				 &c->u.pcontext.transfer_syntax);
	if (!ok) {
		DEBUG(10, ("SEC_VT check pcontext transfer_syntax failed: "
			   "%s vs. %s\n",
			   ndr_syntax_id_to_string(mem_ctx,
					&pcontext->transfer_syntax),
			   ndr_syntax_id_to_string(mem_ctx,
					&c->u.pcontext.transfer_syntax)));
		goto err_ctx_free;
	}

	ok = true;
err_ctx_free:
	talloc_free(mem_ctx);
	return ok;
}

static bool dcerpc_sec_vt_hdr2_check(const struct dcerpc_sec_vt_header2 *header2,
				     struct dcerpc_sec_vt *c)
{
	if (header2 == NULL) {
		if (c->command & DCERPC_SEC_VT_MUST_PROCESS) {
			DEBUG(10, ("SEC_VT check Header2 must_process_command failed\n"));
			return false;
		}

		return true;
	}

	if (!dcerpc_sec_vt_header2_equal(header2, &c->u.header2)) {
		DEBUG(10, ("SEC_VT check Header2 failed\n"));
		return false;
	}

	return true;
}

bool dcerpc_sec_verification_trailer_check(
		const struct dcerpc_sec_verification_trailer *vt,
		const uint32_t *bitmask1,
		const struct dcerpc_sec_vt_pcontext *pcontext,
		const struct dcerpc_sec_vt_header2 *header2)
{
	size_t i;

	if (!dcerpc_sec_vt_is_valid(vt)) {
		return false;
	}

	for (i=0; i < vt->count.count; i++) {
		bool ok;
		struct dcerpc_sec_vt *c = &vt->commands[i];

		switch (c->command & DCERPC_SEC_VT_COMMAND_ENUM) {
		case DCERPC_SEC_VT_COMMAND_BITMASK1:
			ok = dcerpc_sec_vt_bitmask_check(bitmask1, c);
			if (!ok) {
				return false;
			}
			break;

		case DCERPC_SEC_VT_COMMAND_PCONTEXT:
			ok = dcerpc_sec_vt_pctx_check(pcontext, c);
			if (!ok) {
				return false;
			}
			break;

		case DCERPC_SEC_VT_COMMAND_HEADER2: {
			ok = dcerpc_sec_vt_hdr2_check(header2, c);
			if (!ok) {
				return false;
			}
			break;
		}

		default:
			if (c->command & DCERPC_SEC_VT_MUST_PROCESS) {
				DEBUG(10, ("SEC_VT check Unknown must_process_command failed\n"));
				return false;
			}

			break;
		}
	}

	return true;
}

static const struct ndr_syntax_id dcerpc_bind_time_features_prefix  = {
	.uuid = {
		.time_low = 0x6cb71c2c,
		.time_mid = 0x9812,
		.time_hi_and_version = 0x4540,
		.clock_seq = {0x00, 0x00},
		.node = {0x00,0x00,0x00,0x00,0x00,0x00}
	},
	.if_version = 1,
};

bool dcerpc_extract_bind_time_features(struct ndr_syntax_id s, uint64_t *_features)
{
	uint8_t values[8];
	uint64_t features = 0;

	values[0] = s.uuid.clock_seq[0];
	values[1] = s.uuid.clock_seq[1];
	values[2] = s.uuid.node[0];
	values[3] = s.uuid.node[1];
	values[4] = s.uuid.node[2];
	values[5] = s.uuid.node[3];
	values[6] = s.uuid.node[4];
	values[7] = s.uuid.node[5];

	ZERO_STRUCT(s.uuid.clock_seq);
	ZERO_STRUCT(s.uuid.node);

	if (!ndr_syntax_id_equal(&s, &dcerpc_bind_time_features_prefix)) {
		if (_features != NULL) {
			*_features = 0;
		}
		return false;
	}

	features = BVAL(values, 0);

	if (_features != NULL) {
		*_features = features;
	}

	return true;
}

struct ndr_syntax_id dcerpc_construct_bind_time_features(uint64_t features)
{
	struct ndr_syntax_id s = dcerpc_bind_time_features_prefix;
	uint8_t values[8];

	SBVAL(values, 0, features);

	s.uuid.clock_seq[0] = values[0];
	s.uuid.clock_seq[1] = values[1];
	s.uuid.node[0]      = values[2];
	s.uuid.node[1]      = values[3];
	s.uuid.node[2]      = values[4];
	s.uuid.node[3]      = values[5];
	s.uuid.node[4]      = values[6];
	s.uuid.node[5]      = values[7];

	return s;
}

NTSTATUS dcerpc_generic_session_key(DATA_BLOB *session_key)
{
	*session_key = data_blob_null;

	/* this took quite a few CPU cycles to find ... */
	session_key->data = discard_const_p(unsigned char, "SystemLibraryDTC");
	session_key->length = 16;
	return NT_STATUS_OK;
}

/*
   push a ncacn_packet into a blob, potentially with auth info
*/
NTSTATUS dcerpc_ncacn_push_auth(DATA_BLOB *blob,
				TALLOC_CTX *mem_ctx,
				struct ncacn_packet *pkt,
				struct dcerpc_auth *auth_info)
{
	struct ndr_push *ndr;
	enum ndr_err_code ndr_err;

	ndr = ndr_push_init_ctx(mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}

	if (auth_info) {
		pkt->auth_length = auth_info->credentials.length;
	} else {
		pkt->auth_length = 0;
	}

	ndr_err = ndr_push_ncacn_packet(ndr, NDR_SCALARS|NDR_BUFFERS, pkt);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	if (auth_info) {
#if 0
		/* the s3 rpc server doesn't handle auth padding in
		   bind requests. Use zero auth padding to keep us
		   working with old servers */
		uint32_t offset = ndr->offset;
		ndr_err = ndr_push_align(ndr, 16);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return ndr_map_error2ntstatus(ndr_err);
		}
		auth_info->auth_pad_length = ndr->offset - offset;
#else
		auth_info->auth_pad_length = 0;
#endif
		ndr_err = ndr_push_dcerpc_auth(ndr, NDR_SCALARS|NDR_BUFFERS, auth_info);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return ndr_map_error2ntstatus(ndr_err);
		}
	}

	*blob = ndr_push_blob(ndr);

	/* fill in the frag length */
	dcerpc_set_frag_length(blob, blob->length);

	return NT_STATUS_OK;
}

/*
  log a rpc packet in a format suitable for ndrdump. This is especially useful
  for sealed packets, where ethereal cannot easily see the contents

  this triggers if "dcesrv:stubs directory" is set and present
  for all packets that fail to parse
*/
void dcerpc_log_packet(const char *packet_log_dir,
		       const char *interface_name,
		       uint32_t opnum, uint32_t flags,
		       const DATA_BLOB *pkt,
		       const char *why)
{
	const int num_examples = 20;
	int i;

	if (packet_log_dir == NULL) {
		return;
	}

	for (i=0;i<num_examples;i++) {
		char *name=NULL;
		int ret;
		bool saved;
		ret = asprintf(&name, "%s/%s-%u.%d.%s.%s",
			       packet_log_dir, interface_name, opnum, i,
			       (flags&NDR_IN)?"in":"out",
			       why);
		if (ret == -1) {
			return;
		}

		saved = file_save(name, pkt->data, pkt->length);
		if (saved) {
			DBG_DEBUG("Logged rpc packet to %s\n", name);
			free(name);
			break;
		}
		free(name);
	}
}


#ifdef DEVELOPER

/*
 * Save valid, well-formed DCE/RPC stubs to use as a seed for
 * ndr_fuzz_X
 */
void dcerpc_save_ndr_fuzz_seed(TALLOC_CTX *mem_ctx,
			       DATA_BLOB raw_blob,
			       const char *dump_dir,
			       const char *iface_name,
			       int flags,
			       int opnum,
			       bool ndr64)
{
	char *fname = NULL;
	const char *sub_dir = NULL;
	TALLOC_CTX *temp_ctx = talloc_new(mem_ctx);
	DATA_BLOB blob;
	int ret, rc;
	uint8_t digest[20];
	DATA_BLOB digest_blob;
	char *digest_hex;
	uint16_t fuzz_flags = 0;

	/*
	 * We want to save the 'stub' in a per-pipe subdirectory, with
	 * the ndr_fuzz_X header 4 byte header. For the sake of
	 * convenience (this is a developer only function), we mkdir
	 * -p the sub-directories when they are needed.
	 */

	if (dump_dir == NULL) {
		return;
	}

	temp_ctx = talloc_stackframe();

	sub_dir = talloc_asprintf(temp_ctx, "%s/%s",
				  dump_dir,
				  iface_name);
	if (sub_dir == NULL) {
		talloc_free(temp_ctx);
		return;
	}
	ret = mkdir_p(sub_dir, 0755);
	if (ret && errno != EEXIST) {
		DBG_ERR("could not create %s\n", sub_dir);
		talloc_free(temp_ctx);
		return;
	}

	blob.length = raw_blob.length + 4;
	blob.data = talloc_array(sub_dir,
				 uint8_t,
				 blob.length);
	if (blob.data == NULL) {
		DBG_ERR("could not allocate for fuzz seeds! (%s)\n",
			iface_name);
		talloc_free(temp_ctx);
		return;
	}

	if (ndr64) {
		fuzz_flags = 4;
	}
	if (flags & NDR_IN) {
		fuzz_flags |= 1;
	} else if (flags & NDR_OUT) {
		fuzz_flags |= 2;
	}

	SSVAL(blob.data, 0, fuzz_flags);
	SSVAL(blob.data, 2, opnum);

	memcpy(&blob.data[4],
	       raw_blob.data,
	       raw_blob.length);

	/*
	 * This matches how oss-fuzz names the corpus input files, due
	 * to a preference from libFuzzer
	 */
	rc = gnutls_hash_fast(GNUTLS_DIG_SHA1,
			      blob.data,
			      blob.length,
			      digest);
	if (rc < 0) {
		/*
		 * This prints a better error message, eg if SHA1 is
		 * disabled
		 */
		NTSTATUS status = gnutls_error_to_ntstatus(rc,
						  NT_STATUS_HASH_NOT_SUPPORTED);
		DBG_ERR("Failed to generate SHA1 to save fuzz seed: %s",
			nt_errstr(status));
		talloc_free(temp_ctx);
		return;
	}

	digest_blob.data = digest;
	digest_blob.length = sizeof(digest);
	digest_hex = data_blob_hex_string_lower(temp_ctx, &digest_blob);

	fname = talloc_asprintf(temp_ctx, "%s/%s",
				sub_dir,
				digest_hex);
	if (fname == NULL) {
		talloc_free(temp_ctx);
		return;
	}

	/*
	 * If this fails, it is most likely because that file already
	 * exists.  This is fine, it means we already have this
	 * sample
	 */
	file_save(fname,
		  blob.data,
		  blob.length);

	talloc_free(temp_ctx);
}

#endif /*if DEVELOPER, enveloping _dcesrv_save_ndr_fuzz_seed() */
