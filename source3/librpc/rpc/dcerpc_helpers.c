/*
 *  DCERPC Helper routines
 *  Günther Deschner <gd@samba.org> 2010.
 *  Simo Sorce <idra@samba.org> 2010.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#include "includes.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "librpc/crypto/gse.h"
#include "auth/gensec/gensec.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_PARSE

/**
* @brief NDR Encodes a ncacn_packet
*
* @param mem_ctx	The memory context the blob will be allocated on
* @param ptype		The DCERPC packet type
* @param pfc_flags	The DCERPC PFC Falgs
* @param auth_length	The length of the trailing auth blob
* @param call_id	The call ID
* @param u		The payload of the packet
* @param blob [out]	The encoded blob if successful
*
* @return an NTSTATUS error code
*/
NTSTATUS dcerpc_push_ncacn_packet(TALLOC_CTX *mem_ctx,
				  enum dcerpc_pkt_type ptype,
				  uint8_t pfc_flags,
				  uint16_t auth_length,
				  uint32_t call_id,
				  union dcerpc_payload *u,
				  DATA_BLOB *blob)
{
	struct ncacn_packet r;
	enum ndr_err_code ndr_err;

	r.rpc_vers		= 5;
	r.rpc_vers_minor	= 0;
	r.ptype			= ptype;
	r.pfc_flags		= pfc_flags;
	r.drep[0]		= DCERPC_DREP_LE;
	r.drep[1]		= 0;
	r.drep[2]		= 0;
	r.drep[3]		= 0;
	r.auth_length		= auth_length;
	r.call_id		= call_id;
	r.u			= *u;

	ndr_err = ndr_push_struct_blob(blob, mem_ctx, &r,
		(ndr_push_flags_fn_t)ndr_push_ncacn_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	dcerpc_set_frag_length(blob, blob->length);


	if (DEBUGLEVEL >= 10) {
		/* set frag len for print function */
		r.frag_length = blob->length;
		NDR_PRINT_DEBUG(ncacn_packet, &r);
	}

	return NT_STATUS_OK;
}

/**
* @brief Decodes a ncacn_packet
*
* @param mem_ctx	The memory context on which to allocate the packet
*			elements
* @param blob		The blob of data to decode
* @param r		An empty ncacn_packet, must not be NULL
* @param bigendian	Whether the packet is bignedian encoded
*
* @return a NTSTATUS error code
*/
NTSTATUS dcerpc_pull_ncacn_packet(TALLOC_CTX *mem_ctx,
				  const DATA_BLOB *blob,
				  struct ncacn_packet *r,
				  bool bigendian)
{
	enum ndr_err_code ndr_err;
	struct ndr_pull *ndr;

	ndr = ndr_pull_init_blob(blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}
	if (bigendian) {
		ndr->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	if (CVAL(blob->data, DCERPC_PFC_OFFSET) & DCERPC_PFC_FLAG_OBJECT_UUID) {
		ndr->flags |= LIBNDR_FLAG_OBJECT_PRESENT;
	}

	ndr_err = ndr_pull_ncacn_packet(ndr, NDR_SCALARS|NDR_BUFFERS, r);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(ndr);
		return ndr_map_error2ntstatus(ndr_err);
	}
	talloc_free(ndr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(ncacn_packet, r);
	}

	if (r->frag_length != blob->length) {
		return NT_STATUS_RPC_PROTOCOL_ERROR;
	}

	return NT_STATUS_OK;
}

/**
* @brief NDR Encodes a dcerpc_auth structure
*
* @param mem_ctx	  The memory context the blob will be allocated on
* @param auth_type	  The DCERPC Authentication Type
* @param auth_level	  The DCERPC Authentication Level
* @param auth_pad_length  The padding added to the packet this blob will be
*			   appended to.
* @param auth_context_id  The context id
* @param credentials	  The authentication credentials blob (signature)
* @param blob [out]	  The encoded blob if successful
*
* @return a NTSTATUS error code
*/
NTSTATUS dcerpc_push_dcerpc_auth(TALLOC_CTX *mem_ctx,
				 enum dcerpc_AuthType auth_type,
				 enum dcerpc_AuthLevel auth_level,
				 uint8_t auth_pad_length,
				 uint32_t auth_context_id,
				 const DATA_BLOB *credentials,
				 DATA_BLOB *blob)
{
	struct dcerpc_auth r;
	enum ndr_err_code ndr_err;

	r.auth_type		= auth_type;
	r.auth_level		= auth_level;
	r.auth_pad_length	= auth_pad_length;
	r.auth_reserved		= 0;
	r.auth_context_id	= auth_context_id;
	r.credentials		= *credentials;

	ndr_err = ndr_push_struct_blob(blob, mem_ctx, &r,
		(ndr_push_flags_fn_t)ndr_push_dcerpc_auth);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(dcerpc_auth, &r);
	}

	return NT_STATUS_OK;
}

/**
* @brief Decodes a dcerpc_auth blob
*
* @param mem_ctx	The memory context on which to allocate the packet
*			elements
* @param blob		The blob of data to decode
* @param r		An empty dcerpc_auth structure, must not be NULL
*
* @return a NTSTATUS error code
*/
NTSTATUS dcerpc_pull_dcerpc_auth(TALLOC_CTX *mem_ctx,
				 const DATA_BLOB *blob,
				 struct dcerpc_auth *r,
				 bool bigendian)
{
	enum ndr_err_code ndr_err;
	struct ndr_pull *ndr;

	ndr = ndr_pull_init_blob(blob, mem_ctx);
	if (!ndr) {
		return NT_STATUS_NO_MEMORY;
	}
	if (bigendian) {
		ndr->flags |= LIBNDR_FLAG_BIGENDIAN;
	}

	ndr_err = ndr_pull_dcerpc_auth(ndr, NDR_SCALARS|NDR_BUFFERS, r);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(ndr);
		return ndr_map_error2ntstatus(ndr_err);
	}
	talloc_free(ndr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(dcerpc_auth, r);
	}

	return NT_STATUS_OK;
}

/**
* @brief Calculate how much data we can in a packet, including calculating
*	 auth token and pad lengths.
*
* @param auth		The pipe_auth_data structure for this pipe.
* @param header_len	The length of the packet header
* @param data_left	The data left in the send buffer
* @param max_xmit_frag	The max fragment size.
* @param data_to_send	[out] The max data we will send in the pdu
* @param frag_len	[out] The total length of the fragment
* @param auth_len	[out] The length of the auth trailer
* @param pad_len	[out] The padding to be applied
*
* @return A NT Error status code.
*/
NTSTATUS dcerpc_guess_sizes(struct pipe_auth_data *auth,
			    size_t header_len, size_t data_left,
			    size_t max_xmit_frag,
			    size_t *data_to_send, size_t *frag_len,
			    size_t *auth_len, size_t *pad_len)
{
	size_t max_len;
	size_t mod_len;
	struct gensec_security *gensec_security;

	/* no auth token cases first */
	switch (auth->auth_level) {
	case DCERPC_AUTH_LEVEL_NONE:
	case DCERPC_AUTH_LEVEL_CONNECT:
	case DCERPC_AUTH_LEVEL_PACKET:
		max_len = max_xmit_frag - header_len;
		*data_to_send = MIN(max_len, data_left);
		*pad_len = 0;
		*auth_len = 0;
		*frag_len = header_len + *data_to_send;
		return NT_STATUS_OK;

	case DCERPC_AUTH_LEVEL_PRIVACY:
		break;

	case DCERPC_AUTH_LEVEL_INTEGRITY:
		break;

	default:
		return NT_STATUS_INVALID_PARAMETER;
	}


	/* Sign/seal case, calculate auth and pad lengths */

	max_len = max_xmit_frag - header_len - DCERPC_AUTH_TRAILER_LENGTH;

	/* Treat the same for all authenticated rpc requests. */
	switch (auth->auth_type) {
	case DCERPC_AUTH_TYPE_SPNEGO:
	case DCERPC_AUTH_TYPE_NTLMSSP:
	case DCERPC_AUTH_TYPE_KRB5:
	case DCERPC_AUTH_TYPE_SCHANNEL:
		gensec_security = auth->auth_ctx;
		mod_len = (max_len % DCERPC_AUTH_PAD_ALIGNMENT);
		*auth_len = gensec_sig_size(gensec_security, max_len - mod_len);
		if (*auth_len == 0) {
			return NT_STATUS_INTERNAL_ERROR;
		}
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	max_len -= *auth_len;
	mod_len = (max_len % DCERPC_AUTH_PAD_ALIGNMENT);
	max_len -= mod_len;

	*data_to_send = MIN(max_len, data_left);

	*pad_len = DCERPC_AUTH_PAD_LENGTH(*data_to_send);

	*frag_len = header_len + *data_to_send + *pad_len
			+ DCERPC_AUTH_TRAILER_LENGTH + *auth_len;

	return NT_STATUS_OK;
}

/*******************************************************************
 Create and add the NTLMSSP sign/seal auth data.
 ********************************************************************/

static NTSTATUS add_generic_auth_footer(struct gensec_security *gensec_security,
					enum dcerpc_AuthLevel auth_level,
					DATA_BLOB *rpc_out)
{
	uint16_t data_and_pad_len = rpc_out->length
					- DCERPC_RESPONSE_LENGTH
					- DCERPC_AUTH_TRAILER_LENGTH;
	DATA_BLOB auth_blob;
	NTSTATUS status;

	if (!gensec_security) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		/* Data portion is encrypted. */
		status = gensec_seal_packet(gensec_security,
					    rpc_out->data,
					    rpc_out->data
					    + DCERPC_RESPONSE_LENGTH,
					    data_and_pad_len,
					    rpc_out->data,
					    rpc_out->length,
					    &auth_blob);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		break;

	case DCERPC_AUTH_LEVEL_INTEGRITY:
		/* Data is signed. */
		status = gensec_sign_packet(gensec_security,
					    rpc_out->data,
					    rpc_out->data
					    + DCERPC_RESPONSE_LENGTH,
					    data_and_pad_len,
					    rpc_out->data,
					    rpc_out->length,
					    &auth_blob);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		break;

	default:
		/* Can't happen. */
		smb_panic("bad auth level");
		/* Notreached. */
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Finally attach the blob. */
	if (!data_blob_append(NULL, rpc_out,
				auth_blob.data, auth_blob.length)) {
		DEBUG(0, ("Failed to add %u bytes auth blob.\n",
			  (unsigned int)auth_blob.length));
		return NT_STATUS_NO_MEMORY;
	}
	data_blob_free(&auth_blob);

	return NT_STATUS_OK;
}

/*******************************************************************
 Check/unseal the NTLMSSP auth data. (Unseal in place).
 ********************************************************************/

static NTSTATUS get_generic_auth_footer(struct gensec_security *gensec_security,
					enum dcerpc_AuthLevel auth_level,
					DATA_BLOB *data, DATA_BLOB *full_pkt,
					DATA_BLOB *auth_token)
{
	if (gensec_security == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		/* Data portion is encrypted. */
		return gensec_unseal_packet(gensec_security,
					    data->data,
					    data->length,
					    full_pkt->data,
					    full_pkt->length,
					    auth_token);

	case DCERPC_AUTH_LEVEL_INTEGRITY:
		/* Data is signed. */
		return gensec_check_packet(gensec_security,
					   data->data,
					   data->length,
					   full_pkt->data,
					   full_pkt->length,
					   auth_token);

	default:
		return NT_STATUS_INVALID_PARAMETER;
	}
}

/**
* @brief   Append an auth footer according to what is the current mechanism
*
* @param auth		The pipe_auth_data associated with the connection
* @param pad_len	The padding used in the packet
* @param rpc_out	Packet blob up to and including the auth header
*
* @return A NTSTATUS error code.
*/
NTSTATUS dcerpc_add_auth_footer(struct pipe_auth_data *auth,
				size_t pad_len, DATA_BLOB *rpc_out)
{
	struct gensec_security *gensec_security;
	const char pad[DCERPC_AUTH_PAD_ALIGNMENT] = { 0, };
	DATA_BLOB auth_info;
	DATA_BLOB auth_blob;
	NTSTATUS status;

	if (auth->auth_type == DCERPC_AUTH_TYPE_NONE) {
		return NT_STATUS_OK;
	}

	if (pad_len) {
		SMB_ASSERT(pad_len <= ARRAY_SIZE(pad));

		/* Copy the sign/seal padding data. */
		if (!data_blob_append(NULL, rpc_out, pad, pad_len)) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* marshall the dcerpc_auth with an actually empty auth_blob.
	 * This is needed because the ntmlssp signature includes the
	 * auth header. We will append the actual blob later. */
	auth_blob = data_blob_null;
	status = dcerpc_push_dcerpc_auth(rpc_out->data,
					 auth->auth_type,
					 auth->auth_level,
					 pad_len,
					 1 /* context id. */,
					 &auth_blob,
					 &auth_info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* append the header */
	if (!data_blob_append(NULL, rpc_out,
				auth_info.data, auth_info.length)) {
		DEBUG(0, ("Failed to add %u bytes auth blob.\n",
			  (unsigned int)auth_info.length));
		return NT_STATUS_NO_MEMORY;
	}
	data_blob_free(&auth_info);

	/* Generate any auth sign/seal and add the auth footer. */
	switch (auth->auth_type) {
	case DCERPC_AUTH_TYPE_NONE:
		status = NT_STATUS_OK;
		break;
	default:
		gensec_security = auth->auth_ctx;
		status = add_generic_auth_footer(gensec_security,
						 auth->auth_level,
						 rpc_out);
		break;
	}

	return status;
}

/**
* @brief Check authentication for request/response packets
*
* @param auth		The auth data for the connection
* @param pkt		The actual ncacn_packet
* @param pkt_trailer	The stub_and_verifier part of the packet
* @param header_size	The header size
* @param raw_pkt	The whole raw packet data blob
* @param pad_len	[out] The padding length used in the packet
*
* @return A NTSTATUS error code
*/
NTSTATUS dcerpc_check_auth(struct pipe_auth_data *auth,
			   struct ncacn_packet *pkt,
			   DATA_BLOB *pkt_trailer,
			   size_t header_size,
			   DATA_BLOB *raw_pkt,
			   size_t *pad_len)
{
	struct gensec_security *gensec_security;
	NTSTATUS status;
	struct dcerpc_auth auth_info;
	uint32_t auth_length;
	DATA_BLOB full_pkt;
	DATA_BLOB data;

	switch (auth->auth_level) {
	case DCERPC_AUTH_LEVEL_PRIVACY:
		DEBUG(10, ("Requested Privacy.\n"));
		break;

	case DCERPC_AUTH_LEVEL_INTEGRITY:
		DEBUG(10, ("Requested Integrity.\n"));
		break;

	case DCERPC_AUTH_LEVEL_CONNECT:
		if (pkt->auth_length != 0) {
			break;
		}
		*pad_len = 0;
		return NT_STATUS_OK;

	case DCERPC_AUTH_LEVEL_NONE:
		if (pkt->auth_length != 0) {
			DEBUG(3, ("Got non-zero auth len on non "
				  "authenticated connection!\n"));
			return NT_STATUS_INVALID_PARAMETER;
		}
		*pad_len = 0;
		return NT_STATUS_OK;

	default:
		DEBUG(3, ("Unimplemented Auth Level %d",
			  auth->auth_level));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Paranioa checks for auth_length. */
	if (pkt->auth_length > pkt->frag_length) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}
	if (((unsigned int)pkt->auth_length
	     + DCERPC_AUTH_TRAILER_LENGTH < (unsigned int)pkt->auth_length) ||
	    ((unsigned int)pkt->auth_length
	     + DCERPC_AUTH_TRAILER_LENGTH < DCERPC_AUTH_TRAILER_LENGTH)) {
		/* Integer wrap attempt. */
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}

	status = dcerpc_pull_auth_trailer(pkt, pkt, pkt_trailer,
					  &auth_info, &auth_length, false);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	data = data_blob_const(raw_pkt->data + header_size,
				pkt_trailer->length - auth_length);
	full_pkt = data_blob_const(raw_pkt->data,
				raw_pkt->length - auth_info.credentials.length);

	switch (auth->auth_type) {
	case DCERPC_AUTH_TYPE_NONE:
		return NT_STATUS_OK;

	default:
		DEBUG(10, ("GENSEC auth\n"));

		gensec_security = auth->auth_ctx;
		status = get_generic_auth_footer(gensec_security,
						 auth->auth_level,
						 &data, &full_pkt,
						 &auth_info.credentials);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		break;
	}

	/* TODO: remove later
	 * this is still needed because in the server code the
	 * pkt_trailer actually has a copy of the raw data, and they
	 * are still both used in later calls */
	if (auth->auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		memcpy(pkt_trailer->data, data.data, data.length);
	}

	*pad_len = auth_info.auth_pad_length;
	data_blob_free(&auth_info.credentials);
	return NT_STATUS_OK;
}

