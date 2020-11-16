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

#include "replace.h"
#include "system/network.h"
#include <tevent.h>
#include "lib/util/talloc_stack.h"
#include "lib/util/debug.h"
#include "lib/util/byteorder.h"
#include "lib/util/samba_util.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_util.h"
#include "librpc/rpc/dcerpc_pkt_auth.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "rpc_common.h"
#include "lib/util/bitmap.h"
#include "auth/gensec/gensec.h"
#include "lib/util/mkdir_p.h"
#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/crypto.h>

NTSTATUS dcerpc_ncacn_pull_pkt_auth(const struct dcerpc_auth *auth_state,
				    struct gensec_security *gensec,
				    bool check_pkt_auth_fields,
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

	if (check_pkt_auth_fields) {
		if (auth.auth_type != auth_state->auth_type) {
			return NT_STATUS_ACCESS_DENIED;
		}

		if (auth.auth_level != auth_state->auth_level) {
			return NT_STATUS_ACCESS_DENIED;
		}

		if (auth.auth_context_id != auth_state->auth_context_id) {
			return NT_STATUS_ACCESS_DENIED;
		}
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
