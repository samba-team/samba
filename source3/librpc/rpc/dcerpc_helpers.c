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
#include "librpc/gen_ndr/ndr_schannel.h"

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

	ndr_err = ndr_pull_ncacn_packet(ndr, NDR_SCALARS|NDR_BUFFERS, r);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(ndr);
		return ndr_map_error2ntstatus(ndr_err);
	}
	talloc_free(ndr);

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(ncacn_packet, r);
	}

	return NT_STATUS_OK;
}

/**
* @brief NDR Encodes a NL_AUTH_MESSAGE
*
* @param mem_ctx	The memory context the blob will be allocated on
* @param r		The NL_AUTH_MESSAGE to encode
* @param blob [out]	The encoded blob if successful
*
* @return a NTSTATUS error code
*/
NTSTATUS dcerpc_push_schannel_bind(TALLOC_CTX *mem_ctx,
				   struct NL_AUTH_MESSAGE *r,
				   DATA_BLOB *blob)
{
	enum ndr_err_code ndr_err;

	ndr_err = ndr_push_struct_blob(blob, mem_ctx, r,
		(ndr_push_flags_fn_t)ndr_push_NL_AUTH_MESSAGE);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(NL_AUTH_MESSAGE, r);
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
