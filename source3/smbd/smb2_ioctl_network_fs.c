/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) David Disseldorp 2012

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
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/smb/smb_common.h"
#include "../libcli/security/security.h"
#include "../lib/util/tevent_ntstatus.h"
#include "include/ntioctl.h"
#include "../librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_ioctl.h"
#include "smb2_ioctl_private.h"
#include "../lib/tsocket/tsocket.h"
#include "lib/messages_ctdb.h"
#include "ctdbd_conn.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SMB2

static void copychunk_pack_limits(struct srv_copychunk_rsp *cc_rsp)
{
	cc_rsp->chunks_written = COPYCHUNK_MAX_CHUNKS;
	cc_rsp->chunk_bytes_written = COPYCHUNK_MAX_CHUNK_LEN;
	cc_rsp->total_bytes_written = COPYCHUNK_MAX_TOTAL_LEN;
}

static NTSTATUS copychunk_check_limits(struct srv_copychunk_copy *cc_copy)
{
	uint32_t i;
	uint32_t total_len = 0;

	/*
	 * [MS-SMB2] 3.3.5.15.6 Handling a Server-Side Data Copy Request
	 * Send and invalid parameter response if:
	 * - The ChunkCount value is greater than
	 *   ServerSideCopyMaxNumberofChunks
	 */
	if (cc_copy->chunk_count > COPYCHUNK_MAX_CHUNKS) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	for (i = 0; i < cc_copy->chunk_count; i++) {
		/*
		 * - The Length value in a single chunk is greater than
		 *   ServerSideCopyMaxChunkSize or equal to zero.
		 */
		if ((cc_copy->chunks[i].length == 0)
		 || (cc_copy->chunks[i].length > COPYCHUNK_MAX_CHUNK_LEN)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		total_len += cc_copy->chunks[i].length;
	}
	/*
	 * - Sum of Lengths in all chunks is greater than
	 *   ServerSideCopyMaxDataSize
	 */
	if (total_len > COPYCHUNK_MAX_TOTAL_LEN) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

struct fsctl_srv_copychunk_state {
	struct tevent_context *ev;
	struct connection_struct *conn;
	struct srv_copychunk_copy cc_copy;
	uint32_t current_chunk;
	NTSTATUS status;
	off_t total_written;
	uint32_t ctl_code;
	DATA_BLOB token;
	struct files_struct *src_fsp;
	struct files_struct *dst_fsp;
	enum {
		COPYCHUNK_OUT_EMPTY = 0,
		COPYCHUNK_OUT_LIMITS,
		COPYCHUNK_OUT_RSP,
	} out_data;
};
static void fsctl_srv_copychunk_vfs_done(struct tevent_req *subreq);

static NTSTATUS fsctl_srv_copychunk_loop(struct tevent_req *req);

static struct tevent_req *fsctl_srv_copychunk_send(TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   uint32_t ctl_code,
						   struct files_struct *dst_fsp,
						   DATA_BLOB *in_input,
						   size_t in_max_output,
						   struct smbd_smb2_request *smb2req)
{
	struct tevent_req *req = NULL;
	struct fsctl_srv_copychunk_state *state = NULL;
	enum ndr_err_code ndr_ret;
	NTSTATUS status;

	/* handler for both copy-chunk variants */
	SMB_ASSERT((ctl_code == FSCTL_SRV_COPYCHUNK)
		|| (ctl_code == FSCTL_SRV_COPYCHUNK_WRITE));

	req = tevent_req_create(mem_ctx, &state,
				struct fsctl_srv_copychunk_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct fsctl_srv_copychunk_state) {
		.conn = dst_fsp->conn,
		.ev = ev,
		.ctl_code = ctl_code,
		.dst_fsp = dst_fsp,
	};

	if (in_max_output < sizeof(struct srv_copychunk_rsp)) {
		DEBUG(3, ("max output %d not large enough to hold copy chunk "
			  "response %lu\n", (int)in_max_output,
			  (unsigned long)sizeof(struct srv_copychunk_rsp)));
		state->status = NT_STATUS_INVALID_PARAMETER;
		tevent_req_nterror(req, state->status);
		return tevent_req_post(req, ev);
	}

	ndr_ret = ndr_pull_struct_blob(in_input, mem_ctx, &state->cc_copy,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_copy);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		DEBUG(0, ("failed to unmarshall copy chunk req\n"));
		state->status = NT_STATUS_INVALID_PARAMETER;
		tevent_req_nterror(req, state->status);
		return tevent_req_post(req, ev);
	}

	state->token = data_blob_const(state->cc_copy.source_key,
				       sizeof(state->cc_copy.source_key));

	state->status = copychunk_check_limits(&state->cc_copy);
	if (!NT_STATUS_IS_OK(state->status)) {
		DEBUG(3, ("copy chunk req exceeds limits\n"));
		state->out_data = COPYCHUNK_OUT_LIMITS;
		tevent_req_nterror(req, state->status);
		return tevent_req_post(req, ev);
	}

	/* any errors from here onwards should carry copychunk response data */
	state->out_data = COPYCHUNK_OUT_RSP;

	status = fsctl_srv_copychunk_loop(req);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static NTSTATUS fsctl_srv_copychunk_loop(struct tevent_req *req)
{
	struct fsctl_srv_copychunk_state *state = tevent_req_data(
		req, struct fsctl_srv_copychunk_state);
	struct tevent_req *subreq = NULL;
	uint32_t length = 0;
	off_t source_off = 0;
	off_t target_off = 0;

	/*
	 * chunk_count can be 0 which must either just do nothing returning
	 * success saying number of copied chunks is 0 (verified against
	 * Windows).
	 *
	 * Or it can be a special macOS copyfile request, so we send this into
	 * the VFS, vfs_fruit if loaded implements the macOS copyile semantics.
	 */
	if (state->cc_copy.chunk_count > 0) {
		struct srv_copychunk *chunk = NULL;

		chunk = &state->cc_copy.chunks[state->current_chunk];
		length = chunk->length;
		source_off = chunk->source_off;
		target_off = chunk->target_off;
	}

	subreq = SMB_VFS_OFFLOAD_WRITE_SEND(state->dst_fsp->conn,
					 state,
					 state->ev,
					 state->ctl_code,
					 &state->token,
					 source_off,
					 state->dst_fsp,
					 target_off,
					 length);
	if (tevent_req_nomem(subreq, req)) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq,	fsctl_srv_copychunk_vfs_done, req);

	return NT_STATUS_OK;
}

static void fsctl_srv_copychunk_vfs_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct fsctl_srv_copychunk_state *state = tevent_req_data(
		req, struct fsctl_srv_copychunk_state);
	off_t chunk_nwritten;
	NTSTATUS status;

	status = SMB_VFS_OFFLOAD_WRITE_RECV(state->conn, subreq,
					 &chunk_nwritten);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("copy chunk failed [%s] chunk [%u] of [%u]\n",
			nt_errstr(status),
			(unsigned int)state->current_chunk,
			(unsigned int)state->cc_copy.chunk_count);
		tevent_req_nterror(req, status);
		return;
	}

	DBG_DEBUG("good copy chunk [%u] of [%u]\n",
		  (unsigned int)state->current_chunk,
		  (unsigned int)state->cc_copy.chunk_count);
	state->total_written += chunk_nwritten;

	if (state->cc_copy.chunk_count == 0) {
		/*
		 * This must not produce an error but just return a chunk count
		 * of 0 in the response.
		 */
		tevent_req_done(req);
		return;
	}

	state->current_chunk++;
	if (state->current_chunk == state->cc_copy.chunk_count) {
		tevent_req_done(req);
		return;
	}

	status = fsctl_srv_copychunk_loop(req);
	if (tevent_req_nterror(req, status)) {
		return;
	}
}

static NTSTATUS fsctl_srv_copychunk_recv(struct tevent_req *req,
					 struct srv_copychunk_rsp *cc_rsp,
					 bool *pack_rsp)
{
	struct fsctl_srv_copychunk_state *state = tevent_req_data(req,
					struct fsctl_srv_copychunk_state);
	NTSTATUS status;

	switch (state->out_data) {
	case COPYCHUNK_OUT_EMPTY:
		*pack_rsp = false;
		break;
	case COPYCHUNK_OUT_LIMITS:
		/* 2.2.32.1 - send back our maximum transfer size limits */
		copychunk_pack_limits(cc_rsp);
		*pack_rsp = true;
		break;
	case COPYCHUNK_OUT_RSP:
		cc_rsp->chunks_written = state->current_chunk;
		cc_rsp->chunk_bytes_written = 0;
		cc_rsp->total_bytes_written = state->total_written;
		*pack_rsp = true;
		break;
	default:	/* not reached */
		assert(1);
		break;
	}
	status = tevent_req_simple_recv_ntstatus(req);
	return status;
}

static NTSTATUS fsctl_network_iface_info(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct smbXsrv_connection *xconn,
					 DATA_BLOB *in_input,
					 uint32_t in_max_output,
					 DATA_BLOB *out_output)
{
	struct fsctl_net_iface_info *array = NULL;
	struct fsctl_net_iface_info *first = NULL;
	struct fsctl_net_iface_info *last = NULL;
	size_t i;
	size_t num_ifaces = iface_count();
	enum ndr_err_code ndr_err;
	struct ctdb_public_ip_list_old *ips = NULL;

	if (in_input->length != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	*out_output = data_blob_null;

	if (lp_clustering()) {
		int ret;

		ret = ctdbd_control_get_public_ips(messaging_ctdb_connection(),
						   0, /* flags */
						   mem_ctx,
						   &ips);
		if (ret != 0) {
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	array = talloc_zero_array(mem_ctx,
				  struct fsctl_net_iface_info,
				  num_ifaces);
	if (array == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i < num_ifaces; i++) {
		struct fsctl_net_iface_info *cur = &array[i];
		const struct interface *iface = get_interface(i);
		const struct sockaddr_storage *ifss = &iface->ip;
		const void *ifptr = ifss;
		const struct sockaddr *ifsa = (const struct sockaddr *)ifptr;
		struct tsocket_address *a = NULL;
		char *addr;
		bool ok;
		int ret;

		ret = tsocket_address_bsd_from_sockaddr(array,
					ifsa, sizeof(struct sockaddr_storage),
					&a);
		if (ret != 0) {
			return map_nt_error_from_unix_common(errno);
		}

		ok = tsocket_address_is_inet(a, "ip");
		if (!ok) {
			continue;
		}

		addr = tsocket_address_inet_addr_string(a, array);
		if (addr == NULL) {
			TALLOC_FREE(array);
			return NT_STATUS_NO_MEMORY;
		}

		if (ips != NULL) {
			bool is_public_ip;

			is_public_ip = ctdbd_find_in_public_ips(ips, ifss);
			if (is_public_ip) {
				DBG_DEBUG("Interface [%s] - "
					  "has public ip - "
					  "skipping address [%s].\n",
					  iface->name, addr);
				continue;
			}
		}

		cur->ifindex = iface->if_index;
		if (cur->ifindex == 0) {
			/*
			 * Did not get interface index from kernel,
			 * nor from the config. ==> Apply a common
			 * default value for these cases.
			 */
			cur->ifindex = UINT32_MAX;
		}
		cur->capability = iface->capability;
		cur->linkspeed = iface->linkspeed;
		if (cur->linkspeed == 0) {
			DBG_DEBUG("Link speed 0 on interface [%s] - skipping "
				  "address [%s].\n", iface->name, addr);
			continue;
		}

		ok = tsocket_address_is_inet(a, "ipv4");
		if (ok) {
			cur->sockaddr.family = FSCTL_NET_IFACE_AF_INET;
			cur->sockaddr.saddr.saddr_in.ipv4 = addr;
		}
		ok = tsocket_address_is_inet(a, "ipv6");
		if (ok) {
			cur->sockaddr.family = FSCTL_NET_IFACE_AF_INET6;
			cur->sockaddr.saddr.saddr_in6.ipv6 = addr;
		}

		if (first == NULL) {
			first = cur;
		}
		if (last != NULL) {
			last->next = cur;
		}
		last = cur;
	}

	if (first == NULL) {
		TALLOC_FREE(array);
		return NT_STATUS_OK;
	}

	if (DEBUGLEVEL >= 10) {
		NDR_PRINT_DEBUG(fsctl_net_iface_info, first);
	}

	ndr_err = ndr_push_struct_blob(out_output, mem_ctx, first,
			(ndr_push_flags_fn_t)ndr_push_fsctl_net_iface_info);
	TALLOC_FREE(array);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	return NT_STATUS_OK;
}

static NTSTATUS fsctl_validate_neg_info(TALLOC_CTX *mem_ctx,
				        struct tevent_context *ev,
				        struct smbXsrv_connection *conn,
				        DATA_BLOB *in_input,
				        uint32_t in_max_output,
				        DATA_BLOB *out_output,
					bool *disconnect)
{
	uint32_t in_capabilities;
	DATA_BLOB in_guid_blob;
	struct GUID in_guid;
	uint16_t in_security_mode;
	uint16_t in_num_dialects;
	uint16_t dialect;
	DATA_BLOB out_guid_blob;
	NTSTATUS status;
	enum protocol_types protocol = PROTOCOL_NONE;

	if (lp_server_max_protocol() <= PROTOCOL_SMB2_02) {
		/*
		 * With SMB 2.02 we didn't get the
		 * capabitities, client guid, security mode
		 * and dialects the client would have offered.
		 *
		 * So we behave compatible with a true
		 * SMB 2.02 server and return NT_STATUS_FILE_CLOSED.
		 *
		 * As SMB >= 2.10 offers the two phase SMB2 Negotiate
		 * we keep supporting FSCTL_VALIDATE_NEGOTIATE_INFO
		 * starting with SMB 2.10, while Windows only supports
		 * it starting with SMB > 2.10.
		 */
		return NT_STATUS_FILE_CLOSED;
	}

	if (in_input->length < 0x18) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	in_capabilities = IVAL(in_input->data, 0x00);
	in_guid_blob = data_blob_const(in_input->data + 0x04, 16);
	in_security_mode = SVAL(in_input->data, 0x14);
	in_num_dialects = SVAL(in_input->data, 0x16);

	if (in_input->length < (0x18 + in_num_dialects*2)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (in_max_output < 0x18) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	status = GUID_from_ndr_blob(&in_guid_blob, &in_guid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * From: [MS-SMB2]
	 * 3.3.5.15.12 Handling a Validate Negotiate Info Request
	 *
	 * The server MUST determine the greatest common dialect
	 * between the dialects it implements and the Dialects array
	 * of the VALIDATE_NEGOTIATE_INFO request. If no dialect is
	 * matched, or if the value is not equal to Connection.Dialect,
	 * the server MUST terminate the transport connection
	 * and free the Connection object.
	 */
	protocol = smbd_smb2_protocol_dialect_match(in_input->data + 0x18,
						    in_num_dialects,
						    &dialect);
	if (conn->protocol != protocol) {
		*disconnect = true;
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!GUID_equal(&in_guid, &conn->smb2.client.guid)) {
		*disconnect = true;
		return NT_STATUS_ACCESS_DENIED;
	}

	if (in_security_mode != conn->smb2.client.security_mode) {
		*disconnect = true;
		return NT_STATUS_ACCESS_DENIED;
	}

	if (in_capabilities != conn->smb2.client.capabilities) {
		*disconnect = true;
		return NT_STATUS_ACCESS_DENIED;
	}

	status = GUID_to_ndr_blob(&conn->smb2.server.guid, mem_ctx,
				  &out_guid_blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*out_output = data_blob_talloc(mem_ctx, NULL, 0x18);
	if (out_output->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	SIVAL(out_output->data, 0x00, conn->smb2.server.capabilities);
	memcpy(out_output->data+0x04, out_guid_blob.data, 16);
	SSVAL(out_output->data, 0x14, conn->smb2.server.security_mode);
	SSVAL(out_output->data, 0x16, conn->smb2.server.dialect);

	return NT_STATUS_OK;
}

static void smb2_ioctl_network_fs_copychunk_done(struct tevent_req *subreq);
static void smb2_ioctl_network_fs_offload_read_done(struct tevent_req *subreq);

struct tevent_req *smb2_ioctl_network_fs(uint32_t ctl_code,
					 struct tevent_context *ev,
					 struct tevent_req *req,
					 struct smbd_smb2_ioctl_state *state)
{
	struct tevent_req *subreq;
	NTSTATUS status;

	switch (ctl_code) {
	/*
	 * [MS-SMB2] 2.2.31
	 * FSCTL_SRV_COPYCHUNK is issued when a handle has
	 * FILE_READ_DATA and FILE_WRITE_DATA access to the file;
	 * FSCTL_SRV_COPYCHUNK_WRITE is issued when a handle only has
	 * FILE_WRITE_DATA access.
	 */
	case FSCTL_SRV_COPYCHUNK_WRITE:	/* FALL THROUGH */
	case FSCTL_SRV_COPYCHUNK:
		subreq = fsctl_srv_copychunk_send(state, ev,
						  ctl_code,
						  state->fsp,
						  &state->in_input,
						  state->in_max_output,
						  state->smb2req);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					smb2_ioctl_network_fs_copychunk_done,
					req);
		return req;
		break;
	case FSCTL_QUERY_NETWORK_INTERFACE_INFO:
		if (!state->smbreq->xconn->client->server_multi_channel_enabled)
		{
			if (IS_IPC(state->smbreq->conn)) {
				status = NT_STATUS_FS_DRIVER_REQUIRED;
			} else {
				status = NT_STATUS_INVALID_DEVICE_REQUEST;
			}

			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}

		status = fsctl_network_iface_info(state, ev,
						  state->smbreq->xconn,
						  &state->in_input,
						  state->in_max_output,
						  &state->out_output);
		if (!tevent_req_nterror(req, status)) {
			tevent_req_done(req);
		}
		return tevent_req_post(req, ev);
		break;
	case FSCTL_VALIDATE_NEGOTIATE_INFO:
		status = fsctl_validate_neg_info(state, ev,
						 state->smbreq->xconn,
						 &state->in_input,
						 state->in_max_output,
						 &state->out_output,
						 &state->disconnect);
		if (!tevent_req_nterror(req, status)) {
			tevent_req_done(req);
		}
		return tevent_req_post(req, ev);
		break;
	case FSCTL_SRV_REQUEST_RESUME_KEY:
		subreq = SMB_VFS_OFFLOAD_READ_SEND(state,
						   ev,
						   state->fsp,
						   FSCTL_SRV_REQUEST_RESUME_KEY,
						   0, 0, 0);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq, smb2_ioctl_network_fs_offload_read_done, req);
		return req;

	default: {
		uint8_t *out_data = NULL;
		uint32_t out_data_len = 0;

		if (state->fsp == NULL) {
			status = NT_STATUS_NOT_SUPPORTED;
		} else {
			status = SMB_VFS_FSCTL(state->fsp,
					       state,
					       ctl_code,
					       state->smbreq->flags2,
					       state->in_input.data,
					       state->in_input.length,
					       &out_data,
					       state->in_max_output,
					       &out_data_len);
			state->out_output = data_blob_const(out_data, out_data_len);
			if (NT_STATUS_IS_OK(status)) {
				tevent_req_done(req);
				return tevent_req_post(req, ev);
			}
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
			if (IS_IPC(state->smbreq->conn)) {
				status = NT_STATUS_FS_DRIVER_REQUIRED;
			} else {
				status = NT_STATUS_INVALID_DEVICE_REQUEST;
			}
		}

		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
		break;
	}
	}

	tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
	return tevent_req_post(req, ev);
}

static void smb2_ioctl_network_fs_copychunk_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct smbd_smb2_ioctl_state *ioctl_state = tevent_req_data(req,
						struct smbd_smb2_ioctl_state);
	struct srv_copychunk_rsp cc_rsp;
	NTSTATUS status;
	bool pack_rsp = false;

	ZERO_STRUCT(cc_rsp);
	status = fsctl_srv_copychunk_recv(subreq, &cc_rsp, &pack_rsp);
	TALLOC_FREE(subreq);
	if (pack_rsp == true) {
		enum ndr_err_code ndr_ret;
		ndr_ret = ndr_push_struct_blob(&ioctl_state->out_output,
					       ioctl_state,
					       &cc_rsp,
				(ndr_push_flags_fn_t)ndr_push_srv_copychunk_rsp);
		if (ndr_ret != NDR_ERR_SUCCESS) {
			status = NT_STATUS_INTERNAL_ERROR;
		}
	}

	if (!tevent_req_nterror(req, status)) {
		tevent_req_done(req);
	}
}

static void smb2_ioctl_network_fs_offload_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbd_smb2_ioctl_state *state = tevent_req_data(
		req, struct smbd_smb2_ioctl_state);
	struct req_resume_key_rsp rkey_rsp;
	enum ndr_err_code ndr_ret;
	DATA_BLOB token;
	NTSTATUS status;

	status = SMB_VFS_OFFLOAD_READ_RECV(subreq,
					   state->fsp->conn,
					   state,
					   &token);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (token.length != sizeof(rkey_rsp.resume_key)) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	ZERO_STRUCT(rkey_rsp);
	memcpy(rkey_rsp.resume_key, token.data, token.length);

	ndr_ret = ndr_push_struct_blob(&state->out_output, state, &rkey_rsp,
			(ndr_push_flags_fn_t)ndr_push_req_resume_key_rsp);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	tevent_req_done(req);
	return;
}
