/* 
   Unix SMB2 implementation.
   
   Copyright (C) Stefan Metzmacher	2005
   
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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "smb_server/smb_server.h"
#include "smb_server/service_smb_proto.h"
#include "smb_server/smb2/smb2_server.h"
#include "librpc/gen_ndr/security.h"
#include "smbd/service_stream.h"
#include "ntvfs/ntvfs.h"

/*
  send an oplock break request to a client
*/
static NTSTATUS smb2srv_send_oplock_break(void *p, struct ntvfs_handle *ntvfs, uint8_t level)
{
	DEBUG(0,("TODO: we don't pass SMB2 oplock breaks to the Clients yet!\n"));
	return NT_STATUS_OK;
}

struct ntvfs_handle *smb2srv_pull_handle(struct smb2srv_request *req, const uint8_t *base, uint_t offset)
{
	struct smbsrv_tcon *tcon;
	struct smbsrv_handle *handle;
	uint64_t hid;
	uint32_t tid;
	uint32_t pad;

	hid = BVAL(base, offset);
	tid = IVAL(base, offset + 8);
	pad = IVAL(base, offset + 12);

	if (pad != 0xFFFFFFFF) {
		return NULL;
	}

/* TODO: add comments */
	tcon = req->tcon;
	if (tid != req->tcon->tid) {
		tcon = smbsrv_smb2_tcon_find(req->session, tid, req->request_time);
	}

	handle = smbsrv_smb2_handle_find(tcon, hid, req->request_time);
	if (!handle) {
		return NULL;
	}

	req->tcon = tcon;
	return handle->ntvfs;
}

void smb2srv_push_handle(uint8_t *base, uint_t offset, struct ntvfs_handle *ntvfs)
{
	struct smbsrv_handle *handle = talloc_get_type(ntvfs->frontend_data.private_data,
				       struct smbsrv_handle);

	/* 
	 * the handle is 128 bit on the wire
	 */
	SBVAL(base, offset,	handle->hid);
	SIVAL(base, offset + 8,	handle->tcon->tid);
	SIVAL(base, offset + 12,0xFFFFFFFF);
}

static NTSTATUS smb2srv_handle_create_new(void *private_data, struct ntvfs_request *ntvfs, struct ntvfs_handle **_h)
{
	struct smb2srv_request *req = talloc_get_type(ntvfs->frontend_data.private_data,
				      struct smb2srv_request);
	struct smbsrv_handle *handle;
	struct ntvfs_handle *h;

	handle = smbsrv_handle_new(req->session, req->tcon, req, req->request_time);
	if (!handle) return NT_STATUS_INSUFFICIENT_RESOURCES;

	h = talloc_zero(handle, struct ntvfs_handle);
	if (!h) goto nomem;

	/* 
	 * note: we don't set handle->ntvfs yet,
	 *       this will be done by smbsrv_handle_make_valid()
	 *       this makes sure the handle is invalid for clients
	 *       until the ntvfs subsystem has made it valid
	 */
	h->ctx		= ntvfs->ctx;
	h->session_info	= ntvfs->session_info;
	h->smbpid	= ntvfs->smbpid;

	h->frontend_data.private_data = handle;

	*_h = h;
	return NT_STATUS_OK;
nomem:
	talloc_free(handle);
	return NT_STATUS_NO_MEMORY;
}

static NTSTATUS smb2srv_handle_make_valid(void *private_data, struct ntvfs_handle *h)
{
	struct smbsrv_tcon *tcon = talloc_get_type(private_data, struct smbsrv_tcon);
	struct smbsrv_handle *handle = talloc_get_type(h->frontend_data.private_data,
						       struct smbsrv_handle);
	/* this tells the frontend that the handle is valid */
	handle->ntvfs = h;
	/* this moves the smbsrv_request to the smbsrv_tcon memory context */
	talloc_steal(tcon, handle);
	return NT_STATUS_OK;
}

static void smb2srv_handle_destroy(void *private_data, struct ntvfs_handle *h)
{
	struct smbsrv_handle *handle = talloc_get_type(h->frontend_data.private_data,
						       struct smbsrv_handle);
	talloc_free(handle);
}

static struct ntvfs_handle *smb2srv_handle_search_by_wire_key(void *private_data, struct ntvfs_request *ntvfs, const DATA_BLOB *key)
{
	return NULL;
}

static DATA_BLOB smb2srv_handle_get_wire_key(void *private_data, struct ntvfs_handle *handle, TALLOC_CTX *mem_ctx)
{
	return data_blob(NULL, 0);
}

static NTSTATUS smb2srv_tcon_backend(struct smb2srv_request *req, union smb_tcon *io)
{
	struct smbsrv_tcon *tcon;
	NTSTATUS status;
	enum ntvfs_type type;
	uint16_t type_smb2;
	int snum;
	const char *service = io->smb2.in.path;

	if (strncmp(service, "\\\\", 2) == 0) {
		const char *p = strchr(service+2, '\\');
		if (p) {
			service = p + 1;
		}
	}

	snum = lp_find_valid_service(service);
	if (snum == -1) {
		DEBUG(0,("smb2srv_tcon_backend: couldn't find service %s\n", service));
		return NT_STATUS_BAD_NETWORK_NAME;
	}

	if (!socket_check_access(req->smb_conn->connection->socket, 
				 lp_servicename(snum), 
				 lp_hostsallow(snum), 
				 lp_hostsdeny(snum))) {
		return NT_STATUS_ACCESS_DENIED;
	}

	/* work out what sort of connection this is */
	if (strcmp(lp_fstype(snum), "IPC") == 0) {
		type = NTVFS_IPC;
		type_smb2 = 0x0003;
	} else if (lp_print_ok(snum)) {
		type = NTVFS_PRINT;
		type_smb2 = 0x0002;
	} else {
		type = NTVFS_DISK;
		type_smb2 = 0x0001;
	}

	tcon = smbsrv_smb2_tcon_new(req->session, lp_servicename(snum));
	if (!tcon) {
		DEBUG(0,("smb2srv_tcon_backend: Couldn't find free connection.\n"));
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}
	req->tcon = tcon;

	/* init ntvfs function pointers */
	status = ntvfs_init_connection(tcon, snum, type,
				       req->smb_conn->negotiate.protocol,
				       req->smb_conn->connection->event.ctx,
				       req->smb_conn->connection->msg_ctx,
				       req->smb_conn->connection->server_id,
				       &tcon->ntvfs);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("smb2srv_tcon_backend: ntvfs_init_connection failed for service %s\n", 
			  lp_servicename(snum)));
		goto failed;
	}

	status = ntvfs_set_oplock_handler(tcon->ntvfs, smb2srv_send_oplock_break, tcon);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("smb2srv_tcon_backend: NTVFS failed to set the oplock handler!\n"));
		goto failed;
	}

	status = ntvfs_set_addr_callbacks(tcon->ntvfs, smbsrv_get_my_addr, smbsrv_get_peer_addr, req->smb_conn);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("smb2srv_tcon_backend: NTVFS failed to set the addr callbacks!\n"));
		goto failed;
	}

	status = ntvfs_set_handle_callbacks(tcon->ntvfs,
					    smb2srv_handle_create_new,
					    smb2srv_handle_make_valid,
					    smb2srv_handle_destroy,
					    smb2srv_handle_search_by_wire_key,
					    smb2srv_handle_get_wire_key,
					    tcon);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("smb2srv_tcon_backend: NTVFS failed to set the handle callbacks!\n"));
		goto failed;
	}

	req->ntvfs = ntvfs_request_create(req->tcon->ntvfs, req,
					  req->session->session_info,
					  0, /* TODO: fill in PID */
					  0, /* TODO: fill in MID */
					  req->request_time,
					  req, NULL, 0);
	if (!req->ntvfs) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	/* Invoke NTVFS connection hook */
	status = ntvfs_connect(req->ntvfs, lp_servicename(snum));
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("smb2srv_tcon_backend: NTVFS ntvfs_connect() failed!\n"));
		goto failed;
	}

	io->smb2.out.unknown1	= type_smb2; /* 1 - DISK, 2 - Print, 3 - IPC */
	io->smb2.out.unknown2	= 0x00000000;
	io->smb2.out.unknown3	= 0x00000000;
	io->smb2.out.access_mask= SEC_RIGHTS_FILE_ALL;

	io->smb2.out.tid	= tcon->tid;

	return NT_STATUS_OK;

failed:
	req->tcon = NULL;
	talloc_free(tcon);
	return status;
}

static void smb2srv_tcon_send(struct smb2srv_request *req, union smb_tcon *io)
{
	if (NT_STATUS_IS_ERR(req->status)) {
		smb2srv_send_error(req, req->status);
		return;
	}

	SMB2SRV_CHECK(smb2srv_setup_reply(req, 0x10, False, 0));

	SBVAL(req->out.hdr,	SMB2_HDR_TID,	io->smb2.out.tid);

	SSVAL(req->out.body,	0x02,		io->smb2.out.unknown1);
	SIVAL(req->out.body,	0x04,		io->smb2.out.unknown2);
	SIVAL(req->out.body,	0x08,		io->smb2.out.unknown3);
	SIVAL(req->out.body,	0x0C,		io->smb2.out.access_mask);

	smb2srv_send_reply(req);
}

void smb2srv_tcon_recv(struct smb2srv_request *req)
{
	union smb_tcon *io;

	SMB2SRV_CHECK_BODY_SIZE(req, 0x08, True);
	SMB2SRV_TALLOC_IO_PTR(io, union smb_tcon);

	io->smb2.level		= RAW_TCON_SMB2;
	io->smb2.in.unknown1	= SVAL(req->in.body, 0x02);
	SMB2SRV_CHECK(smb2_pull_o16s16_string(&req->in, io, req->in.body+0x04, &io->smb2.in.path));

	req->status = smb2srv_tcon_backend(req, io);

	if (req->control_flags & SMB2SRV_REQ_CTRL_FLAG_NOT_REPLY) {
		talloc_free(req);
		return;
	}
	smb2srv_tcon_send(req, io);
}

static NTSTATUS smb2srv_tdis_backend(struct smb2srv_request *req)
{
	/* TODO: call ntvfs backends to close file of this tcon */
	talloc_free(req->tcon);
	req->tcon = NULL;
	return NT_STATUS_OK;
}

static void smb2srv_tdis_send(struct smb2srv_request *req)
{
	NTSTATUS status;

	if (NT_STATUS_IS_ERR(req->status)) {
		smb2srv_send_error(req, req->status);
		return;
	}

	status = smb2srv_setup_reply(req, 0x04, False, 0);
	if (!NT_STATUS_IS_OK(status)) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(status));
		talloc_free(req);
		return;
	}

	SSVAL(req->out.body, 0x02, 0);

	smb2srv_send_reply(req);
}

void smb2srv_tdis_recv(struct smb2srv_request *req)
{
	uint16_t _pad;

	SMB2SRV_CHECK_BODY_SIZE(req, 0x04, False);

	_pad	= SVAL(req->in.body, 0x02);

	req->status = smb2srv_tdis_backend(req);

	if (req->control_flags & SMB2SRV_REQ_CTRL_FLAG_NOT_REPLY) {
		talloc_free(req);
		return;
	}
	smb2srv_tdis_send(req);
}
