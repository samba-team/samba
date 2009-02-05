/* 
   Unix SMB/CIFS implementation.
   default IPC$ NTVFS backend

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher 2004-2005

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
/*
  this implements the IPC$ backend, called by the NTVFS subsystem to
  handle requests on IPC$ shares
*/


#include "includes.h"
#include "../lib/util/dlinklist.h"
#include "ntvfs/ntvfs.h"
#include "libcli/rap/rap.h"
#include "ntvfs/ipc/proto.h"
#include "rpc_server/dcerpc_server.h"
#include "libcli/raw/ioctl.h"
#include "param/param.h"

/* this is the private structure used to keep the state of an open
   ipc$ connection. It needs to keep information about all open
   pipes */
struct ipc_private {
	struct ntvfs_module_context *ntvfs;

	struct dcesrv_context *dcesrv;

	/* a list of open pipes */
	struct pipe_state {
		struct pipe_state *next, *prev;
		struct ipc_private *ipriv;
		const char *pipe_name;
		struct ntvfs_handle *handle;
		struct dcesrv_connection *dce_conn;
		uint16_t ipc_state;
	} *pipe_list;
};


/*
  find a open pipe give a file handle
*/
static struct pipe_state *pipe_state_find(struct ipc_private *ipriv, struct ntvfs_handle *handle)
{
	struct pipe_state *s;
	void *p;

	p = ntvfs_handle_get_backend_data(handle, ipriv->ntvfs);
	if (!p) return NULL;

	s = talloc_get_type(p, struct pipe_state);
	if (!s) return NULL;

	return s;
}

/*
  find a open pipe give a wire fnum
*/
static struct pipe_state *pipe_state_find_key(struct ipc_private *ipriv, struct ntvfs_request *req, const DATA_BLOB *key)
{
	struct ntvfs_handle *h;

	h = ntvfs_handle_search_by_wire_key(ipriv->ntvfs, req, key);
	if (!h) return NULL;

	return pipe_state_find(ipriv, h);
}


/*
  connect to a share - always works 
*/
static NTSTATUS ipc_connect(struct ntvfs_module_context *ntvfs,
			    struct ntvfs_request *req, const char *sharename)
{
	NTSTATUS status;
	struct ipc_private *ipriv;

	ntvfs->ctx->fs_type = talloc_strdup(ntvfs->ctx, "IPC");
	NT_STATUS_HAVE_NO_MEMORY(ntvfs->ctx->fs_type);

	ntvfs->ctx->dev_type = talloc_strdup(ntvfs->ctx, "IPC");
	NT_STATUS_HAVE_NO_MEMORY(ntvfs->ctx->dev_type);

	/* prepare the private state for this connection */
	ipriv = talloc(ntvfs, struct ipc_private);
	NT_STATUS_HAVE_NO_MEMORY(ipriv);

	ntvfs->private_data = ipriv;

	ipriv->ntvfs = ntvfs;
	ipriv->pipe_list = NULL;

	/* setup the DCERPC server subsystem */
	status = dcesrv_init_ipc_context(ipriv, ntvfs->ctx->lp_ctx, &ipriv->dcesrv);
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
}

/*
  disconnect from a share
*/
static NTSTATUS ipc_disconnect(struct ntvfs_module_context *ntvfs)
{
	return NT_STATUS_OK;
}

/*
  delete a file
*/
static NTSTATUS ipc_unlink(struct ntvfs_module_context *ntvfs,
			   struct ntvfs_request *req,
			   union smb_unlink *unl)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  check if a directory exists
*/
static NTSTATUS ipc_chkpath(struct ntvfs_module_context *ntvfs,
			    struct ntvfs_request *req,
			    union smb_chkpath *cp)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  return info on a pathname
*/
static NTSTATUS ipc_qpathinfo(struct ntvfs_module_context *ntvfs,
			      struct ntvfs_request *req, union smb_fileinfo *info)
{
	switch (info->generic.level) {
	case  RAW_FILEINFO_GENERIC:
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	case RAW_FILEINFO_GETATTR:
		return NT_STATUS_ACCESS_DENIED;
	default:
		return ntvfs_map_qpathinfo(ntvfs, req, info);
	}
}

/*
  set info on a pathname
*/
static NTSTATUS ipc_setpathinfo(struct ntvfs_module_context *ntvfs,
				struct ntvfs_request *req, union smb_setfileinfo *st)
{
	return NT_STATUS_ACCESS_DENIED;
}


/*
  destroy a open pipe structure
*/
static int ipc_fd_destructor(struct pipe_state *p)
{
	DLIST_REMOVE(p->ipriv->pipe_list, p);
	ntvfs_handle_remove_backend_data(p->handle, p->ipriv->ntvfs);
	return 0;
}

static struct socket_address *ipc_get_my_addr(struct dcesrv_connection *dce_conn, TALLOC_CTX *mem_ctx)
{
	struct ipc_private *ipriv = dce_conn->transport.private_data;

	return ntvfs_get_my_addr(ipriv->ntvfs, mem_ctx);
}

static struct socket_address *ipc_get_peer_addr(struct dcesrv_connection *dce_conn, TALLOC_CTX *mem_ctx)
{
	struct ipc_private *ipriv = dce_conn->transport.private_data;

	return ntvfs_get_peer_addr(ipriv->ntvfs, mem_ctx);
}

/*
  open a file backend - used for MSRPC pipes
*/
static NTSTATUS ipc_open_generic(struct ntvfs_module_context *ntvfs,
				 struct ntvfs_request *req, const char *fname, 
				 struct pipe_state **ps)
{
	struct pipe_state *p;
	NTSTATUS status;
	struct dcerpc_binding *ep_description;
	struct ipc_private *ipriv = ntvfs->private_data;
	struct ntvfs_handle *h;

	status = ntvfs_handle_new(ntvfs, req, &h);
	NT_STATUS_NOT_OK_RETURN(status);

	p = talloc(h, struct pipe_state);
	NT_STATUS_HAVE_NO_MEMORY(p);

	ep_description = talloc(req, struct dcerpc_binding);
	NT_STATUS_HAVE_NO_MEMORY(ep_description);

	while (fname[0] == '\\') fname++;

	p->pipe_name = talloc_asprintf(p, "\\pipe\\%s", fname);
	NT_STATUS_HAVE_NO_MEMORY(p->pipe_name);

	p->handle = h;
	p->ipc_state = 0x5ff;

	/*
	  we're all set, now ask the dcerpc server subsystem to open the 
	  endpoint. At this stage the pipe isn't bound, so we don't
	  know what interface the user actually wants, just that they want
	  one of the interfaces attached to this pipe endpoint.
	*/
	ep_description->transport = NCACN_NP;
	ep_description->endpoint = talloc_reference(ep_description, p->pipe_name);

	/* The session info is refcount-increased in the 
	 * dcesrv_endpoint_search_connect() function
	 */
	status = dcesrv_endpoint_search_connect(ipriv->dcesrv,
						p,
						ep_description, 
						h->session_info,
						ntvfs->ctx->event_ctx,
						ntvfs->ctx->msg_ctx,
						ntvfs->ctx->server_id,
						0,
						&p->dce_conn);
	NT_STATUS_NOT_OK_RETURN(status);

	p->dce_conn->transport.private_data		= ipriv;
	p->dce_conn->transport.report_output_data	= NULL;
	p->dce_conn->transport.get_my_addr		= ipc_get_my_addr;
	p->dce_conn->transport.get_peer_addr		= ipc_get_peer_addr;
	
	DLIST_ADD(ipriv->pipe_list, p);

	p->ipriv = ipriv;

	talloc_set_destructor(p, ipc_fd_destructor);

	status = ntvfs_handle_set_backend_data(h, ipriv->ntvfs, p);
	NT_STATUS_NOT_OK_RETURN(status);

	*ps = p;
	return NT_STATUS_OK;
}

/*
  open a file with ntcreatex - used for MSRPC pipes
*/
static NTSTATUS ipc_open_ntcreatex(struct ntvfs_module_context *ntvfs,
				   struct ntvfs_request *req, union smb_open *oi)
{
	struct pipe_state *p;
	NTSTATUS status;

	status = ipc_open_generic(ntvfs, req, oi->ntcreatex.in.fname, &p);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ZERO_STRUCT(oi->ntcreatex.out);
	oi->ntcreatex.out.file.ntvfs= p->handle;
	oi->ntcreatex.out.ipc_state = p->ipc_state;
	oi->ntcreatex.out.file_type = FILE_TYPE_MESSAGE_MODE_PIPE;

	return status;
}

/*
  open a file with openx - used for MSRPC pipes
*/
static NTSTATUS ipc_open_openx(struct ntvfs_module_context *ntvfs,
			       struct ntvfs_request *req, union smb_open *oi)
{
	struct pipe_state *p;
	NTSTATUS status;
	const char *fname = oi->openx.in.fname;

	status = ipc_open_generic(ntvfs, req, fname, &p);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ZERO_STRUCT(oi->openx.out);
	oi->openx.out.file.ntvfs= p->handle;
	oi->openx.out.ftype	= 2;
	oi->openx.out.devstate	= p->ipc_state;
	
	return status;
}

/*
  open a file with SMB2 Create - used for MSRPC pipes
*/
static NTSTATUS ipc_open_smb2(struct ntvfs_module_context *ntvfs,
			      struct ntvfs_request *req, union smb_open *oi)
{
	struct pipe_state *p;
	NTSTATUS status;

	status = ipc_open_generic(ntvfs, req, oi->smb2.in.fname, &p);
	NT_STATUS_NOT_OK_RETURN(status);

	ZERO_STRUCT(oi->smb2.out);
	oi->smb2.out.file.ntvfs		= p->handle;
	oi->smb2.out.oplock_level	= oi->smb2.in.oplock_level;
	oi->smb2.out.create_action	= NTCREATEX_ACTION_EXISTED;
	oi->smb2.out.create_time	= 0;
	oi->smb2.out.access_time	= 0;
	oi->smb2.out.write_time		= 0;
	oi->smb2.out.change_time	= 0;
	oi->smb2.out.alloc_size		= 4096;
	oi->smb2.out.size		= 0;
	oi->smb2.out.file_attr		= FILE_ATTRIBUTE_NORMAL;
	oi->smb2.out.reserved2		= 0;

	return status;
}

/*
  open a file - used for MSRPC pipes
*/
static NTSTATUS ipc_open(struct ntvfs_module_context *ntvfs,
				struct ntvfs_request *req, union smb_open *oi)
{
	NTSTATUS status;

	switch (oi->generic.level) {
	case RAW_OPEN_NTCREATEX:
		status = ipc_open_ntcreatex(ntvfs, req, oi);
		break;
	case RAW_OPEN_OPENX:
		status = ipc_open_openx(ntvfs, req, oi);
		break;
	case RAW_OPEN_SMB2:
		status = ipc_open_smb2(ntvfs, req, oi);
		break;
	default:
		status = NT_STATUS_NOT_SUPPORTED;
		break;
	}

	return status;
}

/*
  create a directory
*/
static NTSTATUS ipc_mkdir(struct ntvfs_module_context *ntvfs,
			  struct ntvfs_request *req, union smb_mkdir *md)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  remove a directory
*/
static NTSTATUS ipc_rmdir(struct ntvfs_module_context *ntvfs,
			  struct ntvfs_request *req, struct smb_rmdir *rd)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  rename a set of files
*/
static NTSTATUS ipc_rename(struct ntvfs_module_context *ntvfs,
			   struct ntvfs_request *req, union smb_rename *ren)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  copy a set of files
*/
static NTSTATUS ipc_copy(struct ntvfs_module_context *ntvfs,
			 struct ntvfs_request *req, struct smb_copy *cp)
{
	return NT_STATUS_ACCESS_DENIED;
}

static NTSTATUS ipc_readx_dcesrv_output(void *private_data, DATA_BLOB *out, size_t *nwritten)
{
	DATA_BLOB *blob = private_data;

	if (out->length < blob->length) {
		blob->length = out->length;
	}
	memcpy(blob->data, out->data, blob->length);
	*nwritten = blob->length;
	return NT_STATUS_OK;
}

/*
  read from a file
*/
static NTSTATUS ipc_read(struct ntvfs_module_context *ntvfs,
			 struct ntvfs_request *req, union smb_read *rd)
{
	struct ipc_private *ipriv = ntvfs->private_data;
	DATA_BLOB data;
	struct pipe_state *p;
	NTSTATUS status = NT_STATUS_OK;

	if (rd->generic.level != RAW_READ_GENERIC) {
		return ntvfs_map_read(ntvfs, req, rd);
	}

	p = pipe_state_find(ipriv, rd->readx.in.file.ntvfs);
	if (!p) {
		return NT_STATUS_INVALID_HANDLE;
	}

	data.length = rd->readx.in.maxcnt;
	data.data = rd->readx.out.data;
	if (data.length > UINT16_MAX) {
		data.length = UINT16_MAX;
	}

	if (data.length != 0) {
		status = dcesrv_output(p->dce_conn, &data, ipc_readx_dcesrv_output);
		if (NT_STATUS_IS_ERR(status)) {
			return status;
		}
	}

	rd->readx.out.remaining = 0;
	rd->readx.out.compaction_mode = 0;
	rd->readx.out.nread = data.length;

	return status;
}

/*
  write to a file
*/
static NTSTATUS ipc_write(struct ntvfs_module_context *ntvfs,
			  struct ntvfs_request *req, union smb_write *wr)
{
	struct ipc_private *ipriv = ntvfs->private_data;
	DATA_BLOB data;
	struct pipe_state *p;
	NTSTATUS status;

	if (wr->generic.level != RAW_WRITE_GENERIC) {
		return ntvfs_map_write(ntvfs, req, wr);
	}

	data.data = discard_const_p(void, wr->writex.in.data);
	data.length = wr->writex.in.count;

	p = pipe_state_find(ipriv, wr->writex.in.file.ntvfs);
	if (!p) {
		return NT_STATUS_INVALID_HANDLE;
	}

	status = dcesrv_input(p->dce_conn, &data);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	wr->writex.out.nwritten = data.length;
	wr->writex.out.remaining = 0;

	return NT_STATUS_OK;
}

/*
  seek in a file
*/
static NTSTATUS ipc_seek(struct ntvfs_module_context *ntvfs,
			 struct ntvfs_request *req,
			 union smb_seek *io)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  flush a file
*/
static NTSTATUS ipc_flush(struct ntvfs_module_context *ntvfs,
			  struct ntvfs_request *req,
			  union smb_flush *io)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  close a file
*/
static NTSTATUS ipc_close(struct ntvfs_module_context *ntvfs,
			  struct ntvfs_request *req, union smb_close *io)
{
	struct ipc_private *ipriv = ntvfs->private_data;
	struct pipe_state *p;

	if (io->generic.level != RAW_CLOSE_CLOSE) {
		return ntvfs_map_close(ntvfs, req, io);
	}

	p = pipe_state_find(ipriv, io->close.in.file.ntvfs);
	if (!p) {
		return NT_STATUS_INVALID_HANDLE;
	}

	talloc_free(p);

	return NT_STATUS_OK;
}

/*
  exit - closing files
*/
static NTSTATUS ipc_exit(struct ntvfs_module_context *ntvfs,
			 struct ntvfs_request *req)
{
	struct ipc_private *ipriv = ntvfs->private_data;
	struct pipe_state *p, *next;
	
	for (p=ipriv->pipe_list; p; p=next) {
		next = p->next;
		if (p->handle->session_info == req->session_info &&
		    p->handle->smbpid == req->smbpid) {
			talloc_free(p);
		}
	}

	return NT_STATUS_OK;
}

/*
  logoff - closing files open by the user
*/
static NTSTATUS ipc_logoff(struct ntvfs_module_context *ntvfs,
			   struct ntvfs_request *req)
{
	struct ipc_private *ipriv = ntvfs->private_data;
	struct pipe_state *p, *next;
	
	for (p=ipriv->pipe_list; p; p=next) {
		next = p->next;
		if (p->handle->session_info == req->session_info) {
			talloc_free(p);
		}
	}

	return NT_STATUS_OK;
}

/*
  setup for an async call
*/
static NTSTATUS ipc_async_setup(struct ntvfs_module_context *ntvfs,
				struct ntvfs_request *req,
				void *private_data)
{
	return NT_STATUS_OK;
}

/*
  cancel an async call
*/
static NTSTATUS ipc_cancel(struct ntvfs_module_context *ntvfs,
			   struct ntvfs_request *req)
{
	return NT_STATUS_UNSUCCESSFUL;
}

/*
  lock a byte range
*/
static NTSTATUS ipc_lock(struct ntvfs_module_context *ntvfs,
			 struct ntvfs_request *req, union smb_lock *lck)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  set info on a open file
*/
static NTSTATUS ipc_setfileinfo(struct ntvfs_module_context *ntvfs,
				struct ntvfs_request *req, union smb_setfileinfo *info)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  query info on a open file
*/
static NTSTATUS ipc_qfileinfo(struct ntvfs_module_context *ntvfs,
			      struct ntvfs_request *req, union smb_fileinfo *info)
{
	struct ipc_private *ipriv = ntvfs->private_data;
	struct pipe_state *p = pipe_state_find(ipriv, info->generic.in.file.ntvfs);
	if (!p) {
		return NT_STATUS_INVALID_HANDLE;
	}
	switch (info->generic.level) {
	case RAW_FILEINFO_GENERIC: 
	{
		ZERO_STRUCT(info->generic.out);
		info->generic.out.attrib = FILE_ATTRIBUTE_NORMAL;
		info->generic.out.fname.s = strrchr(p->pipe_name, '\\');
		info->generic.out.alloc_size = 4096;
		info->generic.out.nlink = 1;
		/* What the heck?  Match Win2k3: IPC$ pipes are delete pending */
		info->generic.out.delete_pending = 1;
		return NT_STATUS_OK;
	}
	case RAW_FILEINFO_ALT_NAME_INFO:
	case RAW_FILEINFO_ALT_NAME_INFORMATION:
	case RAW_FILEINFO_STREAM_INFO:
	case RAW_FILEINFO_STREAM_INFORMATION:
	case RAW_FILEINFO_COMPRESSION_INFO:
	case RAW_FILEINFO_COMPRESSION_INFORMATION:
	case RAW_FILEINFO_NETWORK_OPEN_INFORMATION:
	case RAW_FILEINFO_ATTRIBUTE_TAG_INFORMATION:
		return NT_STATUS_INVALID_PARAMETER;
	case  RAW_FILEINFO_ALL_EAS:
		return NT_STATUS_ACCESS_DENIED;
	default:
		return ntvfs_map_qfileinfo(ntvfs, req, info);
	}
	
	return NT_STATUS_ACCESS_DENIED;
}


/*
  return filesystem info
*/
static NTSTATUS ipc_fsinfo(struct ntvfs_module_context *ntvfs,
			   struct ntvfs_request *req, union smb_fsinfo *fs)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  return print queue info
*/
static NTSTATUS ipc_lpq(struct ntvfs_module_context *ntvfs,
			struct ntvfs_request *req, union smb_lpq *lpq)
{
	return NT_STATUS_ACCESS_DENIED;
}

/* 
   list files in a directory matching a wildcard pattern
*/
static NTSTATUS ipc_search_first(struct ntvfs_module_context *ntvfs,
			  struct ntvfs_request *req, union smb_search_first *io,
			  void *search_private, 
			  bool (*callback)(void *, const union smb_search_data *))
{
	return NT_STATUS_ACCESS_DENIED;
}

/* 
   continue listing files in a directory 
*/
static NTSTATUS ipc_search_next(struct ntvfs_module_context *ntvfs,
			 struct ntvfs_request *req, union smb_search_next *io,
			 void *search_private, 
			 bool (*callback)(void *, const union smb_search_data *))
{
	return NT_STATUS_ACCESS_DENIED;
}

/* 
   end listing files in a directory 
*/
static NTSTATUS ipc_search_close(struct ntvfs_module_context *ntvfs,
			  struct ntvfs_request *req, union smb_search_close *io)
{
	return NT_STATUS_ACCESS_DENIED;
}

static NTSTATUS ipc_trans_dcesrv_output(void *private_data, DATA_BLOB *out, size_t *nwritten)
{
	NTSTATUS status = NT_STATUS_OK;
	DATA_BLOB *blob = private_data;

	if (out->length > blob->length) {
		status = STATUS_BUFFER_OVERFLOW;
	}

	if (out->length < blob->length) {
		blob->length = out->length;
	}
	memcpy(blob->data, out->data, blob->length);
	*nwritten = blob->length;
	return status;
}

/* SMBtrans - handle a DCERPC command */
static NTSTATUS ipc_dcerpc_cmd(struct ntvfs_module_context *ntvfs,
			       struct ntvfs_request *req, struct smb_trans2 *trans)
{
	struct pipe_state *p;
	struct ipc_private *ipriv = ntvfs->private_data;
	NTSTATUS status;
	DATA_BLOB fnum_key;
	uint16_t fnum;

	/*
	 * the fnum is in setup[1], a 16 bit value
	 * the setup[*] values are already in host byteorder
	 * but ntvfs_handle_search_by_wire_key() expects
	 * network byteorder
	 */
	SSVAL(&fnum, 0, trans->in.setup[1]);
	fnum_key = data_blob_const(&fnum, 2);

	p = pipe_state_find_key(ipriv, req, &fnum_key);
	if (!p) {
		return NT_STATUS_INVALID_HANDLE;
	}

	trans->out.data = data_blob_talloc(req, NULL, trans->in.max_data);
	if (!trans->out.data.data) {
		return NT_STATUS_NO_MEMORY;
	}

	/* pass the data to the dcerpc server. Note that we don't
	   expect this to fail, and things like NDR faults are not
	   reported at this stage. Those sorts of errors happen in the
	   dcesrv_output stage */
	status = dcesrv_input(p->dce_conn, &trans->in.data);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	  now ask the dcerpc system for some output. This doesn't yet handle
	  async calls. Again, we only expect NT_STATUS_OK. If the call fails then
	  the error is encoded at the dcerpc level
	*/
	status = dcesrv_output(p->dce_conn, &trans->out.data, ipc_trans_dcesrv_output);
	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	trans->out.setup_count = 0;
	trans->out.setup = NULL;
	trans->out.params = data_blob(NULL, 0);

	return status;
}


/* SMBtrans - set named pipe state */
static NTSTATUS ipc_set_nm_pipe_state(struct ntvfs_module_context *ntvfs,
				      struct ntvfs_request *req, struct smb_trans2 *trans)
{
	struct ipc_private *ipriv = ntvfs->private_data;
	struct pipe_state *p;
	DATA_BLOB fnum_key;

	/* the fnum is in setup[1] */
	fnum_key = data_blob_const(&trans->in.setup[1], sizeof(trans->in.setup[1]));

	p = pipe_state_find_key(ipriv, req, &fnum_key);
	if (!p) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if (trans->in.params.length != 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	p->ipc_state = SVAL(trans->in.params.data, 0);

	trans->out.setup_count = 0;
	trans->out.setup = NULL;
	trans->out.params = data_blob(NULL, 0);
	trans->out.data = data_blob(NULL, 0);

	return NT_STATUS_OK;
}


/* SMBtrans - used to provide access to SMB pipes */
static NTSTATUS ipc_trans(struct ntvfs_module_context *ntvfs,
				struct ntvfs_request *req, struct smb_trans2 *trans)
{
	NTSTATUS status;

	if (strequal(trans->in.trans_name, "\\PIPE\\LANMAN"))
		return ipc_rap_call(req, ntvfs->ctx->event_ctx, ntvfs->ctx->lp_ctx, trans);

       	if (trans->in.setup_count != 2) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (trans->in.setup[0]) {
	case TRANSACT_SETNAMEDPIPEHANDLESTATE:
		status = ipc_set_nm_pipe_state(ntvfs, req, trans);
		break;
	case TRANSACT_DCERPCCMD:
		status = ipc_dcerpc_cmd(ntvfs, req, trans);
		break;
	default:
		status = NT_STATUS_INVALID_PARAMETER;
		break;
	}

	return status;
}

static NTSTATUS ipc_ioctl_smb2(struct ntvfs_module_context *ntvfs,
			       struct ntvfs_request *req, union smb_ioctl *io)
{
	struct pipe_state *p;
	struct ipc_private *ipriv = ntvfs->private_data;
	NTSTATUS status;

	switch (io->smb2.in.function) {
	case FSCTL_NAMED_PIPE_READ_WRITE:
		break;

	default:
		return NT_STATUS_FS_DRIVER_REQUIRED;
	}

	p = pipe_state_find(ipriv, io->smb2.in.file.ntvfs);
	if (!p) {
		return NT_STATUS_INVALID_HANDLE;
	}

	io->smb2.out.out = data_blob_talloc(req, NULL, io->smb2.in.max_response_size);
	NT_STATUS_HAVE_NO_MEMORY(io->smb2.out.out.data);

	/* pass the data to the dcerpc server. Note that we don't
	   expect this to fail, and things like NDR faults are not
	   reported at this stage. Those sorts of errors happen in the
	   dcesrv_output stage */
	status = dcesrv_input(p->dce_conn, &io->smb2.in.out);
	NT_STATUS_NOT_OK_RETURN(status);

	/*
	  now ask the dcerpc system for some output. This doesn't yet handle
	  async calls. Again, we only expect NT_STATUS_OK. If the call fails then
	  the error is encoded at the dcerpc level
	*/
	status = dcesrv_output(p->dce_conn, &io->smb2.out.out, ipc_trans_dcesrv_output);
	NT_STATUS_IS_ERR_RETURN(status);

	io->smb2.out._pad	= 0;
	io->smb2.out.function	= io->smb2.in.function;
	io->smb2.out.unknown2	= 0;
	io->smb2.out.unknown3	= 0;
	io->smb2.out.in		= io->smb2.in.out;

	return status;
}

/*
  ioctl interface
*/
static NTSTATUS ipc_ioctl(struct ntvfs_module_context *ntvfs,
			  struct ntvfs_request *req, union smb_ioctl *io)
{
	switch (io->generic.level) {
	case RAW_IOCTL_SMB2:
		return ipc_ioctl_smb2(ntvfs, req, io);

	case RAW_IOCTL_SMB2_NO_HANDLE:
		return NT_STATUS_FS_DRIVER_REQUIRED;

	default:
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_ACCESS_DENIED;
}


/*
  initialialise the IPC backend, registering ourselves with the ntvfs subsystem
 */
NTSTATUS ntvfs_ipc_init(void)
{
	NTSTATUS ret;
	struct ntvfs_ops ops;
	NTVFS_CURRENT_CRITICAL_SIZES(vers);

	ZERO_STRUCT(ops);
	
	/* fill in the name and type */
	ops.name = "default";
	ops.type = NTVFS_IPC;

	/* fill in all the operations */
	ops.connect = ipc_connect;
	ops.disconnect = ipc_disconnect;
	ops.unlink = ipc_unlink;
	ops.chkpath = ipc_chkpath;
	ops.qpathinfo = ipc_qpathinfo;
	ops.setpathinfo = ipc_setpathinfo;
	ops.open = ipc_open;
	ops.mkdir = ipc_mkdir;
	ops.rmdir = ipc_rmdir;
	ops.rename = ipc_rename;
	ops.copy = ipc_copy;
	ops.ioctl = ipc_ioctl;
	ops.read = ipc_read;
	ops.write = ipc_write;
	ops.seek = ipc_seek;
	ops.flush = ipc_flush;	
	ops.close = ipc_close;
	ops.exit = ipc_exit;
	ops.lock = ipc_lock;
	ops.setfileinfo = ipc_setfileinfo;
	ops.qfileinfo = ipc_qfileinfo;
	ops.fsinfo = ipc_fsinfo;
	ops.lpq = ipc_lpq;
	ops.search_first = ipc_search_first;
	ops.search_next = ipc_search_next;
	ops.search_close = ipc_search_close;
	ops.trans = ipc_trans;
	ops.logoff = ipc_logoff;
	ops.async_setup = ipc_async_setup;
	ops.cancel = ipc_cancel;

	/* register ourselves with the NTVFS subsystem. */
	ret = ntvfs_register(&ops, &vers);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register IPC backend!\n"));
		return ret;
	}

	return ret;
}
