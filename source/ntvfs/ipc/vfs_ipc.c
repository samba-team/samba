/* 
   Unix SMB/CIFS implementation.
   default IPC$ NTVFS backend

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher 2004-2005

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
/*
  this implements the IPC$ backend, called by the NTVFS subsystem to
  handle requests on IPC$ shares
*/


#include "includes.h"
#include "dlinklist.h"
#include "smb_server/smb_server.h"
#include "ntvfs/ntvfs.h"
#include "ntvfs/ipc/proto.h"
#include "rpc_server/dcerpc_server.h"

#define IPC_BASE_FNUM 0x400

/* this is the private structure used to keep the state of an open
   ipc$ connection. It needs to keep information about all open
   pipes */
struct ipc_private {
	struct idr_context *idtree_fnum;

	struct dcesrv_context *dcesrv;

	/* a list of open pipes */
	struct pipe_state {
		struct pipe_state *next, *prev;
		struct ipc_private *private;
		const char *pipe_name;
		uint16_t fnum;
		struct dcesrv_connection *dce_conn;
		uint16_t ipc_state;
		/* we need to remember the session it was opened on,
		   as it is illegal to operate on someone elses fnum */
		struct smbsrv_session *session;

		/* we need to remember the client pid that 
		   opened the file so SMBexit works */
		uint16_t smbpid;
	} *pipe_list;

};


/*
  find a open pipe give a file descriptor
*/
static struct pipe_state *pipe_state_find(struct ipc_private *private, uint16_t fnum)
{
	return idr_find(private->idtree_fnum, fnum);
}


/*
  connect to a share - always works 
*/
static NTSTATUS ipc_connect(struct ntvfs_module_context *ntvfs,
			    struct ntvfs_request *req, const char *sharename)
{
	NTSTATUS status;
	struct smbsrv_tcon *tcon = req->tcon;
	struct ipc_private *private;

	tcon->fs_type = talloc_strdup(tcon, "IPC");
	NT_STATUS_HAVE_NO_MEMORY(tcon->fs_type);

	tcon->dev_type = talloc_strdup(tcon, "IPC");
	NT_STATUS_HAVE_NO_MEMORY(tcon->dev_type);

	/* prepare the private state for this connection */
	private = talloc(ntvfs, struct ipc_private);
	NT_STATUS_HAVE_NO_MEMORY(private);

	ntvfs->private_data = private;

	private->pipe_list = NULL;

	private->idtree_fnum = idr_init(private);
	NT_STATUS_HAVE_NO_MEMORY(private->idtree_fnum);

	/* setup the DCERPC server subsystem */
	status = dcesrv_init_ipc_context(private, &private->dcesrv);
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
  ioctl interface - we don't do any
*/
static NTSTATUS ipc_ioctl(struct ntvfs_module_context *ntvfs,
			  struct ntvfs_request *req, union smb_ioctl *io)
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
	return NT_STATUS_ACCESS_DENIED;
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
static int ipc_fd_destructor(void *ptr)
{
	struct pipe_state *p = ptr;
	idr_remove(p->private->idtree_fnum, p->fnum);
	DLIST_REMOVE(p->private->pipe_list, p);
	return 0;
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
	struct ipc_private *private = ntvfs->private_data;
	int fnum;
	struct stream_connection *srv_conn = req->smb_conn->connection;

	if (!req->session || !req->session->session_info) {
		return NT_STATUS_ACCESS_DENIED;
	}

	p = talloc(req, struct pipe_state);
	NT_STATUS_HAVE_NO_MEMORY(p);

	ep_description = talloc(req, struct dcerpc_binding);
	NT_STATUS_HAVE_NO_MEMORY(ep_description);

	while (fname[0] == '\\') fname++;

	p->pipe_name = talloc_asprintf(p, "\\pipe\\%s", fname);
	NT_STATUS_HAVE_NO_MEMORY(p->pipe_name);

	fnum = idr_get_new_above(private->idtree_fnum, p, IPC_BASE_FNUM, UINT16_MAX);
	if (fnum == -1) {
		return NT_STATUS_TOO_MANY_OPENED_FILES;
	}

	p->fnum = fnum;
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
	status = dcesrv_endpoint_search_connect(private->dcesrv,
						p,
						ep_description, 
						req->session->session_info,
						srv_conn,
						0,
						&p->dce_conn);
	if (!NT_STATUS_IS_OK(status)) {
		idr_remove(private->idtree_fnum, p->fnum);
		return status;
	}

	DLIST_ADD(private->pipe_list, p);

	p->smbpid = req->smbpid;
	p->session = req->session;
	p->private = private;

	*ps = p;

	talloc_steal(private, p);

	talloc_set_destructor(p, ipc_fd_destructor);

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
	oi->ntcreatex.file.fnum = p->fnum;
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
	oi->openx.file.fnum = p->fnum;
	oi->openx.out.ftype = 2;
	oi->openx.out.devstate = p->ipc_state;
	
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
	struct ipc_private *private = ntvfs->private_data;
	DATA_BLOB data;
	uint16_t fnum;
	struct pipe_state *p;
	NTSTATUS status = NT_STATUS_OK;

	if (rd->generic.level != RAW_READ_GENERIC) {
		return ntvfs_map_read(ntvfs, req, rd);
	}

	fnum = rd->readx.file.fnum;

	p = pipe_state_find(private, fnum);
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
	struct ipc_private *private = ntvfs->private_data;
	DATA_BLOB data;
	uint16_t fnum;
	struct pipe_state *p;
	NTSTATUS status;

	if (wr->generic.level != RAW_WRITE_GENERIC) {
		return ntvfs_map_write(ntvfs, req, wr);
	}

	fnum = wr->writex.file.fnum;
	data.data = discard_const_p(void, wr->writex.in.data);
	data.length = wr->writex.in.count;

	p = pipe_state_find(private, fnum);
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
	struct ipc_private *private = ntvfs->private_data;
	struct pipe_state *p;

	if (io->generic.level != RAW_CLOSE_CLOSE) {
		return ntvfs_map_close(ntvfs, req, io);
	}

	p = pipe_state_find(private, io->close.file.fnum);
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
	struct ipc_private *private = ntvfs->private_data;
	struct pipe_state *p, *next;
	
	for (p=private->pipe_list; p; p=next) {
		next = p->next;
		if (p->smbpid == req->smbpid) {
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
	struct ipc_private *private = ntvfs->private_data;
	struct pipe_state *p, *next;
	
	for (p=private->pipe_list; p; p=next) {
		next = p->next;
		if (p->session == req->session) {
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
				void *private)
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
			  BOOL (*callback)(void *, union smb_search_data *))
{
	return NT_STATUS_ACCESS_DENIED;
}

/* 
   continue listing files in a directory 
*/
static NTSTATUS ipc_search_next(struct ntvfs_module_context *ntvfs,
			 struct ntvfs_request *req, union smb_search_next *io,
			 void *search_private, 
			 BOOL (*callback)(void *, union smb_search_data *))
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
	struct ipc_private *private = ntvfs->private_data;
	NTSTATUS status;

	/* the fnum is in setup[1] */
	p = pipe_state_find(private, trans->in.setup[1]);
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
	struct ipc_private *private = ntvfs->private_data;
	struct pipe_state *p;

	/* the fnum is in setup[1] */
	p = pipe_state_find(private, trans->in.setup[1]);
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
		return ipc_rap_call(req, trans);

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



/*
  initialialise the IPC backend, registering ourselves with the ntvfs subsystem
 */
NTSTATUS ntvfs_ipc_init(void)
{
	NTSTATUS ret;
	struct ntvfs_ops ops;

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
	ret = ntvfs_register(&ops);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register IPC backend!\n"));
		return ret;
	}

	return ret;
}
