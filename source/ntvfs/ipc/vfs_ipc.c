/* 
   Unix SMB/CIFS implementation.
   default IPC$ NTVFS backend
   Copyright (C) Andrew Tridgell 2003

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

/* this is the private structure used to keep the state of an open
   ipc$ connection. It needs to keep information about all open
   pipes */
struct ipc_private {

	uint16 next_fnum;
	uint16 num_open;

	/* a list of open pipes */
	struct pipe_state {
		struct pipe_state *next, *prev;
		TALLOC_CTX *mem_ctx;
		const char *pipe_name;
		uint16 fnum;
		struct dcesrv_state *pipe_state;
	} *pipe_list;

};


/*
  find the next fnum available on this connection
*/
static uint16 find_next_fnum(struct ipc_private *ipc)
{
	struct pipe_state *p;
	uint32 ret;

	if (ipc->num_open == 0xFFFF) {
		return 0;
	}

again:
	ret = ipc->next_fnum++;

	for (p=ipc->pipe_list; p; p=p->next) {
		if (p->fnum == ret) {
			goto again;
		}
	}

	return ret;
}


/*
  shutdown a single pipe. Called on a close or disconnect
*/
static void pipe_shutdown(struct ipc_private *private, struct pipe_state *p)
{
	TALLOC_CTX *mem_ctx = private->pipe_list->mem_ctx;
	dcesrv_endpoint_disconnect(private->pipe_list->pipe_state);
	DLIST_REMOVE(private->pipe_list, private->pipe_list);
	talloc_destroy(mem_ctx);
}


/*
  find a open pipe give a file descriptor
*/
static struct pipe_state *pipe_state_find(struct ipc_private *private, uint16 fnum)
{
	struct pipe_state *p;
	
	for (p=private->pipe_list; p; p=p->next) {
		if (p->fnum == fnum) {
			return p;
		}
	}

	return NULL;
}


/*
  connect to a share - always works 
*/
static NTSTATUS ipc_connect(struct request_context *req, const char *sharename)
{
	struct tcon_context *conn = req->conn;
	struct ipc_private *private;

	conn->fs_type = talloc_strdup(conn->mem_ctx, "IPC");
	conn->dev_type = talloc_strdup(conn->mem_ctx, "IPC");

	/* prepare the private state for this connection */
	private = talloc(conn->mem_ctx, sizeof(struct ipc_private));
	if (!private) {
		return NT_STATUS_NO_MEMORY;
	}
	conn->ntvfs_private = (void *)private;

	private->pipe_list = NULL;
	private->next_fnum = 1;
	private->num_open = 0;

	return NT_STATUS_OK;
}

/*
  disconnect from a share
*/
static NTSTATUS ipc_disconnect(struct tcon_context *tcon)
{
	struct ipc_private *private = tcon->ntvfs_private;

	/* close any pipes that are open. Discard any unread data */
	while (private->pipe_list) {
		pipe_shutdown(private, private->pipe_list);
	}

	return NT_STATUS_OK;
}

/*
  delete a file
*/
static NTSTATUS ipc_unlink(struct request_context *req, struct smb_unlink *unl)
{
	return NT_STATUS_ACCESS_DENIED;
}


/*
  ioctl interface - we don't do any
*/
static NTSTATUS ipc_ioctl(struct request_context *req, union smb_ioctl *io)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  check if a directory exists
*/
static NTSTATUS ipc_chkpath(struct request_context *req, struct smb_chkpath *cp)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  return info on a pathname
*/
static NTSTATUS ipc_qpathinfo(struct request_context *req, union smb_fileinfo *info)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  set info on a pathname
*/
static NTSTATUS ipc_setpathinfo(struct request_context *req, union smb_setfileinfo *st)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  open a file - used for MSRPC pipes
*/
static NTSTATUS ipc_open(struct request_context *req, union smb_open *oi)
{
	struct pipe_state *p;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;
	struct dcesrv_endpoint endpoint;
	struct ipc_private *private = req->conn->ntvfs_private;

	/* for now only handle NTcreateX style opens */
	if (oi->generic.level != RAW_OPEN_NTCREATEX) {
		return NT_STATUS_ACCESS_DENIED;
	}

	mem_ctx = talloc_init("ipc_open '%s'", oi->ntcreatex.in.fname);
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	p = talloc(mem_ctx, sizeof(struct pipe_state));
	if (!p) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	p->mem_ctx = mem_ctx;

	p->pipe_name = talloc_strdup(mem_ctx, oi->ntcreatex.in.fname);
	if (!p->pipe_name) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	p->fnum = find_next_fnum(private);
	if (p->fnum == 0) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_TOO_MANY_OPENED_FILES;
	}

	if (strncasecmp(p->pipe_name, "\\pipe\\", 6) != 0) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	p->pipe_name += 6;

	/*
	  we're all set, now ask the dcerpc server subsystem to open the 
	  endpoint. At this stage the pipe isn't bound, so we don't
	  know what interface the user actually wants, just that they want
	  one of the interfaces attached to this pipe endpoint.

	  TODO: note that we aren't passing any credentials here. We
	  will need to do that once the credentials infrastructure is
	  finalised for Samba4
	*/

	endpoint.type = ENDPOINT_SMB;
	endpoint.info.smb_pipe = p->pipe_name;

	status = dcesrv_endpoint_connect(req->smb, &endpoint, &p->pipe_state);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return status;
	}

	private->num_open++;

	DLIST_ADD(private->pipe_list, p);

	ZERO_STRUCT(oi->ntcreatex.out);
	oi->ntcreatex.out.fnum = p->fnum;

	return NT_STATUS_OK;
}

/*
  create a directory
*/
static NTSTATUS ipc_mkdir(struct request_context *req, union smb_mkdir *md)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  remove a directory
*/
static NTSTATUS ipc_rmdir(struct request_context *req, struct smb_rmdir *rd)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  rename a set of files
*/
static NTSTATUS ipc_rename(struct request_context *req, union smb_rename *ren)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  copy a set of files
*/
static NTSTATUS ipc_copy(struct request_context *req, struct smb_copy *cp)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  read from a file
*/
static NTSTATUS ipc_read(struct request_context *req, union smb_read *rd)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  write to a file
*/
static NTSTATUS ipc_write(struct request_context *req, union smb_write *wr)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  seek in a file
*/
static NTSTATUS ipc_seek(struct request_context *req, struct smb_seek *io)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  flush a file
*/
static NTSTATUS ipc_flush(struct request_context *req, struct smb_flush *io)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  close a file
*/
static NTSTATUS ipc_close(struct request_context *req, union smb_close *io)
{
	struct ipc_private *private = req->conn->ntvfs_private;
	struct pipe_state *p;

	if (io->generic.level != RAW_CLOSE_CLOSE) {
		return NT_STATUS_ACCESS_DENIED;
	}

	p = pipe_state_find(private, io->close.in.fnum);
	if (!p) {
		return NT_STATUS_INVALID_HANDLE;
	}

	pipe_shutdown(private, p);
	private->num_open--;

	return NT_STATUS_OK;
}

/*
  exit - closing files?
*/
static NTSTATUS ipc_exit(struct request_context *req)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  lock a byte range
*/
static NTSTATUS ipc_lock(struct request_context *req, union smb_lock *lck)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  set info on a open file
*/
static NTSTATUS ipc_setfileinfo(struct request_context *req, union smb_setfileinfo *info)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  query info on a open file
*/
static NTSTATUS ipc_qfileinfo(struct request_context *req, union smb_fileinfo *info)
{
	return NT_STATUS_ACCESS_DENIED;
}


/*
  return filesystem info
*/
static NTSTATUS ipc_fsinfo(struct request_context *req, union smb_fsinfo *fs)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  return print queue info
*/
static NTSTATUS ipc_lpq(struct request_context *req, union smb_lpq *lpq)
{
	return NT_STATUS_ACCESS_DENIED;
}

/* 
   list files in a directory matching a wildcard pattern
*/
NTSTATUS ipc_search_first(struct request_context *req, union smb_search_first *io,
			  void *search_private, 
			  BOOL (*callback)(void *, union smb_search_data *))
{
	return NT_STATUS_ACCESS_DENIED;
}

/* 
   continue listing files in a directory 
*/
NTSTATUS ipc_search_next(struct request_context *req, union smb_search_next *io,
			 void *search_private, 
			 BOOL (*callback)(void *, union smb_search_data *))
{
	return NT_STATUS_ACCESS_DENIED;
}

/* 
   end listing files in a directory 
*/
NTSTATUS ipc_search_close(struct request_context *req, union smb_search_close *io)
{
	return NT_STATUS_ACCESS_DENIED;
}


/*
  initialialise the IPC backend, registering ourselves with the ntvfs subsystem
 */
NTSTATUS ntvfs_ipc_init(void)
{
	NTSTATUS ret;
	struct ntvfs_ops ops;

	ZERO_STRUCT(ops);
	
	/* fill in all the operations */
	ops.name = "ipc";
	ops.type = NTVFS_IPC;
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

	/* register ourselves with the NTVFS subsystem. */
	ret = register_backend("ntvfs", &ops);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register IPC backend!\n"));
		return ret;
	}

	return ret;
}
