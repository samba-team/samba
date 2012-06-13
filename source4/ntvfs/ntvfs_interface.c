/* 
   Unix SMB/CIFS implementation.
   NTVFS interface functions

   Copyright (C) Stefan (metze) Metzmacher 2004

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
#include "ntvfs/ntvfs.h"
#include "lib/tsocket/tsocket.h"

/* connect/disconnect */
NTSTATUS ntvfs_connect(struct ntvfs_request *req, union smb_tcon *tcon)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->connect_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->connect_fn(ntvfs, req, tcon);
}

NTSTATUS ntvfs_disconnect(struct ntvfs_context *ntvfs_ctx)
{
	struct ntvfs_module_context *ntvfs;
	if (ntvfs_ctx == NULL) {
		return NT_STATUS_INVALID_CONNECTION;
	}
	ntvfs = ntvfs_ctx->modules;
	if (!ntvfs->ops->disconnect_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->disconnect_fn(ntvfs);
}

/* async setup - called by a backend that wants to setup any state for
   a async request */
NTSTATUS ntvfs_async_setup(struct ntvfs_request *req, void *private_data)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->async_setup_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->async_setup_fn(ntvfs, req, private_data);
}

/* filesystem operations */
NTSTATUS ntvfs_fsinfo(struct ntvfs_request *req, union smb_fsinfo *fs)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->fsinfo_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->fsinfo_fn(ntvfs, req, fs);
}

/* path operations */
NTSTATUS ntvfs_unlink(struct ntvfs_request *req, union smb_unlink *unl)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->unlink_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->unlink_fn(ntvfs, req, unl);
}

NTSTATUS ntvfs_chkpath(struct ntvfs_request *req, union smb_chkpath *cp)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->chkpath_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->chkpath_fn(ntvfs, req, cp);
}

NTSTATUS ntvfs_qpathinfo(struct ntvfs_request *req, union smb_fileinfo *st)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->qpathinfo_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->qpathinfo_fn(ntvfs, req, st);
}

NTSTATUS ntvfs_setpathinfo(struct ntvfs_request *req, union smb_setfileinfo *st)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->setpathinfo_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->setpathinfo_fn(ntvfs, req, st);
}

NTSTATUS ntvfs_open(struct ntvfs_request *req, union smb_open *oi)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->open_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->open_fn(ntvfs, req, oi);
}

NTSTATUS ntvfs_mkdir(struct ntvfs_request *req, union smb_mkdir *md)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->mkdir_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->mkdir_fn(ntvfs, req, md);
}

NTSTATUS ntvfs_rmdir(struct ntvfs_request *req, struct smb_rmdir *rd)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->rmdir_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->rmdir_fn(ntvfs, req, rd);
}

NTSTATUS ntvfs_rename(struct ntvfs_request *req, union smb_rename *ren)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->rename_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->rename_fn(ntvfs, req, ren);
}

NTSTATUS ntvfs_copy(struct ntvfs_request *req, struct smb_copy *cp)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->copy_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->copy_fn(ntvfs, req, cp);
}

/* directory search */
NTSTATUS ntvfs_search_first(struct ntvfs_request *req, union smb_search_first *io, void *private_data,
				     bool ntvfs_callback(void *private_data, const union smb_search_data *file))
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->search_first_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->search_first_fn(ntvfs, req, io, private_data, ntvfs_callback);
}

NTSTATUS ntvfs_search_next(struct ntvfs_request *req, union smb_search_next *io, void *private_data,
				    bool ntvfs_callback(void *private_data, const union smb_search_data *file))
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->search_next_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->search_next_fn(ntvfs, req, io, private_data, ntvfs_callback);
}

NTSTATUS ntvfs_search_close(struct ntvfs_request *req, union smb_search_close *io)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->search_close_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->search_close_fn(ntvfs, req, io);
}

/* operations on open files */
NTSTATUS ntvfs_ioctl(struct ntvfs_request *req, union smb_ioctl *io)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->ioctl_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->ioctl_fn(ntvfs, req, io);
}

NTSTATUS ntvfs_read(struct ntvfs_request *req, union smb_read *io)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->read_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->read_fn(ntvfs, req, io);
}

NTSTATUS ntvfs_write(struct ntvfs_request *req, union smb_write *io)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->write_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->write_fn(ntvfs, req, io);
}

NTSTATUS ntvfs_seek(struct ntvfs_request *req, union smb_seek *io)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->seek_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->seek_fn(ntvfs, req, io);
}

NTSTATUS ntvfs_flush(struct ntvfs_request *req,
			      union smb_flush *flush)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->flush_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->flush_fn(ntvfs, req, flush);
}

NTSTATUS ntvfs_lock(struct ntvfs_request *req, union smb_lock *lck)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->lock_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->lock_fn(ntvfs, req, lck);
}

NTSTATUS ntvfs_qfileinfo(struct ntvfs_request *req, union smb_fileinfo *info)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->qfileinfo_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->qfileinfo_fn(ntvfs, req, info);
}

NTSTATUS ntvfs_setfileinfo(struct ntvfs_request *req, union smb_setfileinfo *info)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->setfileinfo_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->setfileinfo_fn(ntvfs, req, info);
}

NTSTATUS ntvfs_close(struct ntvfs_request *req, union smb_close *io)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->close_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->close_fn(ntvfs, req, io);
}

/* trans interface - used by IPC backend for pipes and RAP calls */
NTSTATUS ntvfs_trans(struct ntvfs_request *req, struct smb_trans2 *trans)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->trans_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->trans_fn(ntvfs, req, trans);
}

/* trans2 interface - only used by CIFS backend to prover complete passthru for testing */
NTSTATUS ntvfs_trans2(struct ntvfs_request *req, struct smb_trans2 *trans2)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->trans2_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->trans2_fn(ntvfs, req, trans2);
}

/* printing specific operations */
NTSTATUS ntvfs_lpq(struct ntvfs_request *req, union smb_lpq *lpq)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->lpq_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->lpq_fn(ntvfs, req, lpq);
}

/* logoff - called when a vuid is closed */
NTSTATUS ntvfs_logoff(struct ntvfs_request *req)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->logoff_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->logoff_fn(ntvfs, req);
}

NTSTATUS ntvfs_exit(struct ntvfs_request *req)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->exit_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->exit_fn(ntvfs, req);
}

/*
  change notify request
*/
NTSTATUS ntvfs_notify(struct ntvfs_request *req, union smb_notify *info)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->notify_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->notify_fn(ntvfs, req, info);
}

/*
  cancel an outstanding async request
*/
NTSTATUS ntvfs_cancel(struct ntvfs_request *req)
{
	struct ntvfs_module_context *ntvfs = req->ctx->modules;
	if (!ntvfs->ops->cancel_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->ops->cancel_fn(ntvfs, req);
}

/* initial setup */
NTSTATUS ntvfs_next_connect(struct ntvfs_module_context *ntvfs, 
				     struct ntvfs_request *req,
				     union smb_tcon *tcon)
{
	if (!ntvfs->next || !ntvfs->next->ops->connect_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->connect_fn(ntvfs->next, req, tcon);
}

NTSTATUS ntvfs_next_disconnect(struct ntvfs_module_context *ntvfs)
{
	if (!ntvfs->next || !ntvfs->next->ops->disconnect_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->disconnect_fn(ntvfs->next);
}

/* async_setup - called when setting up for a async request */
NTSTATUS ntvfs_next_async_setup(struct ntvfs_module_context *ntvfs, 
					 struct ntvfs_request *req, 
					 void *private_data)
{
	if (!ntvfs->next || !ntvfs->next->ops->async_setup_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->async_setup_fn(ntvfs->next, req, private_data);
}

/* filesystem operations */
NTSTATUS ntvfs_next_fsinfo(struct ntvfs_module_context *ntvfs, 
				    struct ntvfs_request *req,
				    union smb_fsinfo *fs)
{
	if (!ntvfs->next || !ntvfs->next->ops->fsinfo_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->fsinfo_fn(ntvfs->next, req, fs);
}

/* path operations */
NTSTATUS ntvfs_next_unlink(struct ntvfs_module_context *ntvfs, 
				    struct ntvfs_request *req,
				    union smb_unlink *unl)
{
	if (!ntvfs->next || !ntvfs->next->ops->unlink_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->unlink_fn(ntvfs->next, req, unl);
}

NTSTATUS ntvfs_next_chkpath(struct ntvfs_module_context *ntvfs, 
				     struct ntvfs_request *req,
				     union smb_chkpath *cp)
{
	if (!ntvfs->next || !ntvfs->next->ops->chkpath_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->chkpath_fn(ntvfs->next, req, cp);
}

NTSTATUS ntvfs_next_qpathinfo(struct ntvfs_module_context *ntvfs, 
				       struct ntvfs_request *req,
				       union smb_fileinfo *st)
{
	if (!ntvfs->next || !ntvfs->next->ops->qpathinfo_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->qpathinfo_fn(ntvfs->next, req, st);
}

NTSTATUS ntvfs_next_setpathinfo(struct ntvfs_module_context *ntvfs, 
					 struct ntvfs_request *req,
					 union smb_setfileinfo *st)
{
	if (!ntvfs->next || !ntvfs->next->ops->setpathinfo_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->setpathinfo_fn(ntvfs->next, req, st);
}

NTSTATUS ntvfs_next_mkdir(struct ntvfs_module_context *ntvfs, 
				   struct ntvfs_request *req,
				   union smb_mkdir *md)
{
	if (!ntvfs->next || !ntvfs->next->ops->mkdir_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->mkdir_fn(ntvfs->next, req, md);
}

NTSTATUS ntvfs_next_rmdir(struct ntvfs_module_context *ntvfs, 
				   struct ntvfs_request *req,
				   struct smb_rmdir *rd)
{
	if (!ntvfs->next || !ntvfs->next->ops->rmdir_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->rmdir_fn(ntvfs->next, req, rd);
}

NTSTATUS ntvfs_next_rename(struct ntvfs_module_context *ntvfs, 
				    struct ntvfs_request *req,
				    union smb_rename *ren)
{
	if (!ntvfs->next || !ntvfs->next->ops->rename_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->rename_fn(ntvfs->next, req, ren);
}

NTSTATUS ntvfs_next_copy(struct ntvfs_module_context *ntvfs, 
				  struct ntvfs_request *req,
				  struct smb_copy *cp)
{
	if (!ntvfs->next || !ntvfs->next->ops->copy_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->copy_fn(ntvfs->next, req, cp);
}

NTSTATUS ntvfs_next_open(struct ntvfs_module_context *ntvfs, 
				  struct ntvfs_request *req,
				  union smb_open *oi)
{
	if (!ntvfs->next || !ntvfs->next->ops->open_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->open_fn(ntvfs->next, req, oi);
}


/* directory search */
NTSTATUS ntvfs_next_search_first(struct ntvfs_module_context *ntvfs, 
					  struct ntvfs_request *req,
					  union smb_search_first *io, void *private_data,
					  bool (*callback)(void *private_data, const union smb_search_data *file))
{
	if (!ntvfs->next || !ntvfs->next->ops->search_first_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->search_first_fn(ntvfs->next, req, io, private_data, callback);
}

NTSTATUS ntvfs_next_search_next(struct ntvfs_module_context *ntvfs, 
					 struct ntvfs_request *req,
					 union smb_search_next *io, void *private_data,
					 bool (*callback)(void *private_data, const union smb_search_data *file))
{
	if (!ntvfs->next || !ntvfs->next->ops->search_next_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->search_next_fn(ntvfs->next, req, io, private_data, callback);
}

NTSTATUS ntvfs_next_search_close(struct ntvfs_module_context *ntvfs, 
					  struct ntvfs_request *req,
					  union smb_search_close *io)
{
	if (!ntvfs->next || !ntvfs->next->ops->search_close_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->search_close_fn(ntvfs->next, req, io);
}

/* operations on open files */
NTSTATUS ntvfs_next_ioctl(struct ntvfs_module_context *ntvfs, 
				   struct ntvfs_request *req,
				   union smb_ioctl *io)
{
	if (!ntvfs->next || !ntvfs->next->ops->ioctl_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->ioctl_fn(ntvfs->next, req, io);
}

NTSTATUS ntvfs_next_read(struct ntvfs_module_context *ntvfs, 
				  struct ntvfs_request *req,
				  union smb_read *io)
{
	if (!ntvfs->next || !ntvfs->next->ops->read_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->read_fn(ntvfs->next, req, io);
}

NTSTATUS ntvfs_next_write(struct ntvfs_module_context *ntvfs, 
				   struct ntvfs_request *req,
				   union smb_write *io)
{
	if (!ntvfs->next || !ntvfs->next->ops->write_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->write_fn(ntvfs->next, req, io);
}

NTSTATUS ntvfs_next_seek(struct ntvfs_module_context *ntvfs, 
				  struct ntvfs_request *req,
				  union smb_seek *io)
{
	if (!ntvfs->next || !ntvfs->next->ops->seek_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->seek_fn(ntvfs->next, req, io);
}

NTSTATUS ntvfs_next_flush(struct ntvfs_module_context *ntvfs, 
				   struct ntvfs_request *req,
				   union smb_flush *flush)
{
	if (!ntvfs->next || !ntvfs->next->ops->flush_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->flush_fn(ntvfs->next, req, flush);
}

NTSTATUS ntvfs_next_lock(struct ntvfs_module_context *ntvfs, 
				  struct ntvfs_request *req,
				  union smb_lock *lck)
{
	if (!ntvfs->next || !ntvfs->next->ops->lock_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->lock_fn(ntvfs->next, req, lck);
}

NTSTATUS ntvfs_next_qfileinfo(struct ntvfs_module_context *ntvfs, 
				       struct ntvfs_request *req,
				       union smb_fileinfo *info)
{
	if (!ntvfs->next || !ntvfs->next->ops->qfileinfo_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->qfileinfo_fn(ntvfs->next, req, info);
}

NTSTATUS ntvfs_next_setfileinfo(struct ntvfs_module_context *ntvfs, 
					 struct ntvfs_request *req,
					 union smb_setfileinfo *info)
{
	if (!ntvfs->next || !ntvfs->next->ops->setfileinfo_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->setfileinfo_fn(ntvfs->next, req, info);
}

NTSTATUS ntvfs_next_close(struct ntvfs_module_context *ntvfs, 
				   struct ntvfs_request *req,
				   union smb_close *io)
{
	if (!ntvfs->next || !ntvfs->next->ops->close_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->close_fn(ntvfs->next, req, io);
}

/* trans interface - used by IPC backend for pipes and RAP calls */
NTSTATUS ntvfs_next_trans(struct ntvfs_module_context *ntvfs, 
				   struct ntvfs_request *req,
				   struct smb_trans2 *trans)
{
	if (!ntvfs->next || !ntvfs->next->ops->trans_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->trans_fn(ntvfs->next, req, trans);
}

/* trans2 interface - only used by CIFS backend to prover complete passthru for testing */
NTSTATUS ntvfs_next_trans2(struct ntvfs_module_context *ntvfs, 
				    struct ntvfs_request *req,
				    struct smb_trans2 *trans2)
{
	if (!ntvfs->next || !ntvfs->next->ops->trans2_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->trans2_fn(ntvfs->next, req, trans2);
}

/*
  change notify request
*/
NTSTATUS ntvfs_next_notify(struct ntvfs_module_context *ntvfs,
				    struct ntvfs_request *req,
				    union smb_notify *info)
{
	if (!ntvfs->next || !ntvfs->next->ops->notify_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->notify_fn(ntvfs->next, req, info);
}

/* cancel - called to cancel an outstanding async request */
NTSTATUS ntvfs_next_cancel(struct ntvfs_module_context *ntvfs, 
				    struct ntvfs_request *req)
{
	if (!ntvfs->next || !ntvfs->next->ops->cancel_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->cancel_fn(ntvfs->next, req);
}

/* printing specific operations */
NTSTATUS ntvfs_next_lpq(struct ntvfs_module_context *ntvfs, 
				 struct ntvfs_request *req,
				 union smb_lpq *lpq)
{
	if (!ntvfs->next || !ntvfs->next->ops->lpq_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->lpq_fn(ntvfs->next, req, lpq);
}


/* logoff - called when a vuid is closed */
NTSTATUS ntvfs_next_logoff(struct ntvfs_module_context *ntvfs, 
				    struct ntvfs_request *req)
{
	if (!ntvfs->next || !ntvfs->next->ops->logoff_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->logoff_fn(ntvfs->next, req);
}

NTSTATUS ntvfs_next_exit(struct ntvfs_module_context *ntvfs, 
				  struct ntvfs_request *req)
{
	if (!ntvfs->next || !ntvfs->next->ops->exit_fn) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ntvfs->next->ops->exit_fn(ntvfs->next, req);
}

/* client connection callback */
NTSTATUS ntvfs_set_addresses(struct ntvfs_context *ntvfs,
			     const struct tsocket_address *local_address,
			     const struct tsocket_address *remote_address)
{
	ntvfs->client.local_address = tsocket_address_copy(local_address, ntvfs);
	NT_STATUS_HAVE_NO_MEMORY(ntvfs->client.local_address);

	ntvfs->client.remote_address = tsocket_address_copy(remote_address, ntvfs);
	NT_STATUS_HAVE_NO_MEMORY(ntvfs->client.remote_address);

	return NT_STATUS_OK;
}

const struct tsocket_address *ntvfs_get_local_address(struct ntvfs_module_context *ntvfs)
{
	return ntvfs->ctx->client.local_address;
}

const struct tsocket_address *ntvfs_get_remote_address(struct ntvfs_module_context *ntvfs)
{
	return ntvfs->ctx->client.remote_address;
}

/* oplock helpers */
NTSTATUS ntvfs_set_oplock_handler(struct ntvfs_context *ntvfs,
					   NTSTATUS (*handler)(void *private_data, struct ntvfs_handle *handle, uint8_t level),
					   void *private_data)
{
	ntvfs->oplock.handler		= handler;
	ntvfs->oplock.private_data	= private_data;
	return NT_STATUS_OK;
}

NTSTATUS ntvfs_send_oplock_break(struct ntvfs_module_context *ntvfs,
					  struct ntvfs_handle *handle, uint8_t level)
{
	if (!ntvfs->ctx->oplock.handler) {
		return NT_STATUS_OK;
	}

	return ntvfs->ctx->oplock.handler(ntvfs->ctx->oplock.private_data, handle, level);
}

