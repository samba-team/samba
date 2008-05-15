/* 
   Unix SMB/CIFS implementation.

   CIFS-to-SMB2 NTVFS filesystem backend

   Copyright (C) Andrew Tridgell 2008

   largely based on vfs_cifs.c which was 
      Copyright (C) Andrew Tridgell 2003
      Copyright (C) James J Myers 2003 <myersjj@samba.org>

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
  this implements a CIFS->CIFS NTVFS filesystem backend. 
  
*/

#include "includes.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "libcli/smb_composite/smb_composite.h"
#include "auth/auth.h"
#include "auth/credentials/credentials.h"
#include "ntvfs/ntvfs.h"
#include "lib/util/dlinklist.h"
#include "param/param.h"
#include "libcli/resolve/resolve.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"

struct cvfs_file {
	struct cvfs_file *prev, *next;
	uint16_t fnum;
	struct ntvfs_handle *h;
};

/* this is stored in ntvfs_private */
struct cvfs_private {
	struct smb2_tree *tree;
	struct smbcli_transport *transport;
	struct ntvfs_module_context *ntvfs;
	struct async_info *pending;
	struct cvfs_file *files;

	/* a handle on the root of the share */
	/* TODO: leaving this handle open could prevent other users
	   from opening the share with exclusive access. We probably
	   need to open it on demand */
	struct smb2_handle roothandle;
};


/* a structure used to pass information to an async handler */
struct async_info {
	struct async_info *next, *prev;
	struct cvfs_private *cvfs;
	struct ntvfs_request *req;
	struct smb2_request *c_req;
	struct cvfs_file *f;
	void *parms;
};

#define SETUP_FILE_HERE(f) do { \
	f = ntvfs_handle_get_backend_data(io->generic.in.file.ntvfs, ntvfs); \
	if (!f) return NT_STATUS_INVALID_HANDLE; \
	io->generic.in.file.fnum = f->fnum; \
} while (0)

#define SETUP_FILE do { \
	struct cvfs_file *f; \
	SETUP_FILE_HERE(f); \
} while (0)

#define SMB2_SERVER		"smb2:server"
#define SMB2_USER		"smb2:user"
#define SMB2_PASSWORD		"smb2:password"
#define SMB2_DOMAIN		"smb2:domain"
#define SMB2_SHARE		"smb2:share"
#define SMB2_USE_MACHINE_ACCT	"smb2:use-machine-account"

#define SMB2_USE_MACHINE_ACCT_DEFAULT	false

/*
  a handler for oplock break events from the server - these need to be passed
  along to the client
 */
static bool oplock_handler(struct smbcli_transport *transport, uint16_t tid, uint16_t fnum, uint8_t level, void *p_private)
{
	struct cvfs_private *private = p_private;
	NTSTATUS status;
	struct ntvfs_handle *h = NULL;
	struct cvfs_file *f;

	for (f=private->files; f; f=f->next) {
		if (f->fnum != fnum) continue;
		h = f->h;
		break;
	}

	if (!h) {
		DEBUG(5,("vfs_smb2: ignoring oplock break level %d for fnum %d\n", level, fnum));
		return true;
	}

	DEBUG(5,("vfs_smb2: sending oplock break level %d for fnum %d\n", level, fnum));
	status = ntvfs_send_oplock_break(private->ntvfs, h, level);
	if (!NT_STATUS_IS_OK(status)) return false;
	return true;
}

/*
  return a handle to the root of the share
*/
static NTSTATUS smb2_get_roothandle(struct smb2_tree *tree, struct smb2_handle *handle)
{
	struct smb2_create io;
	NTSTATUS status;

	ZERO_STRUCT(io);
	io.in.oplock_level = 0;
	io.in.desired_access = SEC_STD_SYNCHRONIZE | SEC_DIR_READ_ATTRIBUTE | SEC_DIR_LIST;
	io.in.file_attributes   = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	io.in.create_options = 0;
	io.in.fname = NULL;

	status = smb2_create(tree, tree, &io);
	NT_STATUS_NOT_OK_RETURN(status);

	*handle = io.out.file.handle;

	return NT_STATUS_OK;
}

/*
  connect to a share - used when a tree_connect operation comes in.
*/
static NTSTATUS cvfs_connect(struct ntvfs_module_context *ntvfs, 
			     struct ntvfs_request *req, const char *sharename)
{
	NTSTATUS status;
	struct cvfs_private *private;
	const char *host, *user, *pass, *domain, *remote_share;
	struct composite_context *creq;
	struct share_config *scfg = ntvfs->ctx->config;
	struct smb2_tree *tree;

	struct cli_credentials *credentials;
	bool machine_account;

	/* Here we need to determine which server to connect to.
	 * For now we use parametric options, type cifs.
	 * Later we will use security=server and auth_server.c.
	 */
	host = share_string_option(scfg, SMB2_SERVER, NULL);
	user = share_string_option(scfg, SMB2_USER, NULL);
	pass = share_string_option(scfg, SMB2_PASSWORD, NULL);
	domain = share_string_option(scfg, SMB2_DOMAIN, NULL);
	remote_share = share_string_option(scfg, SMB2_SHARE, NULL);
	if (!remote_share) {
		remote_share = sharename;
	}

	machine_account = share_bool_option(scfg, SMB2_USE_MACHINE_ACCT, SMB2_USE_MACHINE_ACCT_DEFAULT);

	private = talloc_zero(ntvfs, struct cvfs_private);
	if (!private) {
		return NT_STATUS_NO_MEMORY;
	}

	ntvfs->private_data = private;

	if (!host) {
		DEBUG(1,("CIFS backend: You must supply server\n"));
		return NT_STATUS_INVALID_PARAMETER;
	} 
	
	if (user && pass) {
		DEBUG(5, ("CIFS backend: Using specified password\n"));
		credentials = cli_credentials_init(private);
		if (!credentials) {
			return NT_STATUS_NO_MEMORY;
		}
		cli_credentials_set_conf(credentials, ntvfs->ctx->lp_ctx);
		cli_credentials_set_username(credentials, user, CRED_SPECIFIED);
		if (domain) {
			cli_credentials_set_domain(credentials, domain, CRED_SPECIFIED);
		}
		cli_credentials_set_password(credentials, pass, CRED_SPECIFIED);
	} else if (machine_account) {
		DEBUG(5, ("CIFS backend: Using machine account\n"));
		credentials = cli_credentials_init(private);
		cli_credentials_set_conf(credentials, ntvfs->ctx->lp_ctx);
		if (domain) {
			cli_credentials_set_domain(credentials, domain, CRED_SPECIFIED);
		}
		status = cli_credentials_set_machine_account(credentials, ntvfs->ctx->lp_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else if (req->session_info->credentials) {
		DEBUG(5, ("CIFS backend: Using delegated credentials\n"));
		credentials = req->session_info->credentials;
	} else {
		DEBUG(1,("CIFS backend: NO delegated credentials found: You must supply server, user and password or the client must supply delegated credentials\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	creq = smb2_connect_send(private, host, remote_share, 
				 lp_resolve_context(ntvfs->ctx->lp_ctx),
				 credentials,
				 ntvfs->ctx->event_ctx);

	status = smb2_connect_recv(creq, private, &tree);
	NT_STATUS_NOT_OK_RETURN(status);

	status = smb2_get_roothandle(tree, &private->roothandle);
	NT_STATUS_NOT_OK_RETURN(status);

	private->tree = tree;
	private->transport = private->tree->session->transport;
	private->ntvfs = ntvfs;

	ntvfs->ctx->fs_type = talloc_strdup(ntvfs->ctx, "NTFS");
	NT_STATUS_HAVE_NO_MEMORY(ntvfs->ctx->fs_type);
	ntvfs->ctx->dev_type = talloc_strdup(ntvfs->ctx, "A:");
	NT_STATUS_HAVE_NO_MEMORY(ntvfs->ctx->dev_type);

	/* we need to receive oplock break requests from the server */
	/* TODO: enable oplocks 
	smbcli_oplock_handler(private->transport, oplock_handler, private);
	*/
	return NT_STATUS_OK;
}

/*
  disconnect from a share
*/
static NTSTATUS cvfs_disconnect(struct ntvfs_module_context *ntvfs)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct async_info *a, *an;

	/* first cleanup pending requests */
	for (a=private->pending; a; a = an) {
		an = a->next;
		smb2_request_destroy(a->c_req);
		talloc_free(a);
	}

	talloc_free(private);
	ntvfs->private_data = NULL;

	return NT_STATUS_OK;
}

/*
  destroy an async info structure
*/
static int async_info_destructor(struct async_info *async)
{
	DLIST_REMOVE(async->cvfs->pending, async);
	return 0;
}

/*
  a handler for simple async replies
  this handler can only be used for functions that don't return any
  parameters (those that just return a status code)
 */
static void async_simple(struct smb2_request *c_req)
{
	struct async_info *async = c_req->async.private;
	struct ntvfs_request *req = async->req;

	smb2_request_receive(c_req);
	req->async_states->status = smb2_request_destroy(c_req);
	talloc_free(async);
	req->async_states->send_fn(req);
}


/* save some typing for the simple functions */
#define ASYNC_RECV_TAIL_F(io, async_fn, file) do { \
	if (!c_req) return NT_STATUS_UNSUCCESSFUL; \
	{ \
		struct async_info *async; \
		async = talloc(req, struct async_info); \
		if (!async) return NT_STATUS_NO_MEMORY; \
		async->parms = io; \
		async->req = req; \
		async->f = file; \
		async->cvfs = private; \
		async->c_req = c_req; \
		DLIST_ADD(private->pending, async); \
		c_req->async.private = async; \
		talloc_set_destructor(async, async_info_destructor); \
	} \
	c_req->async.fn = async_fn; \
	req->async_states->state |= NTVFS_ASYNC_STATE_ASYNC; \
	return NT_STATUS_OK; \
} while (0)

#define ASYNC_RECV_TAIL(io, async_fn) ASYNC_RECV_TAIL_F(io, async_fn, NULL)

#define SIMPLE_ASYNC_TAIL ASYNC_RECV_TAIL(NULL, async_simple)

/*
  delete a file - the dirtype specifies the file types to include in the search. 
  The name can contain CIFS wildcards, but rarely does (except with OS/2 clients)
*/
static NTSTATUS cvfs_unlink(struct ntvfs_module_context *ntvfs, 
			    struct ntvfs_request *req, union smb_unlink *unl)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	return NT_STATUS_NOT_IMPLEMENTED;
	/* see if the front end will allow us to perform this
	   function asynchronously.  */
	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_unlink(private->tree, unl);
	}

	c_req = smb_raw_unlink_send(private->tree, unl);

	SIMPLE_ASYNC_TAIL;
}

/*
  a handler for async ioctl replies
 */
static void async_ioctl(struct smbcli_request *c_req)
{
	struct async_info *async = c_req->async.private;
	struct ntvfs_request *req = async->req;
	req->async_states->status = smb_raw_ioctl_recv(c_req, req, async->parms);
	talloc_free(async);
	req->async_states->send_fn(req);
}

/*
  ioctl interface
*/
static NTSTATUS cvfs_ioctl(struct ntvfs_module_context *ntvfs, 
			   struct ntvfs_request *req, union smb_ioctl *io)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	SETUP_FILE;

	/* see if the front end will allow us to perform this
	   function asynchronously.  */
	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_ioctl(private->tree, req, io);
	}

	c_req = smb_raw_ioctl_send(private->tree, io);

	ASYNC_RECV_TAIL(io, async_ioctl);
}

/*
  check if a directory exists
*/
static NTSTATUS cvfs_chkpath(struct ntvfs_module_context *ntvfs, 
			     struct ntvfs_request *req, union smb_chkpath *cp)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smb2_request *c_req;
	struct smb2_find f;
	
	/* SMB2 doesn't have a chkpath operation, and also doesn't
	 have a query path info call, so the best seems to be to do a
	 find call, using the roothandle we established at connect
	 time */
	ZERO_STRUCT(f);
	f.in.file.handle	= private->roothandle;
	f.in.level              = SMB2_FIND_DIRECTORY_INFO;
	f.in.pattern		= cp->chkpath.in.path;
	/* SMB2 find doesn't accept \ or the empty string - this is the best
	   approximation */
	if (strcmp(f.in.pattern, "\\") == 0 || 
	    strcmp(f.in.pattern, "") == 0) {
		f.in.pattern		= "?";
	}
	f.in.continue_flags	= SMB2_CONTINUE_FLAG_SINGLE | SMB2_CONTINUE_FLAG_RESTART;
	f.in.max_response_size	= 0x1000;
	
	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb2_find(private->tree, req, &f);
	}

	c_req = smb2_find_send(private->tree, &f);

	SIMPLE_ASYNC_TAIL;
}

/*
  a handler for async qpathinfo replies
 */
static void async_qpathinfo(struct smbcli_request *c_req)
{
	struct async_info *async = c_req->async.private;
	struct ntvfs_request *req = async->req;
	return NT_STATUS_NOT_IMPLEMENTED;
	req->async_states->status = smb_raw_pathinfo_recv(c_req, req, async->parms);
	talloc_free(async);
	req->async_states->send_fn(req);
}

/*
  return info on a pathname
*/
static NTSTATUS cvfs_qpathinfo(struct ntvfs_module_context *ntvfs, 
			       struct ntvfs_request *req, union smb_fileinfo *info)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_pathinfo(private->tree, req, info);
	}

	c_req = smb_raw_pathinfo_send(private->tree, info);

	ASYNC_RECV_TAIL(info, async_qpathinfo);
}

/*
  a handler for async qfileinfo replies
 */
static void async_qfileinfo(struct smbcli_request *c_req)
{
	struct async_info *async = c_req->async.private;
	struct ntvfs_request *req = async->req;
	return NT_STATUS_NOT_IMPLEMENTED;
	req->async_states->status = smb_raw_fileinfo_recv(c_req, req, async->parms);
	talloc_free(async);
	req->async_states->send_fn(req);
}

/*
  query info on a open file
*/
static NTSTATUS cvfs_qfileinfo(struct ntvfs_module_context *ntvfs, 
			       struct ntvfs_request *req, union smb_fileinfo *io)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	return NT_STATUS_NOT_IMPLEMENTED;
	SETUP_FILE;

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_fileinfo(private->tree, req, io);
	}

	c_req = smb_raw_fileinfo_send(private->tree, io);

	ASYNC_RECV_TAIL(io, async_qfileinfo);
}


/*
  set info on a pathname
*/
static NTSTATUS cvfs_setpathinfo(struct ntvfs_module_context *ntvfs, 
				 struct ntvfs_request *req, union smb_setfileinfo *st)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	return NT_STATUS_NOT_IMPLEMENTED;
	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_setpathinfo(private->tree, st);
	}

	c_req = smb_raw_setpathinfo_send(private->tree, st);

	SIMPLE_ASYNC_TAIL;
}


/*
  a handler for async open replies
 */
static void async_open(struct smbcli_request *c_req)
{
	struct async_info *async = c_req->async.private;
	struct cvfs_private *cvfs = async->cvfs;
	struct ntvfs_request *req = async->req;
	struct cvfs_file *f = async->f;
	union smb_open *io = async->parms;
	union smb_handle *file;
	talloc_free(async);
	req->async_states->status = smb_raw_open_recv(c_req, req, io);
	SMB_OPEN_OUT_FILE(io, file);
	f->fnum = file->fnum;
	file->ntvfs = NULL;
	if (!NT_STATUS_IS_OK(req->async_states->status)) goto failed;
	req->async_states->status = ntvfs_handle_set_backend_data(f->h, cvfs->ntvfs, f);
	if (!NT_STATUS_IS_OK(req->async_states->status)) goto failed;
	file->ntvfs = f->h;
	DLIST_ADD(cvfs->files, f);
failed:
	req->async_states->send_fn(req);
}

/*
  open a file
*/
static NTSTATUS cvfs_open(struct ntvfs_module_context *ntvfs, 
			  struct ntvfs_request *req, union smb_open *io)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;
	struct ntvfs_handle *h;
	struct cvfs_file *f;
	NTSTATUS status;

	return NT_STATUS_NOT_IMPLEMENTED;
	if (io->generic.level != RAW_OPEN_GENERIC) {
		return ntvfs_map_open(ntvfs, req, io);
	}

	status = ntvfs_handle_new(ntvfs, req, &h);
	NT_STATUS_NOT_OK_RETURN(status);

	f = talloc_zero(h, struct cvfs_file);
	NT_STATUS_HAVE_NO_MEMORY(f);
	f->h = h;

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		union smb_handle *file;

		status = smb_raw_open(private->tree, req, io);
		NT_STATUS_NOT_OK_RETURN(status);

		SMB_OPEN_OUT_FILE(io, file);
		f->fnum = file->fnum;
		file->ntvfs = NULL;
		status = ntvfs_handle_set_backend_data(f->h, private->ntvfs, f);
		NT_STATUS_NOT_OK_RETURN(status);
		file->ntvfs = f->h;
		DLIST_ADD(private->files, f);

		return NT_STATUS_OK;
	}

	c_req = smb_raw_open_send(private->tree, io);

	ASYNC_RECV_TAIL_F(io, async_open, f);
}

/*
  create a directory
*/
static NTSTATUS cvfs_mkdir(struct ntvfs_module_context *ntvfs, 
			   struct ntvfs_request *req, union smb_mkdir *md)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	return NT_STATUS_NOT_IMPLEMENTED;
	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_mkdir(private->tree, md);
	}

	c_req = smb_raw_mkdir_send(private->tree, md);

	SIMPLE_ASYNC_TAIL;
}

/*
  remove a directory
*/
static NTSTATUS cvfs_rmdir(struct ntvfs_module_context *ntvfs, 
			   struct ntvfs_request *req, struct smb_rmdir *rd)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	return NT_STATUS_NOT_IMPLEMENTED;
	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_rmdir(private->tree, rd);
	}
	c_req = smb_raw_rmdir_send(private->tree, rd);

	SIMPLE_ASYNC_TAIL;
}

/*
  rename a set of files
*/
static NTSTATUS cvfs_rename(struct ntvfs_module_context *ntvfs, 
			    struct ntvfs_request *req, union smb_rename *ren)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	return NT_STATUS_NOT_IMPLEMENTED;

	if (ren->nttrans.level == RAW_RENAME_NTTRANS) {
		struct cvfs_file *f;
		f = ntvfs_handle_get_backend_data(ren->nttrans.in.file.ntvfs, ntvfs);
		if (!f) return NT_STATUS_INVALID_HANDLE;
		ren->nttrans.in.file.fnum = f->fnum;
	}

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_rename(private->tree, ren);
	}

	c_req = smb_raw_rename_send(private->tree, ren);

	SIMPLE_ASYNC_TAIL;
}

/*
  copy a set of files
*/
static NTSTATUS cvfs_copy(struct ntvfs_module_context *ntvfs, 
			  struct ntvfs_request *req, struct smb_copy *cp)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/*
  a handler for async read replies
 */
static void async_read(struct smbcli_request *c_req)
{
	struct async_info *async = c_req->async.private;
	struct ntvfs_request *req = async->req;
	req->async_states->status = smb_raw_read_recv(c_req, async->parms);
	talloc_free(async);
	req->async_states->send_fn(req);
}

/*
  read from a file
*/
static NTSTATUS cvfs_read(struct ntvfs_module_context *ntvfs, 
			  struct ntvfs_request *req, union smb_read *io)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	return NT_STATUS_NOT_IMPLEMENTED;
	if (io->generic.level != RAW_READ_GENERIC) {
		return ntvfs_map_read(ntvfs, req, io);
	}

	SETUP_FILE;

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_read(private->tree, io);
	}

	c_req = smb_raw_read_send(private->tree, io);

	ASYNC_RECV_TAIL(io, async_read);
}

/*
  a handler for async write replies
 */
static void async_write(struct smbcli_request *c_req)
{
	struct async_info *async = c_req->async.private;
	struct ntvfs_request *req = async->req;
	req->async_states->status = smb_raw_write_recv(c_req, async->parms);
	talloc_free(async);
	req->async_states->send_fn(req);
}

/*
  write to a file
*/
static NTSTATUS cvfs_write(struct ntvfs_module_context *ntvfs, 
			   struct ntvfs_request *req, union smb_write *io)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	return NT_STATUS_NOT_IMPLEMENTED;
	if (io->generic.level != RAW_WRITE_GENERIC) {
		return ntvfs_map_write(ntvfs, req, io);
	}
	SETUP_FILE;

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_write(private->tree, io);
	}

	c_req = smb_raw_write_send(private->tree, io);

	ASYNC_RECV_TAIL(io, async_write);
}

/*
  a handler for async seek replies
 */
static void async_seek(struct smbcli_request *c_req)
{
	struct async_info *async = c_req->async.private;
	struct ntvfs_request *req = async->req;
	req->async_states->status = smb_raw_seek_recv(c_req, async->parms);
	talloc_free(async);
	req->async_states->send_fn(req);
}

/*
  seek in a file
*/
static NTSTATUS cvfs_seek(struct ntvfs_module_context *ntvfs, 
			  struct ntvfs_request *req,
			  union smb_seek *io)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	return NT_STATUS_NOT_IMPLEMENTED;
	SETUP_FILE;

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_seek(private->tree, io);
	}

	c_req = smb_raw_seek_send(private->tree, io);

	ASYNC_RECV_TAIL(io, async_seek);
}

/*
  flush a file
*/
static NTSTATUS cvfs_flush(struct ntvfs_module_context *ntvfs, 
			   struct ntvfs_request *req,
			   union smb_flush *io)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	return NT_STATUS_NOT_IMPLEMENTED;
	switch (io->generic.level) {
	case RAW_FLUSH_FLUSH:
		SETUP_FILE;
		break;
	case RAW_FLUSH_ALL:
		io->generic.in.file.fnum = 0xFFFF;
		break;
	case RAW_FLUSH_SMB2:
		return NT_STATUS_INVALID_LEVEL;
	}

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_flush(private->tree, io);
	}

	c_req = smb_raw_flush_send(private->tree, io);

	SIMPLE_ASYNC_TAIL;
}

/*
  close a file
*/
static NTSTATUS cvfs_close(struct ntvfs_module_context *ntvfs, 
			   struct ntvfs_request *req, union smb_close *io)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;
	struct cvfs_file *f;

	return NT_STATUS_NOT_IMPLEMENTED;
	if (io->generic.level != RAW_CLOSE_GENERIC) {
		return ntvfs_map_close(ntvfs, req, io);
	}
	SETUP_FILE_HERE(f);
	/* Note, we aren't free-ing f, or it's h here. Should we?
	   even if file-close fails, we'll remove it from the list,
	   what else would we do? Maybe we should not remove until
	   after the proxied call completes? */
	DLIST_REMOVE(private->files, f);

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_close(private->tree, io);
	}

	c_req = smb_raw_close_send(private->tree, io);

	SIMPLE_ASYNC_TAIL;
}

/*
  exit - closing files open by the pid
*/
static NTSTATUS cvfs_exit(struct ntvfs_module_context *ntvfs, 
			  struct ntvfs_request *req)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	return NT_STATUS_NOT_IMPLEMENTED;
	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_exit(private->tree->session);
	}

	c_req = smb_raw_exit_send(private->tree->session);

	SIMPLE_ASYNC_TAIL;
}

/*
  logoff - closing files open by the user
*/
static NTSTATUS cvfs_logoff(struct ntvfs_module_context *ntvfs, 
			    struct ntvfs_request *req)
{
	/* we can't do this right in the cifs backend .... */
	return NT_STATUS_OK;
}

/*
  setup for an async call - nothing to do yet
*/
static NTSTATUS cvfs_async_setup(struct ntvfs_module_context *ntvfs, 
				 struct ntvfs_request *req, 
				 void *private)
{
	return NT_STATUS_OK;
}

/*
  cancel an async call
*/
static NTSTATUS cvfs_cancel(struct ntvfs_module_context *ntvfs, 
			    struct ntvfs_request *req)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct async_info *a;

	return NT_STATUS_NOT_IMPLEMENTED;
	/* find the matching request */
	for (a=private->pending;a;a=a->next) {
		if (a->req == req) {
			break;
		}
	}

	if (a == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	return smb_raw_ntcancel(a->c_req);
}

/*
  lock a byte range
*/
static NTSTATUS cvfs_lock(struct ntvfs_module_context *ntvfs, 
			  struct ntvfs_request *req, union smb_lock *io)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	return NT_STATUS_NOT_IMPLEMENTED;
	if (io->generic.level != RAW_LOCK_GENERIC) {
		return ntvfs_map_lock(ntvfs, req, io);
	}
	SETUP_FILE;

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_lock(private->tree, io);
	}

	c_req = smb_raw_lock_send(private->tree, io);
	SIMPLE_ASYNC_TAIL;
}

/*
  set info on a open file
*/
static NTSTATUS cvfs_setfileinfo(struct ntvfs_module_context *ntvfs, 
				 struct ntvfs_request *req, 
				 union smb_setfileinfo *io)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	return NT_STATUS_NOT_IMPLEMENTED;
	SETUP_FILE;

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_setfileinfo(private->tree, io);
	}
	c_req = smb_raw_setfileinfo_send(private->tree, io);

	SIMPLE_ASYNC_TAIL;
}


/*
  a handler for async fsinfo replies
 */
static void async_fsinfo(struct smb2_request *c_req)
{
	struct async_info *async = c_req->async.private;
	struct ntvfs_request *req = async->req;
	req->async_states->status = smb2_getinfo_fs_recv(c_req, req, async->parms);
	talloc_free(async);
	req->async_states->send_fn(req);
}

/*
  return filesystem space info
*/
static NTSTATUS cvfs_fsinfo(struct ntvfs_module_context *ntvfs, 
			    struct ntvfs_request *req, union smb_fsinfo *fs)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smb2_request *c_req;
	enum smb_fsinfo_level level = fs->generic.level;

	switch (level) {
		/* some levels go straight through */
	case RAW_QFS_VOLUME_INFORMATION:
	case RAW_QFS_SIZE_INFORMATION:
	case RAW_QFS_DEVICE_INFORMATION:
	case RAW_QFS_ATTRIBUTE_INFORMATION:
	case RAW_QFS_QUOTA_INFORMATION:
	case RAW_QFS_FULL_SIZE_INFORMATION:
	case RAW_QFS_OBJECTID_INFORMATION:
		break;

		/* some get mapped */
	case RAW_QFS_VOLUME_INFO:
		level = RAW_QFS_VOLUME_INFORMATION;
		break;
	case RAW_QFS_SIZE_INFO:
		level = RAW_QFS_SIZE_INFORMATION;
		break;
	case RAW_QFS_DEVICE_INFO:
		level = RAW_QFS_DEVICE_INFORMATION;
		break;
	case RAW_QFS_ATTRIBUTE_INFO:
		level = RAW_QFS_ATTRIBUTE_INFO;
		break;

	default:
		/* the rest get refused for now */
		DEBUG(0,("fsinfo level %u not possible on SMB2\n",
			 (unsigned)fs->generic.level));
		break;
	}

	fs->generic.level = level;
	fs->generic.handle = private->roothandle;

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb2_getinfo_fs(private->tree, req, fs);
	}

	c_req = smb2_getinfo_fs_send(private->tree, fs);

	ASYNC_RECV_TAIL(fs, async_fsinfo);
}

/*
  return print queue info
*/
static NTSTATUS cvfs_lpq(struct ntvfs_module_context *ntvfs, 
			 struct ntvfs_request *req, union smb_lpq *lpq)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/* 
   list files in a directory matching a wildcard pattern
*/
static NTSTATUS cvfs_search_first(struct ntvfs_module_context *ntvfs, 
				  struct ntvfs_request *req, union smb_search_first *io, 
				  void *search_private, 
				  bool (*callback)(void *, const union smb_search_data *))
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smb2_find f;
	enum smb_search_data_level smb2_level;
	uint32_t continue_flags = 0;
	uint_t count, i;
	union smb_search_data *data;
	NTSTATUS status;

	if (io->generic.level != RAW_SEARCH_TRANS2) {
		DEBUG(0,("We only support trans2 search in smb2 backend\n"));
		return NT_STATUS_NOT_SUPPORTED;
	}

	switch (io->generic.data_level) {
	case RAW_SEARCH_DATA_DIRECTORY_INFO:
		smb2_level = SMB2_FIND_DIRECTORY_INFO;
		break;
	case RAW_SEARCH_DATA_FULL_DIRECTORY_INFO:
		smb2_level = SMB2_FIND_FULL_DIRECTORY_INFO;
		break;
	case RAW_SEARCH_DATA_BOTH_DIRECTORY_INFO:
		smb2_level = SMB2_FIND_BOTH_DIRECTORY_INFO;
		break;
	case RAW_SEARCH_DATA_NAME_INFO:
		smb2_level = SMB2_FIND_NAME_INFO;
		break;
	case RAW_SEARCH_DATA_ID_FULL_DIRECTORY_INFO:
		smb2_level = SMB2_FIND_ID_FULL_DIRECTORY_INFO;
		break;
	case RAW_SEARCH_DATA_ID_BOTH_DIRECTORY_INFO:
		smb2_level = SMB2_FIND_ID_BOTH_DIRECTORY_INFO;
		break;
	default:
		DEBUG(0,("Unsupported search level %u for smb2 backend\n",
			 (unsigned)io->generic.data_level));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* we do the search on the roothandle. This only works because
	   search is synchronous, otherwise we'd have no way to
	   distinguish multiple searches happening at once
	*/
	ZERO_STRUCT(f);
	f.in.file.handle	= private->roothandle;
	f.in.level              = smb2_level;
	f.in.pattern		= io->t2ffirst.in.pattern;
	while (f.in.pattern[0] == '\\') {
		f.in.pattern++;
	}
	f.in.continue_flags	= 0;
	f.in.max_response_size	= 0x10000;

	status = smb2_find_level(private->tree, req, &f, &count, &data);
	NT_STATUS_NOT_OK_RETURN(status);	

	for (i=0;i<count;i++) {
		if (!callback(search_private, &data[i])) break;
	}

	io->t2ffirst.out.handle = 0;
	io->t2ffirst.out.count = i;
	/* TODO: fix end_of_file */
	io->t2ffirst.out.end_of_search = 1;

	talloc_free(data);
	
	return NT_STATUS_OK;
}

/* continue a search */
static NTSTATUS cvfs_search_next(struct ntvfs_module_context *ntvfs, 
				 struct ntvfs_request *req, union smb_search_next *io, 
				 void *search_private, 
				 bool (*callback)(void *, const union smb_search_data *))
{
	struct cvfs_private *private = ntvfs->private_data;

	return NT_STATUS_NOT_IMPLEMENTED;

	return smb_raw_search_next(private->tree, req, io, search_private, callback);
}

/* close a search */
static NTSTATUS cvfs_search_close(struct ntvfs_module_context *ntvfs, 
				  struct ntvfs_request *req, union smb_search_close *io)
{
	struct cvfs_private *private = ntvfs->private_data;

	return NT_STATUS_NOT_IMPLEMENTED;

	return smb_raw_search_close(private->tree, io);
}

/* SMBtrans - not used on file shares */
static NTSTATUS cvfs_trans(struct ntvfs_module_context *ntvfs, 
			   struct ntvfs_request *req,
			   struct smb_trans2 *trans2)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  a handler for async change notify replies
 */
static void async_changenotify(struct smbcli_request *c_req)
{
	struct async_info *async = c_req->async.private;
	struct ntvfs_request *req = async->req;
	req->async_states->status = smb_raw_changenotify_recv(c_req, req, async->parms);
	talloc_free(async);
	req->async_states->send_fn(req);
}

/* change notify request - always async */
static NTSTATUS cvfs_notify(struct ntvfs_module_context *ntvfs, 
			    struct ntvfs_request *req,
			    union smb_notify *io)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;
	int saved_timeout = private->transport->options.request_timeout;
	struct cvfs_file *f;

	return NT_STATUS_NOT_IMPLEMENTED;
	if (io->nttrans.level != RAW_NOTIFY_NTTRANS) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	f = ntvfs_handle_get_backend_data(io->nttrans.in.file.ntvfs, ntvfs);
	if (!f) return NT_STATUS_INVALID_HANDLE;
	io->nttrans.in.file.fnum = f->fnum;

	/* this request doesn't make sense unless its async */
	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* we must not timeout on notify requests - they wait
	   forever */
	private->transport->options.request_timeout = 0;

	c_req = smb_raw_changenotify_send(private->tree, io);

	private->transport->options.request_timeout = saved_timeout;

	ASYNC_RECV_TAIL(io, async_changenotify);
}

/*
  initialise the CIFS->CIFS backend, registering ourselves with the ntvfs subsystem
 */
NTSTATUS ntvfs_smb2_init(void)
{
	NTSTATUS ret;
	struct ntvfs_ops ops;
	NTVFS_CURRENT_CRITICAL_SIZES(vers);

	ZERO_STRUCT(ops);

	/* fill in the name and type */
	ops.name = "smb2";
	ops.type = NTVFS_DISK;
	
	/* fill in all the operations */
	ops.connect = cvfs_connect;
	ops.disconnect = cvfs_disconnect;
	ops.unlink = cvfs_unlink;
	ops.chkpath = cvfs_chkpath;
	ops.qpathinfo = cvfs_qpathinfo;
	ops.setpathinfo = cvfs_setpathinfo;
	ops.open = cvfs_open;
	ops.mkdir = cvfs_mkdir;
	ops.rmdir = cvfs_rmdir;
	ops.rename = cvfs_rename;
	ops.copy = cvfs_copy;
	ops.ioctl = cvfs_ioctl;
	ops.read = cvfs_read;
	ops.write = cvfs_write;
	ops.seek = cvfs_seek;
	ops.flush = cvfs_flush;	
	ops.close = cvfs_close;
	ops.exit = cvfs_exit;
	ops.lock = cvfs_lock;
	ops.setfileinfo = cvfs_setfileinfo;
	ops.qfileinfo = cvfs_qfileinfo;
	ops.fsinfo = cvfs_fsinfo;
	ops.lpq = cvfs_lpq;
	ops.search_first = cvfs_search_first;
	ops.search_next = cvfs_search_next;
	ops.search_close = cvfs_search_close;
	ops.trans = cvfs_trans;
	ops.logoff = cvfs_logoff;
	ops.async_setup = cvfs_async_setup;
	ops.cancel = cvfs_cancel;
	ops.notify = cvfs_notify;

	/* register ourselves with the NTVFS subsystem. We register
	   under the name 'smb2'. */
	ret = ntvfs_register(&ops, &vers);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register SMB2 backend\n"));
	}
	
	return ret;
}
