/* 
   Unix SMB/CIFS implementation.

   CIFS-on-CIFS NTVFS filesystem backend

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) James J Myers 2003 <myersjj@samba.org>

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
  this implements a CIFS->CIFS NTVFS filesystem backend. 
  
*/

#include "includes.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/smb_composite/smb_composite.h"
#include "auth/auth.h"
#include "auth/credentials/credentials.h"
#include "ntvfs/ntvfs.h"
#include "lib/util/dlinklist.h"

struct cvfs_file {
	struct cvfs_file *prev, *next;
	uint16_t fnum;
	struct ntvfs_handle *h;
};

/* this is stored in ntvfs_private */
struct cvfs_private {
	struct smbcli_tree *tree;
	struct smbcli_transport *transport;
	struct ntvfs_module_context *ntvfs;
	struct async_info *pending;
	struct cvfs_file *files;
	BOOL map_generic;
	BOOL map_trans2;
};


/* a structure used to pass information to an async handler */
struct async_info {
	struct async_info *next, *prev;
	struct cvfs_private *cvfs;
	struct ntvfs_request *req;
	struct smbcli_request *c_req;
	struct cvfs_file *f;
	void *parms;
};

#define SETUP_PID private->tree->session->pid = req->smbpid

#define SETUP_FILE do { \
	struct cvfs_file *f; \
	f = ntvfs_handle_get_backend_data(io->generic.in.file.ntvfs, ntvfs); \
	if (!f) return NT_STATUS_INVALID_HANDLE; \
	io->generic.in.file.fnum = f->fnum; \
} while (0) 

#define SETUP_PID_AND_FILE do { \
	SETUP_PID; \
	SETUP_FILE; \
} while (0)

#define CIFS_SERVER		"cifs:server"
#define CIFS_USER		"cifs:user"
#define CIFS_PASSWORD		"cifs:password"
#define CIFS_DOMAIN		"cifs:domain"
#define CIFS_SHARE		"cifs:share"
#define CIFS_USE_MACHINE_ACCT	"cifs:use-machine-account"
#define CIFS_MAP_GENERIC	"cifs:map-generic"
#define CIFS_MAP_TRANS2		"cifs:map-trans2"

#define CIFS_USE_MACHINE_ACCT_DEFAULT	False
#define CIFS_MAP_GENERIC_DEFAULT	False
#define CIFS_MAP_TRANS2_DEFAULT		True

/*
  a handler for oplock break events from the server - these need to be passed
  along to the client
 */
static BOOL oplock_handler(struct smbcli_transport *transport, uint16_t tid, uint16_t fnum, uint8_t level, void *p_private)
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
		DEBUG(5,("vfs_cifs: ignoring oplock break level %d for fnum %d\n", level, fnum));
		return True;
	}

	DEBUG(5,("vfs_cifs: sending oplock break level %d for fnum %d\n", level, fnum));
	status = ntvfs_send_oplock_break(private->ntvfs, h, level);
	if (!NT_STATUS_IS_OK(status)) return False;
	return True;
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
	struct smb_composite_connect io;
	struct composite_context *creq;
	struct share_config *scfg = ntvfs->ctx->config;

	struct cli_credentials *credentials;
	BOOL machine_account;

	/* Here we need to determine which server to connect to.
	 * For now we use parametric options, type cifs.
	 * Later we will use security=server and auth_server.c.
	 */
	host = share_string_option(scfg, CIFS_SERVER, NULL);
	user = share_string_option(scfg, CIFS_USER, NULL);
	pass = share_string_option(scfg, CIFS_PASSWORD, NULL);
	domain = share_string_option(scfg, CIFS_DOMAIN, NULL);
	remote_share = share_string_option(scfg, CIFS_SHARE, NULL);
	if (!remote_share) {
		remote_share = sharename;
	}

	machine_account = share_bool_option(scfg, CIFS_USE_MACHINE_ACCT, CIFS_USE_MACHINE_ACCT_DEFAULT);

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
		cli_credentials_set_conf(credentials);
		cli_credentials_set_username(credentials, user, CRED_SPECIFIED);
		if (domain) {
			cli_credentials_set_domain(credentials, domain, CRED_SPECIFIED);
		}
		cli_credentials_set_password(credentials, pass, CRED_SPECIFIED);
	} else if (machine_account) {
		DEBUG(5, ("CIFS backend: Using machine account\n"));
		credentials = cli_credentials_init(private);
		cli_credentials_set_conf(credentials);
		if (domain) {
			cli_credentials_set_domain(credentials, domain, CRED_SPECIFIED);
		}
		status = cli_credentials_set_machine_account(credentials);
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

	/* connect to the server, using the smbd event context */
	io.in.dest_host = host;
	io.in.port = 0;
	io.in.called_name = host;
	io.in.credentials = credentials;
	io.in.fallback_to_anonymous = False;
	io.in.workgroup = lp_workgroup();
	io.in.service = remote_share;
	io.in.service_type = "?????";
	
	creq = smb_composite_connect_send(&io, private, ntvfs->ctx->event_ctx);
	status = smb_composite_connect_recv(creq, private);
	NT_STATUS_NOT_OK_RETURN(status);

	private->tree = io.out.tree;

	private->transport = private->tree->session->transport;
	SETUP_PID;
	private->ntvfs = ntvfs;

	ntvfs->ctx->fs_type = talloc_strdup(ntvfs->ctx, "NTFS");
	NT_STATUS_HAVE_NO_MEMORY(ntvfs->ctx->fs_type);
	ntvfs->ctx->dev_type = talloc_strdup(ntvfs->ctx, "A:");
	NT_STATUS_HAVE_NO_MEMORY(ntvfs->ctx->dev_type);

	/* we need to receive oplock break requests from the server */
	smbcli_oplock_handler(private->transport, oplock_handler, private);

	private->map_generic = share_bool_option(scfg, CIFS_MAP_GENERIC, CIFS_MAP_GENERIC_DEFAULT);

	private->map_trans2 = share_bool_option(scfg, CIFS_MAP_TRANS2, CIFS_MAP_TRANS2_DEFAULT);

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
		smbcli_request_destroy(a->c_req);
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
static void async_simple(struct smbcli_request *c_req)
{
	struct async_info *async = c_req->async.private;
	struct ntvfs_request *req = async->req;
	req->async_states->status = smbcli_request_simple_recv(c_req);
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

	SETUP_PID;

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

	SETUP_PID_AND_FILE;

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
	struct smbcli_request *c_req;

	SETUP_PID;

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_chkpath(private->tree, cp);
	}

	c_req = smb_raw_chkpath_send(private->tree, cp);

	SIMPLE_ASYNC_TAIL;
}

/*
  a handler for async qpathinfo replies
 */
static void async_qpathinfo(struct smbcli_request *c_req)
{
	struct async_info *async = c_req->async.private;
	struct ntvfs_request *req = async->req;
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

	SETUP_PID;

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

	SETUP_PID_AND_FILE;

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

	SETUP_PID;

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

	SETUP_PID;

	if (io->generic.level != RAW_OPEN_GENERIC &&
	    private->map_generic) {
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

	SETUP_PID;

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

	SETUP_PID;

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

	SETUP_PID;

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

	SETUP_PID;

	if (io->generic.level != RAW_READ_GENERIC &&
	    private->map_generic) {
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

	SETUP_PID;

	if (io->generic.level != RAW_WRITE_GENERIC &&
	    private->map_generic) {
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

	SETUP_PID_AND_FILE;

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

	SETUP_PID;
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

	SETUP_PID;

	if (io->generic.level != RAW_CLOSE_GENERIC &&
	    private->map_generic) {
		return ntvfs_map_close(ntvfs, req, io);
	}
	SETUP_FILE;

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

	SETUP_PID;

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

	SETUP_PID;

	if (io->generic.level != RAW_LOCK_GENERIC &&
	    private->map_generic) {
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

	SETUP_PID_AND_FILE;

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_setfileinfo(private->tree, io);
	}
	c_req = smb_raw_setfileinfo_send(private->tree, io);

	SIMPLE_ASYNC_TAIL;
}


/*
  a handler for async fsinfo replies
 */
static void async_fsinfo(struct smbcli_request *c_req)
{
	struct async_info *async = c_req->async.private;
	struct ntvfs_request *req = async->req;
	req->async_states->status = smb_raw_fsinfo_recv(c_req, req, async->parms);
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
	struct smbcli_request *c_req;

	SETUP_PID;

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_fsinfo(private->tree, req, fs);
	}

	c_req = smb_raw_fsinfo_send(private->tree, req, fs);

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
				  BOOL (*callback)(void *, const union smb_search_data *))
{
	struct cvfs_private *private = ntvfs->private_data;

	SETUP_PID;

	return smb_raw_search_first(private->tree, req, io, search_private, callback);
}

/* continue a search */
static NTSTATUS cvfs_search_next(struct ntvfs_module_context *ntvfs, 
				 struct ntvfs_request *req, union smb_search_next *io, 
				 void *search_private, 
				 BOOL (*callback)(void *, const union smb_search_data *))
{
	struct cvfs_private *private = ntvfs->private_data;

	SETUP_PID;

	return smb_raw_search_next(private->tree, req, io, search_private, callback);
}

/* close a search */
static NTSTATUS cvfs_search_close(struct ntvfs_module_context *ntvfs, 
				  struct ntvfs_request *req, union smb_search_close *io)
{
	struct cvfs_private *private = ntvfs->private_data;

	SETUP_PID;

	return smb_raw_search_close(private->tree, io);
}

/*
  a handler for async trans2 replies
 */
static void async_trans2(struct smbcli_request *c_req)
{
	struct async_info *async = c_req->async.private;
	struct ntvfs_request *req = async->req;
	req->async_states->status = smb_raw_trans2_recv(c_req, req, async->parms);
	talloc_free(async);
	req->async_states->send_fn(req);
}

/* raw trans2 */
static NTSTATUS cvfs_trans2(struct ntvfs_module_context *ntvfs, 
			    struct ntvfs_request *req,
			    struct smb_trans2 *trans2)
{
	struct cvfs_private *private = ntvfs->private_data;
	struct smbcli_request *c_req;

	if (private->map_trans2) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	SETUP_PID;

	if (!(req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return smb_raw_trans2(private->tree, req, trans2);
	}

	c_req = smb_raw_trans2_send(private->tree, trans2);

	ASYNC_RECV_TAIL(trans2, async_trans2);
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

	if (io->nttrans.level != RAW_NOTIFY_NTTRANS) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	SETUP_PID;

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
NTSTATUS ntvfs_cifs_init(void)
{
	NTSTATUS ret;
	struct ntvfs_ops ops;
	NTVFS_CURRENT_CRITICAL_SIZES(vers);

	ZERO_STRUCT(ops);

	/* fill in the name and type */
	ops.name = "cifs";
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
	ops.trans2 = cvfs_trans2;

	/* register ourselves with the NTVFS subsystem. We register
	   under the name 'cifs'. */
	ret = ntvfs_register(&ops, &vers);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register CIFS backend!\n"));
	}
	
	return ret;
}
