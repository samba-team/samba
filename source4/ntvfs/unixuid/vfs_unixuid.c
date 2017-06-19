/* 
   Unix SMB/CIFS implementation.

   a pass-thru NTVFS module to setup a security context using unix
   uid/gid

   Copyright (C) Andrew Tridgell 2004

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
#include "system/filesys.h"
#include "system/passwd.h"
#include "auth/auth.h"
#include "ntvfs/ntvfs.h"
#include "libcli/wbclient/wbclient.h"
#define TEVENT_DEPRECATED
#include <tevent.h>
#include "../lib/util/setid.h"

NTSTATUS ntvfs_unixuid_init(TALLOC_CTX *);

struct unixuid_private {
	struct security_unix_token *last_sec_ctx;
	struct security_token *last_token;
};


/*
  pull the current security context into a security_unix_token
*/
static struct security_unix_token *save_unix_security(TALLOC_CTX *mem_ctx)
{
	struct security_unix_token *sec = talloc(mem_ctx, struct security_unix_token);
	if (sec == NULL) {
		return NULL;
	}
	sec->uid = geteuid();
	sec->gid = getegid();
	sec->ngroups = getgroups(0, NULL);
	if (sec->ngroups == -1) {
		talloc_free(sec);
		return NULL;
	}
	sec->groups = talloc_array(sec, gid_t, sec->ngroups);
	if (sec->groups == NULL) {
		talloc_free(sec);
		return NULL;
	}

	if (getgroups(sec->ngroups, sec->groups) != sec->ngroups) {
		talloc_free(sec);
		return NULL;
	}

	return sec;
}

/*
  set the current security context from a security_unix_token
*/
static NTSTATUS set_unix_security(struct security_unix_token *sec)
{
	samba_seteuid(0);

	if (samba_setgroups(sec->ngroups, sec->groups) != 0) {
		DBG_ERR("*** samba_setgroups failed\n");
		return NT_STATUS_ACCESS_DENIED;
	}
	if (samba_setegid(sec->gid) != 0) {
		DBG_ERR("*** samba_setegid(%u) failed\n", sec->gid);
		return NT_STATUS_ACCESS_DENIED;
	}
	if (samba_seteuid(sec->uid) != 0) {
		DBG_ERR("*** samba_seteuid(%u) failed\n", sec->uid);
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_OK;
}

static int unixuid_nesting_level;

/*
  called at the start and end of a tevent nesting loop. Needs to save/restore
  unix security context
 */
static int unixuid_event_nesting_hook(struct tevent_context *ev,
				      void *private_data,
				      uint32_t level,
				      bool begin,
				      void *stack_ptr,
				      const char *location)
{
	struct security_unix_token *sec_ctx;

	if (unixuid_nesting_level == 0) {
		/* we don't need to do anything unless we are nested
		   inside of a call in this module */
		return 0;
	}

	if (begin) {
		sec_ctx = save_unix_security(ev);
		if (sec_ctx == NULL) {
			DEBUG(0,("%s: Failed to save security context\n", location));
			return -1;
		}
		*(struct security_unix_token **)stack_ptr = sec_ctx;
		if (samba_seteuid(0) != 0 || samba_setegid(0) != 0) {
			DEBUG(0,("%s: Failed to change to root\n", location));
			return -1;			
		}
	} else {
		/* called when we come out of a nesting level */
		NTSTATUS status;

		sec_ctx = *(struct security_unix_token **)stack_ptr;
		if (sec_ctx == NULL) {
			/* this happens the first time this function
			   is called, as we install the hook while
			   inside an event in unixuid_connect() */
			return 0;
		}

		sec_ctx = talloc_get_type_abort(sec_ctx, struct security_unix_token);
		status = set_unix_security(sec_ctx);
		talloc_free(sec_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("%s: Failed to revert security context (%s)\n", 
				 location, nt_errstr(status)));
			return -1;
		}
	}

	return 0;
}


/*
  form a security_unix_token from the current security_token
*/
static NTSTATUS nt_token_to_unix_security(struct ntvfs_module_context *ntvfs,
					  struct ntvfs_request *req,
					  struct security_token *token,
					  struct security_unix_token **sec)
{
	return security_token_to_unix_token(req, token, sec);
}

/*
  setup our unix security context according to the session authentication info
*/
static NTSTATUS unixuid_setup_security(struct ntvfs_module_context *ntvfs,
				       struct ntvfs_request *req, struct security_unix_token **sec)
{
	struct unixuid_private *priv = ntvfs->private_data;
	struct security_token *token;
	struct security_unix_token *newsec;
	NTSTATUS status;

	/* If we are asked to set up, but have not had a successful
	 * session setup or tree connect, then these may not be filled
	 * in.  ACCESS_DENIED is the right error code here */
	if (req->session_info == NULL || priv == NULL) {
		return NT_STATUS_ACCESS_DENIED;
	}

	token = req->session_info->security_token;

	*sec = save_unix_security(ntvfs);
	if (*sec == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (token == priv->last_token) {
		newsec = priv->last_sec_ctx;
	} else {
		status = nt_token_to_unix_security(ntvfs, req, token, &newsec);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(*sec);
			return status;
		}
		if (priv->last_sec_ctx) {
			talloc_free(priv->last_sec_ctx);
		}
		priv->last_sec_ctx = newsec;
		priv->last_token = token;
		talloc_steal(priv, newsec);
	}

	status = set_unix_security(newsec);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(*sec);
		return status;
	}

	return NT_STATUS_OK;
}

/*
  this pass through macro operates on request contexts
*/
#define PASS_THRU_REQ(ntvfs, req, op, args) do { \
	NTSTATUS status2; \
	struct security_unix_token *sec; \
	status = unixuid_setup_security(ntvfs, req, &sec); \
	NT_STATUS_NOT_OK_RETURN(status); \
	unixuid_nesting_level++; \
	status = ntvfs_next_##op args; \
	unixuid_nesting_level--; \
	status2 = set_unix_security(sec); \
	talloc_free(sec); \
	if (!NT_STATUS_IS_OK(status2)) smb_panic("Unable to reset security context"); \
} while (0)



/*
  connect to a share - used when a tree_connect operation comes in.
*/
static NTSTATUS unixuid_connect(struct ntvfs_module_context *ntvfs,
				struct ntvfs_request *req, union smb_tcon *tcon)
{
	struct unixuid_private *priv;
	NTSTATUS status;

	priv = talloc(ntvfs, struct unixuid_private);
	if (!priv) {
		return NT_STATUS_NO_MEMORY;
	}

	priv->last_sec_ctx = NULL;
	priv->last_token = NULL;
	ntvfs->private_data = priv;

	tevent_loop_set_nesting_hook(ntvfs->ctx->event_ctx, 
				     unixuid_event_nesting_hook,
				     &unixuid_nesting_level);

	/* we don't use PASS_THRU_REQ here, as the connect operation runs with 
	   root privileges. This allows the backends to setup any database
	   links they might need during the connect. */
	status = ntvfs_next_connect(ntvfs, req, tcon);

	return status;
}

/*
  disconnect from a share
*/
static NTSTATUS unixuid_disconnect(struct ntvfs_module_context *ntvfs)
{
	struct unixuid_private *priv = ntvfs->private_data;
	NTSTATUS status;

	talloc_free(priv);
	ntvfs->private_data = NULL;

	status = ntvfs_next_disconnect(ntvfs);
 
	return status;
}


/*
  delete a file
*/
static NTSTATUS unixuid_unlink(struct ntvfs_module_context *ntvfs,
			      struct ntvfs_request *req,
			      union smb_unlink *unl)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, unlink, (ntvfs, req, unl));

	return status;
}

/*
  ioctl interface
*/
static NTSTATUS unixuid_ioctl(struct ntvfs_module_context *ntvfs,
			     struct ntvfs_request *req, union smb_ioctl *io)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, ioctl, (ntvfs, req, io));

	return status;
}

/*
  check if a directory exists
*/
static NTSTATUS unixuid_chkpath(struct ntvfs_module_context *ntvfs,
			        struct ntvfs_request *req,
				union smb_chkpath *cp)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, chkpath, (ntvfs, req, cp));

	return status;
}

/*
  return info on a pathname
*/
static NTSTATUS unixuid_qpathinfo(struct ntvfs_module_context *ntvfs,
				 struct ntvfs_request *req, union smb_fileinfo *info)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, qpathinfo, (ntvfs, req, info));

	return status;
}

/*
  query info on a open file
*/
static NTSTATUS unixuid_qfileinfo(struct ntvfs_module_context *ntvfs,
				 struct ntvfs_request *req, union smb_fileinfo *info)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, qfileinfo, (ntvfs, req, info));

	return status;
}


/*
  set info on a pathname
*/
static NTSTATUS unixuid_setpathinfo(struct ntvfs_module_context *ntvfs,
				   struct ntvfs_request *req, union smb_setfileinfo *st)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, setpathinfo, (ntvfs, req, st));

	return status;
}

/*
  open a file
*/
static NTSTATUS unixuid_open(struct ntvfs_module_context *ntvfs,
			     struct ntvfs_request *req, union smb_open *io)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, open, (ntvfs, req, io));

	return status;
}

/*
  create a directory
*/
static NTSTATUS unixuid_mkdir(struct ntvfs_module_context *ntvfs,
			     struct ntvfs_request *req, union smb_mkdir *md)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, mkdir, (ntvfs, req, md));

	return status;
}

/*
  remove a directory
*/
static NTSTATUS unixuid_rmdir(struct ntvfs_module_context *ntvfs,
			     struct ntvfs_request *req, struct smb_rmdir *rd)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, rmdir, (ntvfs, req, rd));

	return status;
}

/*
  rename a set of files
*/
static NTSTATUS unixuid_rename(struct ntvfs_module_context *ntvfs,
			      struct ntvfs_request *req, union smb_rename *ren)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, rename, (ntvfs, req, ren));

	return status;
}

/*
  copy a set of files
*/
static NTSTATUS unixuid_copy(struct ntvfs_module_context *ntvfs,
			    struct ntvfs_request *req, struct smb_copy *cp)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, copy, (ntvfs, req, cp));

	return status;
}

/*
  read from a file
*/
static NTSTATUS unixuid_read(struct ntvfs_module_context *ntvfs,
			    struct ntvfs_request *req, union smb_read *rd)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, read, (ntvfs, req, rd));

	return status;
}

/*
  write to a file
*/
static NTSTATUS unixuid_write(struct ntvfs_module_context *ntvfs,
			     struct ntvfs_request *req, union smb_write *wr)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, write, (ntvfs, req, wr));

	return status;
}

/*
  seek in a file
*/
static NTSTATUS unixuid_seek(struct ntvfs_module_context *ntvfs,
			     struct ntvfs_request *req,
			     union smb_seek *io)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, seek, (ntvfs, req, io));

	return status;
}

/*
  flush a file
*/
static NTSTATUS unixuid_flush(struct ntvfs_module_context *ntvfs,
			      struct ntvfs_request *req,
			      union smb_flush *io)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, flush, (ntvfs, req, io));

	return status;
}

/*
  close a file
*/
static NTSTATUS unixuid_close(struct ntvfs_module_context *ntvfs,
			     struct ntvfs_request *req, union smb_close *io)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, close, (ntvfs, req, io));

	return status;
}

/*
  exit - closing files
*/
static NTSTATUS unixuid_exit(struct ntvfs_module_context *ntvfs,
			    struct ntvfs_request *req)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, exit, (ntvfs, req));

	return status;
}

/*
  logoff - closing files
*/
static NTSTATUS unixuid_logoff(struct ntvfs_module_context *ntvfs,
			      struct ntvfs_request *req)
{
	struct unixuid_private *priv = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, logoff, (ntvfs, req));

	priv->last_token = NULL;

	return status;
}

/*
  async setup
*/
static NTSTATUS unixuid_async_setup(struct ntvfs_module_context *ntvfs,
				    struct ntvfs_request *req, 
				    void *private_data)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, async_setup, (ntvfs, req, private_data));

	return status;
}

/*
  cancel an async request
*/
static NTSTATUS unixuid_cancel(struct ntvfs_module_context *ntvfs,
			       struct ntvfs_request *req)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, cancel, (ntvfs, req));

	return status;
}

/*
  change notify
*/
static NTSTATUS unixuid_notify(struct ntvfs_module_context *ntvfs,
			       struct ntvfs_request *req, union smb_notify *info)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, notify, (ntvfs, req, info));

	return status;
}

/*
  lock a byte range
*/
static NTSTATUS unixuid_lock(struct ntvfs_module_context *ntvfs,
			    struct ntvfs_request *req, union smb_lock *lck)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, lock, (ntvfs, req, lck));

	return status;
}

/*
  set info on a open file
*/
static NTSTATUS unixuid_setfileinfo(struct ntvfs_module_context *ntvfs,
				   struct ntvfs_request *req, 
				   union smb_setfileinfo *info)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, setfileinfo, (ntvfs, req, info));

	return status;
}


/*
  return filesystem space info
*/
static NTSTATUS unixuid_fsinfo(struct ntvfs_module_context *ntvfs,
			      struct ntvfs_request *req, union smb_fsinfo *fs)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, fsinfo, (ntvfs, req, fs));

	return status;
}

/*
  return print queue info
*/
static NTSTATUS unixuid_lpq(struct ntvfs_module_context *ntvfs,
			   struct ntvfs_request *req, union smb_lpq *lpq)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, lpq, (ntvfs, req, lpq));

	return status;
}

/* 
   list files in a directory matching a wildcard pattern
*/
static NTSTATUS unixuid_search_first(struct ntvfs_module_context *ntvfs,
				    struct ntvfs_request *req, union smb_search_first *io, 
				    void *search_private, 
				    bool (*callback)(void *, const union smb_search_data *))
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, search_first, (ntvfs, req, io, search_private, callback));

	return status;
}

/* continue a search */
static NTSTATUS unixuid_search_next(struct ntvfs_module_context *ntvfs,
				   struct ntvfs_request *req, union smb_search_next *io, 
				   void *search_private, 
				   bool (*callback)(void *, const union smb_search_data *))
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, search_next, (ntvfs, req, io, search_private, callback));

	return status;
}

/* close a search */
static NTSTATUS unixuid_search_close(struct ntvfs_module_context *ntvfs,
				    struct ntvfs_request *req, union smb_search_close *io)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, search_close, (ntvfs, req, io));

	return status;
}

/* SMBtrans - not used on file shares */
static NTSTATUS unixuid_trans(struct ntvfs_module_context *ntvfs,
			     struct ntvfs_request *req, struct smb_trans2 *trans2)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, trans, (ntvfs, req, trans2));

	return status;
}

/*
  initialise the unixuid backend, registering ourselves with the ntvfs subsystem
 */
NTSTATUS ntvfs_unixuid_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;
	struct ntvfs_ops ops;
	NTVFS_CURRENT_CRITICAL_SIZES(vers);

	ZERO_STRUCT(ops);

	/* fill in all the operations */
	ops.connect_fn = unixuid_connect;
	ops.disconnect_fn = unixuid_disconnect;
	ops.unlink_fn = unixuid_unlink;
	ops.chkpath_fn = unixuid_chkpath;
	ops.qpathinfo_fn = unixuid_qpathinfo;
	ops.setpathinfo_fn = unixuid_setpathinfo;
	ops.open_fn = unixuid_open;
	ops.mkdir_fn = unixuid_mkdir;
	ops.rmdir_fn = unixuid_rmdir;
	ops.rename_fn = unixuid_rename;
	ops.copy_fn = unixuid_copy;
	ops.ioctl_fn = unixuid_ioctl;
	ops.read_fn = unixuid_read;
	ops.write_fn = unixuid_write;
	ops.seek_fn = unixuid_seek;
	ops.flush_fn = unixuid_flush;
	ops.close_fn = unixuid_close;
	ops.exit_fn = unixuid_exit;
	ops.lock_fn = unixuid_lock;
	ops.setfileinfo_fn = unixuid_setfileinfo;
	ops.qfileinfo_fn = unixuid_qfileinfo;
	ops.fsinfo_fn = unixuid_fsinfo;
	ops.lpq_fn = unixuid_lpq;
	ops.search_first_fn = unixuid_search_first;
	ops.search_next_fn = unixuid_search_next;
	ops.search_close_fn = unixuid_search_close;
	ops.trans_fn = unixuid_trans;
	ops.logoff_fn = unixuid_logoff;
	ops.async_setup_fn = unixuid_async_setup;
	ops.cancel_fn = unixuid_cancel;
	ops.notify_fn = unixuid_notify;

	ops.name = "unixuid";

	/* we register under all 3 backend types, as we are not type specific */
	ops.type = NTVFS_DISK;	
	ret = ntvfs_register(&ops, &vers);
	if (!NT_STATUS_IS_OK(ret)) goto failed;

	ops.type = NTVFS_PRINT;	
	ret = ntvfs_register(&ops, &vers);
	if (!NT_STATUS_IS_OK(ret)) goto failed;

	ops.type = NTVFS_IPC;	
	ret = ntvfs_register(&ops, &vers);
	if (!NT_STATUS_IS_OK(ret)) goto failed;
	
failed:
	return ret;
}
