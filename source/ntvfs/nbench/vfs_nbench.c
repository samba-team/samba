/* 
   Unix SMB/CIFS implementation.

   a pass-thru NTVFS module to record a NBENCH load file

   Copyright (C) Andrew Tridgell 2004

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
  "passthru" in this module refers to the next level of NTVFS being used
*/

#include "includes.h"

/* this is stored in ntvfs_private */
struct nbench_private {
	int log_fd;
};

/*
  log one request to the nbench log
*/
static void nbench_log(struct nbench_private *private, 
		       const char *format, ...) PRINTF_ATTRIBUTE(2, 3);

static void nbench_log(struct nbench_private *private, 
		       const char *format, ...)
{
	va_list ap;
	char *s = NULL;

	va_start(ap, format);
	vasprintf(&s, format, ap);
	va_end(ap);

	write(private->log_fd, s, strlen(s));
	free(s);
}

/*
  this pass through macro operates on request contexts, and disables
  async calls. 

  async calls are a pain for the nbench module as it makes pulling the
  status code and any result parameters much harder.
*/
#define PASS_THRU_REQ(ntvfs, req, op, args) do { \
	req->control_flags &= ~REQ_CONTROL_MAY_ASYNC; \
	status = ntvfs_next_##op args; \
} while (0)


/*
  connect to a share - used when a tree_connect operation comes in.
*/
static NTSTATUS nbench_connect(struct ntvfs_module_context *ntvfs,
			       struct smbsrv_request *req, const char *sharename)
{
	struct nbench_private *private;
	NTSTATUS status;
	char *logname = NULL;

	private = talloc_p(req->tcon, struct nbench_private);
	if (!private) {
		return NT_STATUS_NO_MEMORY;
	}

	asprintf(&logname, "/tmp/nbenchlog%d.%u", ntvfs->depth, getpid());
	private->log_fd = sys_open(logname, O_WRONLY|O_CREAT|O_APPEND, 0644);
	free(logname);

	if (private->log_fd == -1) {
		DEBUG(0,("Failed to open nbench log\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	ntvfs->private_data = private;

	status = ntvfs_next_connect(ntvfs, req, sharename);

	return status;
}

/*
  disconnect from a share
*/
static NTSTATUS nbench_disconnect(struct ntvfs_module_context *ntvfs,
				  struct smbsrv_tcon *tcon)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	close(private->log_fd);

	status = ntvfs_next_disconnect(ntvfs, tcon);
 
	return status;
}

/*
  delete a file - the dirtype specifies the file types to include in the search. 
  The name can contain CIFS wildcards, but rarely does (except with OS/2 clients)
*/
static NTSTATUS nbench_unlink(struct ntvfs_module_context *ntvfs,
			      struct smbsrv_request *req, struct smb_unlink *unl)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, unlink, (ntvfs, req, unl));

	nbench_log(private, "Unlink \"%s\" 0x%x %s\n", 
		   unl->in.pattern, unl->in.attrib, 
		   get_nt_error_c_code(status));

	return status;
}

/*
  ioctl interface
*/
static NTSTATUS nbench_ioctl(struct ntvfs_module_context *ntvfs,
			     struct smbsrv_request *req, union smb_ioctl *io)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, ioctl, (ntvfs, req, io));

	nbench_log(private, "Ioctl - NOT HANDLED\n");

	return status;
}

/*
  check if a directory exists
*/
static NTSTATUS nbench_chkpath(struct ntvfs_module_context *ntvfs,
			       struct smbsrv_request *req, struct smb_chkpath *cp)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, chkpath, (ntvfs, req, cp));

	nbench_log(private, "Chkpath \"%s\" %s\n", 
		   cp->in.path, 
		   get_nt_error_c_code(status));

	return status;
}

/*
  return info on a pathname
*/
static NTSTATUS nbench_qpathinfo(struct ntvfs_module_context *ntvfs,
				 struct smbsrv_request *req, union smb_fileinfo *info)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, qpathinfo, (ntvfs, req, info));

	nbench_log(private, "QUERY_PATH_INFORMATION \"%s\" %d %s\n", 
		   info->generic.in.fname, 
		   info->generic.level,
		   get_nt_error_c_code(status));

	return status;
}

/*
  query info on a open file
*/
static NTSTATUS nbench_qfileinfo(struct ntvfs_module_context *ntvfs,
				 struct smbsrv_request *req, union smb_fileinfo *info)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, qfileinfo, (ntvfs, req, info));

	nbench_log(private, "QUERY_FILE_INFORMATION %d %d %s\n", 
		   info->generic.in.fnum, 
		   info->generic.level,
		   get_nt_error_c_code(status));

	return status;
}


/*
  set info on a pathname
*/
static NTSTATUS nbench_setpathinfo(struct ntvfs_module_context *ntvfs,
				   struct smbsrv_request *req, union smb_setfileinfo *st)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, setpathinfo, (ntvfs, req, st));

	nbench_log(private, "SET_PATH_INFORMATION \"%s\" %d %s\n", 
		   st->generic.file.fname, 
		   st->generic.level,
		   get_nt_error_c_code(status));

	return status;
}

/*
  open a file
*/
static NTSTATUS nbench_open(struct ntvfs_module_context *ntvfs,
			    struct smbsrv_request *req, union smb_open *io)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, open, (ntvfs, req, io));

	DEBUG(0,("%d: %s\n", ntvfs->depth, get_nt_error_c_code(status)));

	switch (io->generic.level) {
	case RAW_OPEN_NTCREATEX:
		nbench_log(private, "NTCreateX \"%s\" 0x%x 0x%x %d %s\n", 
			   io->ntcreatex.in.fname, 
			   io->ntcreatex.in.create_options, 
			   io->ntcreatex.in.open_disposition, 
			   io->ntcreatex.out.fnum,
			   get_nt_error_c_code(status));
		break;

	default:
		nbench_log(private, "Open-%d - NOT HANDLED\n",
			   io->generic.level);
		break;
	}

	return status;
}

/*
  create a directory
*/
static NTSTATUS nbench_mkdir(struct ntvfs_module_context *ntvfs,
			     struct smbsrv_request *req, union smb_mkdir *md)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, mkdir, (ntvfs, req, md));

	nbench_log(private, "Mkdir - NOT HANDLED\n");

	return status;
}

/*
  remove a directory
*/
static NTSTATUS nbench_rmdir(struct ntvfs_module_context *ntvfs,
			     struct smbsrv_request *req, struct smb_rmdir *rd)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, rmdir, (ntvfs, req, rd));

	nbench_log(private, "Rmdir \"%s\" %s\n", 
		   rd->in.path, 
		   get_nt_error_c_code(status));

	return status;
}

/*
  rename a set of files
*/
static NTSTATUS nbench_rename(struct ntvfs_module_context *ntvfs,
			      struct smbsrv_request *req, union smb_rename *ren)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, rename, (ntvfs, req, ren));

	switch (ren->generic.level) {
	case RAW_RENAME_RENAME:
		nbench_log(private, "Rename \"%s\" \"%s\" %s\n", 
			   ren->rename.in.pattern1, 
			   ren->rename.in.pattern2, 
			   get_nt_error_c_code(status));
		break;

	default:
		nbench_log(private, "Rename-%d - NOT HANDLED\n",
			   ren->generic.level);
		break;
	}

	return status;
}

/*
  copy a set of files
*/
static NTSTATUS nbench_copy(struct ntvfs_module_context *ntvfs,
			    struct smbsrv_request *req, struct smb_copy *cp)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, copy, (ntvfs, req, cp));

	nbench_log(private, "Copy - NOT HANDLED\n");

	return status;
}

/*
  read from a file
*/
static NTSTATUS nbench_read(struct ntvfs_module_context *ntvfs,
			    struct smbsrv_request *req, union smb_read *rd)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, read, (ntvfs, req, rd));

	switch (rd->generic.level) {
	case RAW_READ_READX:
		nbench_log(private, "ReadX %d %d %d %d %s\n", 
			   rd->readx.in.fnum, 
			   (int)rd->readx.in.offset,
			   rd->readx.in.maxcnt,
			   rd->readx.out.nread,
			   get_nt_error_c_code(status));
		break;
	default:
		nbench_log(private, "Read-%d - NOT HANDLED\n",
			   rd->generic.level);
		break;
	}

	return status;
}

/*
  write to a file
*/
static NTSTATUS nbench_write(struct ntvfs_module_context *ntvfs,
			     struct smbsrv_request *req, union smb_write *wr)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, write, (ntvfs, req, wr));

	switch (wr->generic.level) {
	case RAW_WRITE_WRITEX:
		nbench_log(private, "WriteX %d %d %d %d %s\n", 
			   wr->writex.in.fnum, 
			   (int)wr->writex.in.offset,
			   wr->writex.in.count,
			   wr->writex.out.nwritten,
			   get_nt_error_c_code(status));
		break;

	case RAW_WRITE_WRITE:
		nbench_log(private, "Write %d %d %d %d %s\n", 
			   wr->write.in.fnum, 
			   wr->write.in.offset,
			   wr->write.in.count,
			   wr->write.out.nwritten,
			   get_nt_error_c_code(status));
		break;

	default:
		nbench_log(private, "Write-%d - NOT HANDLED\n",
			   wr->generic.level);
		break;
	}

	return status;
}

/*
  seek in a file
*/
static NTSTATUS nbench_seek(struct ntvfs_module_context *ntvfs,
			    struct smbsrv_request *req, struct smb_seek *io)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, seek, (ntvfs, req, io));

	nbench_log(private, "Seek - NOT HANDLED\n");

	return status;
}

/*
  flush a file
*/
static NTSTATUS nbench_flush(struct ntvfs_module_context *ntvfs,
			     struct smbsrv_request *req, struct smb_flush *io)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, flush, (ntvfs, req, io));

	nbench_log(private, "Flush %d %s\n",
		   io->in.fnum,
		   get_nt_error_c_code(status));

	return status;
}

/*
  close a file
*/
static NTSTATUS nbench_close(struct ntvfs_module_context *ntvfs,
			     struct smbsrv_request *req, union smb_close *io)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, close, (ntvfs, req, io));

	switch (io->generic.level) {
	case RAW_CLOSE_CLOSE:
		nbench_log(private, "Close %d %s\n",
			   io->close.in.fnum,
			   get_nt_error_c_code(status));
		break;

	default:
		nbench_log(private, "Close-%d - NOT HANDLED\n",
			   io->generic.level);
		break;
	}		

	return status;
}

/*
  exit - closing files
*/
static NTSTATUS nbench_exit(struct ntvfs_module_context *ntvfs,
			    struct smbsrv_request *req)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, exit, (ntvfs, req));

	return status;
}

/*
  logoff - closing files
*/
static NTSTATUS nbench_logoff(struct ntvfs_module_context *ntvfs,
			      struct smbsrv_request *req)
{
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, logoff, (ntvfs, req));

	return status;
}

/*
  async setup
*/
static NTSTATUS nbench_async_setup(struct ntvfs_module_context *ntvfs,
				   struct smbsrv_request *req,
				   void *private)
{
	return NT_STATUS_OK;
}

/*
  lock a byte range
*/
static NTSTATUS nbench_lock(struct ntvfs_module_context *ntvfs,
			    struct smbsrv_request *req, union smb_lock *lck)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, lock, (ntvfs, req, lck));

	if (lck->generic.level == RAW_LOCK_LOCKX &&
	    lck->lockx.in.lock_cnt == 1 &&
	    lck->lockx.in.ulock_cnt == 0) {
		nbench_log(private, "LockX %d %d %d %s\n", 
			   lck->lockx.in.fnum,
			   (int)lck->lockx.in.locks[0].offset,
			   (int)lck->lockx.in.locks[0].count,
			   get_nt_error_c_code(status));
	} else if (lck->generic.level == RAW_LOCK_LOCKX &&
		   lck->lockx.in.ulock_cnt == 1) {
		nbench_log(private, "UnlockX %d %d %d %s\n", 
			   lck->lockx.in.fnum,
			   (int)lck->lockx.in.locks[0].offset,
			   (int)lck->lockx.in.locks[0].count,
			   get_nt_error_c_code(status));
	} else {
		nbench_log(private, "Lock-%d - NOT HANDLED\n", lck->generic.level);
	}

	return status;
}

/*
  set info on a open file
*/
static NTSTATUS nbench_setfileinfo(struct ntvfs_module_context *ntvfs,
				   struct smbsrv_request *req, 
				   union smb_setfileinfo *info)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, setfileinfo, (ntvfs, req, info));

	nbench_log(private, "SET_FILE_INFORMATION %d %d %s\n", 
		   info->generic.file.fnum,
		   info->generic.level,
		   get_nt_error_c_code(status));

	return status;
}


/*
  return filesystem space info
*/
static NTSTATUS nbench_fsinfo(struct ntvfs_module_context *ntvfs,
			      struct smbsrv_request *req, union smb_fsinfo *fs)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, fsinfo, (ntvfs, req, fs));

	nbench_log(private, "QUERY_FS_INFORMATION %d %s\n", 
		   fs->generic.level, 
		   get_nt_error_c_code(status));

	return status;
}

/*
  return print queue info
*/
static NTSTATUS nbench_lpq(struct ntvfs_module_context *ntvfs,
			   struct smbsrv_request *req, union smb_lpq *lpq)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, lpq, (ntvfs, req, lpq));

	nbench_log(private, "Lpq-%d - NOT HANDLED\n", lpq->generic.level);

	return status;
}

/* 
   list files in a directory matching a wildcard pattern
*/
static NTSTATUS nbench_search_first(struct ntvfs_module_context *ntvfs,
				    struct smbsrv_request *req, union smb_search_first *io, 
				    void *search_private, 
				    BOOL (*callback)(void *, union smb_search_data *))
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, search_first, (ntvfs, req, io, search_private, callback));

	switch (io->generic.level) {
	case RAW_SEARCH_BOTH_DIRECTORY_INFO:
		nbench_log(private, "FIND_FIRST \"%s\" %d %d %d %s\n", 
			   io->t2ffirst.in.pattern,
			   io->generic.level,
			   io->t2ffirst.in.max_count,
			   io->t2ffirst.out.count,
			   get_nt_error_c_code(status));
		break;
		
	default:
		nbench_log(private, "Search-%d - NOT HANDLED\n", io->generic.level);
		break;
	}

	return status;
}

/* continue a search */
static NTSTATUS nbench_search_next(struct ntvfs_module_context *ntvfs,
				   struct smbsrv_request *req, union smb_search_next *io, 
				   void *search_private, 
				   BOOL (*callback)(void *, union smb_search_data *))
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, search_next, (ntvfs, req, io, search_private, callback));

	nbench_log(private, "Searchnext-%d - NOT HANDLED\n", io->generic.level);

	return status;
}

/* close a search */
static NTSTATUS nbench_search_close(struct ntvfs_module_context *ntvfs,
				    struct smbsrv_request *req, union smb_search_close *io)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, search_close, (ntvfs, req, io));

	nbench_log(private, "Searchclose-%d - NOT HANDLED\n", io->generic.level);

	return status;
}

/* SMBtrans - not used on file shares */
static NTSTATUS nbench_trans(struct ntvfs_module_context *ntvfs,
			     struct smbsrv_request *req, struct smb_trans2 *trans2)
{
	struct nbench_private *private = ntvfs->private_data;
	NTSTATUS status;

	PASS_THRU_REQ(ntvfs, req, trans, (ntvfs, req, trans2));

	nbench_log(private, "Trans - NOT HANDLED\n");

	return status;
}

/*
  initialise the nbench backend, registering ourselves with the ntvfs subsystem
 */
NTSTATUS ntvfs_nbench_init(void)
{
	NTSTATUS ret;
	struct ntvfs_ops ops;

	ZERO_STRUCT(ops);

	/* fill in the name and type */
	ops.name = "nbench";
	ops.type = NTVFS_DISK;
	
	/* fill in all the operations */
	ops.connect = nbench_connect;
	ops.disconnect = nbench_disconnect;
	ops.unlink = nbench_unlink;
	ops.chkpath = nbench_chkpath;
	ops.qpathinfo = nbench_qpathinfo;
	ops.setpathinfo = nbench_setpathinfo;
	ops.open = nbench_open;
	ops.mkdir = nbench_mkdir;
	ops.rmdir = nbench_rmdir;
	ops.rename = nbench_rename;
	ops.copy = nbench_copy;
	ops.ioctl = nbench_ioctl;
	ops.read = nbench_read;
	ops.write = nbench_write;
	ops.seek = nbench_seek;
	ops.flush = nbench_flush;	
	ops.close = nbench_close;
	ops.exit = nbench_exit;
	ops.lock = nbench_lock;
	ops.setfileinfo = nbench_setfileinfo;
	ops.qfileinfo = nbench_qfileinfo;
	ops.fsinfo = nbench_fsinfo;
	ops.lpq = nbench_lpq;
	ops.search_first = nbench_search_first;
	ops.search_next = nbench_search_next;
	ops.search_close = nbench_search_close;
	ops.trans = nbench_trans;
	ops.logoff = nbench_logoff;
	ops.async_setup = nbench_async_setup;

	/* we don't register a trans2 handler as we want to be able to
	   log individual trans2 requests */
	ops.trans2 = NULL;

	/* register ourselves with the NTVFS subsystem. */
	ret = register_backend("ntvfs", &ops);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register nbench backend!\n"));
	}
	
	return ret;
}
