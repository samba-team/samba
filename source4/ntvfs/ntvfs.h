/* 
   Unix SMB/CIFS implementation.
   NTVFS structures and defines
   Copyright (C) Andrew Tridgell			2003
   
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

/* modules can use the following to determine if the interface has changed */
#define NTVFS_INTERFACE_VERSION 1



/* the ntvfs operations structure - contains function pointers to 
   the backend implementations of each operation */
struct ntvfs_ops {
	const char *name;
	enum ntvfs_type type;
	
	/* initial setup */
	NTSTATUS (*connect)(struct request_context *req, const char *sharename);
	NTSTATUS (*disconnect)(struct smbsrv_tcon *tcon);

	/* path operations */
	NTSTATUS (*unlink)(struct request_context *req, struct smb_unlink *unl);
	NTSTATUS (*chkpath)(struct request_context *req, struct smb_chkpath *cp);
	NTSTATUS (*qpathinfo)(struct request_context *req, union smb_fileinfo *st);
	NTSTATUS (*setpathinfo)(struct request_context *req, union smb_setfileinfo *st);
	NTSTATUS (*open)(struct request_context *req, union smb_open *oi);
	NTSTATUS (*mkdir)(struct request_context *req, union smb_mkdir *md);
	NTSTATUS (*rmdir)(struct request_context *req, struct smb_rmdir *rd);
	NTSTATUS (*rename)(struct request_context *req, union smb_rename *ren);
	NTSTATUS (*copy)(struct request_context *req, struct smb_copy *cp);

	/* directory search */
	NTSTATUS (*search_first)(struct request_context *req, union smb_search_first *io, void *private,
				 BOOL (*callback)(void *private, union smb_search_data *file));
	NTSTATUS (*search_next)(struct request_context *req, union smb_search_next *io, void *private,
				 BOOL (*callback)(void *private, union smb_search_data *file));
	NTSTATUS (*search_close)(struct request_context *req, union smb_search_close *io);

	/* operations on open files */
	NTSTATUS (*ioctl)(struct request_context *req, union smb_ioctl *io);
	NTSTATUS (*read)(struct request_context *req, union smb_read *io);
	NTSTATUS (*write)(struct request_context *req, union smb_write *io);
	NTSTATUS (*seek)(struct request_context *req, struct smb_seek *io);
	NTSTATUS (*flush)(struct request_context *req, struct smb_flush *flush);
	NTSTATUS (*close)(struct request_context *req, union smb_close *io);
	NTSTATUS (*exit)(struct request_context *req);
	NTSTATUS (*lock)(struct request_context *req, union smb_lock *lck);
	NTSTATUS (*setfileinfo)(struct request_context *req, union smb_setfileinfo *info);
	NTSTATUS (*qfileinfo)(struct request_context *req, union smb_fileinfo *info);

	/* filesystem operations */
	NTSTATUS (*fsinfo)(struct request_context *req, union smb_fsinfo *fs);

	/* printing specific operations */
	NTSTATUS (*lpq)(struct request_context *req, union smb_lpq *lpq);

	/* trans2 interface - only used by CIFS backend to prover complete passthru for testing */
	NTSTATUS (*trans2)(struct request_context *req, struct smb_trans2 *trans2);

	/* trans interface - used by IPC backend for pipes and RAP calls */
	NTSTATUS (*trans)(struct request_context *req, struct smb_trans2 *trans);
};


/* this structure is used by backends to determine the size of some critical types */
struct ntvfs_critical_sizes {
	int interface_version;
	int sizeof_ntvfs_ops;
	int sizeof_SMB_OFF_T;
	int sizeof_smbsrv_tcon;
	int sizeof_request_context;
};
