/* 
   Unix SMB/CIFS implementation.
   NTVFS structures and defines
   Copyright (C) Andrew Tridgell			2003
   Copyright (C) Stefan Metzmacher			2004
   
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
/* version 1 -> 0 - make module stacking easier -- metze */
#define NTVFS_INTERFACE_VERSION 0

struct ntvfs_module_context;

/* each backend has to be one one of the following 3 basic types. In
 * earlier versions of Samba backends needed to handle all types, now
 * we implement them separately. */
enum ntvfs_type {NTVFS_DISK, NTVFS_PRINT, NTVFS_IPC};

/* the ntvfs operations structure - contains function pointers to 
   the backend implementations of each operation */
struct ntvfs_ops {
	const char *name;
	enum ntvfs_type type;
	
	/* initial setup */
	NTSTATUS (*connect)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, const char *sharename);
	NTSTATUS (*disconnect)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_tcon *tcon);

	/* path operations */
	NTSTATUS (*unlink)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, struct smb_unlink *unl);
	NTSTATUS (*chkpath)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, struct smb_chkpath *cp);
	NTSTATUS (*qpathinfo)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_fileinfo *st);
	NTSTATUS (*setpathinfo)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_setfileinfo *st);
	NTSTATUS (*open)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_open *oi);
	NTSTATUS (*mkdir)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_mkdir *md);
	NTSTATUS (*rmdir)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, struct smb_rmdir *rd);
	NTSTATUS (*rename)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_rename *ren);
	NTSTATUS (*copy)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, struct smb_copy *cp);

	/* directory search */
	NTSTATUS (*search_first)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_search_first *io, void *private,
				 BOOL (*callback)(void *private, union smb_search_data *file));
	NTSTATUS (*search_next)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_search_next *io, void *private,
				 BOOL (*callback)(void *private, union smb_search_data *file));
	NTSTATUS (*search_close)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_search_close *io);

	/* operations on open files */
	NTSTATUS (*ioctl)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_ioctl *io);
	NTSTATUS (*read)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_read *io);
	NTSTATUS (*write)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_write *io);
	NTSTATUS (*seek)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, struct smb_seek *io);
	NTSTATUS (*flush)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, struct smb_flush *flush);
	NTSTATUS (*close)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_close *io);
	NTSTATUS (*exit)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req);
	NTSTATUS (*lock)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_lock *lck);
	NTSTATUS (*setfileinfo)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_setfileinfo *info);
	NTSTATUS (*qfileinfo)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_fileinfo *info);

	/* filesystem operations */
	NTSTATUS (*fsinfo)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_fsinfo *fs);

	/* printing specific operations */
	NTSTATUS (*lpq)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, union smb_lpq *lpq);

	/* trans2 interface - only used by CIFS backend to prover complete passthru for testing */
	NTSTATUS (*trans2)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, struct smb_trans2 *trans2);

	/* trans interface - used by IPC backend for pipes and RAP calls */
	NTSTATUS (*trans)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req, struct smb_trans2 *trans);

	/* logoff - called when a vuid is closed */
	NTSTATUS (*logoff)(struct ntvfs_module_context *ntvfs, 
				struct smbsrv_request *req);
};

struct ntvfs_module_context {
	struct ntvfs_module_context *prev, *next;
	void *private_data;
	const struct ntvfs_ops *ops;
	int depth;
};

struct ntvfs_context {
	enum ntvfs_type type;
	/* 
	 * linked list of module contexts
	 */
	struct ntvfs_module_context *modules;
};

/* this structure is used by backends to determine the size of some critical types */
struct ntvfs_critical_sizes {
	int interface_version;
	int sizeof_ntvfs_context;
	int sizeof_ntvfs_module_context;
	int sizeof_ntvfs_ops;
	int sizeof_smbsrv_tcon;
	int sizeof_smbsrv_request;
};
