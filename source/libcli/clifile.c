/* 
   Unix SMB/CIFS implementation.
   client file operations
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Jeremy Allison 2001-2002
   Copyright (C) James Myers 2003
   
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

#include "includes.h"

/****************************************************************************
 Hard/Symlink a file (UNIX extensions).
****************************************************************************/

static NTSTATUS cli_link_internal(struct cli_tree *tree, 
				  const char *fname_src, 
				  const char *fname_dst, BOOL hard_link)
{
	union smb_setfileinfo parms;
	NTSTATUS status;

	if (hard_link) {
		parms.generic.level = RAW_SFILEINFO_UNIX_HLINK;
		parms.unix_hlink.file.fname = fname_src;
		parms.unix_hlink.in.link_dest = fname_dst;
	} else {
		parms.generic.level = RAW_SFILEINFO_UNIX_LINK;
		parms.unix_link.file.fname = fname_src;
		parms.unix_link.in.link_dest = fname_dst;
	}
	
	status = smb_raw_setpathinfo(tree, &parms);

	return status;
}

/****************************************************************************
 Map standard UNIX permissions onto wire representations.
****************************************************************************/
static uint32_t unix_perms_to_wire(mode_t perms)
{
        unsigned int ret = 0;

        ret |= ((perms & S_IXOTH) ?  UNIX_X_OTH : 0);
        ret |= ((perms & S_IWOTH) ?  UNIX_W_OTH : 0);
        ret |= ((perms & S_IROTH) ?  UNIX_R_OTH : 0);
        ret |= ((perms & S_IXGRP) ?  UNIX_X_GRP : 0);
        ret |= ((perms & S_IWGRP) ?  UNIX_W_GRP : 0);
        ret |= ((perms & S_IRGRP) ?  UNIX_R_GRP : 0);
        ret |= ((perms & S_IXUSR) ?  UNIX_X_USR : 0);
        ret |= ((perms & S_IWUSR) ?  UNIX_W_USR : 0);
        ret |= ((perms & S_IRUSR) ?  UNIX_R_USR : 0);
#ifdef S_ISVTX
        ret |= ((perms & S_ISVTX) ?  UNIX_STICKY : 0);
#endif
#ifdef S_ISGID
        ret |= ((perms & S_ISGID) ?  UNIX_SET_GID : 0);
#endif
#ifdef S_ISUID
        ret |= ((perms & S_ISUID) ?  UNIX_SET_UID : 0);
#endif
        return ret;
}

/****************************************************************************
 Symlink a file (UNIX extensions).
****************************************************************************/
NTSTATUS cli_unix_symlink(struct cli_tree *tree, const char *fname_src, 
			  const char *fname_dst)
{
	return cli_link_internal(tree, fname_src, fname_dst, False);
}

/****************************************************************************
 Hard a file (UNIX extensions).
****************************************************************************/
NTSTATUS cli_unix_hardlink(struct cli_tree *tree, const char *fname_src, 
			   const char *fname_dst)
{
	return cli_link_internal(tree, fname_src, fname_dst, True);
}


/****************************************************************************
 Chmod or chown a file internal (UNIX extensions).
****************************************************************************/
static NTSTATUS cli_unix_chmod_chown_internal(struct cli_tree *tree, 
					      const char *fname, 
					      uint32_t mode, uint32_t uid, 
					      uint32_t gid)
{
	union smb_setfileinfo parms;
	NTSTATUS status;

	parms.generic.level = SMB_SFILEINFO_UNIX_BASIC;
	parms.unix_basic.file.fname = fname;
	parms.unix_basic.in.uid = uid;
	parms.unix_basic.in.gid = gid;
	parms.unix_basic.in.mode = mode;
	
	status = smb_raw_setpathinfo(tree, &parms);

	return status;
}

/****************************************************************************
 chmod a file (UNIX extensions).
****************************************************************************/

NTSTATUS cli_unix_chmod(struct cli_tree *tree, const char *fname, mode_t mode)
{
	return cli_unix_chmod_chown_internal(tree, fname, 
					     unix_perms_to_wire(mode), 
					     SMB_UID_NO_CHANGE, 
					     SMB_GID_NO_CHANGE);
}

/****************************************************************************
 chown a file (UNIX extensions).
****************************************************************************/
NTSTATUS cli_unix_chown(struct cli_tree *tree, const char *fname, uid_t uid, 
			gid_t gid)
{
	return cli_unix_chmod_chown_internal(tree, fname, SMB_MODE_NO_CHANGE, 
					     (uint32_t)uid, (uint32_t)gid);
}


/****************************************************************************
 Rename a file.
****************************************************************************/
NTSTATUS cli_rename(struct cli_tree *tree, const char *fname_src, 
		    const char *fname_dst)
{
	union smb_rename parms;

	parms.generic.level = RAW_RENAME_RENAME;
	parms.rename.in.attrib = FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_DIRECTORY;
	parms.rename.in.pattern1 = fname_src;
	parms.rename.in.pattern2 = fname_dst;

	return smb_raw_rename(tree, &parms);
}


/****************************************************************************
 Delete a file.
****************************************************************************/
NTSTATUS cli_unlink(struct cli_tree *tree, const char *fname)
{
	struct smb_unlink parms;

	parms.in.pattern = fname;
	if (strchr(fname, '*')) {
		parms.in.attrib = FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN;
	} else {
		parms.in.attrib = FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_DIRECTORY;
	}

	return smb_raw_unlink(tree, &parms);
}

/****************************************************************************
 Create a directory.
****************************************************************************/
NTSTATUS cli_mkdir(struct cli_tree *tree, const char *dname)
{
	union smb_mkdir parms;

	parms.mkdir.level = RAW_MKDIR_MKDIR;
	parms.mkdir.in.path = dname;

	return smb_raw_mkdir(tree, &parms);
}


/****************************************************************************
 Remove a directory.
****************************************************************************/
NTSTATUS cli_rmdir(struct cli_tree *tree, const char *dname)
{
	struct smb_rmdir parms;

	parms.in.path = dname;

	return smb_raw_rmdir(tree, &parms);
}


/****************************************************************************
 Set or clear the delete on close flag.
****************************************************************************/
NTSTATUS cli_nt_delete_on_close(struct cli_tree *tree, int fnum, BOOL flag)
{
	union smb_setfileinfo parms;
	NTSTATUS status;

	parms.disposition_info.level = RAW_SFILEINFO_DISPOSITION_INFO;
	parms.disposition_info.file.fnum = fnum;
	parms.disposition_info.in.delete_on_close = flag;
	
	status = smb_raw_setfileinfo(tree, &parms);

	return status;
}


/****************************************************************************
 Create/open a file - exposing the full horror of the NT API :-).
 Used in CIFS-on-CIFS NTVFS.
****************************************************************************/
int cli_nt_create_full(struct cli_tree *tree, const char *fname,
		       uint32_t CreatFlags, uint32_t DesiredAccess,
		       uint32_t FileAttributes, uint32_t ShareAccess,
		       uint32_t CreateDisposition, uint32_t CreateOptions,
		       uint8_t SecurityFlags)
{
	union smb_open open_parms;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;

	mem_ctx = talloc_init("raw_open");
	if (!mem_ctx) return -1;

	open_parms.ntcreatex.level = RAW_OPEN_NTCREATEX;
	open_parms.ntcreatex.in.flags = CreatFlags;
	open_parms.ntcreatex.in.root_fid = 0;
	open_parms.ntcreatex.in.access_mask = DesiredAccess;
	open_parms.ntcreatex.in.file_attr = FileAttributes;
	open_parms.ntcreatex.in.alloc_size = 0;
	open_parms.ntcreatex.in.share_access = ShareAccess;
	open_parms.ntcreatex.in.open_disposition = CreateDisposition;
	open_parms.ntcreatex.in.create_options = CreateOptions;
	open_parms.ntcreatex.in.impersonation = 0;
	open_parms.ntcreatex.in.security_flags = SecurityFlags;
	open_parms.ntcreatex.in.fname = fname;

	status = smb_raw_open(tree, mem_ctx, &open_parms);
	talloc_destroy(mem_ctx);

	if (NT_STATUS_IS_OK(status)) {
		return open_parms.ntcreatex.out.fnum;
	}
	
	return -1;
}


/****************************************************************************
 Open a file (using SMBopenx)
 WARNING: if you open with O_WRONLY then getattrE won't work!
****************************************************************************/
int cli_open(struct cli_tree *tree, const char *fname, int flags, 
	     int share_mode)
{
	union smb_open open_parms;
	unsigned openfn=0;
	unsigned accessmode=0;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;

	mem_ctx = talloc_init("raw_open");
	if (!mem_ctx) return -1;

	if (flags & O_CREAT) {
		openfn |= OPENX_OPEN_FUNC_CREATE;
	}
	if (!(flags & O_EXCL)) {
		if (flags & O_TRUNC) {
			openfn |= OPENX_OPEN_FUNC_TRUNC;
		} else {
			openfn |= OPENX_OPEN_FUNC_OPEN;
		}
	}

	accessmode = (share_mode<<OPENX_MODE_DENY_SHIFT);

	if ((flags & O_ACCMODE) == O_RDWR) {
		accessmode |= OPENX_MODE_ACCESS_RDWR;
	} else if ((flags & O_ACCMODE) == O_WRONLY) {
		accessmode |= OPENX_MODE_ACCESS_WRITE;
	} 

#if defined(O_SYNC)
	if ((flags & O_SYNC) == O_SYNC) {
		accessmode |= OPENX_MODE_WRITE_THRU;
	}
#endif

	if (share_mode == DENY_FCB) {
		accessmode = OPENX_MODE_ACCESS_FCB | OPENX_MODE_DENY_FCB;
	}

	open_parms.openx.level = RAW_OPEN_OPENX;
	open_parms.openx.in.flags = 0;
	open_parms.openx.in.open_mode = accessmode;
	open_parms.openx.in.search_attrs = FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN;
	open_parms.openx.in.file_attrs = 0;
	open_parms.openx.in.write_time = 0;
	open_parms.openx.in.open_func = openfn;
	open_parms.openx.in.size = 0;
	open_parms.openx.in.timeout = 0;
	open_parms.openx.in.fname = fname;

	status = smb_raw_open(tree, mem_ctx, &open_parms);
	talloc_destroy(mem_ctx);

	if (NT_STATUS_IS_OK(status)) {
		return open_parms.openx.out.fnum;
	}

	return -1;
}


/****************************************************************************
 Close a file.
****************************************************************************/
NTSTATUS cli_close(struct cli_tree *tree, int fnum)
{
	union smb_close close_parms;
	NTSTATUS status;

	close_parms.close.level = RAW_CLOSE_CLOSE;
	close_parms.close.in.fnum = fnum;
	close_parms.close.in.write_time = 0;
	status = smb_raw_close(tree, &close_parms);
	return status;
}

/****************************************************************************
 send a lock with a specified locktype 
 this is used for testing LOCKING_ANDX_CANCEL_LOCK
****************************************************************************/
NTSTATUS cli_locktype(struct cli_tree *tree, int fnum, 
		      uint32_t offset, uint32_t len, int timeout, 
		      uint8_t locktype)
{
	union smb_lock parms;
	struct smb_lock_entry lock[1];
	NTSTATUS status;

	parms.lockx.level = RAW_LOCK_LOCKX;
	parms.lockx.in.fnum = fnum;
	parms.lockx.in.mode = locktype;
	parms.lockx.in.timeout = timeout;
	parms.lockx.in.ulock_cnt = 0;
	parms.lockx.in.lock_cnt = 1;
	lock[0].pid = tree->session->pid;
	lock[0].offset = offset;
	lock[0].count = len;
	parms.lockx.in.locks = &lock[0];

	status = smb_raw_lock(tree, &parms);
	
	return status;
}


/****************************************************************************
 Lock a file.
****************************************************************************/
NTSTATUS cli_lock(struct cli_tree *tree, int fnum, 
		  uint32_t offset, uint32_t len, int timeout, 
		  enum brl_type lock_type)
{
	union smb_lock parms;
	struct smb_lock_entry lock[1];
	NTSTATUS status;

	parms.lockx.level = RAW_LOCK_LOCKX;
	parms.lockx.in.fnum = fnum;
	parms.lockx.in.mode = (lock_type == READ_LOCK? 1 : 0);
	parms.lockx.in.timeout = timeout;
	parms.lockx.in.ulock_cnt = 0;
	parms.lockx.in.lock_cnt = 1;
	lock[0].pid = tree->session->pid;
	lock[0].offset = offset;
	lock[0].count = len;
	parms.lockx.in.locks = &lock[0];

	status = smb_raw_lock(tree, &parms);

	return status;
}


/****************************************************************************
 Unlock a file.
****************************************************************************/
NTSTATUS cli_unlock(struct cli_tree *tree, int fnum, uint32_t offset, uint32_t len)
{
	union smb_lock parms;
	struct smb_lock_entry lock[1];
	NTSTATUS status;

	parms.lockx.level = RAW_LOCK_LOCKX;
	parms.lockx.in.fnum = fnum;
	parms.lockx.in.mode = 0;
	parms.lockx.in.timeout = 0;
	parms.lockx.in.ulock_cnt = 1;
	parms.lockx.in.lock_cnt = 0;
	lock[0].pid = tree->session->pid;
	lock[0].offset = offset;
	lock[0].count = len;
	parms.lockx.in.locks = &lock[0];
	
	status = smb_raw_lock(tree, &parms);
	return status;
}
	

/****************************************************************************
 Lock a file with 64 bit offsets.
****************************************************************************/
NTSTATUS cli_lock64(struct cli_tree *tree, int fnum, 
		    SMB_OFF_T offset, SMB_OFF_T len, int timeout, 
		    enum brl_type lock_type)
{
	union smb_lock parms;
	int ltype;
	struct smb_lock_entry lock[1];
	NTSTATUS status;

	if (!(tree->session->transport->negotiate.capabilities & CAP_LARGE_FILES)) {
		return cli_lock(tree, fnum, offset, len, timeout, lock_type);
	}

	parms.lockx.level = RAW_LOCK_LOCKX;
	parms.lockx.in.fnum = fnum;
	
	ltype = (lock_type == READ_LOCK? 1 : 0);
	ltype |= LOCKING_ANDX_LARGE_FILES;
	parms.lockx.in.mode = ltype;
	parms.lockx.in.timeout = timeout;
	parms.lockx.in.ulock_cnt = 0;
	parms.lockx.in.lock_cnt = 1;
	lock[0].pid = tree->session->pid;
	lock[0].offset = offset;
	lock[0].count = len;
	parms.lockx.in.locks = &lock[0];

	status = smb_raw_lock(tree, &parms);
	
	return status;
}


/****************************************************************************
 Unlock a file with 64 bit offsets.
****************************************************************************/
NTSTATUS cli_unlock64(struct cli_tree *tree, int fnum, SMB_OFF_T offset, 
		      SMB_OFF_T len)
{
	union smb_lock parms;
	struct smb_lock_entry lock[1];
	NTSTATUS status;

	if (!(tree->session->transport->negotiate.capabilities & CAP_LARGE_FILES)) {
		return cli_unlock(tree, fnum, offset, len);
	}

	parms.lockx.level = RAW_LOCK_LOCKX;
	parms.lockx.in.fnum = fnum;
	parms.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	parms.lockx.in.timeout = 0;
	parms.lockx.in.ulock_cnt = 1;
	parms.lockx.in.lock_cnt = 0;
	lock[0].pid = tree->session->pid;
	lock[0].offset = offset;
	lock[0].count = len;
	parms.lockx.in.locks = &lock[0];

	status = smb_raw_lock(tree, &parms);

	return status;
}


/****************************************************************************
 Do a SMBgetattrE call.
****************************************************************************/
NTSTATUS cli_getattrE(struct cli_tree *tree, int fnum,
		      uint16_t *attr, size_t *size,
		      time_t *c_time, time_t *a_time, time_t *m_time)
{		
	union smb_fileinfo parms;
	NTSTATUS status;

	parms.getattre.level = RAW_FILEINFO_GETATTRE;
	parms.getattre.in.fnum = fnum;

	status = smb_raw_fileinfo(tree, NULL, &parms);

	if (!NT_STATUS_IS_OK(status))
		return status;

	if (size) {
		*size = parms.getattre.out.size;
	}

	if (attr) {
		*attr = parms.getattre.out.attrib;
	}

	if (c_time) {
		*c_time = parms.getattre.out.create_time;
	}

	if (a_time) {
		*a_time = parms.getattre.out.access_time;
	}

	if (m_time) {
		*m_time = parms.getattre.out.write_time;
	}

	return status;
}

/****************************************************************************
 Do a SMBgetatr call
****************************************************************************/
NTSTATUS cli_getatr(struct cli_tree *tree, const char *fname, 
		    uint16_t *attr, size_t *size, time_t *t)
{
	union smb_fileinfo parms;
	NTSTATUS status;

	parms.getattr.level = RAW_FILEINFO_GETATTR;
	parms.getattr.in.fname = fname;

	status = smb_raw_pathinfo(tree, NULL, &parms);
	
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (size) {
		*size = parms.getattr.out.size;
	}

	if (t) {
		*t = parms.getattr.out.write_time;
	}

	if (attr) {
		*attr = parms.getattr.out.attrib;
	}

	return status;
}


/****************************************************************************
 Do a SMBsetatr call.
****************************************************************************/
NTSTATUS cli_setatr(struct cli_tree *tree, const char *fname, uint16_t mode, 
		    time_t t)
{
	union smb_setfileinfo parms;
	NTSTATUS status;

	parms.setattr.level = RAW_SFILEINFO_SETATTR;
	parms.setattr.in.attrib = mode;
	parms.setattr.in.write_time = t;
	parms.setattr.file.fname = fname;
	
	status = smb_raw_setpathinfo(tree, &parms);

	return status;
}


/****************************************************************************
 Check for existence of a dir.
****************************************************************************/
NTSTATUS cli_chkpath(struct cli_tree *tree, const char *path)
{
	struct smb_chkpath parms;
	char *path2;
	NTSTATUS status;

	path2 = strdup(path);
	trim_string(path2,NULL,"\\");
	if (!*path2) {
		free(path2);
		path2 = strdup("\\");
	}

	parms.in.path = path2;
	
	status = smb_raw_chkpath(tree, &parms);

	free(path2);

	return status;
}


/****************************************************************************
 Query disk space.
****************************************************************************/
NTSTATUS cli_dskattr(struct cli_tree *tree, int *bsize, int *total, int *avail)
{
	union smb_fsinfo fsinfo_parms;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;

	mem_ctx = talloc_init("cli_dskattr");

	fsinfo_parms.dskattr.level = RAW_QFS_DSKATTR;
	status = smb_raw_fsinfo(tree, mem_ctx, &fsinfo_parms);
	if (NT_STATUS_IS_OK(status)) {
		*bsize = fsinfo_parms.dskattr.out.block_size;
		*total = fsinfo_parms.dskattr.out.units_total;
		*avail = fsinfo_parms.dskattr.out.units_free;
	}

	talloc_destroy(mem_ctx);
	
	return status;
}


/****************************************************************************
 Create and open a temporary file.
****************************************************************************/
int cli_ctemp(struct cli_tree *tree, const char *path, char **tmp_path)
{
	union smb_open open_parms;
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;

	mem_ctx = talloc_init("raw_open");
	if (!mem_ctx) return -1;

	open_parms.openx.level = RAW_OPEN_CTEMP;
	open_parms.ctemp.in.attrib = 0;
	open_parms.ctemp.in.directory = path;

	status = smb_raw_open(tree, mem_ctx, &open_parms);
	if (tmp_path) {
		*tmp_path = strdup(open_parms.ctemp.out.name);
	}
	talloc_destroy(mem_ctx);
	if (NT_STATUS_IS_OK(status)) {
		return open_parms.ctemp.out.fnum;
	}
	return -1;
}
