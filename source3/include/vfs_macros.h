/*
   Unix SMB/CIFS implementation.
   VFS wrapper macros
   Copyright (C) Stefan (metze) Metzmacher	2003
   Copyright (C) Volker Lendecke		2009

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

#ifndef _VFS_MACROS_H
#define _VFS_MACROS_H

/*******************************************************************
 Don't access conn->vfs.ops.* directly!!!
 Use this macros!
 (Fixes should go also into the vfs_opaque_* and vfs_next_* macros!)
********************************************************************/

/* Disk operations */
#define SMB_VFS_CONNECT(conn, service, user) \
	smb_vfs_call_connect((conn)->vfs_handles, (service), (user))
#define SMB_VFS_NEXT_CONNECT(handle, service, user) \
	smb_vfs_call_connect((handle)->next, (service), (user))

#define SMB_VFS_DISCONNECT(conn) \
	smb_vfs_call_disconnect((conn)->vfs_handles)
#define SMB_VFS_NEXT_DISCONNECT(handle) \
	smb_vfs_call_disconnect((handle)->next)

#define SMB_VFS_DISK_FREE(conn, path, small_query, bsize, dfree ,dsize) \
	smb_vfs_call_disk_free((conn)->vfs_handles, (path), (small_query), (bsize), (dfree), (dsize))
#define SMB_VFS_NEXT_DISK_FREE(handle, path, small_query, bsize, dfree ,dsize)\
	smb_vfs_call_disk_free((handle)->next, (path), (small_query), (bsize), (dfree), (dsize))

#define SMB_VFS_GET_QUOTA(conn, qtype, id, qt) \
	smb_vfs_call_get_quota((conn)->vfs_handles, (qtype), (id), (qt))
#define SMB_VFS_NEXT_GET_QUOTA(handle, qtype, id, qt) \
	smb_vfs_call_get_quota((handle)->next, (qtype), (id), (qt))

#define SMB_VFS_SET_QUOTA(conn, qtype, id, qt) \
	smb_vfs_call_set_quota((conn)->vfs_handles, (qtype), (id), (qt))
#define SMB_VFS_NEXT_SET_QUOTA(handle, qtype, id, qt) \
	smb_vfs_call_set_quota((handle)->next, (qtype), (id), (qt))

#define SMB_VFS_GET_SHADOW_COPY_DATA(fsp,shadow_copy_data,labels) \
	smb_vfs_call_get_shadow_copy_data((fsp)->conn->vfs_handles, (fsp), (shadow_copy_data), (labels))
#define SMB_VFS_NEXT_GET_SHADOW_COPY_DATA(handle, fsp, shadow_copy_data ,labels) \
	smb_vfs_call_get_shadow_copy_data((handle)->next, (fsp), (shadow_copy_data), (labels))

#define SMB_VFS_STATVFS(conn, path, statbuf) \
	smb_vfs_call_statvfs((conn)->vfs_handles, (path), (statbuf))
#define SMB_VFS_NEXT_STATVFS(handle, path, statbuf) \
	smb_vfs_call_statvfs((handle)->next, (path), (statbuf))

#define SMB_VFS_FS_CAPABILITIES(conn, p_ts_res) \
	smb_vfs_call_fs_capabilities((conn)->vfs_handles, (p_ts_res))
#define SMB_VFS_NEXT_FS_CAPABILITIES(handle, p_ts_res) \
	smb_vfs_call_fs_capabilities((handle)->next, (p_ts_res))

/*
 * Note: that "struct dfs_GetDFSReferral *r"
 * needs to be a valid TALLOC_CTX
 */
#define SMB_VFS_GET_DFS_REFERRALS(conn, r) \
	smb_vfs_call_get_dfs_referrals((conn)->vfs_handles, (r))
#define SMB_VFS_NEXT_GET_DFS_REFERRALS(handle, r) \
	smb_vfs_call_get_dfs_referrals((handle)->next, (r))

/* Directory operations */
#define SMB_VFS_OPENDIR(conn, fname, mask, attr) \
	smb_vfs_call_opendir((conn)->vfs_handles, (fname), (mask), (attr))
#define SMB_VFS_NEXT_OPENDIR(handle, fname, mask, attr) \
	smb_vfs_call_opendir((handle)->next, (fname), (mask), (attr))

#define SMB_VFS_FDOPENDIR(fsp, mask, attr) \
	smb_vfs_call_fdopendir((fsp)->conn->vfs_handles, (fsp), (mask), (attr))
#define SMB_VFS_NEXT_FDOPENDIR(handle, fsp, mask, attr) \
	smb_vfs_call_fdopendir((handle)->next, (fsp), (mask), (attr))

#define SMB_VFS_READDIR(conn, dirp, sbuf) \
	smb_vfs_call_readdir((conn)->vfs_handles, (dirp), (sbuf))
#define SMB_VFS_NEXT_READDIR(handle, dirp, sbuf) \
	smb_vfs_call_readdir((handle)->next, (dirp), (sbuf))

#define SMB_VFS_SEEKDIR(conn, dirp, offset) \
	smb_vfs_call_seekdir((conn)->vfs_handles, (dirp), (offset))
#define SMB_VFS_NEXT_SEEKDIR(handle, dirp, offset) \
	smb_vfs_call_seekdir((handle)->next, (dirp), (offset))

#define SMB_VFS_TELLDIR(conn, dirp) \
	smb_vfs_call_telldir((conn)->vfs_handles, (dirp))
#define SMB_VFS_NEXT_TELLDIR(handle, dirp) \
	smb_vfs_call_telldir((handle)->next, (dirp))

#define SMB_VFS_REWINDDIR(conn, dirp) \
	smb_vfs_call_rewind_dir((conn)->vfs_handles, (dirp))
#define SMB_VFS_NEXT_REWINDDIR(handle, dirp) \
	smb_vfs_call_rewind_dir((handle)->next, (dirp))

#define SMB_VFS_MKDIR(conn, path, mode) \
	smb_vfs_call_mkdir((conn)->vfs_handles,(path), (mode))
#define SMB_VFS_NEXT_MKDIR(handle, path, mode) \
	smb_vfs_call_mkdir((handle)->next,(path), (mode))

#define SMB_VFS_RMDIR(conn, path) \
	smb_vfs_call_rmdir((conn)->vfs_handles, (path))
#define SMB_VFS_NEXT_RMDIR(handle, path) \
	smb_vfs_call_rmdir((handle)->next, (path))

#define SMB_VFS_CLOSEDIR(conn, dir) \
	smb_vfs_call_closedir((conn)->vfs_handles, dir)
#define SMB_VFS_NEXT_CLOSEDIR(handle, dir) \
	smb_vfs_call_closedir((handle)->next, (dir))

#define SMB_VFS_INIT_SEARCH_OP(conn, dirp) \
	smb_vfs_call_init_search_op((conn)->vfs_handles, (dirp))
#define SMB_VFS_NEXT_INIT_SEARCH_OP(handle, dirp) \
	smb_vfs_call_init_search_op((handle)->next, (dirp))

/* File operations */
#define SMB_VFS_OPEN(conn, fname, fsp, flags, mode) \
	smb_vfs_call_open((conn)->vfs_handles, (fname), (fsp), (flags), (mode))
#define SMB_VFS_NEXT_OPEN(handle, fname, fsp, flags, mode) \
	smb_vfs_call_open((handle)->next, (fname), (fsp), (flags), (mode))

#define SMB_VFS_CREATE_FILE(conn, req, root_dir_fid, smb_fname, access_mask, share_access, create_disposition, \
        create_options, file_attributes, oplock_request, allocation_size, private_flags, sd, ea_list, result, pinfo) \
	smb_vfs_call_create_file((conn)->vfs_handles, (req), (root_dir_fid), (smb_fname), (access_mask), (share_access), (create_disposition), \
        (create_options), (file_attributes), (oplock_request), (allocation_size), (private_flags), (sd), (ea_list), (result), (pinfo))
#define SMB_VFS_NEXT_CREATE_FILE(handle, req, root_dir_fid, smb_fname, access_mask, share_access, create_disposition, \
        create_options, file_attributes, oplock_request, allocation_size, private_flags, sd, ea_list, result, pinfo) \
	smb_vfs_call_create_file((handle)->next, (req), (root_dir_fid), (smb_fname), (access_mask), (share_access), (create_disposition), \
        (create_options), (file_attributes), (oplock_request), (allocation_size), (private_flags), (sd), (ea_list), (result), (pinfo))

#define SMB_VFS_CLOSE(fsp) \
	smb_vfs_call_close((fsp)->conn->vfs_handles, (fsp))
#define SMB_VFS_NEXT_CLOSE(handle, fsp) \
	smb_vfs_call_close((handle)->next, (fsp))

#define SMB_VFS_READ(fsp, data, n) \
	smb_vfs_call_read((fsp)->conn->vfs_handles, (fsp), (data), (n))
#define SMB_VFS_NEXT_READ(handle, fsp, data, n) \
	smb_vfs_call_read((handle)->next, (fsp), (data), (n))

#define SMB_VFS_PREAD(fsp, data, n, off) \
	smb_vfs_call_pread((fsp)->conn->vfs_handles, (fsp), (data), (n), (off))
#define SMB_VFS_NEXT_PREAD(handle, fsp, data, n, off) \
	smb_vfs_call_pread((handle)->next, (fsp), (data), (n), (off))

#define SMB_VFS_PREAD_SEND(mem_ctx, ev, fsp, data, n, off) \
	smb_vfs_call_pread_send((fsp)->conn->vfs_handles, (mem_ctx), (ev), \
				(fsp), (data), (n), (off))
#define SMB_VFS_NEXT_PREAD_SEND(mem_ctx, ev, handle, fsp, data, n, off)	\
	smb_vfs_call_pread_send((handle)->next, (mem_ctx), (ev), (fsp), \
				(data), (n), (off))

#define SMB_VFS_WRITE(fsp, data, n) \
	smb_vfs_call_write((fsp)->conn->vfs_handles, (fsp), (data), (n))
#define SMB_VFS_NEXT_WRITE(handle, fsp, data, n) \
	smb_vfs_call_write((handle)->next, (fsp), (data), (n))

#define SMB_VFS_PWRITE(fsp, data, n, off) \
	smb_vfs_call_pwrite((fsp)->conn->vfs_handles, (fsp), (data), (n), (off))
#define SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, off) \
	smb_vfs_call_pwrite((handle)->next, (fsp), (data), (n), (off))

#define SMB_VFS_PWRITE_SEND(mem_ctx, ev, fsp, data, n, off) \
	smb_vfs_call_pwrite_send((fsp)->conn->vfs_handles, (mem_ctx), (ev), \
				(fsp), (data), (n), (off))
#define SMB_VFS_NEXT_PWRITE_SEND(mem_ctx, ev, handle, fsp, data, n, off) \
	smb_vfs_call_pwrite_send((handle)->next, (mem_ctx), (ev), (fsp), \
				(data), (n), (off))

#define SMB_VFS_LSEEK(fsp, offset, whence) \
	smb_vfs_call_lseek((fsp)->conn->vfs_handles, (fsp), (offset), (whence))
#define SMB_VFS_NEXT_LSEEK(handle, fsp, offset, whence) \
	smb_vfs_call_lseek((handle)->next, (fsp), (offset), (whence))

#define SMB_VFS_SENDFILE(tofd, fromfsp, header, offset, count) \
	smb_vfs_call_sendfile((fromfsp)->conn->vfs_handles, (tofd), (fromfsp), (header), (offset), (count))
#define SMB_VFS_NEXT_SENDFILE(handle, tofd, fromfsp, header, offset, count) \
	smb_vfs_call_sendfile((handle)->next, (tofd), (fromfsp), (header), (offset), (count))

#define SMB_VFS_RECVFILE(fromfd, tofsp, offset, count) \
	smb_vfs_call_recvfile((tofsp)->conn->vfs_handles, (fromfd), (tofsp), (offset), (count))
#define SMB_VFS_NEXT_RECVFILE(handle, fromfd, tofsp, offset, count) \
	smb_vfs_call_recvfile((handle)->next, (fromfd), (tofsp), (offset), (count))

#define SMB_VFS_RENAME(conn, old, new) \
	smb_vfs_call_rename((conn)->vfs_handles, (old), (new))
#define SMB_VFS_NEXT_RENAME(handle, old, new) \
	smb_vfs_call_rename((handle)->next, (old), (new))

#define SMB_VFS_FSYNC(fsp) \
	smb_vfs_call_fsync((fsp)->conn->vfs_handles, (fsp))
#define SMB_VFS_NEXT_FSYNC(handle, fsp) \
	smb_vfs_call_fsync((handle)->next, (fsp))

#define SMB_VFS_FSYNC_SEND(mem_ctx, ev, fsp) \
	smb_vfs_call_fsync_send((fsp)->conn->vfs_handles, (mem_ctx), (ev), \
				(fsp))
#define SMB_VFS_NEXT_FSYNC_SEND(mem_ctx, ev, handle, fsp)		\
	smb_vfs_call_fsync_send((handle)->next, (mem_ctx), (ev), (fsp))

#define SMB_VFS_STAT(conn, smb_fname) \
	smb_vfs_call_stat((conn)->vfs_handles, (smb_fname))
#define SMB_VFS_NEXT_STAT(handle, smb_fname) \
	smb_vfs_call_stat((handle)->next, (smb_fname))

#define SMB_VFS_FSTAT(fsp, sbuf) \
	smb_vfs_call_fstat((fsp)->conn->vfs_handles, (fsp), (sbuf))
#define SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf) \
	smb_vfs_call_fstat((handle)->next, (fsp), (sbuf))

#define SMB_VFS_LSTAT(conn, smb_fname) \
	smb_vfs_call_lstat((conn)->vfs_handles, (smb_fname))
#define SMB_VFS_NEXT_LSTAT(handle, smb_fname) \
	smb_vfs_call_lstat((handle)->next, (smb_fname))

#define SMB_VFS_GET_ALLOC_SIZE(conn, fsp, sbuf) \
	smb_vfs_call_get_alloc_size((conn)->vfs_handles, (fsp), (sbuf))
#define SMB_VFS_NEXT_GET_ALLOC_SIZE(conn, fsp, sbuf) \
	smb_vfs_call_get_alloc_size((conn)->next, (fsp), (sbuf))

#define SMB_VFS_UNLINK(conn, path) \
	smb_vfs_call_unlink((conn)->vfs_handles, (path))
#define SMB_VFS_NEXT_UNLINK(handle, path) \
	smb_vfs_call_unlink((handle)->next, (path))

#define SMB_VFS_CHMOD(conn, path, mode) \
	smb_vfs_call_chmod((conn)->vfs_handles, (path), (mode))
#define SMB_VFS_NEXT_CHMOD(handle, path, mode) \
	smb_vfs_call_chmod((handle)->next, (path), (mode))

#define SMB_VFS_FCHMOD(fsp, mode) \
	smb_vfs_call_fchmod((fsp)->conn->vfs_handles, (fsp), (mode))
#define SMB_VFS_NEXT_FCHMOD(handle, fsp, mode) \
	smb_vfs_call_fchmod((handle)->next, (fsp), (mode))

#define SMB_VFS_CHOWN(conn, path, uid, gid) \
	smb_vfs_call_chown((conn)->vfs_handles, (path), (uid), (gid))
#define SMB_VFS_NEXT_CHOWN(handle, path, uid, gid) \
	smb_vfs_call_chown((handle)->next, (path), (uid), (gid))

#define SMB_VFS_FCHOWN(fsp, uid, gid) \
	smb_vfs_call_fchown((fsp)->conn->vfs_handles, (fsp), (uid), (gid))
#define SMB_VFS_NEXT_FCHOWN(handle, fsp, uid, gid) \
	smb_vfs_call_fchown((handle)->next, (fsp), (uid), (gid))

#define SMB_VFS_LCHOWN(conn, path, uid, gid) \
	smb_vfs_call_lchown((conn)->vfs_handles, (path), (uid), (gid))
#define SMB_VFS_NEXT_LCHOWN(handle, path, uid, gid) \
	smb_vfs_call_lchown((handle)->next, (path), (uid), (gid))

#define SMB_VFS_CHDIR(conn, path) \
	smb_vfs_call_chdir((conn)->vfs_handles, (path))
#define SMB_VFS_NEXT_CHDIR(handle, path) \
	smb_vfs_call_chdir((handle)->next, (path))

#define SMB_VFS_GETWD(conn) \
	smb_vfs_call_getwd((conn)->vfs_handles)
#define SMB_VFS_NEXT_GETWD(handle) \
	smb_vfs_call_getwd((handle)->next)

#define SMB_VFS_NTIMES(conn, path, ts) \
	smb_vfs_call_ntimes((conn)->vfs_handles, (path), (ts))
#define SMB_VFS_NEXT_NTIMES(handle, path, ts) \
	smb_vfs_call_ntimes((handle)->next, (path), (ts))

#define SMB_VFS_FTRUNCATE(fsp, offset) \
	smb_vfs_call_ftruncate((fsp)->conn->vfs_handles, (fsp), (offset))
#define SMB_VFS_NEXT_FTRUNCATE(handle, fsp, offset) \
	smb_vfs_call_ftruncate((handle)->next, (fsp), (offset))

#define SMB_VFS_FALLOCATE(fsp, mode, offset, len) \
	smb_vfs_call_fallocate((fsp)->conn->vfs_handles, (fsp), (mode), (offset), (len))
#define SMB_VFS_NEXT_FALLOCATE(handle, fsp, mode, offset, len) \
	smb_vfs_call_fallocate((handle)->next, (fsp), (mode), (offset), (len))

#define SMB_VFS_LOCK(fsp, op, offset, count, type) \
	smb_vfs_call_lock((fsp)->conn->vfs_handles, (fsp), (op), (offset), (count), (type))
#define SMB_VFS_NEXT_LOCK(handle, fsp, op, offset, count, type) \
	smb_vfs_call_lock((handle)->next, (fsp), (op), (offset), (count), (type))

#define SMB_VFS_KERNEL_FLOCK(fsp, share_mode, access_mask) \
	smb_vfs_call_kernel_flock((fsp)->conn->vfs_handles, (fsp), (share_mode), (access_mask))
#define SMB_VFS_NEXT_KERNEL_FLOCK(handle, fsp, share_mode, access_mask)	\
	smb_vfs_call_kernel_flock((handle)->next, (fsp), (share_mode), (access_mask))

#define SMB_VFS_LINUX_SETLEASE(fsp, leasetype) \
	smb_vfs_call_linux_setlease((fsp)->conn->vfs_handles, (fsp), (leasetype))
#define SMB_VFS_NEXT_LINUX_SETLEASE(handle, fsp, leasetype) \
	smb_vfs_call_linux_setlease((handle)->next, (fsp), (leasetype))

#define SMB_VFS_GETLOCK(fsp, poffset, pcount, ptype, ppid) \
	smb_vfs_call_getlock((fsp)->conn->vfs_handles, (fsp), (poffset), (pcount), (ptype), (ppid))
#define SMB_VFS_NEXT_GETLOCK(handle, fsp, poffset, pcount, ptype, ppid) \
	smb_vfs_call_getlock((handle)->next, (fsp), (poffset), (pcount), (ptype), (ppid))

#define SMB_VFS_SYMLINK(conn, oldpath, newpath) \
	smb_vfs_call_symlink((conn)->vfs_handles, (oldpath), (newpath))
#define SMB_VFS_NEXT_SYMLINK(handle, oldpath, newpath) \
	smb_vfs_call_symlink((handle)->next, (oldpath), (newpath))

#define SMB_VFS_READLINK(conn, path, buf, bufsiz) \
	smb_vfs_call_readlink((conn)->vfs_handles, (path), (buf), (bufsiz))
#define SMB_VFS_NEXT_READLINK(handle, path, buf, bufsiz) \
	smb_vfs_call_readlink((handle)->next, (path), (buf), (bufsiz))

#define SMB_VFS_LINK(conn, oldpath, newpath) \
	smb_vfs_call_link((conn)->vfs_handles, (oldpath), (newpath))
#define SMB_VFS_NEXT_LINK(handle, oldpath, newpath) \
	smb_vfs_call_link((handle)->next, (oldpath), (newpath))

#define SMB_VFS_MKNOD(conn, path, mode, dev) \
	smb_vfs_call_mknod((conn)->vfs_handles, (path), (mode), (dev))
#define SMB_VFS_NEXT_MKNOD(handle, path, mode, dev) \
	smb_vfs_call_mknod((handle)->next, (path), (mode), (dev))

#define SMB_VFS_REALPATH(conn, path) \
	smb_vfs_call_realpath((conn)->vfs_handles, (path))
#define SMB_VFS_NEXT_REALPATH(handle, path) \
	smb_vfs_call_realpath((handle)->next, (path))

#define SMB_VFS_NOTIFY_WATCH(conn, ctx, path, filter, subdir_filter, callback, private_data, handle_p) \
	smb_vfs_call_notify_watch((conn)->vfs_handles, (ctx), (path), (filter), (subdir_filter), (callback), (private_data), (handle_p))
#define SMB_VFS_NEXT_NOTIFY_WATCH(conn, ctx, path, filter, subdir_filter, callback, private_data, handle_p) \
	smb_vfs_call_notify_watch((conn)->next, (ctx), (path), (filter), (subdir_filter), (callback), (private_data), (handle_p))

#define SMB_VFS_CHFLAGS(conn, path, flags) \
	smb_vfs_call_chflags((conn)->vfs_handles, (path), (flags))
#define SMB_VFS_NEXT_CHFLAGS(handle, path, flags) \
	smb_vfs_call_chflags((handle)->next, (path), (flags))

#define SMB_VFS_FILE_ID_CREATE(conn, sbuf) \
	smb_vfs_call_file_id_create((conn)->vfs_handles, (sbuf))
#define SMB_VFS_NEXT_FILE_ID_CREATE(handle, sbuf) \
	smb_vfs_call_file_id_create((handle)->next, (sbuf))

#define SMB_VFS_STREAMINFO(conn, fsp, fname, mem_ctx, num_streams, streams) \
	smb_vfs_call_streaminfo((conn)->vfs_handles, (fsp), (fname), (mem_ctx), (num_streams), (streams))
#define SMB_VFS_NEXT_STREAMINFO(handle, fsp, fname, mem_ctx, num_streams, streams) \
	smb_vfs_call_streaminfo((handle)->next, (fsp), (fname), (mem_ctx), (num_streams), (streams))

#define SMB_VFS_GET_REAL_FILENAME(conn, path, name, mem_ctx, found_name) \
	smb_vfs_call_get_real_filename((conn)->vfs_handles, (path), (name), (mem_ctx), (found_name))
#define SMB_VFS_NEXT_GET_REAL_FILENAME(handle, path, name, mem_ctx, found_name) \
	smb_vfs_call_get_real_filename((handle)->next, (path), (name), (mem_ctx), (found_name))

#define SMB_VFS_CONNECTPATH(conn, fname) \
	smb_vfs_call_connectpath((conn)->vfs_handles, (fname))
#define SMB_VFS_NEXT_CONNECTPATH(conn, fname) \
	smb_vfs_call_connectpath((conn)->next, (fname))

#define SMB_VFS_BRL_LOCK_WINDOWS(conn, br_lck, plock, blocking_lock, blr) \
	smb_vfs_call_brl_lock_windows((conn)->vfs_handles, (br_lck), (plock), (blocking_lock), (blr))
#define SMB_VFS_NEXT_BRL_LOCK_WINDOWS(handle, br_lck, plock, blocking_lock, blr) \
	smb_vfs_call_brl_lock_windows((handle)->next, (br_lck), (plock), (blocking_lock), (blr))

#define SMB_VFS_BRL_UNLOCK_WINDOWS(conn, msg_ctx, br_lck, plock) \
	smb_vfs_call_brl_unlock_windows((conn)->vfs_handles, (msg_ctx), (br_lck), (plock))
#define SMB_VFS_NEXT_BRL_UNLOCK_WINDOWS(handle, msg_ctx, br_lck, plock) \
	smb_vfs_call_brl_unlock_windows((handle)->next, (msg_ctx), (br_lck), (plock))

#define SMB_VFS_BRL_CANCEL_WINDOWS(conn, br_lck, plock, blr) \
	smb_vfs_call_brl_cancel_windows((conn)->vfs_handles, (br_lck), (plock), (blr))
#define SMB_VFS_NEXT_BRL_CANCEL_WINDOWS(handle, br_lck, plock, blr) \
	smb_vfs_call_brl_cancel_windows((handle)->next, (br_lck), (plock), (blr))

#define SMB_VFS_STRICT_LOCK(conn, fsp, plock) \
	smb_vfs_call_strict_lock((conn)->vfs_handles, (fsp), (plock))
#define SMB_VFS_NEXT_STRICT_LOCK(handle, fsp, plock) \
	smb_vfs_call_strict_lock((handle)->next, (fsp), (plock))

#define SMB_VFS_STRICT_UNLOCK(conn, fsp, plock) \
	smb_vfs_call_strict_unlock((conn)->vfs_handles, (fsp), (plock))
#define SMB_VFS_NEXT_STRICT_UNLOCK(handle, fsp, plock) \
	smb_vfs_call_strict_unlock((handle)->next, (fsp), (plock))

#define SMB_VFS_TRANSLATE_NAME(conn, name, direction, mem_ctx, mapped_name) \
	smb_vfs_call_translate_name((conn)->vfs_handles, (name), (direction), (mem_ctx), (mapped_name))
#define SMB_VFS_NEXT_TRANSLATE_NAME(handle, name, direction, mem_ctx, mapped_name) \
	smb_vfs_call_translate_name((handle)->next, (name), (direction), (mem_ctx), (mapped_name))

#define SMB_VFS_FSCTL(fsp, ctx, function, req_flags, in_data, in_len, out_data, max_out_len, out_len) \
	smb_vfs_call_fsctl((fsp)->conn->vfs_handles, (fsp), (ctx), (function), (req_flags), (in_data), (in_len), (out_data), (max_out_len), (out_len))

#define SMB_VFS_NEXT_FSCTL(handle, fsp, ctx, function, req_flags, in_data, in_len, out_data, max_out_len, out_len) \
	smb_vfs_call_fsctl((handle)->next, (fsp), (ctx), (function), (req_flags), (in_data), (in_len), (out_data), (max_out_len), (out_len))

#define SMB_VFS_FGET_NT_ACL(fsp, security_info, mem_ctx, ppdesc)		\
		smb_vfs_call_fget_nt_acl((fsp)->conn->vfs_handles, (fsp), (security_info), (mem_ctx), (ppdesc))
#define SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info, mem_ctx, ppdesc) \
	smb_vfs_call_fget_nt_acl((handle)->next, (fsp), (security_info), (mem_ctx), (ppdesc))

#define SMB_VFS_GET_NT_ACL(conn, name, security_info, mem_ctx, ppdesc)	\
	smb_vfs_call_get_nt_acl((conn)->vfs_handles, (name), (security_info), (mem_ctx), (ppdesc))
#define SMB_VFS_NEXT_GET_NT_ACL(handle, name, security_info, mem_ctx, ppdesc) \
	smb_vfs_call_get_nt_acl((handle)->next, (name), (security_info), (mem_ctx), (ppdesc))

#define SMB_VFS_AUDIT_FILE(conn, name, sacl, access_requested, access_denied) \
	smb_vfs_call_audit_file((conn)->vfs_handles, (name), (sacl), (access_requested), (access_denied))
#define SMB_VFS_NEXT_AUDIT_FILE(handle, name, sacl, access_requested, access_denied) \
	smb_vfs_call_audit_file((handle)->next, (name), (sacl), (access_requested), (access_denied))

#define SMB_VFS_FSET_NT_ACL(fsp, security_info_sent, psd) \
	smb_vfs_call_fset_nt_acl((fsp)->conn->vfs_handles, (fsp), (security_info_sent), (psd))
#define SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd) \
	smb_vfs_call_fset_nt_acl((handle)->next, (fsp), (security_info_sent), (psd))

#define SMB_VFS_CHMOD_ACL(conn, name, mode) \
	smb_vfs_call_chmod_acl((conn)->vfs_handles, (name), (mode))
#define SMB_VFS_NEXT_CHMOD_ACL(handle, name, mode) \
	smb_vfs_call_chmod_acl((handle)->next, (name), (mode))

#define SMB_VFS_FCHMOD_ACL(fsp, mode) \
	smb_vfs_call_fchmod_acl((fsp)->conn->vfs_handles, (fsp), (mode))
#define SMB_VFS_NEXT_FCHMOD_ACL(handle, fsp, mode) \
	smb_vfs_call_fchmod_acl((handle)->next, (fsp), (mode))

#define SMB_VFS_SYS_ACL_GET_FILE(conn, path_p, type, mem_ctx)		\
	smb_vfs_call_sys_acl_get_file((conn)->vfs_handles, (path_p), (type), (mem_ctx))
#define SMB_VFS_NEXT_SYS_ACL_GET_FILE(handle, path_p, type, mem_ctx)		\
	smb_vfs_call_sys_acl_get_file((handle)->next, (path_p), (type), (mem_ctx))

#define SMB_VFS_SYS_ACL_GET_FD(fsp, mem_ctx) \
	smb_vfs_call_sys_acl_get_fd((fsp)->conn->vfs_handles, (fsp), (mem_ctx))
#define SMB_VFS_NEXT_SYS_ACL_GET_FD(handle, fsp, mem_ctx) \
	smb_vfs_call_sys_acl_get_fd((handle)->next, (fsp), (mem_ctx))

#define SMB_VFS_SYS_ACL_BLOB_GET_FILE(conn, path_p, mem_ctx, blob_description, blob)	\
	smb_vfs_call_sys_acl_blob_get_file((conn)->vfs_handles, (path_p), (mem_ctx), (blob_description), (blob))
#define SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FILE(handle, path_p, mem_ctx, blob_description, blob) \
	smb_vfs_call_sys_acl_blob_get_file((handle)->next, (path_p), (mem_ctx), (blob_description), (blob))

#define SMB_VFS_SYS_ACL_BLOB_GET_FD(fsp, mem_ctx, blob_description, blob)			\
	smb_vfs_call_sys_acl_blob_get_fd((fsp)->conn->vfs_handles, (fsp), (mem_ctx), (blob_description), (blob))
#define SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FD(handle, fsp, mem_ctx, blob_description, blob)	\
	smb_vfs_call_sys_acl_blob_get_fd((handle)->next, (fsp), mem_ctx, (blob_description), (blob))

#define SMB_VFS_SYS_ACL_SET_FILE(conn, name, acltype, theacl) \
	smb_vfs_call_sys_acl_set_file((conn)->vfs_handles, (name), (acltype), (theacl))
#define SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle, name, acltype, theacl) \
	smb_vfs_call_sys_acl_set_file((handle)->next, (name), (acltype), (theacl))

#define SMB_VFS_SYS_ACL_SET_FD(fsp, theacl) \
	smb_vfs_call_sys_acl_set_fd((fsp)->conn->vfs_handles, (fsp), (theacl))
#define SMB_VFS_NEXT_SYS_ACL_SET_FD(handle, fsp, theacl) \
	smb_vfs_call_sys_acl_set_fd((handle)->next, (fsp), (theacl))

#define SMB_VFS_SYS_ACL_DELETE_DEF_FILE(conn, path) \
	smb_vfs_call_sys_acl_delete_def_file((conn)->vfs_handles, (path))
#define SMB_VFS_NEXT_SYS_ACL_DELETE_DEF_FILE(handle, path) \
	smb_vfs_call_sys_acl_delete_def_file((handle)->next, (path))

#define SMB_VFS_GETXATTR(conn,path,name,value,size) \
	smb_vfs_call_getxattr((conn)->vfs_handles,(path),(name),(value),(size))
#define SMB_VFS_NEXT_GETXATTR(handle,path,name,value,size) \
	smb_vfs_call_getxattr((handle)->next,(path),(name),(value),(size))

#define SMB_VFS_FGETXATTR(fsp,name,value,size) \
	smb_vfs_call_fgetxattr((fsp)->conn->vfs_handles, (fsp), (name),(value),(size))
#define SMB_VFS_NEXT_FGETXATTR(handle,fsp,name,value,size) \
	smb_vfs_call_fgetxattr((handle)->next,(fsp),(name),(value),(size))

#define SMB_VFS_LISTXATTR(conn,path,list,size) \
	smb_vfs_call_listxattr((conn)->vfs_handles,(path),(list),(size))
#define SMB_VFS_NEXT_LISTXATTR(handle,path,list,size) \
	smb_vfs_call_listxattr((handle)->next,(path),(list),(size))

#define SMB_VFS_FLISTXATTR(fsp,list,size) \
	smb_vfs_call_flistxattr((fsp)->conn->vfs_handles, (fsp), (list),(size))
#define SMB_VFS_NEXT_FLISTXATTR(handle,fsp,list,size) \
	smb_vfs_call_flistxattr((handle)->next,(fsp),(list),(size))

#define SMB_VFS_REMOVEXATTR(conn,path,name) \
	smb_vfs_call_removexattr((conn)->vfs_handles,(path),(name))
#define SMB_VFS_NEXT_REMOVEXATTR(handle,path,name) \
	smb_vfs_call_removexattr((handle)->next,(path),(name))

#define SMB_VFS_FREMOVEXATTR(fsp,name) \
	smb_vfs_call_fremovexattr((fsp)->conn->vfs_handles, (fsp), (name))
#define SMB_VFS_NEXT_FREMOVEXATTR(handle,fsp,name) \
	smb_vfs_call_fremovexattr((handle)->next,(fsp),(name))

#define SMB_VFS_SETXATTR(conn,path,name,value,size,flags) \
	smb_vfs_call_setxattr((conn)->vfs_handles,(path),(name),(value),(size),(flags))
#define SMB_VFS_NEXT_SETXATTR(handle,path,name,value,size,flags) \
	smb_vfs_call_setxattr((handle)->next,(path),(name),(value),(size),(flags))

#define SMB_VFS_FSETXATTR(fsp,name,value,size,flags) \
	smb_vfs_call_fsetxattr((fsp)->conn->vfs_handles, (fsp), (name),(value),(size),(flags))
#define SMB_VFS_NEXT_FSETXATTR(handle,fsp,name,value,size,flags) \
	smb_vfs_call_fsetxattr((handle)->next,(fsp),(name),(value),(size),(flags))

#define SMB_VFS_AIO_FORCE(fsp) \
	smb_vfs_call_aio_force((fsp)->conn->vfs_handles, (fsp))
#define SMB_VFS_NEXT_AIO_FORCE(handle,fsp) \
	smb_vfs_call_aio_force((handle)->next,(fsp))

#define SMB_VFS_IS_OFFLINE(conn,fname,sbuf) \
	smb_vfs_call_is_offline((conn)->vfs_handles,(fname),(sbuf))
#define SMB_VFS_NEXT_IS_OFFLINE(handle,fname,sbuf) \
	smb_vfs_call_is_offline((handle)->next,(fname),(sbuf))

#define SMB_VFS_SET_OFFLINE(conn,fname) \
	smb_vfs_call_set_offline((conn)->vfs_handles,(fname))
#define SMB_VFS_NEXT_SET_OFFLINE(handle,fname) \
	smb_vfs_call_set_offline((handle)->next, (fname))

/* durable handle operations */

#define SMB_VFS_DURABLE_COOKIE(fsp, mem_ctx, cookie) \
	smb_vfs_call_durable_cookie((fsp)->conn->vfs_handles, \
				    (fsp), (mem_ctx), (cookie))
#define SMB_VFS_NEXT_DURABLE_COOKIE(handle, fsp, mem_ctx, cookie) \
	smb_vfs_call_durable_cookie(((handle)->next, \
				    (fsp), (mem_ctx), (cookie))

#define SMB_VFS_DURABLE_DISCONNECT(fsp, old_cookie, mem_ctx, new_cookie) \
	smb_vfs_call_durable_disconnect((fsp)->conn->vfs_handles, \
					(fsp), (old_cookie), (mem_ctx), (new_cookie))
#define SMB_VFS_NEXT_DURABLE_DISCONNECT(handle, fsp, old_cookie, mem_ctx, new_cookie) \
	smb_vfs_call_durable_disconnect((handle)->next, \
					(fsp), (old_cookie), (mem_ctx), (new_cookie))

#define SMB_VFS_DURABLE_RECONNECT(conn, smb1req, op, old_cookie, mem_ctx, fsp, new_cookie) \
	smb_vfs_call_durable_reconnect((conn)->vfs_handles, \
				       (smb1req), (op), (old_cookie), \
				       (mem_ctx), (fsp), (new_cookie))
#define SMB_VFS_NEXT_DURABLE_RECONNECT(handle, smb1req, op, old_cookie, mem_ctx, fsp, new_cookie) \
	smb_vfs_call_durable_reconnect((handle)->next, \
					(smb1req), (op), (old_cookie), \
					(mem_ctx), (fsp), (new_cookie))

#endif /* _VFS_MACROS_H */
