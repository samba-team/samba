/*

 * LTTNG VFS module for samba. Trace VFS functions using lttng

 * Copyright (C) Dongmao Zhang <deanraccoon@gmail.com>

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

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER vfs_lttng

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "modules/vfs_lttng_tp.h"

#if !defined(VFS_LTTNG_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define VFS_LTTNG_TP_H

#include <lttng/tracepoint.h>
#include <includes.h> 
    
/* vfs_lttng_connect START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_connect_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_connect_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_connect END*/

/* vfs_lttng_disconnect START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_disconnect_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_disconnect_exit,
    TP_ARGS(
    ),
    TP_FIELDS(
    )
)
/* vfs_lttng_disconnect END*/

/* vfs_lttng_disk_free START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_disk_free_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_disk_free_exit,
    TP_ARGS(
        uint64_t, result
    ),
    TP_FIELDS(
        ctf_integer(uint64_t, retval, result)
    )
)
/* vfs_lttng_disk_free END*/

/* vfs_lttng_get_quota START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_quota_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_quota_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_get_quota END*/

/* vfs_lttng_set_quota START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_set_quota_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_set_quota_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_set_quota END*/

/* vfs_lttng_get_shadow_copy_data START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_shadow_copy_data_enter,
    TP_ARGS(
        struct files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_shadow_copy_data_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_get_shadow_copy_data END*/

/* vfs_lttng_statvfs START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_statvfs_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_statvfs_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_statvfs END*/

/* vfs_lttng_fs_capabilities START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fs_capabilities_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fs_capabilities_exit,
    TP_ARGS(
        uint32_t, result
    ),
    TP_FIELDS(
        ctf_integer(uint32_t, retval, result)
    )
)
/* vfs_lttng_fs_capabilities END*/

/* vfs_lttng_get_dfs_referrals START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_dfs_referrals_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_dfs_referrals_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_get_dfs_referrals END*/

/* vfs_lttng_opendir START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_opendir_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_opendir_exit,
    TP_ARGS(
    ),
    TP_FIELDS(
    )
)
/* vfs_lttng_opendir END*/

/* vfs_lttng_fdopendir START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fdopendir_enter,
    TP_ARGS(
        files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fdopendir_exit,
    TP_ARGS(
    ),
    TP_FIELDS(
    )
)
/* vfs_lttng_fdopendir END*/

/* vfs_lttng_readdir START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_readdir_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_readdir_exit,
    TP_ARGS(
    ),
    TP_FIELDS(
    )
)
/* vfs_lttng_readdir END*/

/* vfs_lttng_seekdir START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_seekdir_enter,
    TP_ARGS(
        long, offset
    ),
    TP_FIELDS(
        ctf_integer(off_t, offset, offset)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_seekdir_exit,
    TP_ARGS(
    ),
    TP_FIELDS(
    )
)
/* vfs_lttng_seekdir END*/

/* vfs_lttng_telldir START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_telldir_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_telldir_exit,
    TP_ARGS(
        long, result
    ),
    TP_FIELDS(
        ctf_integer(long, retval, result)
    )
)
/* vfs_lttng_telldir END*/

/* vfs_lttng_mkdir START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_mkdir_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname,
        mode_t, mode
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
        ctf_integer(mode_t, mode, mode)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_mkdir_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_mkdir END*/

/* vfs_lttng_rmdir START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_rmdir_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_rmdir_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_rmdir END*/

/* vfs_lttng_closedir START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_closedir_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_closedir_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_closedir END*/

/* vfs_lttng_open START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_open_enter,
    TP_ARGS(
        struct smb_filename *, fname,
        int, flags,
        mode_t, mode
    ),
    TP_FIELDS(
        ctf_string(filename, fname->base_name)
        ctf_integer(int, flags, flags)
        ctf_integer(mode_t, mode, mode)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_open_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_open END*/

/* vfs_lttng_create_file START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_create_file_enter,
    TP_ARGS(
        struct smb_filename *, fname
    ),
    TP_FIELDS(
        ctf_string(filename, fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_create_file_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_create_file END*/

/* vfs_lttng_close START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_close_enter,
    TP_ARGS(
        files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_close_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_close END*/


/* vfs_lttng_pread START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_pread_enter,
    TP_ARGS(
        files_struct *, fsp,
        size_t, n,
        off_t, offset
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
        ctf_integer(size_t, n, n)
        ctf_integer(off_t, offset, offset)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_pread_exit,
    TP_ARGS(
        ssize_t, result
    ),
    TP_FIELDS(
        ctf_integer(ssize_t, retval, result)
    )
)
/* vfs_lttng_pread END*/


/* vfs_lttng_pwrite START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_pwrite_enter,
    TP_ARGS(
        files_struct *, fsp,
        size_t, n,
        off_t, offset
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
        ctf_integer(size_t, n, n)
        ctf_integer(off_t, offset, offset)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_pwrite_exit,
    TP_ARGS(
        ssize_t, result
    ),
    TP_FIELDS(
        ctf_integer(ssize_t, retval, result)
    )
)
/* vfs_lttng_pwrite END*/

/* vfs_lttng_lseek START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_lseek_enter,
    TP_ARGS(
        files_struct *, fsp,
        off_t, offset
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
        ctf_integer(off_t, offset, offset)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_lseek_exit,
    TP_ARGS(
        off_t, result
    ),
    TP_FIELDS(
        ctf_integer(off_t, retval, result)
    )
)
/* vfs_lttng_lseek END*/

/* vfs_lttng_sendfile START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sendfile_enter,
    TP_ARGS(
        int, tofd,
        off_t, offset,
        size_t, n
    ),
    TP_FIELDS(
        ctf_integer(int, tofd, tofd)
        ctf_integer(off_t, offset, offset)
        ctf_integer(size_t, n, n)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sendfile_exit,
    TP_ARGS(
        ssize_t, result
    ),
    TP_FIELDS(
        ctf_integer(ssize_t, retval, result)
    )
)
/* vfs_lttng_sendfile END*/

/* vfs_lttng_recvfile START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_recvfile_enter,
    TP_ARGS(
        off_t, offset,
        size_t, n
    ),
    TP_FIELDS(
        ctf_integer(off_t, offset, offset)
        ctf_integer(size_t, n, n)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_recvfile_exit,
    TP_ARGS(
        ssize_t, result
    ),
    TP_FIELDS(
        ctf_integer(ssize_t, retval, result)
    )
)
/* vfs_lttng_recvfile END*/

/* vfs_lttng_rename START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_rename_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_rename_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_rename END*/

/* vfs_lttng_stat START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_stat_enter,
    TP_ARGS(
        struct smb_filename *, fname
    ),
    TP_FIELDS(
        ctf_string(filename, fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_stat_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_stat END*/

/* vfs_lttng_fstat START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fstat_enter,
    TP_ARGS(
        files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fstat_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_fstat END*/

/* vfs_lttng_lstat START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_lstat_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_lstat_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_lstat END*/

/* vfs_lttng_get_alloc_size START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_alloc_size_enter,
    TP_ARGS(
    ),
    TP_FIELDS(
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_alloc_size_exit,
    TP_ARGS(
        uint64_t, result
    ),
    TP_FIELDS(
        ctf_integer(uint64_t, retval, result)
    )
)
/* vfs_lttng_get_alloc_size END*/

/* vfs_lttng_unlink START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_unlink_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_unlink_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_unlink END*/

/* vfs_lttng_chmod START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_chmod_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname,
        mode_t, mode
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
        ctf_integer(mode_t, mode, mode)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_chmod_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_chmod END*/

/* vfs_lttng_fchmod START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fchmod_enter,
    TP_ARGS(
        files_struct *, fsp,
        mode_t, mode
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
        ctf_integer(mode_t, mode, mode)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fchmod_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_fchmod END*/

/* vfs_lttng_chown START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_chown_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_chown_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_chown END*/

/* vfs_lttng_fchown START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fchown_enter,
    TP_ARGS(
        files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fchown_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_fchown END*/

/* vfs_lttng_lchown START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_lchown_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_lchown_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_lchown END*/

/* vfs_lttng_chdir START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_chdir_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_chdir_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_chdir END*/

/* vfs_lttng_getwd START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_getwd_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_getwd_exit,
    TP_ARGS(
    ),
    TP_FIELDS(
    )
)
/* vfs_lttng_getwd END*/

/* vfs_lttng_ntimes START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_ntimes_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_ntimes_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_ntimes END*/

/* vfs_lttng_ftruncate START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_ftruncate_enter,
    TP_ARGS(
        files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_ftruncate_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_ftruncate END*/

/* vfs_lttng_fallocate START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fallocate_enter,
    TP_ARGS(
        files_struct *, fsp,
        uint32_t, mode,
        off_t, offset
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
        ctf_integer(mode_t, mode, mode)
        ctf_integer(off_t, offset, offset)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fallocate_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_fallocate END*/

/* vfs_lttng_lock START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_lock_enter,
    TP_ARGS(
        files_struct *, fsp,
        off_t, offset
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
        ctf_integer(off_t, offset, offset)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_lock_exit,
    TP_ARGS(
        bool, result
    ),
    TP_FIELDS(
        ctf_integer(bool, retval, result)
    )
)
/* vfs_lttng_lock END*/

/* vfs_lttng_kernel_flock START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_kernel_flock_enter,
    TP_ARGS(
        struct files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_kernel_flock_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_kernel_flock END*/

/* vfs_lttng_linux_setlease START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_linux_setlease_enter,
    TP_ARGS(
        files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_linux_setlease_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_linux_setlease END*/

/* vfs_lttng_getlock START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_getlock_enter,
    TP_ARGS(
        files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_getlock_exit,
    TP_ARGS(
        bool, result
    ),
    TP_FIELDS(
        ctf_integer(bool, retval, result)
    )
)
/* vfs_lttng_getlock END*/

/* vfs_lttng_symlink START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_symlink_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_symlink_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_symlink END*/

/* vfs_lttng_readlink START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_readlink_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_readlink_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_readlink END*/

/* vfs_lttng_link START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_link_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_link_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_link END*/

/* vfs_lttng_mknod START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_mknod_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname,
        mode_t, mode
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
        ctf_integer(mode_t, mode, mode)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_mknod_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_mknod END*/

/* vfs_lttng_realpath START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_realpath_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_realpath_exit,
    TP_ARGS(
    ),
    TP_FIELDS(
    )
)
/* vfs_lttng_realpath END*/

/* vfs_lttng_chflags START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_chflags_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname,
        unsigned int, flags
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
        ctf_integer(int, flags, flags)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_chflags_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_chflags END*/

/* vfs_lttng_file_id_create START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_file_id_create_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_file_id_create_exit,
    TP_ARGS(
    ),
    TP_FIELDS(
    )
)
/* vfs_lttng_file_id_create END*/

/* vfs_lttng_offload_read_send START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_offload_read_send_enter,
    TP_ARGS(
        struct files_struct *, fsp,
        off_t, offset
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
        ctf_integer(off_t, offset, offset)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_offload_read_send_exit,
    TP_ARGS(
    ),
    TP_FIELDS(
    )
)
/* vfs_lttng_offload_read_send END*/

/* vfs_lttng_offload_read_recv START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_offload_read_recv_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_offload_read_recv_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_offload_read_recv END*/

/* vfs_lttng_offload_write_send START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_offload_write_send_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_offload_write_send_exit,
    TP_ARGS(
    ),
    TP_FIELDS(
    )
)
/* vfs_lttng_offload_write_send END*/

/* vfs_lttng_offload_write_recv START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_offload_write_recv_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_offload_write_recv_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_offload_write_recv END*/

/* vfs_lttng_get_compression START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_compression_enter,
    TP_ARGS(
        struct files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_compression_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_get_compression END*/

/* vfs_lttng_set_compression START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_set_compression_enter,
    TP_ARGS(
        struct files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_set_compression_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_set_compression END*/

/* vfs_lttng_snap_check_path START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_snap_check_path_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_snap_check_path_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_snap_check_path END*/

/* vfs_lttng_snap_create START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_snap_create_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_snap_create_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_snap_create END*/

/* vfs_lttng_snap_delete START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_snap_delete_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_snap_delete_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_snap_delete END*/

/* vfs_lttng_streaminfo START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_streaminfo_enter,
    TP_ARGS(
        struct files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_streaminfo_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_streaminfo END*/

/* vfs_lttng_get_real_filename START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_real_filename_enter,
    TP_ARGS(
        const char *, name
    ),
    TP_FIELDS(
        ctf_string(name, name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_real_filename_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_get_real_filename END*/

/* vfs_lttng_connectpath START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_connectpath_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_connectpath_exit,
    TP_ARGS(
    ),
    TP_FIELDS(
    )
)
/* vfs_lttng_connectpath END*/

/* vfs_lttng_brl_lock_windows START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_brl_lock_windows_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_brl_lock_windows_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_brl_lock_windows END*/

/* vfs_lttng_brl_unlock_windows START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_brl_unlock_windows_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_brl_unlock_windows_exit,
    TP_ARGS(
        bool, result
    ),
    TP_FIELDS(
        ctf_integer(bool, retval, result)
    )
)
/* vfs_lttng_brl_unlock_windows END*/

/* vfs_lttng_brl_cancel_windows START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_brl_cancel_windows_enter,
    TP_ARGS(
        
    ),
    TP_FIELDS(
        
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_brl_cancel_windows_exit,
    TP_ARGS(
        bool, result
    ),
    TP_FIELDS(
        ctf_integer(bool, retval, result)
    )
)
/* vfs_lttng_brl_cancel_windows END*/

/* vfs_lttng_strict_lock_check START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_strict_lock_check_enter,
    TP_ARGS(
        struct files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_strict_lock_check_exit,
    TP_ARGS(
        bool, result
    ),
    TP_FIELDS(
        ctf_integer(bool, retval, result)
    )
)
/* vfs_lttng_strict_lock_check END*/

/* vfs_lttng_translate_name START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_translate_name_enter,
    TP_ARGS(
        const char *, name
    ),
    TP_FIELDS(
        ctf_string(name, name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_translate_name_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_translate_name END*/

/* vfs_lttng_fsctl START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fsctl_enter,
    TP_ARGS(
        struct files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fsctl_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_fsctl END*/

/* vfs_lttng_get_dos_attributes START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_dos_attributes_enter,
    TP_ARGS(
        struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_dos_attributes_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_get_dos_attributes END*/

/* vfs_lttng_fget_dos_attributes START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fget_dos_attributes_enter,
    TP_ARGS(
        struct files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fget_dos_attributes_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_fget_dos_attributes END*/

/* vfs_lttng_set_dos_attributes START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_set_dos_attributes_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_set_dos_attributes_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_set_dos_attributes END*/

/* vfs_lttng_fset_dos_attributes START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fset_dos_attributes_enter,
    TP_ARGS(
        struct files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fset_dos_attributes_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_fset_dos_attributes END*/

/* vfs_lttng_fget_nt_acl START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fget_nt_acl_enter,
    TP_ARGS(
        files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fget_nt_acl_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_fget_nt_acl END*/

/* vfs_lttng_get_nt_acl START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_nt_acl_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_get_nt_acl_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_get_nt_acl END*/

/* vfs_lttng_fset_nt_acl START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fset_nt_acl_enter,
    TP_ARGS(
        files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fset_nt_acl_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_fset_nt_acl END*/

/* vfs_lttng_audit_file START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_audit_file_enter,
    TP_ARGS(
        struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_audit_file_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_audit_file END*/

/* vfs_lttng_sys_acl_get_file START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sys_acl_get_file_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sys_acl_get_file_exit,
    TP_ARGS(
        SMB_ACL_T, result
    ),
    TP_FIELDS(
        ctf_integer(SMB_ACL_T, retval, result)
    )
)
/* vfs_lttng_sys_acl_get_file END*/

/* vfs_lttng_sys_acl_get_fd START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sys_acl_get_fd_enter,
    TP_ARGS(
        files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sys_acl_get_fd_exit,
    TP_ARGS(
        SMB_ACL_T, result
    ),
    TP_FIELDS(
        ctf_integer(SMB_ACL_T, retval, result)
    )
)
/* vfs_lttng_sys_acl_get_fd END*/

/* vfs_lttng_sys_acl_blob_get_file START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sys_acl_blob_get_file_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sys_acl_blob_get_file_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_sys_acl_blob_get_file END*/

/* vfs_lttng_sys_acl_blob_get_fd START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sys_acl_blob_get_fd_enter,
    TP_ARGS(
        files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sys_acl_blob_get_fd_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_sys_acl_blob_get_fd END*/

/* vfs_lttng_sys_acl_set_file START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sys_acl_set_file_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sys_acl_set_file_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_sys_acl_set_file END*/

/* vfs_lttng_sys_acl_set_fd START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sys_acl_set_fd_enter,
    TP_ARGS(
        files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sys_acl_set_fd_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_sys_acl_set_fd END*/

/* vfs_lttng_sys_acl_delete_def_file START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sys_acl_delete_def_file_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_sys_acl_delete_def_file_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_sys_acl_delete_def_file END*/

/* vfs_lttng_getxattr START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_getxattr_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname,
        const char *, name
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
        ctf_string(name, name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_getxattr_exit,
    TP_ARGS(
        ssize_t, result
    ),
    TP_FIELDS(
        ctf_integer(ssize_t, retval, result)
    )
)
/* vfs_lttng_getxattr END*/

/* vfs_lttng_fgetxattr START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fgetxattr_enter,
    TP_ARGS(
        struct files_struct *, fsp,
        const char *, name
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
        ctf_string(name, name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fgetxattr_exit,
    TP_ARGS(
        ssize_t, result
    ),
    TP_FIELDS(
        ctf_integer(ssize_t, retval, result)
    )
)
/* vfs_lttng_fgetxattr END*/

/* vfs_lttng_listxattr START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_listxattr_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_listxattr_exit,
    TP_ARGS(
        ssize_t, result
    ),
    TP_FIELDS(
        ctf_integer(ssize_t, retval, result)
    )
)
/* vfs_lttng_listxattr END*/

/* vfs_lttng_flistxattr START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_flistxattr_enter,
    TP_ARGS(
        struct files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_flistxattr_exit,
    TP_ARGS(
        ssize_t, result
    ),
    TP_FIELDS(
        ctf_integer(ssize_t, retval, result)
    )
)
/* vfs_lttng_flistxattr END*/

/* vfs_lttng_removexattr START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_removexattr_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname,
        const char *, name
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
        ctf_string(name, name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_removexattr_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_removexattr END*/

/* vfs_lttng_fremovexattr START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fremovexattr_enter,
    TP_ARGS(
        struct files_struct *, fsp,
        const char *, name
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
        ctf_string(name, name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fremovexattr_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_fremovexattr END*/

/* vfs_lttng_setxattr START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_setxattr_enter,
    TP_ARGS(
        const struct smb_filename *, smb_fname,
        const char *, name,
        int, flags
    ),
    TP_FIELDS(
        ctf_string(filename, smb_fname->base_name)
        ctf_string(name, name)
        ctf_integer(int, flags, flags)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_setxattr_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_setxattr END*/

/* vfs_lttng_fsetxattr START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fsetxattr_enter,
    TP_ARGS(
        struct files_struct *, fsp,
        const char *, name,
        int, flags
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
        ctf_string(name, name)
        ctf_integer(int, flags, flags)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_fsetxattr_exit,
    TP_ARGS(
        int, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result)
    )
)
/* vfs_lttng_fsetxattr END*/

/* vfs_lttng_aio_force START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_aio_force_enter,
    TP_ARGS(
        struct files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_aio_force_exit,
    TP_ARGS(
        bool, result
    ),
    TP_FIELDS(
        ctf_integer(bool, retval, result)
    )
)
/* vfs_lttng_aio_force END*/

/* vfs_lttng_durable_cookie START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_durable_cookie_enter,
    TP_ARGS(
        struct files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_durable_cookie_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_durable_cookie END*/

/* vfs_lttng_durable_disconnect START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_durable_disconnect_enter,
    TP_ARGS(
        struct files_struct *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, fsp->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_durable_disconnect_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_durable_disconnect END*/

/* vfs_lttng_durable_reconnect START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_durable_reconnect_enter,
    TP_ARGS(
        struct files_struct * *, fsp
    ),
    TP_FIELDS(
        ctf_string(filename, (*fsp)->fsp_name->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_durable_reconnect_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_durable_reconnect END*/

/* vfs_lttng_readdir_attr START*/
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_readdir_attr_enter,
    TP_ARGS(
        const struct smb_filename *, fname
    ),
    TP_FIELDS(
        ctf_string(filename, fname->base_name)
    )
)
TRACEPOINT_EVENT(
    vfs_lttng,
    vfs_lttng_readdir_attr_exit,
    TP_ARGS(
        NTSTATUS, result
    ),
    TP_FIELDS(
        ctf_integer(int, retval, result.v)
    )
)
/* vfs_lttng_readdir_attr END*/

#endif /* VFS_LTTNG_TP_H */
#include <lttng/tracepoint-event.h>
    
