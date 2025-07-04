/*
   Unix SMB/Netbios implementation.
   SMB client library implementation
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Richard Sharpe 2000, 2002
   Copyright (C) John Terpstra 2000
   Copyright (C) Tom Jansen (Ninja ISD) 2002
   Copyright (C) Derrell Lipman 2003-2008
   Copyright (C) Jeremy Allison 2007, 2008

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
#include "source3/include/client.h"
#include "source3/libsmb/proto.h"
#include "libsmbclient.h"
#include "libsmb_internal.h"
#include "../libcli/smb/smbXcli_base.h"
#include "lib/util/time.h"

/*
 * Generate an inode number from file name for those things that need it
 */

static ino_t generate_inode(const char *name)
{
	if (name == NULL) {
		return (ino_t)-1;
	}
	return (ino_t)str_checksum(name);
}

/*
 * Routine to put basic stat info into a stat structure ... Used by stat and
 * fstat below.
 */

void setup_stat(struct stat *st,
		const char *fname,
		off_t size,
		int attr,
		ino_t ino,
		dev_t dev,
		struct timespec access_time_ts,
		struct timespec change_time_ts,
		struct timespec write_time_ts)
{
	st->st_mode = 0;

	if (attr & FILE_ATTRIBUTE_DIRECTORY) {
		st->st_mode = (S_IFDIR | 0555);
	} else {
		st->st_mode = (S_IFREG | 0444);
	}

	if (attr & FILE_ATTRIBUTE_ARCHIVE) {
		st->st_mode |= S_IXUSR;
	}
	if (attr & FILE_ATTRIBUTE_SYSTEM) {
		st->st_mode |= S_IXGRP;
	}
	if (attr & FILE_ATTRIBUTE_HIDDEN) {
		st->st_mode |= S_IXOTH;
	}
	if (!(attr & FILE_ATTRIBUTE_READONLY)) {
		st->st_mode |= S_IWUSR;
	}

	st->st_size = size;
#ifdef HAVE_STAT_ST_BLKSIZE
	st->st_blksize = 512;
#endif
#ifdef HAVE_STAT_ST_BLOCKS
	st->st_blocks = (size+511)/512;
#endif
#ifdef HAVE_STRUCT_STAT_ST_RDEV
	st->st_rdev = 0;
#endif
	st->st_uid = getuid();
	st->st_gid = getgid();

	if (attr & FILE_ATTRIBUTE_DIRECTORY) {
		st->st_nlink = 2;
	} else {
		st->st_nlink = 1;
	}

	if (ino != 0) {
		st->st_ino = ino;
	} else {
		st->st_ino = generate_inode(fname);
	}

	st->st_dev = dev;

	st->st_atime = access_time_ts.tv_sec;
	set_atimensec(st, access_time_ts.tv_nsec);

	st->st_ctime = change_time_ts.tv_sec;
	set_ctimensec(st, change_time_ts.tv_nsec);

	st->st_mtime = write_time_ts.tv_sec;
	set_mtimensec(st, write_time_ts.tv_nsec);
}

/*
 * Routine to stat a file given a name
 */

int
SMBC_stat_ctx(SMBCCTX *context,
              const char *fname,
              struct stat *st)
{
	SMBCSRV *srv = NULL;
	char *server = NULL;
	char *share = NULL;
	char *user = NULL;
	char *password = NULL;
	char *workgroup = NULL;
	char *path = NULL;
	uint16_t port = 0;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();

	if (!context || !context->internal->initialized) {
		TALLOC_FREE(frame);
		errno = EINVAL;  /* Best I can think of ... */
		return -1;
	}

	if (!fname) {
		TALLOC_FREE(frame);
		errno = EINVAL;
		return -1;
	}

	DEBUG(4, ("smbc_stat(%s)\n", fname));

	if (SMBC_parse_path(frame,
                            context,
                            fname,
                            &workgroup,
                            &server,
                            &port,
                            &share,
                            &path,
                            &user,
                            &password,
                            NULL)) {
		TALLOC_FREE(frame);
		errno = EINVAL;
                return -1;
        }

	if (!user || user[0] == (char)0) {
		user = talloc_strdup(frame, smbc_getUser(context));
		if (!user) {
			TALLOC_FREE(frame);
			errno = ENOMEM;
			return -1;
		}
	}

	srv = SMBC_server(frame, context, True,
                          server, port, share, &workgroup, &user, &password);
	if (!srv) {
		int err = errno;
		TALLOC_FREE(frame);
		errno = err;
		return -1;  /* errno set by SMBC_server */
	}

	status = SMBC_getatr(context, srv, path, st);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		errno = cli_status_to_errno(status);
		return -1;
	}

	TALLOC_FREE(frame);
	return 0;
}

/*
 * Routine to stat a file given an fd
 */

int
SMBC_fstat_ctx(SMBCCTX *context,
               SMBCFILE *file,
               struct stat *st)
{
	struct timespec change_time_ts;
        struct timespec access_time_ts;
        struct timespec write_time_ts;
	off_t size;
	uint32_t attr;
	char *server = NULL;
	char *share = NULL;
	char *user = NULL;
	char *password = NULL;
	char *path = NULL;
        char *targetpath = NULL;
	struct cli_state *targetcli = NULL;
	SMB_INO_T ino = 0;
	uint16_t port = 0;
	struct cli_credentials *creds = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	if (!context || !context->internal->initialized) {
		TALLOC_FREE(frame);
		errno = EINVAL;
		return -1;
	}

	if (!SMBC_dlist_contains(context->internal->files, file)) {
		TALLOC_FREE(frame);
		errno = EBADF;
		return -1;
	}

	if (!file->file) {
		TALLOC_FREE(frame);
		return smbc_getFunctionFstatdir(context)(context, file, st);
	}

	/*d_printf(">>>fstat: parsing %s\n", file->fname);*/
	if (SMBC_parse_path(frame,
                            context,
                            file->fname,
                            NULL,
                            &server,
                            &port,
                            &share,
                            &path,
                            &user,
                            &password,
                            NULL)) {
		TALLOC_FREE(frame);
                errno = EINVAL;
                return -1;
        }

	creds = context->internal->creds;

	/*d_printf(">>>fstat: resolving %s\n", path);*/
	status = cli_resolve_path(frame, "",
				  creds,
				  file->srv->cli, path,
				  &targetcli, &targetpath);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Could not resolve %s\n", path);
		TALLOC_FREE(frame);
                errno = ENOENT;
		return -1;
	}
	/*d_printf(">>>fstat: resolved path as %s\n", targetpath);*/

	if (!NT_STATUS_IS_OK(cli_qfileinfo_basic(
				     targetcli, file->cli_fd, &attr, &size,
				     NULL,
				     &access_time_ts,
				     &write_time_ts,
				     &change_time_ts,
				     &ino))) {
		TALLOC_FREE(frame);
		errno = EINVAL;
		return -1;
	}

	setup_stat(st,
		path,
		size,
		attr,
		ino,
		file->srv->dev,
		access_time_ts,
		change_time_ts,
		write_time_ts);

	TALLOC_FREE(frame);
	return 0;
}


/*
 * Routine to obtain file system information given a path
 */
int
SMBC_statvfs_ctx(SMBCCTX *context,
                 char *path,
                 struct statvfs *st)
{
        int             ret;
        bool            bIsDir;
        struct stat     statbuf;
        SMBCFILE *      pFile;
	TALLOC_CTX *frame = talloc_stackframe();

        /* Determine if the provided path is a file or a folder */
        if (SMBC_stat_ctx(context, path, &statbuf) < 0) {
		int err = errno;
		TALLOC_FREE(frame);
		errno = err;
                return -1;
        }

        /* Is it a file or a directory?  */
        if (S_ISDIR(statbuf.st_mode)) {
                /* It's a directory. */
                if ((pFile = SMBC_opendir_ctx(context, path)) == NULL) {
			int err = errno;
			TALLOC_FREE(frame);
			errno = err;
                        return -1;
                }
                bIsDir = true;
        } else if (S_ISREG(statbuf.st_mode)) {
                /* It's a file. */
                if ((pFile = SMBC_open_ctx(context, path,
                                           O_RDONLY, 0)) == NULL) {
			int err = errno;
			TALLOC_FREE(frame);
			errno = err;
                        return -1;
                }
                bIsDir = false;
        } else {
                /* It's neither a file nor a directory. Not supported. */
		TALLOC_FREE(frame);
                errno = ENOSYS;
                return -1;
        }

        /* Now we have an open file handle, so just use SMBC_fstatvfs */
        ret = SMBC_fstatvfs_ctx(context, pFile, st);

        /* Close the file or directory */
        if (bIsDir) {
                SMBC_closedir_ctx(context, pFile);
        } else {
                SMBC_close_ctx(context, pFile);
        }

	TALLOC_FREE(frame);
        return ret;
}


/*
 * Routine to obtain file system information given an fd
 */

int
SMBC_fstatvfs_ctx(SMBCCTX *context,
                  SMBCFILE *file,
                  struct statvfs *st)
{
        unsigned long flags = 0;
	uint32_t fs_attrs = 0;
	struct cli_state *cli = file->srv->cli;
	struct smbXcli_tcon *tcon;
	TALLOC_CTX *frame = talloc_stackframe();

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		tcon = cli->smb2.tcon;
	} else {
		tcon = cli->smb1.tcon;
	}

        /* Initialize all fields (at least until we actually use them) */
	ZERO_STRUCTP(st);

        /*
         * The state of each flag is such that the same bits are unset as
         * would typically be unset on a local file system on a POSIX OS. Thus
         * the bit is on, for example, only for case-insensitive file systems
         * since most POSIX file systems are case sensitive and fstatvfs()
         * would typically return zero in these bits on such a local file
         * system.
         */

        /* See if the server has UNIX CIFS support */
        if (! SERVER_HAS_UNIX_CIFS(cli)) {
                uint64_t total_allocation_units;
                uint64_t caller_allocation_units;
                uint64_t actual_allocation_units;
                uint64_t sectors_per_allocation_unit;
                uint64_t bytes_per_sector;
		NTSTATUS status;

                /* Nope. If size data is available... */
		status = cli_get_fs_full_size_info(cli,
						   &total_allocation_units,
						   &caller_allocation_units,
						   &actual_allocation_units,
						   &sectors_per_allocation_unit,
						   &bytes_per_sector);
		if (NT_STATUS_IS_OK(status)) {

                        /* ... then provide it */
                        st->f_bsize =
                                (unsigned long) bytes_per_sector;
#ifdef HAVE_FRSIZE
                        st->f_frsize =
                                (unsigned long) sectors_per_allocation_unit;
#endif
                        st->f_blocks =
                                (fsblkcnt_t) total_allocation_units;
                        st->f_bfree =
                                (fsblkcnt_t) actual_allocation_units;
                        st->f_bavail =
                                (fsblkcnt_t) caller_allocation_units;
                }

                flags |= SMBC_VFS_FEATURE_NO_UNIXCIFS;
        } else {
                uint32_t optimal_transfer_size;
                uint32_t block_size;
                uint64_t total_blocks;
                uint64_t blocks_available;
                uint64_t user_blocks_available;
                uint64_t total_file_nodes;
                uint64_t free_file_nodes;
                uint64_t fs_identifier;
		NTSTATUS status;

                /* Has UNIXCIFS. If POSIX filesystem info is available... */
		status = cli_get_posix_fs_info(cli,
					       &optimal_transfer_size,
					       &block_size,
					       &total_blocks,
					       &blocks_available,
					       &user_blocks_available,
					       &total_file_nodes,
					       &free_file_nodes,
					       &fs_identifier);
		if (NT_STATUS_IS_OK(status)) {

                        /* ... then what's provided here takes precedence. */
                        st->f_bsize =
                                (unsigned long) block_size;
                        st->f_blocks =
                                (fsblkcnt_t) total_blocks;
                        st->f_bfree =
                                (fsblkcnt_t) blocks_available;
                        st->f_bavail =
                                (fsblkcnt_t) user_blocks_available;
                        st->f_files =
                                (fsfilcnt_t) total_file_nodes;
                        st->f_ffree =
                                (fsfilcnt_t) free_file_nodes;
#ifdef HAVE_FSID_INT
                        st->f_fsid =
                                (unsigned long) fs_identifier;
#endif
                }
        }

        /* See if the share is case sensitive */
        if (!NT_STATUS_IS_OK(cli_get_fs_attr_info(cli, &fs_attrs))) {
                /*
                 * We can't determine the case sensitivity of
                 * the share. We have no choice but to use the
                 * user-specified case sensitivity setting.
                 */
                if (! smbc_getOptionCaseSensitive(context)) {
                        flags |= SMBC_VFS_FEATURE_CASE_INSENSITIVE;
                }
        } else {
                if (! (fs_attrs & FILE_CASE_SENSITIVE_SEARCH)) {
                        flags |= SMBC_VFS_FEATURE_CASE_INSENSITIVE;
                }
        }

        /* See if DFS is supported */
	if (smbXcli_conn_dfs_supported(cli->conn) &&
	    smbXcli_tcon_is_dfs_share(tcon))
	{
                flags |= SMBC_VFS_FEATURE_DFS;
        }

#if defined(HAVE_STATVFS_F_FLAG)
        st->f_flag = flags;
#elif defined(HAVE_STATVFS_F_FLAGS)
        st->f_flags = flags;
#endif

	TALLOC_FREE(frame);
        return 0;
}
