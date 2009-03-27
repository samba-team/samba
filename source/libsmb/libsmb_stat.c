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
#include "libsmbclient.h"
#include "libsmb_internal.h"


/* 
 * Generate an inode number from file name for those things that need it
 */

static ino_t
generate_inode(SMBCCTX *context,
               const char *name)
{
	if (!context || !context->internal->initialized) {
                
		errno = EINVAL;
		return -1;
                
	}
        
	if (!*name) return 2; /* FIXME, why 2 ??? */
	return (ino_t)str_checksum(name);
        
}

/*
 * Routine to put basic stat info into a stat structure ... Used by stat and
 * fstat below.
 */

static int
setup_stat(SMBCCTX *context,
           struct stat *st,
           char *fname,
           SMB_OFF_T size,
           int mode)
{
	TALLOC_CTX *frame = talloc_stackframe();
        
	st->st_mode = 0;
        
	if (IS_DOS_DIR(mode)) {
		st->st_mode = SMBC_DIR_MODE;
	} else {
		st->st_mode = SMBC_FILE_MODE;
	}
        
	if (IS_DOS_ARCHIVE(mode)) st->st_mode |= S_IXUSR;
	if (IS_DOS_SYSTEM(mode)) st->st_mode |= S_IXGRP;
	if (IS_DOS_HIDDEN(mode)) st->st_mode |= S_IXOTH;
	if (!IS_DOS_READONLY(mode)) st->st_mode |= S_IWUSR;
        
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
        
	if (IS_DOS_DIR(mode)) {
		st->st_nlink = 2;
	} else {
		st->st_nlink = 1;
	}
        
	if (st->st_ino == 0) {
		st->st_ino = generate_inode(context, fname);
	}
        
	TALLOC_FREE(frame);
	return True;  /* FIXME: Is this needed ? */
        
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
	struct timespec write_time_ts;
        struct timespec access_time_ts;
        struct timespec change_time_ts;
	SMB_OFF_T size = 0;
	uint16 mode = 0;
	SMB_INO_T ino = 0;
	TALLOC_CTX *frame = talloc_stackframe();
        
	if (!context || !context->internal->initialized) {
                
		errno = EINVAL;  /* Best I can think of ... */
		TALLOC_FREE(frame);
		return -1;
	}
        
	if (!fname) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}
        
	DEBUG(4, ("smbc_stat(%s)\n", fname));
        
	if (SMBC_parse_path(frame,
                            context,
                            fname,
                            &workgroup,
                            &server,
                            &share,
                            &path,
                            &user,
                            &password,
                            NULL)) {
		errno = EINVAL;
		TALLOC_FREE(frame);
                return -1;
        }
        
	if (!user || user[0] == (char)0) {
		user = talloc_strdup(frame, smbc_getUser(context));
		if (!user) {
			errno = ENOMEM;
			TALLOC_FREE(frame);
			return -1;
		}
	}
        
	srv = SMBC_server(frame, context, True,
                          server, share, &workgroup, &user, &password);
        
	if (!srv) {
		TALLOC_FREE(frame);
		return -1;  /* errno set by SMBC_server */
	}
        
	if (!SMBC_getatr(context, srv, path, &mode, &size,
			 NULL,
                         &access_time_ts,
                         &write_time_ts,
                         &change_time_ts,
                         &ino)) {
		errno = SMBC_errno(context, srv->cli);
		TALLOC_FREE(frame);
		return -1;
	}
        
	st->st_ino = ino;
        
	setup_stat(context, st, (char *) fname, size, mode);
        
	set_atimespec(st, access_time_ts);
	set_ctimespec(st, change_time_ts);
	set_mtimespec(st, write_time_ts);
	st->st_dev   = srv->dev;
        
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
	SMB_OFF_T size;
	uint16 mode;
	char *server = NULL;
	char *share = NULL;
	char *user = NULL;
	char *password = NULL;
	char *path = NULL;
        char *targetpath = NULL;
	struct cli_state *targetcli = NULL;
	SMB_INO_T ino = 0;
	TALLOC_CTX *frame = talloc_stackframe();
        
	if (!context || !context->internal->initialized) {
                
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}
        
	if (!file || !SMBC_dlist_contains(context->internal->files, file)) {
		errno = EBADF;
		TALLOC_FREE(frame);
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
                            &share,
                            &path,
                            &user,
                            &password,
                            NULL)) {
                errno = EINVAL;
		TALLOC_FREE(frame);
                return -1;
        }
        
	/*d_printf(">>>fstat: resolving %s\n", path);*/
	if (!cli_resolve_path(frame, "", file->srv->cli, path,
                              &targetcli, &targetpath)) {
		d_printf("Could not resolve %s\n", path);
                errno = ENOENT;
		TALLOC_FREE(frame);
		return -1;
	}
	/*d_printf(">>>fstat: resolved path as %s\n", targetpath);*/
        
	if (!cli_qfileinfo(targetcli, file->cli_fd, &mode, &size,
                           NULL,
                           &access_time_ts,
                           &write_time_ts,
                           &change_time_ts,
                           &ino)) {
                
		time_t change_time, access_time, write_time;
                
		if (!cli_getattrE(targetcli, file->cli_fd, &mode, &size,
                                  &change_time, &access_time, &write_time)) {
                        
			errno = EINVAL;
			TALLOC_FREE(frame);
			return -1;
		}
                
		change_time_ts = convert_time_t_to_timespec(change_time);
		access_time_ts = convert_time_t_to_timespec(access_time);
		write_time_ts = convert_time_t_to_timespec(write_time);
	}
        
	st->st_ino = ino;
        
	setup_stat(context, st, file->fname, size, mode);
        
	set_atimespec(st, access_time_ts);
	set_ctimespec(st, change_time_ts);
	set_mtimespec(st, write_time_ts);
	st->st_dev = file->srv->dev;
        
	TALLOC_FREE(frame);
	return 0;
        
}
