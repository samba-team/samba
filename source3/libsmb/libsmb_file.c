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
#include "libsmb/libsmb.h"
#include "libsmbclient.h"
#include "libsmb_internal.h"
#include "../libcli/smb/smbXcli_base.h"

/*
 * Routine to open() a file ...
 */

SMBCFILE *
SMBC_open_ctx(SMBCCTX *context,
              const char *fname,
              int flags,
              mode_t mode)
{
	char *server = NULL;
        char *share = NULL;
        char *user = NULL;
        char *password = NULL;
        char *workgroup = NULL;
	char *path = NULL;
	char *targetpath = NULL;
	struct cli_state *targetcli = NULL;
	SMBCSRV *srv   = NULL;
	SMBCFILE *file = NULL;
	uint16_t fd;
	uint16_t port = 0;
	NTSTATUS status = NT_STATUS_OBJECT_PATH_INVALID;
	TALLOC_CTX *frame = talloc_stackframe();

	if (!context || !context->internal->initialized) {
		errno = EINVAL;  /* Best I can think of ... */
		TALLOC_FREE(frame);
		return NULL;
	}

	if (!fname) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return NULL;
	}

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
		errno = EINVAL;
		TALLOC_FREE(frame);
		return NULL;
        }

	if (!user || user[0] == (char)0) {
		user = talloc_strdup(frame, smbc_getUser(context));
		if (!user) {
                	errno = ENOMEM;
			TALLOC_FREE(frame);
			return NULL;
		}
	}

	srv = SMBC_server(frame, context, True,
                          server, port, share, &workgroup, &user, &password);
	if (!srv) {
		if (errno == EPERM) errno = EACCES;
		TALLOC_FREE(frame);
		return NULL;  /* SMBC_server sets errno */
	}

	/* Hmmm, the test for a directory is suspect here ... FIXME */

	if (strlen(path) > 0 && path[strlen(path) - 1] == '\\') {
		status = NT_STATUS_OBJECT_PATH_INVALID;
	} else {
		file = SMB_MALLOC_P(SMBCFILE);
		if (!file) {
			errno = ENOMEM;
			TALLOC_FREE(frame);
			return NULL;
		}

		ZERO_STRUCTP(file);

		/*d_printf(">>>open: resolving %s\n", path);*/
		status = cli_resolve_path(
			frame, "", context->internal->auth_info,
			srv->cli, path, &targetcli, &targetpath);
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("Could not resolve %s\n", path);
                        errno = ENOENT;
			SAFE_FREE(file);
			TALLOC_FREE(frame);
			return NULL;
		}
		/*d_printf(">>>open: resolved %s as %s\n", path, targetpath);*/

		status = cli_open(targetcli, targetpath, flags,
                                   context->internal->share_mode, &fd);
		if (!NT_STATUS_IS_OK(status)) {

			/* Handle the error ... */

			SAFE_FREE(file);
			errno = SMBC_errno(context, targetcli);
			TALLOC_FREE(frame);
			return NULL;
		}

		/* Fill in file struct */

		file->cli_fd  = fd;
		file->fname   = SMB_STRDUP(fname);
		file->srv     = srv;
		file->offset  = 0;
		file->file    = True;
		/*
		 * targetcli is either equal to srv->cli or
		 * is a subsidiary DFS connection. Either way
		 * file->cli_fd belongs to it so we must cache
		 * it for read/write/close, not re-resolve each time.
		 * Re-resolving is both slow and incorrect.
		 */
		file->targetcli = targetcli;

		DLIST_ADD(context->internal->files, file);

                /*
                 * If the file was opened in O_APPEND mode, all write
                 * operations should be appended to the file.  To do that,
                 * though, using this protocol, would require a getattrE()
                 * call for each and every write, to determine where the end
                 * of the file is. (There does not appear to be an append flag
                 * in the protocol.)  Rather than add all of that overhead of
                 * retrieving the current end-of-file offset prior to each
                 * write operation, we'll assume that most append operations
                 * will continuously write, so we'll just set the offset to
                 * the end of the file now and hope that's adequate.
                 *
                 * Note to self: If this proves inadequate, and O_APPEND
                 * should, in some cases, be forced for each write, add a
                 * field in the context options structure, for
                 * "strict_append_mode" which would select between the current
                 * behavior (if FALSE) or issuing a getattrE() prior to each
                 * write and forcing the write to the end of the file (if
                 * TRUE).  Adding that capability will likely require adding
                 * an "append" flag into the _SMBCFILE structure to track
                 * whether a file was opened in O_APPEND mode.  -- djl
                 */
                if (flags & O_APPEND) {
                        if (SMBC_lseek_ctx(context, file, 0, SEEK_END) < 0) {
                                (void) SMBC_close_ctx(context, file);
                                errno = ENXIO;
				TALLOC_FREE(frame);
                                return NULL;
                        }
                }

		TALLOC_FREE(frame);
		return file;
	}

	/* Check if opendir needed ... */

	if (!NT_STATUS_IS_OK(status)) {
		int eno = 0;

		eno = SMBC_errno(context, srv->cli);
		file = smbc_getFunctionOpendir(context)(context, fname);
		if (!file) errno = eno;
		TALLOC_FREE(frame);
		return file;
	}

	errno = EINVAL; /* FIXME, correct errno ? */
	TALLOC_FREE(frame);
	return NULL;
}

/*
 * Routine to create a file
 */

SMBCFILE *
SMBC_creat_ctx(SMBCCTX *context,
               const char *path,
               mode_t mode)
{
	if (!context || !context->internal->initialized) {
		errno = EINVAL;
		return NULL;
	}

	return SMBC_open_ctx(context, path,
                             O_WRONLY | O_CREAT | O_TRUNC, mode);
}

/*
 * Routine to read() a file ...
 */

ssize_t
SMBC_read_ctx(SMBCCTX *context,
              SMBCFILE *file,
              void *buf,
              size_t count)
{
	size_t ret;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

        /*
         * offset:
         *
         * Compiler bug (possibly) -- gcc (GCC) 3.3.5 (Debian 1:3.3.5-2) --
         * appears to pass file->offset (which is type off_t) differently than
         * a local variable of type off_t.  Using local variable "offset" in
         * the call to cli_read() instead of file->offset fixes a problem
         * retrieving data at an offset greater than 4GB.
         */
        off_t offset;

	if (!context || !context->internal->initialized) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	DEBUG(4, ("smbc_read(%p, %zu)\n", file, count));

	if (!SMBC_dlist_contains(context->internal->files, file)) {
		errno = EBADF;
		TALLOC_FREE(frame);
		return -1;
	}

	offset = file->offset;

	/* Check that the buffer exists ... */

	if (buf == NULL) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	status = cli_read(file->targetcli, file->cli_fd, (char *)buf, offset,
			  count, &ret);
	if (!NT_STATUS_IS_OK(status)) {
		errno = SMBC_errno(context, file->targetcli);
		TALLOC_FREE(frame);
		return -1;
	}

	file->offset += ret;

	DEBUG(4, ("  --> %zu\n", ret));

	TALLOC_FREE(frame);
	return ret;  /* Success, ret bytes of data ... */
}

off_t
SMBC_splice_ctx(SMBCCTX *context,
                SMBCFILE *srcfile,
                SMBCFILE *dstfile,
                off_t count,
                int (*splice_cb)(off_t n, void *priv),
                void *priv)
{
	off_t written = 0;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	if (!context || !context->internal->initialized) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	if (!SMBC_dlist_contains(context->internal->files, srcfile)) {
		errno = EBADF;
		TALLOC_FREE(frame);
		return -1;
	}

	if (!SMBC_dlist_contains(context->internal->files, dstfile)) {
		errno = EBADF;
		TALLOC_FREE(frame);
		return -1;
	}

	status = cli_splice(srcfile->targetcli, dstfile->targetcli,
			    srcfile->cli_fd, dstfile->cli_fd,
			    count, srcfile->offset, dstfile->offset, &written,
			    splice_cb, priv);
	if (!NT_STATUS_IS_OK(status)) {
		errno = SMBC_errno(context, srcfile->targetcli);
		TALLOC_FREE(frame);
		return -1;
	}

	srcfile->offset += written;
	dstfile->offset += written;

	TALLOC_FREE(frame);
	return written;
}

/*
 * Routine to write() a file ...
 */

ssize_t
SMBC_write_ctx(SMBCCTX *context,
               SMBCFILE *file,
               const void *buf,
               size_t count)
{
        off_t offset;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	/* First check all pointers before dereferencing them */

	if (!context || !context->internal->initialized) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	if (!SMBC_dlist_contains(context->internal->files, file)) {
		errno = EBADF;
		TALLOC_FREE(frame);
		return -1;
	}

	/* Check that the buffer exists ... */

	if (buf == NULL) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

        offset = file->offset; /* See "offset" comment in SMBC_read_ctx() */

	status = cli_writeall(file->targetcli, file->cli_fd,
			      0, (const uint8_t *)buf, offset, count, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		TALLOC_FREE(frame);
		return -1;
	}

	file->offset += count;

	TALLOC_FREE(frame);
	return count;  /* Success, 0 bytes of data ... */
}

/*
 * Routine to close() a file ...
 */

int
SMBC_close_ctx(SMBCCTX *context,
               SMBCFILE *file)
{
	TALLOC_CTX *frame = talloc_stackframe();

	if (!context || !context->internal->initialized) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	if (!SMBC_dlist_contains(context->internal->files, file)) {
		errno = EBADF;
		TALLOC_FREE(frame);
		return -1;
	}

	/* IS a dir ... */
	if (!file->file) {
		TALLOC_FREE(frame);
		return smbc_getFunctionClosedir(context)(context, file);
	}

	if (!NT_STATUS_IS_OK(cli_close(file->targetcli, file->cli_fd))) {
		SMBCSRV *srv;
		DEBUG(3, ("cli_close failed on %s. purging server.\n",
			  file->fname));
		/* Deallocate slot and remove the server
		 * from the server cache if unused */
		errno = SMBC_errno(context, file->targetcli);
		srv = file->srv;
		DLIST_REMOVE(context->internal->files, file);
		SAFE_FREE(file->fname);
		SAFE_FREE(file);
		smbc_getFunctionRemoveUnusedServer(context)(context, srv);
		TALLOC_FREE(frame);
		return -1;
	}

	DLIST_REMOVE(context->internal->files, file);
	SAFE_FREE(file->fname);
	SAFE_FREE(file);
	TALLOC_FREE(frame);
	return 0;
}

/*
 * Get info from an SMB server on a file. Use a qpathinfo call first
 * and if that fails, use getatr, as Win95 sometimes refuses qpathinfo
 */
bool
SMBC_getatr(SMBCCTX * context,
            SMBCSRV *srv,
            const char *path,
	    struct stat *sb)
{
	char *fixedpath = NULL;
	char *targetpath = NULL;
	struct cli_state *targetcli = NULL;
	uint32_t attr = 0;
	off_t size = 0;
	struct timespec create_time_ts = {0};
	struct timespec access_time_ts = {0};
	struct timespec write_time_ts = {0};
	struct timespec change_time_ts = {0};
	time_t write_time = 0;
	SMB_INO_T ino = 0;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	if (!context || !context->internal->initialized) {
		errno = EINVAL;
		TALLOC_FREE(frame);
 		return False;
 	}

	/* path fixup for . and .. */
	if (ISDOT(path) || ISDOTDOT(path)) {
		fixedpath = talloc_strdup(frame, "\\");
		if (!fixedpath) {
			errno = ENOMEM;
			TALLOC_FREE(frame);
			return False;
		}
	} else {
		fixedpath = talloc_strdup(frame, path);
		if (!fixedpath) {
			errno = ENOMEM;
			TALLOC_FREE(frame);
			return False;
		}
		trim_string(fixedpath, NULL, "\\..");
		trim_string(fixedpath, NULL, "\\.");
	}
	DEBUG(4,("SMBC_getatr: sending qpathinfo\n"));

	status = cli_resolve_path(frame, "", context->internal->auth_info,
				  srv->cli, fixedpath,
				  &targetcli, &targetpath);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Couldn't resolve %s\n", path);
                errno = ENOENT;
		TALLOC_FREE(frame);
		return False;
	}

	if (!srv->no_pathinfo2) {
		status = cli_qpathinfo2(targetcli,
					targetpath,
					&create_time_ts,
					&access_time_ts,
					&write_time_ts,
					&change_time_ts,
					&size,
					&attr,
					&ino);
		if (NT_STATUS_IS_OK(status)) {
			goto setup_stat;
		}
        }

	srv->no_pathinfo2 = True;

	if (!srv->no_pathinfo3) {
		status = cli_qpathinfo3(targetcli,
					targetpath,
					&create_time_ts,
					&access_time_ts,
					&write_time_ts,
					&change_time_ts,
					&size,
					&attr,
					&ino);
		if (NT_STATUS_IS_OK(status)) {
			goto setup_stat;
		}
        }

	srv->no_pathinfo3 = True;

	/* if this is NT then don't bother with the getatr */
	if (smb1cli_conn_capabilities(targetcli->conn) & CAP_NT_SMBS) {
		goto all_failed;
        }

	status = cli_getatr(targetcli, targetpath, &attr, &size, &write_time);
	if (NT_STATUS_IS_OK(status)) {
		struct timespec w_time_ts =
			convert_time_t_to_timespec(write_time);

		access_time_ts = change_time_ts = write_time_ts = w_time_ts;

		goto setup_stat;
	}

setup_stat:
	setup_stat(sb,
		   path,
		   size,
		   attr,
		   ino,
		   srv->dev,
		   access_time_ts,
		   change_time_ts,
		   write_time_ts);

	TALLOC_FREE(frame);
	return true;

all_failed:
	srv->no_pathinfo2 = False;
	srv->no_pathinfo3 = False;

        errno = EPERM;
	TALLOC_FREE(frame);
	return False;
}

/*
 * Set file info on an SMB server.  Use setpathinfo call first.  If that
 * fails, use setattrE..
 *
 * Access and modification time parameters are always used and must be
 * provided.  Create time, if zero, will be determined from the actual create
 * time of the file.  If non-zero, the create time will be set as well.
 *
 * "attr" (attributes) parameter may be set to -1 if it is not to be set.
 */
bool
SMBC_setatr(SMBCCTX * context, SMBCSRV *srv, char *path,
            struct timespec create_time,
            struct timespec access_time,
            struct timespec write_time,
            struct timespec change_time,
            uint16_t attr)
{
        uint16_t fd;
        int ret;
	uint32_t lattr = (uint32_t)attr;
	TALLOC_CTX *frame = talloc_stackframe();

	if (attr == (uint16_t)-1) {
		/*
		 * External ABI only passes in
		 * 16-bits of attribute. Make
		 * sure we correctly map to
		 * (uint32_t)-1 meaning don't
		 * change attributes if attr was
		 * passed in as 16-bit -1.
		 */
		lattr = (uint32_t)-1;
	}


        /*
         * First, try setpathinfo (if qpathinfo succeeded), for it is the
         * modern function for "new code" to be using, and it works given a
         * filename rather than requiring that the file be opened to have its
         * attributes manipulated.
         */
        if (srv->no_pathinfo ||
            !NT_STATUS_IS_OK(cli_setpathinfo_ext(srv->cli, path,
						 create_time,
						 access_time,
						 write_time,
						 change_time,
						 lattr))) {

                /*
                 * setpathinfo is not supported; go to plan B.
                 *
                 * cli_setatr() does not work on win98, and it also doesn't
                 * support setting the access time (only the modification
                 * time), so in all cases, we open the specified file and use
                 * cli_setattrE() which should work on all OS versions, and
                 * supports both times.
                 */

                /* Don't try {q,set}pathinfo() again, with this server */
                srv->no_pathinfo = True;

                /* Open the file */
                if (!NT_STATUS_IS_OK(cli_open(srv->cli, path, O_RDWR, DENY_NONE, &fd))) {
                        errno = SMBC_errno(context, srv->cli);
			TALLOC_FREE(frame);
                        return False;
                }

                /* Set the new attributes */
                ret = NT_STATUS_IS_OK(cli_setattrE(srv->cli, fd,
                                   change_time.tv_sec,
                                   access_time.tv_sec,
                                   write_time.tv_sec));

                /* Close the file */
                cli_close(srv->cli, fd);

                /*
                 * Unfortunately, setattrE() doesn't have a provision for
                 * setting the access attr (attributes).  We'll have to try
                 * cli_setatr() for that, and with only this parameter, it
                 * seems to work on win98.
                 */
                if (ret && attr != (uint16_t) -1) {
                        ret = NT_STATUS_IS_OK(cli_setatr(srv->cli, path, (uint32_t)attr, 0));
                }

                if (! ret) {
                        errno = SMBC_errno(context, srv->cli);
			TALLOC_FREE(frame);
                        return False;
                }
        }

	TALLOC_FREE(frame);
        return True;
}

/*
 * A routine to lseek() a file
 */

off_t
SMBC_lseek_ctx(SMBCCTX *context,
               SMBCFILE *file,
               off_t offset,
               int whence)
{
	off_t size;
	TALLOC_CTX *frame = talloc_stackframe();

	if (!context || !context->internal->initialized) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	if (!SMBC_dlist_contains(context->internal->files, file)) {
		errno = EBADF;
		TALLOC_FREE(frame);
		return -1;
	}

	if (!file->file) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;      /* Can't lseek a dir ... */
	}

	switch (whence) {
	case SEEK_SET:
		file->offset = offset;
		break;
	case SEEK_CUR:
		file->offset += offset;
		break;
	case SEEK_END:
		if (!NT_STATUS_IS_OK(cli_qfileinfo_basic(
					     file->targetcli, file->cli_fd, NULL,
					     &size, NULL, NULL, NULL, NULL,
					     NULL))) {
			errno = EINVAL;
			TALLOC_FREE(frame);
			return -1;
		}
		file->offset = size + offset;
		break;
	default:
		errno = EINVAL;
		break;
	}

	TALLOC_FREE(frame);
	return file->offset;
}


/*
 * Routine to truncate a file given by its file descriptor, to a specified size
 */

int
SMBC_ftruncate_ctx(SMBCCTX *context,
                   SMBCFILE *file,
                   off_t length)
{
	off_t size = length;
	TALLOC_CTX *frame = talloc_stackframe();

	if (!context || !context->internal->initialized) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	if (!SMBC_dlist_contains(context->internal->files, file)) {
		errno = EBADF;
		TALLOC_FREE(frame);
		return -1;
	}

	if (!file->file) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

        if (!NT_STATUS_IS_OK(cli_ftruncate(file->targetcli, file->cli_fd, (uint64_t)size))) {
                errno = EINVAL;
                TALLOC_FREE(frame);
                return -1;
        }

	TALLOC_FREE(frame);
	return 0;
}
