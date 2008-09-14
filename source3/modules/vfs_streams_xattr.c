/*
 * Store streams in xattrs
 *
 * Copyright (C) Volker Lendecke, 2008
 *
 * Partly based on James Peach's Darwin module, which is
 *
 * Copyright (C) James Peach 2006-2007
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

struct stream_io {
	char *base;
	char *xattr_name;
};

static SMB_INO_T stream_inode(const SMB_STRUCT_STAT *sbuf, const char *sname)
{
	struct MD5Context ctx;
        unsigned char hash[16];
	SMB_INO_T result;
	char *upper_sname;

	DEBUG(10, ("stream_inode called for %lu/%lu [%s]\n",
		   (unsigned long)sbuf->st_dev,
		   (unsigned long)sbuf->st_ino, sname));

	upper_sname = talloc_strdup_upper(talloc_tos(), sname);
	SMB_ASSERT(upper_sname != NULL);

        MD5Init(&ctx);
        MD5Update(&ctx, (unsigned char *)&(sbuf->st_dev),
		  sizeof(sbuf->st_dev));
        MD5Update(&ctx, (unsigned char *)&(sbuf->st_ino),
		  sizeof(sbuf->st_ino));
        MD5Update(&ctx, (unsigned char *)upper_sname,
		  talloc_get_size(upper_sname)-1);
        MD5Final(hash, &ctx);

	TALLOC_FREE(upper_sname);

        /* Hopefully all the variation is in the lower 4 (or 8) bytes! */
	memcpy(&result, hash, sizeof(result));

	DEBUG(10, ("stream_inode returns %lu\n", (unsigned long)result));

	return result;
}

static ssize_t get_xattr_size(connection_struct *conn, const char *fname,
			      const char *xattr_name)
{
	NTSTATUS status;
	struct ea_struct ea;
	ssize_t result;

	status = get_ea_value(talloc_tos(), conn, NULL, fname,
			      xattr_name, &ea);

	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}

	result = ea.value.length-1;
	TALLOC_FREE(ea.value.data);
	return result;
}


static int streams_xattr_fstat(vfs_handle_struct *handle, files_struct *fsp,
			       SMB_STRUCT_STAT *sbuf)
{
	struct stream_io *io = (struct stream_io *)
		VFS_FETCH_FSP_EXTENSION(handle, fsp);

	DEBUG(10, ("streams_xattr_fstat called for %d\n", fsp->fh->fd));

	if (io == NULL) {
		return SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	}

	if (SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf) == -1) {
		return -1;
	}

	sbuf->st_size = get_xattr_size(handle->conn, io->base, io->xattr_name);
	if (sbuf->st_size == -1) {
		return -1;
	}

	DEBUG(10, ("sbuf->st_size = %d\n", (int)sbuf->st_size));

	sbuf->st_ino = stream_inode(sbuf, io->xattr_name);
	sbuf->st_mode &= ~S_IFMT;
        sbuf->st_mode |= S_IFREG;
        sbuf->st_blocks = sbuf->st_size % STAT_ST_BLOCKSIZE + 1;

	return 0;
}

static int streams_xattr_stat(vfs_handle_struct *handle, const char *fname,
			      SMB_STRUCT_STAT *sbuf)
{
	NTSTATUS status;
	char *base = NULL, *sname = NULL;
	int result = -1;
	char *xattr_name;

	if (!is_ntfs_stream_name(fname)) {
		return SMB_VFS_NEXT_STAT(handle, fname, sbuf);
	}

	status = split_ntfs_stream_name(talloc_tos(), fname, &base, &sname);
	if (!NT_STATUS_IS_OK(status)) {
		errno = EINVAL;
		return -1;
	}

	if (SMB_VFS_STAT(handle->conn, base, sbuf) == -1) {
		goto fail;
	}

	xattr_name = talloc_asprintf(talloc_tos(), "%s%s",
				     SAMBA_XATTR_DOSSTREAM_PREFIX, sname);
	if (xattr_name == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	sbuf->st_size = get_xattr_size(handle->conn, base, xattr_name);
	if (sbuf->st_size == -1) {
		errno = ENOENT;
		goto fail;
	}

	sbuf->st_ino = stream_inode(sbuf, xattr_name);
	sbuf->st_mode &= ~S_IFMT;
        sbuf->st_mode |= S_IFREG;
        sbuf->st_blocks = sbuf->st_size % STAT_ST_BLOCKSIZE + 1;

	result = 0;
 fail:
	TALLOC_FREE(base);
	TALLOC_FREE(sname);
	return result;
}

static int streams_xattr_lstat(vfs_handle_struct *handle, const char *fname,
			       SMB_STRUCT_STAT *sbuf)
{
	NTSTATUS status;
	char *base, *sname;
	int result = -1;
	char *xattr_name;

	if (!is_ntfs_stream_name(fname)) {
		return SMB_VFS_NEXT_LSTAT(handle, fname, sbuf);
	}

	status = split_ntfs_stream_name(talloc_tos(), fname, &base, &sname);
	if (!NT_STATUS_IS_OK(status)) {
		errno = EINVAL;
		goto fail;
	}

	if (SMB_VFS_LSTAT(handle->conn, base, sbuf) == -1) {
		goto fail;
	}

	xattr_name = talloc_asprintf(talloc_tos(), "%s%s",
				     SAMBA_XATTR_DOSSTREAM_PREFIX, sname);
	if (xattr_name == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	sbuf->st_size = get_xattr_size(handle->conn, base, xattr_name);
	if (sbuf->st_size == -1) {
		errno = ENOENT;
		goto fail;
	}

	sbuf->st_ino = stream_inode(sbuf, xattr_name);
	sbuf->st_mode &= ~S_IFMT;
        sbuf->st_mode |= S_IFREG;
        sbuf->st_blocks = sbuf->st_size % STAT_ST_BLOCKSIZE + 1;

	result = 0;
 fail:
	TALLOC_FREE(base);
	TALLOC_FREE(sname);
	return result;
}

static int streams_xattr_open(vfs_handle_struct *handle,  const char *fname,
			      files_struct *fsp, int flags, mode_t mode)
{
	TALLOC_CTX *frame;
	NTSTATUS status;
	struct stream_io *sio;
	char *base, *sname;
	struct ea_struct ea;
	char *xattr_name;
	int baseflags;
	int hostfd = -1;

	DEBUG(10, ("streams_xattr_open called for %s\n", fname));

	if (!is_ntfs_stream_name(fname)) {
		return SMB_VFS_NEXT_OPEN(handle, fname, fsp, flags, mode);
	}

	frame = talloc_stackframe();

	status = split_ntfs_stream_name(talloc_tos(), fname,
					&base, &sname);
	if (!NT_STATUS_IS_OK(status)) {
		errno = EINVAL;
		goto fail;
	}

	xattr_name = talloc_asprintf(talloc_tos(), "%s%s",
				     SAMBA_XATTR_DOSSTREAM_PREFIX, sname);
	if (xattr_name == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	/*
	 * We use baseflags to turn off nasty side-effects when opening the
	 * underlying file.
         */
        baseflags = flags;
        baseflags &= ~O_TRUNC;
        baseflags &= ~O_EXCL;
        baseflags &= ~O_CREAT;

        hostfd = SMB_VFS_OPEN(handle->conn, base, fsp, baseflags, mode);

        /* It is legit to open a stream on a directory, but the base
         * fd has to be read-only.
         */
        if ((hostfd == -1) && (errno == EISDIR)) {
                baseflags &= ~O_ACCMODE;
                baseflags |= O_RDONLY;
                hostfd = SMB_VFS_OPEN(handle->conn, fname, fsp, baseflags,
				      mode);
        }

        if (hostfd == -1) {
		goto fail;
        }

	status = get_ea_value(talloc_tos(), handle->conn, NULL, base,
			      xattr_name, &ea);

	DEBUG(10, ("get_ea_value returned %s\n", nt_errstr(status)));

	if (!NT_STATUS_IS_OK(status)
	    && !NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		/*
		 * The base file is not there. This is an error even if we got
		 * O_CREAT, the higher levels should have created the base
		 * file for us.
		 */
		DEBUG(10, ("streams_xattr_open: base file %s not around, "
			   "returning ENOENT\n", base));
		errno = ENOENT;
		goto fail;
	}

	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * The attribute does not exist
		 */

                if (flags & O_CREAT) {
			/*
			 * Darn, xattrs need at least 1 byte
			 */
                        char null = '\0';

			DEBUG(10, ("creating attribute %s on file %s\n",
				   xattr_name, base));

                        if (SMB_VFS_SETXATTR(
				handle->conn, base, xattr_name,
				&null, sizeof(null),
				flags & O_EXCL ? XATTR_CREATE : 0) == -1) {
				goto fail;
			}
		}
	}

	if (flags & O_TRUNC) {
		char null = '\0';
		if (SMB_VFS_SETXATTR(
			    handle->conn, base, xattr_name,
			    &null, sizeof(null),
			    flags & O_EXCL ? XATTR_CREATE : 0) == -1) {
			goto fail;
		}
	}

        sio = (struct stream_io *)VFS_ADD_FSP_EXTENSION(handle, fsp,
							struct stream_io);
        if (sio == NULL) {
                errno = ENOMEM;
                goto fail;
        }

        sio->xattr_name = talloc_strdup(VFS_MEMCTX_FSP_EXTENSION(handle, fsp),
					xattr_name);
        sio->base = talloc_strdup(VFS_MEMCTX_FSP_EXTENSION(handle, fsp),
				  base);

	if ((sio->xattr_name == NULL) || (sio->base == NULL)) {
		errno = ENOMEM;
		goto fail;
	}

	TALLOC_FREE(frame);
	return hostfd;

 fail:
	if (hostfd >= 0) {
		/*
		 * BUGBUGBUG -- we would need to call fd_close_posix here, but
		 * we don't have a full fsp yet
		 */
		SMB_VFS_CLOSE(fsp);
	}

	TALLOC_FREE(frame);
	return -1;
}

static int streams_xattr_unlink(vfs_handle_struct *handle,  const char *fname)
{
	NTSTATUS status;
	char *base = NULL;
	char *sname = NULL;
	int ret = -1;
	char *xattr_name;

	if (!is_ntfs_stream_name(fname)) {
		return SMB_VFS_NEXT_UNLINK(handle, fname);
	}

	status = split_ntfs_stream_name(talloc_tos(), fname, &base, &sname);
	if (!NT_STATUS_IS_OK(status)) {
		errno = EINVAL;
		goto fail;
	}

	xattr_name = talloc_asprintf(talloc_tos(), "%s%s",
				     SAMBA_XATTR_DOSSTREAM_PREFIX, sname);
	if (xattr_name == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	ret = SMB_VFS_REMOVEXATTR(handle->conn, base, xattr_name);

	if ((ret == -1) && (errno == ENOATTR)) {
		errno = ENOENT;
		goto fail;
	}

	ret = 0;

 fail:
	TALLOC_FREE(base);
	TALLOC_FREE(sname);
	return ret;
}

static NTSTATUS walk_xattr_streams(connection_struct *conn, files_struct *fsp,
				   const char *fname,
				   bool (*fn)(struct ea_struct *ea,
					      void *private_data),
				   void *private_data)
{
	NTSTATUS status;
	char **names;
	size_t i, num_names;
	size_t prefix_len = strlen(SAMBA_XATTR_DOSSTREAM_PREFIX);

	status = get_ea_names_from_file(talloc_tos(), conn, fsp, fname,
					&names, &num_names);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	for (i=0; i<num_names; i++) {
		struct ea_struct ea;

		if (strncmp(names[i], SAMBA_XATTR_DOSSTREAM_PREFIX,
			    prefix_len) != 0) {
			continue;
		}

		status = get_ea_value(names, conn, fsp, fname, names[i], &ea);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("Could not get ea %s for file %s: %s\n",
				   names[i], fname, nt_errstr(status)));
			continue;
		}

		ea.name = talloc_asprintf(ea.value.data, ":%s",
					  names[i] + prefix_len);
		if (ea.name == NULL) {
			DEBUG(0, ("talloc failed\n"));
			continue;
		}

		if (!fn(&ea, private_data)) {
			TALLOC_FREE(ea.value.data);
			return NT_STATUS_OK;
		}

		TALLOC_FREE(ea.value.data);
	}

	TALLOC_FREE(names);
	return NT_STATUS_OK;
}

static bool add_one_stream(TALLOC_CTX *mem_ctx, unsigned int *num_streams,
			   struct stream_struct **streams,
			   const char *name, SMB_OFF_T size,
			   SMB_OFF_T alloc_size)
{
	struct stream_struct *tmp;

	tmp = TALLOC_REALLOC_ARRAY(mem_ctx, *streams, struct stream_struct,
				   (*num_streams)+1);
	if (tmp == NULL) {
		return false;
	}

	tmp[*num_streams].name = talloc_strdup(tmp, name);
	if (tmp[*num_streams].name == NULL) {
		return false;
	}

	tmp[*num_streams].size = size;
	tmp[*num_streams].alloc_size = alloc_size;

	*streams = tmp;
	*num_streams += 1;
	return true;
}

struct streaminfo_state {
	TALLOC_CTX *mem_ctx;
	vfs_handle_struct *handle;
	unsigned int num_streams;
	struct stream_struct *streams;
	NTSTATUS status;
};

static bool collect_one_stream(struct ea_struct *ea, void *private_data)
{
	struct streaminfo_state *state =
		(struct streaminfo_state *)private_data;

	if (!add_one_stream(state->mem_ctx,
			    &state->num_streams, &state->streams,
			    ea->name, ea->value.length-1,
			    smb_roundup(state->handle->conn,
					ea->value.length-1))) {
		state->status = NT_STATUS_NO_MEMORY;
		return false;
	}

	return true;
}

static NTSTATUS streams_xattr_streaminfo(vfs_handle_struct *handle,
					 struct files_struct *fsp,
					 const char *fname,
					 TALLOC_CTX *mem_ctx,
					 unsigned int *pnum_streams,
					 struct stream_struct **pstreams)
{
	SMB_STRUCT_STAT sbuf;
	int ret;
	NTSTATUS status;
	struct streaminfo_state state;

	if ((fsp != NULL) && (fsp->fh->fd != -1)) {
		if (is_ntfs_stream_name(fsp->fsp_name)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		ret = SMB_VFS_FSTAT(fsp, &sbuf);
	}
	else {
		if (is_ntfs_stream_name(fname)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		ret = SMB_VFS_STAT(handle->conn, fname, &sbuf);
	}

	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}

	state.streams = NULL;
	state.num_streams = 0;

	if (!S_ISDIR(sbuf.st_mode)) {
		if (!add_one_stream(mem_ctx,
				    &state.num_streams, &state.streams,
				    "::$DATA", sbuf.st_size,
				    get_allocation_size(handle->conn, fsp,
							&sbuf))) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	state.mem_ctx = mem_ctx;
	state.handle = handle;
	state.status = NT_STATUS_OK;

	status = walk_xattr_streams(handle->conn, fsp, fname,
				    collect_one_stream, &state);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(state.streams);
		return status;
	}

	if (!NT_STATUS_IS_OK(state.status)) {
		TALLOC_FREE(state.streams);
		return state.status;
	}

	*pnum_streams = state.num_streams;
	*pstreams = state.streams;
	return NT_STATUS_OK;
}

static uint32_t streams_xattr_fs_capabilities(struct vfs_handle_struct *handle)
{
	return SMB_VFS_NEXT_FS_CAPABILITIES(handle) | FILE_NAMED_STREAMS;
}

static ssize_t streams_xattr_pwrite(vfs_handle_struct *handle,
				    files_struct *fsp, const void *data,
				    size_t n, SMB_OFF_T offset)
{
        struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	struct ea_struct ea;
	NTSTATUS status;
	int ret;

	DEBUG(10, ("streams_xattr_pwrite called for %d bytes\n", (int)n));

	if (sio == NULL) {
		return SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
	}

	status = get_ea_value(talloc_tos(), handle->conn, fsp->base_fsp,
			      sio->base, sio->xattr_name, &ea);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}

        if ((offset + n) > ea.value.length-1) {
		uint8 *tmp;

		tmp = TALLOC_REALLOC_ARRAY(talloc_tos(), ea.value.data, uint8,
					   offset + n + 1);

		if (tmp == NULL) {
			TALLOC_FREE(ea.value.data);
                        errno = ENOMEM;
                        return -1;
                }
		ea.value.data = tmp;
		ea.value.length = offset + n + 1;
		ea.value.data[offset+n] = 0;
        }

        memcpy(ea.value.data + offset, data, n);

	ret = SMB_VFS_SETXATTR(fsp->conn, fsp->base_fsp->fsp_name,
				sio->xattr_name,
				ea.value.data, ea.value.length, 0);

	TALLOC_FREE(ea.value.data);

	if (ret == -1) {
		return -1;
	}

	return n;
}

static ssize_t streams_xattr_pread(vfs_handle_struct *handle,
				   files_struct *fsp, void *data,
				   size_t n, SMB_OFF_T offset)
{
        struct stream_io *sio =
		(struct stream_io *)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	struct ea_struct ea;
	NTSTATUS status;
        size_t length, overlap;

	if (sio == NULL) {
		return SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
	}

	status = get_ea_value(talloc_tos(), handle->conn, fsp->base_fsp,
			      sio->base, sio->xattr_name, &ea);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}

	length = ea.value.length-1;

        /* Attempt to read past EOF. */
        if (length <= offset) {
                errno = EINVAL;
                return -1;
        }

        overlap = (offset + n) > length ? (length - offset) : n;
        memcpy(data, ea.value.data + offset, overlap);

	TALLOC_FREE(ea.value.data);
        return overlap;
}

/* VFS operations structure */

static vfs_op_tuple streams_xattr_ops[] = {
	{SMB_VFS_OP(streams_xattr_fs_capabilities), SMB_VFS_OP_FS_CAPABILITIES,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(streams_xattr_open), SMB_VFS_OP_OPEN,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(streams_xattr_stat), SMB_VFS_OP_STAT,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(streams_xattr_fstat), SMB_VFS_OP_FSTAT,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(streams_xattr_lstat), SMB_VFS_OP_LSTAT,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(streams_xattr_pread), SMB_VFS_OP_PREAD,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(streams_xattr_pwrite), SMB_VFS_OP_PWRITE,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(streams_xattr_lstat), SMB_VFS_OP_LSTAT,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(streams_xattr_unlink), SMB_VFS_OP_UNLINK,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(streams_xattr_streaminfo), SMB_VFS_OP_STREAMINFO,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(NULL), SMB_VFS_OP_NOOP, SMB_VFS_LAYER_NOOP}
};

NTSTATUS vfs_streams_xattr_init(void);
NTSTATUS vfs_streams_xattr_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "streams_xattr",
				streams_xattr_ops);
}
