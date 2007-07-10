/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - alternate data streams

   Copyright (C) Andrew Tridgell 2004

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
#include "vfs_posix.h"
#include "librpc/gen_ndr/xattr.h"


/*
  return the list of file streams for RAW_FILEINFO_STREAM_INFORMATION
*/
NTSTATUS pvfs_stream_information(struct pvfs_state *pvfs, 
				 TALLOC_CTX *mem_ctx,
				 struct pvfs_filename *name, int fd, 
				 struct stream_information *info)
{
	struct xattr_DosStreams *streams;
	int i;
	NTSTATUS status;

	streams = talloc(mem_ctx, struct xattr_DosStreams);
	if (streams == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = pvfs_streams_load(pvfs, name, fd, streams);
	if (!NT_STATUS_IS_OK(status)) {
		ZERO_STRUCTP(streams);
	}

	info->num_streams = streams->num_streams+1;
	info->streams = talloc_array(mem_ctx, struct stream_struct, info->num_streams);
	if (!info->streams) {
		return NT_STATUS_NO_MEMORY;
	}

	info->streams[0].size          = name->st.st_size;
	info->streams[0].alloc_size    = name->dos.alloc_size;
	info->streams[0].stream_name.s = talloc_strdup(info->streams, "::$DATA");

	for (i=0;i<streams->num_streams;i++) {
		info->streams[i+1].size          = streams->streams[i].size;
		info->streams[i+1].alloc_size    = streams->streams[i].alloc_size;
		info->streams[i+1].stream_name.s = talloc_asprintf(streams->streams, 
								   ":%s:$DATA",
								   streams->streams[i].name);
	}

	return NT_STATUS_OK;
}


/*
  fill in the stream information for a name
*/
NTSTATUS pvfs_stream_info(struct pvfs_state *pvfs, struct pvfs_filename *name, int fd)
{
	struct xattr_DosStreams *streams;
	int i;
	NTSTATUS status;

	/* the NULL stream always exists */
	if (name->stream_name == NULL) {
		name->stream_exists = True;
		return NT_STATUS_OK;
	}

	streams = talloc(name, struct xattr_DosStreams);
	if (streams == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = pvfs_streams_load(pvfs, name, fd, streams);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(streams);
		return status;
	}

	for (i=0;i<streams->num_streams;i++) {
		struct xattr_DosStream *s = &streams->streams[i];
		if (strcasecmp_m(s->name, name->stream_name) == 0) {
			name->dos.alloc_size = pvfs_round_alloc_size(pvfs, s->alloc_size);
			name->st.st_size     = s->size;
			name->stream_exists = True;
			talloc_free(streams);
			return NT_STATUS_OK;
		}
	}

	talloc_free(streams);

	name->dos.alloc_size = 0;
	name->st.st_size     = 0;
	name->stream_exists = False;

	return NT_STATUS_OK;
}


/*
  update size information for a stream
*/
static NTSTATUS pvfs_stream_update_size(struct pvfs_state *pvfs, struct pvfs_filename *name, int fd,
					off_t size)
{
	struct xattr_DosStreams *streams;
	int i;
	NTSTATUS status;

	streams = talloc(name, struct xattr_DosStreams);
	if (streams == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = pvfs_streams_load(pvfs, name, fd, streams);
	if (!NT_STATUS_IS_OK(status)) {
		ZERO_STRUCTP(streams);
	}

	for (i=0;i<streams->num_streams;i++) {
		struct xattr_DosStream *s = &streams->streams[i];
		if (strcasecmp_m(s->name, name->stream_name) == 0) {
			s->size       = size;
			s->alloc_size = pvfs_round_alloc_size(pvfs, size);
			break;
		}
	}

	if (i == streams->num_streams) {
		struct xattr_DosStream *s;
		streams->streams = talloc_realloc(streams, streams->streams, 
						    struct xattr_DosStream,
						    streams->num_streams+1);
		if (streams->streams == NULL) {
			talloc_free(streams);
			return NT_STATUS_NO_MEMORY;
		}
		streams->num_streams++;
		s = &streams->streams[i];
		
		s->flags      = XATTR_STREAM_FLAG_INTERNAL;
		s->size       = size;
		s->alloc_size = pvfs_round_alloc_size(pvfs, size);
		s->name       = name->stream_name;
	}

	status = pvfs_streams_save(pvfs, name, fd, streams);
	talloc_free(streams);

	return status;
}


/*
  create the xattr for a alternate data stream
*/
NTSTATUS pvfs_stream_create(struct pvfs_state *pvfs, 
			    struct pvfs_filename *name, 
			    int fd)
{
	NTSTATUS status;
	status = pvfs_xattr_create(pvfs, name->full_name, fd, 
				   XATTR_DOSSTREAM_PREFIX, name->stream_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return pvfs_stream_update_size(pvfs, name, fd, 0);
}

/*
  delete the xattr for a alternate data stream
*/
NTSTATUS pvfs_stream_delete(struct pvfs_state *pvfs, 
			    struct pvfs_filename *name, 
			    int fd)
{
	NTSTATUS status;
	struct xattr_DosStreams *streams;
	int i;

	status = pvfs_xattr_delete(pvfs, name->full_name, fd, 
				   XATTR_DOSSTREAM_PREFIX, name->stream_name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	streams = talloc(name, struct xattr_DosStreams);
	if (streams == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = pvfs_streams_load(pvfs, name, fd, streams);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(streams);
		return status;
	}

	for (i=0;i<streams->num_streams;i++) {
		struct xattr_DosStream *s = &streams->streams[i];
		if (strcasecmp_m(s->name, name->stream_name) == 0) {
			memmove(s, s+1, (streams->num_streams - (i+1)) * sizeof(*s));
			streams->num_streams--;
			break;
		}
	}

	status = pvfs_streams_save(pvfs, name, fd, streams);
	talloc_free(streams);

	return status;
}

/*
  the equvalent of pread() on a stream
*/
ssize_t pvfs_stream_read(struct pvfs_state *pvfs,
			 struct pvfs_file_handle *h, void *data, size_t count, off_t offset)
{
	NTSTATUS status;
	DATA_BLOB blob;
	if (count == 0) {
		return 0;
	}
	status = pvfs_xattr_load(pvfs, h, h->name->full_name, h->fd, XATTR_DOSSTREAM_PREFIX,
				 h->name->stream_name, offset+count, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		errno = EIO;
		return -1;
	}
	if (offset >= blob.length) {
		data_blob_free(&blob);
		return 0;
	}
	if (count > blob.length - offset) {
		count = blob.length - offset;
	}
	memcpy(data, blob.data + offset, count);
	data_blob_free(&blob);
	return count;
}


/*
  the equvalent of pwrite() on a stream
*/
ssize_t pvfs_stream_write(struct pvfs_state *pvfs,
			  struct pvfs_file_handle *h, const void *data, size_t count, off_t offset)
{
	NTSTATUS status;
	DATA_BLOB blob;
	if (count == 0) {
		return 0;
	}
	if (offset > XATTR_MAX_STREAM_SIZE) {
		errno = ENOSPC;
		return -1;
	}

	/* we have to load the existing stream, then modify, then save */
	status = pvfs_xattr_load(pvfs, h, h->name->full_name, h->fd, XATTR_DOSSTREAM_PREFIX,
				 h->name->stream_name, offset+count, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		blob = data_blob(NULL, 0);
	}
	if (count+offset > blob.length) {
		blob.data = talloc_realloc(blob.data, blob.data, uint8_t, count+offset);
		if (blob.data == NULL) {
			errno = ENOMEM;
			return -1;
		}
		if (offset > blob.length) {
			memset(blob.data+blob.length, 0, offset - blob.length);
		}
		blob.length = count+offset;
	}
	memcpy(blob.data + offset, data, count);

	status = pvfs_xattr_save(pvfs, h->name->full_name, h->fd, XATTR_DOSSTREAM_PREFIX,
				 h->name->stream_name, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		data_blob_free(&blob);
		/* getting this error mapping right is probably
		   not worth it */
		errno = ENOSPC;
		return -1;
	}

	status = pvfs_stream_update_size(pvfs, h->name, h->fd, blob.length);

	data_blob_free(&blob);

	if (!NT_STATUS_IS_OK(status)) {
		errno = EIO;
		return -1;
	}

	return count;
}

/*
  the equvalent of truncate() on a stream
*/
NTSTATUS pvfs_stream_truncate(struct pvfs_state *pvfs,
			      struct pvfs_filename *name, int fd, off_t length)
{
	NTSTATUS status;
	DATA_BLOB blob;

	if (length > XATTR_MAX_STREAM_SIZE) {
		return NT_STATUS_DISK_FULL;
	}

	/* we have to load the existing stream, then modify, then save */
	status = pvfs_xattr_load(pvfs, name, name->full_name, fd, XATTR_DOSSTREAM_PREFIX,
				 name->stream_name, length, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (length <= blob.length) {
		blob.length = length;
	} else if (length > blob.length) {
		blob.data = talloc_realloc(blob.data, blob.data, uint8_t, length);
		if (blob.data == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		memset(blob.data+blob.length, 0, length - blob.length);
		blob.length = length;
	}

	status = pvfs_xattr_save(pvfs, name->full_name, fd, XATTR_DOSSTREAM_PREFIX,
				 name->stream_name, &blob);
	data_blob_free(&blob);

	if (NT_STATUS_IS_OK(status)) {
		status = pvfs_stream_update_size(pvfs, name, fd, blob.length);
	}

	return status;
}
