/* 
   Unix SMB/CIFS implementation.

   simple NTVFS filesystem backend

   Copyright (C) Andrew Tridgell 2003

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
/*
  this implements a very simple NTVFS filesystem backend. 
  
  this backend largely ignores the POSIX -> CIFS mappings, just doing absolutely
  minimal work to give a working backend.
*/

#include "includes.h"
#include "svfs.h"

/*
  connect to a share - used when a tree_connect operation comes
  in. For a disk based backend we needs to ensure that the base
  directory exists (tho it doesn't need to be accessible by the user,
  that comes later)
*/
static NTSTATUS svfs_connect(struct smbsrv_request *req, const char *sharename)
{
	struct stat st;
	struct tcon_context *conn = req->conn;
	struct svfs_private *private;

	conn->ntvfs_private = talloc(conn->mem_ctx, sizeof(struct svfs_private));

	private = conn->ntvfs_private;

	private->connectpath = talloc_strdup(conn->mem_ctx, lp_pathname(conn->service));

	/* the directory must exist */
	if (stat(private->connectpath, &st) != 0 || !S_ISDIR(st.st_mode)) {
		DEBUG(0,("'%s' is not a directory, when connecting to [%s]\n", 
			 private->connectpath, sharename));
		return NT_STATUS_BAD_NETWORK_NAME;
	}

	conn->fs_type = talloc_strdup(conn->mem_ctx, "NTFS");
	conn->dev_type = talloc_strdup(conn->mem_ctx, "A:");

	return NT_STATUS_OK;
}

/*
  disconnect from a share
*/
static NTSTATUS svfs_disconnect(struct smbsrv_request *req)
{
	return NT_STATUS_OK;
}

/*
  delete a file - the dirtype specifies the file types to include in the search. 
  The name can contain CIFS wildcards, but rarely does (except with OS/2 clients)
*/
static NTSTATUS svfs_unlink(struct smbsrv_request *req, struct smb_unlink *unl)
{
	char *unix_path;

	unix_path = svfs_unix_path(req, unl->in.pattern);

	/* ignoring wildcards ... */
	if (unlink(unix_path) == -1) {
		return map_nt_error_from_unix(errno);
	}

	return NT_STATUS_OK;
}


/*
  ioctl interface - we don't do any
*/
static NTSTATUS svfs_ioctl(struct smbsrv_request *req, struct smb_ioctl *io)
{
	return NT_STATUS_INVALID_PARAMETER;
}

/*
  check if a directory exists
*/
static NTSTATUS svfs_chkpath(struct smbsrv_request *req, struct smb_chkpath *cp)
{
	char *unix_path;
	struct stat st;

	unix_path = svfs_unix_path(req, cp->in.path);

	if (stat(unix_path, &st) == -1) {
		return map_nt_error_from_unix(errno);
	}

	if (!S_ISDIR(st.st_mode)) {
		return NT_STATUS_NOT_A_DIRECTORY;
	}

	return NT_STATUS_OK;
}

/*
  approximately map a struct stat to a fileinfo struct
*/
static NTSTATUS map_fileinfo(struct smbsrv_request *req, union smb_fileinfo *info, struct stat *st)
{
	switch (info->generic.level) {
	case SMB_FILEINFO_NETWORK_OPEN_INFORMATION:
		unix_to_nt_time(&info->netopen.out.create_time, st->st_ctime);
		unix_to_nt_time(&info->netopen.out.access_time, st->st_atime);
		unix_to_nt_time(&info->netopen.out.write_time,  st->st_mtime);
		unix_to_nt_time(&info->netopen.out.change_time, st->st_mtime);
		info->netopen.out.alloc_size = st->st_size;
		info->netopen.out.size = st->st_size;
		info->netopen.out.attrib = svfs_file_attrib(st);
		info->netopen.out.unknown = 0;
		return NT_STATUS_OK;

	case SMB_FILEINFO_ALL_INFO:
		unix_to_nt_time(&info->all_info.out.create_time, st->st_ctime);
		unix_to_nt_time(&info->all_info.out.access_time, st->st_atime);
		unix_to_nt_time(&info->all_info.out.write_time,  st->st_mtime);
		unix_to_nt_time(&info->all_info.out.change_time, st->st_mtime);
		info->all_info.out.attrib = svfs_file_attrib(st);
		info->all_info.out.alloc_size = st->st_size;
		info->all_info.out.size = st->st_size;
		info->all_info.out.nlink = st->st_nlink;
		info->all_info.out.delete_pending = 0;
		info->all_info.out.directory = S_ISDIR(st->st_mode) ? 1 : 0;
		info->all_info.out.index_number = st->st_ino;
		info->all_info.out.ea_size = 0;
		info->all_info.out.access_flags = 0xd01BF; /* what is this!? */
		info->all_info.out.current_offset = 0;
		info->all_info.out.open_mode = 0; /* what do do put here!? */
		info->all_info.out.alignment_requirement = 0; /* what do do put here!? */
		info->all_info.out.fname = talloc_strdup(req->mem_ctx, "TODO - STORE FILENAME");
		return NT_STATUS_OK;

	case SMB_FILEINFO_BASIC:
		unix_to_nt_time(&info->basic.out.create_time, st->st_ctime);
		unix_to_nt_time(&info->basic.out.access_time, st->st_atime);
		unix_to_nt_time(&info->basic.out.write_time,  st->st_mtime);
		unix_to_nt_time(&info->basic.out.change_time, st->st_mtime);
		info->basic.out.attrib = svfs_file_attrib(st);
		return NT_STATUS_OK;

	case SMB_FILEINFO_INFO_STANDARD:
		info->info_standard.out.create_time = st->st_ctime;
		info->info_standard.out.access_time = st->st_atime;
		info->info_standard.out.write_time = st->st_mtime;
		info->info_standard.out.size = st->st_size;
		info->info_standard.out.alloc_size = st->st_size;
		info->info_standard.out.attrib = svfs_file_attrib(st);
		return NT_STATUS_OK;

	case SMB_FILEINFO_INFO_STANDARD_EA:
		info->info_standard_ea.out.create_time = st->st_ctime;
		info->info_standard_ea.out.access_time = st->st_atime;
		info->info_standard_ea.out.write_time = st->st_mtime;
		info->info_standard_ea.out.size = st->st_size;
		info->info_standard_ea.out.alloc_size = st->st_size;
		info->info_standard_ea.out.attrib = svfs_file_attrib(st);
		info->info_standard_ea.out.ea_size = 0;
		return NT_STATUS_OK;

	case SMB_FILEINFO_STANDARD_INFO:
		info->standard_info.out.alloc_size = st->st_size;
		info->standard_info.out.size = st->st_size;
		info->standard_info.out.nlink = st->st_nlink;
		info->standard_info.out.delete_pending = 0;
		info->standard_info.out.directory = S_ISDIR(st->st_mode) ? 1 : 0;
		info->standard_info.out.unknown = 0;
		return NT_STATUS_OK;

	case SMB_FILEINFO_INTERNAL:
		info->internal.out.device = st->st_dev;
		info->internal.out.device = st->st_ino;
		return NT_STATUS_OK;

	case SMB_FILEINFO_EA:
		info->ea.out.unknown = 0;
		return NT_STATUS_OK;

	case SMB_FILEINFO_ATTRIB_TAGINFO:
		info->tag.out.attrib = svfs_file_attrib(st);
		info->tag.out.reparse_tag = 0;
		return NT_STATUS_OK;

	case SMB_FILEINFO_STREAM:
		/* setup a single data stream */
		info->stream.out.num_streams = 1;
		info->stream.out.streams = talloc(req->mem_ctx, sizeof(info->stream.out.streams[0]));
		if (!info->stream.out.streams) {
			return NT_STATUS_NO_MEMORY;
		}
		info->stream.out.streams[0].size = st->st_size;
		info->stream.out.streams[0].alloc_size = st->st_size;
		info->stream.out.streams[0].stream_name = talloc_strdup(req->mem_ctx,"::$DATA");
		return NT_STATUS_OK;
	}

	return NT_STATUS_INVALID_LEVEL;
}

/*
  return info on a pathname
*/
static NTSTATUS svfs_qpathinfo(struct smbsrv_request *req, union smb_fileinfo *info)
{
	char *unix_path;
	struct stat st;

	unix_path = svfs_unix_path(req, info->basic.in.fname);

	if (stat(unix_path, &st) == -1) {
		return map_nt_error_from_unix(errno);
	}

	return map_fileinfo(req, info, &st);
}

/*
  query info on a open file
*/
static NTSTATUS svfs_qfileinfo(struct smbsrv_request *req, union smb_fileinfo *info)
{
	struct stat st;

	if (fstat(info->generic.in.fnum, &st) == -1) {
		return map_nt_error_from_unix(errno);
	}

	return map_fileinfo(req, info, &st);
}


/*
  set info on a pathname
*/
static NTSTATUS svfs_setpathinfo(struct smbsrv_request *req, union smb_setfileinfo *st)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/*
  open a file
*/
static NTSTATUS svfs_open(struct smbsrv_request *req, union smb_open *io)
{
	char *unix_path;
	struct stat st;
	int fd, flags;
	
	if (io->generic.level != SMB_OPEN_GENERIC) {
		return ntvfs_map_open(req, io);
	}

	unix_path = svfs_unix_path(req, io->ntcreatex.in.fname);

	switch (io->generic.in.open_disposition) {
	case FILE_SUPERSEDE:
		flags = O_RDWR | O_CREAT | O_TRUNC;
		break;
	case FILE_OPEN:
		flags = O_RDWR;
		break;
	case FILE_CREATE:
		flags = O_RDWR | O_CREAT | O_EXCL;
		break;
	case FILE_OPEN_IF:
		flags = O_RDWR | O_CREAT;
		break;
	case FILE_OVERWRITE:
		flags = O_RDWR;
		break;
	case FILE_OVERWRITE_IF:
		flags = O_RDWR | O_CREAT | O_TRUNC;
		break;
	default:
		flags = O_RDWR;
		break;
	}

	if (io->generic.in.create_options & FILE_DIRECTORY_FILE) {
		flags = O_RDONLY | O_DIRECTORY;
		switch (io->generic.in.open_disposition) {
		case FILE_CREATE:
			if (mkdir(unix_path, 0755) == -1) {
				return map_nt_error_from_unix(errno);
			}
			break;
		case FILE_OPEN_IF:
			if (mkdir(unix_path, 0755) == -1 && errno != EEXIST) {
				return map_nt_error_from_unix(errno);
			}
			break;
		}
	}

	fd = open(unix_path, flags, 0644);
	if (fd == -1) {
		return map_nt_error_from_unix(errno);
	}

	if (fstat(fd, &st) == -1) {
		close(fd);
		return map_nt_error_from_unix(errno);
	}

	ZERO_STRUCT(io->generic.out);
	
	unix_to_nt_time(&io->generic.out.create_time, st.st_ctime);
	unix_to_nt_time(&io->generic.out.access_time, st.st_atime);
	unix_to_nt_time(&io->generic.out.write_time,  st.st_mtime);
	unix_to_nt_time(&io->generic.out.change_time, st.st_mtime);
	io->generic.out.fnum = fd;
	io->generic.out.alloc_size = st.st_size;
	io->generic.out.size = st.st_size;
	io->generic.out.file_attr = svfs_file_attrib(&st);
	io->generic.out.is_directory = S_ISDIR(st.st_mode) ? 1 : 0;

	return NT_STATUS_OK;
}

/*
  create a directory
*/
static NTSTATUS svfs_mkdir(struct smbsrv_request *req, union smb_mkdir *md)
{
	char *unix_path;

	if (md->generic.level != RAW_MKDIR_MKDIR) {
		return NT_STATUS_INVALID_LEVEL;
	}

	unix_path = svfs_unix_path(req, md->mkdir.in.path);

	if (mkdir(unix_path, 0777) == -1) {
		return map_nt_error_from_unix(errno);
	}

	return NT_STATUS_OK;
}

/*
  remove a directory
*/
static NTSTATUS svfs_rmdir(struct smbsrv_request *req, struct smb_rmdir *rd)
{
	char *unix_path;

	unix_path = svfs_unix_path(req, rd->in.path);

	if (rmdir(unix_path) == -1) {
		return map_nt_error_from_unix(errno);
	}

	return NT_STATUS_OK;
}

/*
  rename a set of files
*/
static NTSTATUS svfs_rename(struct smbsrv_request *req, union smb_rename *ren)
{
	char *unix_path1, *unix_path2;

	unix_path1 = svfs_unix_path(req, ren->in.pattern1);
	unix_path2 = svfs_unix_path(req, ren->in.pattern2);

	if (rename(unix_path1, unix_path2) != 0) {
		return map_nt_error_from_unix(errno);
	}
	
	return NT_STATUS_OK;
}

/*
  copy a set of files
*/
static NTSTATUS svfs_copy(struct smbsrv_request *req, struct smb_copy *cp)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/*
  read from a file
*/
static NTSTATUS svfs_read(struct smbsrv_request *req, union smb_read *rd)
{
	ssize_t ret;

	if (rd->generic.level != SMB_READ_READX) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	ret = pread(rd->readx.in.fnum, 
		    rd->readx.out.data, 
		    rd->readx.in.maxcnt,
		    rd->readx.in.offset);
	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}

	rd->readx.out.nread = ret;
	rd->readx.out.remaining = 0; /* should fill this in? */

	return NT_STATUS_OK;
}

/*
  write to a file
*/
static NTSTATUS svfs_write(struct smbsrv_request *req, union smb_write *wr)
{
	ssize_t ret;

	switch (wr->generic.level) {
	case SMB_WRITE_WRITEX:
		ret = pwrite(wr->writex.in.fnum, 
			     wr->writex.in.data, 
			     wr->writex.in.count,
			     wr->writex.in.offset);
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
		
		wr->writex.out.nwritten = ret;
		wr->writex.out.remaining = 0; /* should fill this in? */

		return NT_STATUS_OK;

	case SMB_WRITE_WRITE:
		if (wr->write.in.count == 0) {
			/* a truncate! */
			ret = ftruncate(wr->write.in.fnum, wr->write.in.offset);
		} else {
			ret = pwrite(wr->write.in.fnum, 
				     wr->write.in.data, 
				     wr->write.in.count,
				     wr->write.in.offset);
		}
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
		
		wr->write.out.nwritten = ret;

		return NT_STATUS_OK;
	}

	return NT_STATUS_NOT_SUPPORTED;
}

/*
  seek in a file
*/
static NTSTATUS svfs_seek(struct smbsrv_request *req, struct smb_seek *io)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/*
  flush a file
*/
static NTSTATUS svfs_flush(struct smbsrv_request *req, struct smb_flush *io)
{
	fsync(io->in.fnum);
	return NT_STATUS_OK;
}

/*
  close a file
*/
static NTSTATUS svfs_close(struct smbsrv_request *req, union smb_close *io)
{
	if (io->generic.level != SMB_CLOSE_CLOSE) {
		/* we need a mapping function */
		return NT_STATUS_INVALID_LEVEL;
	}

	if (close(io->close.in.fnum) != 0) {
		return map_nt_error_from_unix(errno);
	}

	return NT_STATUS_OK;
}

/*
  exit - closing files?
*/
static NTSTATUS svfs_exit(struct smbsrv_request *req)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/*
  lock a byte range
*/
static NTSTATUS svfs_lock(struct smbsrv_request *req, union smb_lock *lck)
{
	DEBUG(0,("REWRITE: not doing byte range locking!\n"));
	return NT_STATUS_OK;
}

/*
  set info on a open file
*/
static NTSTATUS svfs_setfileinfo(struct smbsrv_request *req, 
				 union smb_setfileinfo *info)
{
	DEBUG(0,("REWRITE: svfs_setfileinfo: not doing setfileinfo level %d\n", 
		 info->generic.level));
	switch (info->generic.level) {
	case SMB_SETFILEINFO_BASIC:
		info->basic.out.ea_error_offset = 0;
		break;
	case SMB_SETFILEINFO_END_OF_FILE:
		if (ftruncate(info->eof.in.fnum, info->eof.in.size) != 0) {
			return map_nt_error_from_unix(errno);
		}
		info->eof.out.ea_error_offset = 0;
		break;
	case SMB_SETFILEINFO_ALLOCATION:
		info->eof.out.ea_error_offset = 0;
		break;
	}
	return NT_STATUS_OK;
}


/*
  return filesystem space info
*/
static NTSTATUS svfs_fsinfo(struct smbsrv_request *req, union smb_fsinfo *fs)
{
	struct svfs_private *private = req->conn->ntvfs_private;

	if (fs->generic.level != SMB_FSINFO_GENERIC) {
		return ntvfs_map_fsinfo(req, fs);
	}

	if (sys_fsusage(private->connectpath, 
			&fs->generic.out.blocks_free, 
			&fs->generic.out.blocks_total) == -1) {
		return map_nt_error_from_unix(errno);
	}

	fs->generic.out.block_size = 512;

	return NT_STATUS_OK;
}

/*
  return filesystem attribute info
*/
static NTSTATUS svfs_fsattr(struct smbsrv_request *req, union smb_fsattr *fs)
{
	struct stat st;
	struct svfs_private *private = req->conn->ntvfs_private;

	if (fs->generic.level != SMB_FSATTR_GENERIC) {
		return ntvfs_map_fsattr(req, fs);
	}

	if (stat(private->connectpath, &st) != 0) {
		return map_nt_error_from_unix(errno);
	}

	unix_to_nt_time(&fs->generic.out.create_time, st.st_ctime);
	fs->generic.out.fs_attr = 
		FILE_CASE_PRESERVED_NAMES | 
		FILE_CASE_SENSITIVE_SEARCH | 
		FILE_PERSISTENT_ACLS;
	fs->generic.out.max_file_component_length = 255;
	fs->generic.out.serial_number = 1;
	fs->generic.out.fs_type = talloc_strdup(req->mem_ctx, "NTFS");
	fs->generic.out.volume_name = talloc_strdup(req->mem_ctx, 
						    lp_servicename(req->conn->service));

	return NT_STATUS_OK;
}

/*
  return print queue info
*/
static NTSTATUS svfs_lpq(struct smbsrv_request *req, union smb_lpq *lpq)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/* 
   list files in a directory matching a wildcard pattern
*/
NTSTATUS svfs_search_first(struct smbsrv_request *req, union smb_search_first *io, 
			   void *search_private, 
			   BOOL (*callback)(void *, union smb_search_data *))
{
	struct svfs_dir *dir;
	int i;
	struct svfs_private *private = req->conn->ntvfs_private;
	struct search_state *search;
	union smb_search_data file;
	TALLOC_CTX *mem_ctx;
	uint_t max_count;

	if (io->generic.level != SMB_SEARCH_T2FFIRST_BOTH) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	mem_ctx = talloc_init("svfs_search");

	search = talloc_zero(mem_ctx, sizeof(struct search_state));
	if (!search) {
		return NT_STATUS_NO_MEMORY;
	}

	max_count = io->t2ffirst.in.max_count;

	dir = svfs_list(mem_ctx, req, io->t2ffirst.in.pattern);
	if (!dir) {
		talloc_destroy_pool(mem_ctx);
		return NT_STATUS_FOOBAR;
	}

	search->mem_ctx = mem_ctx;
	search->handle = private->next_search_handle;
	search->dir = dir;

	if (dir->count < max_count) {
		max_count = dir->count;
	}

	for (i=0; i < max_count;i++) {
		ZERO_STRUCT(file);
		unix_to_nt_time(&file.both.create_time, dir->files[i].st.st_ctime);
		unix_to_nt_time(&file.both.access_time, dir->files[i].st.st_atime);
		unix_to_nt_time(&file.both.write_time,  dir->files[i].st.st_mtime);
		unix_to_nt_time(&file.both.change_time, dir->files[i].st.st_mtime);
		file.both.name = dir->files[i].name;
		file.both.short_name = dir->files[i].name;
		file.both.size = dir->files[i].st.st_size;
		file.both.ex_attrib = svfs_file_attrib(&dir->files[i].st);

		if (!callback(search_private, &file)) {
			break;
		}
	}

	search->current_index = i;

	io->t2ffirst.out.count = i;
	io->t2ffirst.out.handle = search->handle;
	io->t2ffirst.out.end_of_search = (i == dir->count) ? 1 : 0;

	/* work out if we are going to keep the search state */
	if ((io->t2ffirst.in.flags & FLAG_TRANS2_FIND_CLOSE) ||
	    ((io->t2ffirst.in.flags & FLAG_TRANS2_FIND_CLOSE_IF_END) && (i == dir->count))) {
		talloc_destroy(search->mem_ctx);
	} else {
		private->next_search_handle++;
		DLIST_ADD(private->search, search);
	}

	return NT_STATUS_OK;
}

/* continue a search */
NTSTATUS svfs_search_next(struct smbsrv_request *req, union smb_search_next *io, 
			   void *search_private, 
			   BOOL (*callback)(void *, union smb_search_data *))
{
	struct svfs_dir *dir;
	int i;
	struct svfs_private *private = req->conn->ntvfs_private;
	struct search_state *search;
	union smb_search_data file;
	uint_t max_count;

	if (io->generic.level != SMB_SEARCH_T2FFIRST_BOTH) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	for (search=private->search; search; search = search->next) {
		if (search->handle == io->t2fnext.in.handle) break;
	}
	
	if (!search) {
		/* we didn't find the search handle */
		return NT_STATUS_FOOBAR;
	}

	dir = search->dir;

	/* the client might be asking for something other than just continuing
	   with the search */
	if (!(io->t2fnext.in.flags & FLAG_TRANS2_FIND_CONTINUE) &&
	    (io->t2fnext.in.flags & FLAG_TRANS2_FIND_REQUIRE_RESUME) &&
	    io->t2fnext.in.last_name && *io->t2fnext.in.last_name) {
		/* look backwards first */
		for (i=search->current_index; i > 0; i--) {
			if (strcmp(io->t2fnext.in.last_name, dir->files[i-1].name) == 0) {
				search->current_index = i;
				goto found;
			}
		}

		/* then look forwards */
		for (i=search->current_index+1; i <= dir->count; i++) {
			if (strcmp(io->t2fnext.in.last_name, dir->files[i-1].name) == 0) {
				search->current_index = i;
				goto found;
			}
		}
	}

found:	
	max_count = search->current_index + io->t2fnext.in.max_count;

	if (max_count > dir->count) {
		max_count = dir->count;
	}

	for (i = search->current_index; i < max_count;i++) {
		ZERO_STRUCT(file);
		unix_to_nt_time(&file.both.create_time, dir->files[i].st.st_ctime);
		unix_to_nt_time(&file.both.access_time, dir->files[i].st.st_atime);
		unix_to_nt_time(&file.both.write_time,  dir->files[i].st.st_mtime);
		unix_to_nt_time(&file.both.change_time, dir->files[i].st.st_mtime);
		file.both.name = dir->files[i].name;
		file.both.short_name = dir->files[i].name;
		file.both.size = dir->files[i].st.st_size;
		file.both.ex_attrib = svfs_file_attrib(&dir->files[i].st);

		if (!callback(search_private, &file)) {
			break;
		}
	}

	io->t2fnext.out.count = i - search->current_index;
	io->t2fnext.out.end_of_search = (i == dir->count) ? 1 : 0;

	search->current_index = i;

	/* work out if we are going to keep the search state */
	if ((io->t2fnext.in.flags & FLAG_TRANS2_FIND_CLOSE) ||
	    ((io->t2fnext.in.flags & FLAG_TRANS2_FIND_CLOSE_IF_END) && (i == dir->count))) {
		DLIST_REMOVE(private->search, search);
		talloc_destroy(search->mem_ctx);
	}

	return NT_STATUS_OK;
}

/* close a search */
NTSTATUS svfs_search_close(struct smbsrv_request *req, union smb_search_close *io)
{
	struct svfs_private *private = req->conn->ntvfs_private;
	struct search_state *search;

	for (search=private->search; search; search = search->next) {
		if (search->handle == io->findclose.in.handle) break;
	}
	
	if (!search) {
		/* we didn't find the search handle */
		return NT_STATUS_FOOBAR;
	}

	DLIST_REMOVE(private->search, search);
	talloc_destroy(search->mem_ctx);

	return NT_STATUS_OK;
}


/*
  initialialise the POSIX disk backend, registering ourselves with the ntvfs subsystem
 */
BOOL posix_vfs_init(void)
{
	BOOL ret;
	struct ntvfs_ops ops;

	ZERO_STRUCT(ops);
	
	/* fill in all the operations */
	ops.connect = svfs_connect;
	ops.disconnect = svfs_disconnect;
	ops.unlink = svfs_unlink;
	ops.chkpath = svfs_chkpath;
	ops.qpathinfo = svfs_qpathinfo;
	ops.setpathinfo = svfs_setpathinfo;
	ops.open = svfs_open;
	ops.mkdir = svfs_mkdir;
	ops.rmdir = svfs_rmdir;
	ops.rename = svfs_rename;
	ops.copy = svfs_copy;
	ops.ioctl = svfs_ioctl;
	ops.read = svfs_read;
	ops.write = svfs_write;
	ops.seek = svfs_seek;
	ops.flush = svfs_flush;	
	ops.close = svfs_close;
	ops.exit = svfs_exit;
	ops.lock = svfs_lock;
	ops.setfileinfo = svfs_setfileinfo;
	ops.qfileinfo = svfs_qfileinfo;
	ops.fsinfo = svfs_fsinfo;
	ops.fsattr = svfs_fsattr;
	ops.lpq = svfs_lpq;
	ops.search_first = svfs_search_first;
	ops.search_next = svfs_search_next;
	ops.search_close = svfs_search_close;

	/* register ourselves with the NTVFS subsystem. We register under the name 'default'
	   as we wish to be the default backend */
	ret = ntvfs_register("simple", NTVFS_DISK, &ops);

	if (!ret) {
		DEBUG(0,("Failed to register POSIX backend!\n"));
		return False;
	}

	return True;
}
