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

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

#define CHECK_READ_ONLY(req) do { if (lp_readonly(req->tcon->service)) return NT_STATUS_ACCESS_DENIED; } while (0)

#ifndef HAVE_PREAD
static ssize_t pread(int __fd, void *__buf, size_t __nbytes, off_t __offset)
{
	if (lseek(__fd, __offset, SEEK_SET) != __offset) {
		return -1;
	}
	return read(__fd, __buf, __nbytes);
}
#endif

#ifndef HAVE_PWRITE
static ssize_t pwrite(int __fd, const void *__buf, size_t __nbytes, off_t __offset)
{
	if (lseek(__fd, __offset, SEEK_SET) != __offset) {
		return -1;
	}
	return write(__fd, __buf, __nbytes);
}
#endif

/*
  connect to a share - used when a tree_connect operation comes
  in. For a disk based backend we needs to ensure that the base
  directory exists (tho it doesn't need to be accessible by the user,
  that comes later)
*/
static NTSTATUS svfs_connect(struct smbsrv_request *req, const char *sharename)
{
	struct stat st;
	struct smbsrv_tcon *tcon = req->tcon;
	struct svfs_private *private;

	tcon->ntvfs_private = talloc_p(tcon, struct svfs_private);

	private = tcon->ntvfs_private;

	private->next_search_handle = 0;
	private->connectpath = talloc_strdup(tcon, lp_pathname(tcon->service));
	private->open_files = NULL;

	/* the directory must exist */
	if (stat(private->connectpath, &st) != 0 || !S_ISDIR(st.st_mode)) {
		DEBUG(0,("'%s' is not a directory, when connecting to [%s]\n", 
			 private->connectpath, sharename));
		return NT_STATUS_BAD_NETWORK_NAME;
	}

	tcon->fs_type = talloc_strdup(tcon, "NTFS");
	tcon->dev_type = talloc_strdup(tcon, "A:");

	DEBUG(0,("WARNING: ntvfs simple: connect to share [%s] with ROOT privileges!!!\n",sharename));

	return NT_STATUS_OK;
}

/*
  disconnect from a share
*/
static NTSTATUS svfs_disconnect(struct smbsrv_tcon *tcon)
{
	return NT_STATUS_OK;
}

/*
  find open file handle given fd
*/
static struct svfs_file *find_fd(struct svfs_private *private, int fd)
{
	struct svfs_file *f;
	for (f=private->open_files;f;f=f->next) {
		if (f->fd == fd) {
			return f;
		}
	}
	return NULL;
}

/*
  delete a file - the dirtype specifies the file types to include in the search. 
  The name can contain CIFS wildcards, but rarely does (except with OS/2 clients)
*/
static NTSTATUS svfs_unlink(struct smbsrv_request *req, struct smb_unlink *unl)
{
	char *unix_path;

	CHECK_READ_ONLY(req);

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
static NTSTATUS svfs_ioctl(struct smbsrv_request *req, union smb_ioctl *io)
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
  approximately map a struct stat to a generic fileinfo struct
*/
static NTSTATUS svfs_map_fileinfo(struct smbsrv_request *req, union smb_fileinfo *info, 
				  struct stat *st, const char *unix_path)
{
	struct svfs_dir *dir = NULL;
	char *pattern = NULL;
	int i;
	const char *s, *short_name;

	s = strrchr(unix_path, '/');
	if (s) {
		short_name = s+1;
	} else {
		short_name = "";
	}

	asprintf(&pattern, "%s:*", unix_path);
	
	if (pattern) {
		dir = svfs_list_unix(req, req, pattern);
	}

	unix_to_nt_time(&info->generic.out.create_time, st->st_ctime);
	unix_to_nt_time(&info->generic.out.access_time, st->st_atime);
	unix_to_nt_time(&info->generic.out.write_time,  st->st_mtime);
	unix_to_nt_time(&info->generic.out.change_time, st->st_mtime);
	info->generic.out.alloc_size = st->st_size;
	info->generic.out.size = st->st_size;
	info->generic.out.attrib = svfs_unix_to_dos_attrib(st->st_mode);
	info->generic.out.alloc_size = st->st_blksize * st->st_blocks;
	info->generic.out.nlink = st->st_nlink;
	info->generic.out.directory = S_ISDIR(st->st_mode) ? 1 : 0;
	info->generic.out.file_id = svfs_file_id(st);
	/* REWRITE: TODO stuff in here */
	info->generic.out.delete_pending = 0;
	info->generic.out.ea_size = 0;
	info->generic.out.num_eas = 0;
	info->generic.out.fname.s = talloc_strdup(req, short_name);
	info->generic.out.alt_fname.s = talloc_strdup(req, short_name);
	info->generic.out.ex_attrib = 0;
	info->generic.out.compressed_size = 0;
	info->generic.out.format = 0;
	info->generic.out.unit_shift = 0;
	info->generic.out.chunk_shift = 0;
	info->generic.out.cluster_shift = 0;
	
	info->generic.out.access_flags = 0;
	info->generic.out.position = 0;
	info->generic.out.mode = 0;
	info->generic.out.alignment_requirement = 0;
	info->generic.out.reparse_tag = 0;
	info->generic.out.num_streams = 0;
	/* setup a single data stream */
	info->generic.out.num_streams = 1 + (dir?dir->count:0);
	info->generic.out.streams = talloc_array_p(req, 
						   struct stream_struct,
						   info->generic.out.num_streams);
	if (!info->generic.out.streams) {
		return NT_STATUS_NO_MEMORY;
	}
	info->generic.out.streams[0].size = st->st_size;
	info->generic.out.streams[0].alloc_size = st->st_size;
	info->generic.out.streams[0].stream_name.s = talloc_strdup(req,"::$DATA");

	for (i=0;dir && i<dir->count;i++) {
		s = strchr(dir->files[i].name, ':');
		info->generic.out.streams[1+i].size = dir->files[i].st.st_size;
		info->generic.out.streams[1+i].alloc_size = dir->files[i].st.st_size;
		info->generic.out.streams[1+i].stream_name.s = s?s:dir->files[i].name;
	}

	return NT_STATUS_OK;
}

/*
  return info on a pathname
*/
static NTSTATUS svfs_qpathinfo(struct smbsrv_request *req, union smb_fileinfo *info)
{
	char *unix_path;
	struct stat st;

	DEBUG(19,("svfs_qpathinfo: file %s level 0x%x\n", info->generic.in.fname, info->generic.level));
	if (info->generic.level != RAW_FILEINFO_GENERIC) {
		return ntvfs_map_qpathinfo(req, info);
	}
	
	unix_path = svfs_unix_path(req, info->generic.in.fname);
	DEBUG(19,("svfs_qpathinfo: file %s\n", unix_path));
	if (stat(unix_path, &st) == -1) {
		DEBUG(19,("svfs_qpathinfo: file %s errno=%d\n", unix_path, errno));
		if (errno == 0)
			errno = ENOENT;
		return map_nt_error_from_unix(errno);
	}
	DEBUG(19,("svfs_qpathinfo: file %s, stat done\n", unix_path));
	return svfs_map_fileinfo(req, info, &st, unix_path);
}

/*
  query info on a open file
*/
static NTSTATUS svfs_qfileinfo(struct smbsrv_request *req, union smb_fileinfo *info)
{
	struct svfs_private *private = req->tcon->ntvfs_private;
	struct svfs_file *f;
	struct stat st;

	if (info->generic.level != RAW_FILEINFO_GENERIC) {
		return ntvfs_map_qfileinfo(req, info);
	}

	f = find_fd(private, info->generic.in.fnum);
	if (!f) {
		return NT_STATUS_INVALID_HANDLE;
	}
	
	if (fstat(info->generic.in.fnum, &st) == -1) {
		if (errno == 0)
			errno = ENOENT;
		return map_nt_error_from_unix(errno);
	}

	return svfs_map_fileinfo(req, info, &st, f->name);
}


/*
  open a file
*/
static NTSTATUS svfs_open(struct smbsrv_request *req, union smb_open *io)
{
	struct svfs_private *private = req->tcon->ntvfs_private;
	char *unix_path;
	struct stat st;
	int fd, flags;
	struct svfs_file *f;
	int create_flags, rdwr_flags;
	
	if (io->generic.level != RAW_OPEN_GENERIC) {
		return ntvfs_map_open(req, io);
	}

	if (lp_readonly(req->tcon->service)) {
		create_flags = 0;
		rdwr_flags = O_RDONLY;
	} else {
		create_flags = O_CREAT;
		rdwr_flags = O_RDWR;
	}

	unix_path = svfs_unix_path(req, io->ntcreatex.in.fname);

	switch (io->generic.in.open_disposition) {
	case NTCREATEX_DISP_SUPERSEDE:
	case NTCREATEX_DISP_OVERWRITE_IF:
		flags = create_flags | O_TRUNC;
		break;
	case NTCREATEX_DISP_OPEN:
	case NTCREATEX_DISP_OVERWRITE:
		flags = 0;
		break;
	case NTCREATEX_DISP_CREATE:
		flags = create_flags | O_EXCL;
		break;
	case NTCREATEX_DISP_OPEN_IF:
		flags = create_flags;
		break;
	default:
		flags = 0;
		break;
	}
	
	flags |= rdwr_flags;

	if (io->generic.in.create_options & NTCREATEX_OPTIONS_DIRECTORY) {
		flags = O_RDONLY | O_DIRECTORY;
		if (lp_readonly(req->tcon->service)) {
			goto do_open;
		}
		switch (io->generic.in.open_disposition) {
		case NTCREATEX_DISP_CREATE:
			if (mkdir(unix_path, 0755) == -1) {
				DEBUG(9,("svfs_open: mkdir %s errno=%d\n", unix_path, errno));
				return map_nt_error_from_unix(errno);
			}
			break;
		case NTCREATEX_DISP_OPEN_IF:
			if (mkdir(unix_path, 0755) == -1 && errno != EEXIST) {
				DEBUG(9,("svfs_open: mkdir %s errno=%d\n", unix_path, errno));
				return map_nt_error_from_unix(errno);
			}
			break;
		}
	}

do_open:
	fd = open(unix_path, flags, 0644);
	if (fd == -1) {
		if (errno == 0)
			errno = ENOENT;
		return map_nt_error_from_unix(errno);
	}

	if (fstat(fd, &st) == -1) {
		DEBUG(9,("svfs_open: fstat errno=%d\n", errno));
		if (errno == 0)
			errno = ENOENT;
		close(fd);
		return map_nt_error_from_unix(errno);
	}

	f = talloc_p(req->tcon, struct svfs_file);
	f->fd = fd;
	f->name = talloc_strdup(req->tcon, unix_path);

	DLIST_ADD(private->open_files, f);

	ZERO_STRUCT(io->generic.out);
	
	unix_to_nt_time(&io->generic.out.create_time, st.st_ctime);
	unix_to_nt_time(&io->generic.out.access_time, st.st_atime);
	unix_to_nt_time(&io->generic.out.write_time,  st.st_mtime);
	unix_to_nt_time(&io->generic.out.change_time, st.st_mtime);
	io->generic.out.fnum = fd;
	io->generic.out.alloc_size = st.st_size;
	io->generic.out.size = st.st_size;
	io->generic.out.attrib = svfs_unix_to_dos_attrib(st.st_mode);
	io->generic.out.is_directory = S_ISDIR(st.st_mode) ? 1 : 0;

	return NT_STATUS_OK;
}

/*
  create a directory
*/
static NTSTATUS svfs_mkdir(struct smbsrv_request *req, union smb_mkdir *md)
{
	char *unix_path;

	CHECK_READ_ONLY(req);

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

	CHECK_READ_ONLY(req);

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

	CHECK_READ_ONLY(req);

	if (ren->generic.level != RAW_RENAME_RENAME) {
		return NT_STATUS_INVALID_LEVEL;
	}

	unix_path1 = svfs_unix_path(req, ren->rename.in.pattern1);
	unix_path2 = svfs_unix_path(req, ren->rename.in.pattern2);

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

	if (rd->generic.level != RAW_READ_READX) {
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
	rd->readx.out.compaction_mode = 0; 

	return NT_STATUS_OK;
}

/*
  write to a file
*/
static NTSTATUS svfs_write(struct smbsrv_request *req, union smb_write *wr)
{
	ssize_t ret;

	CHECK_READ_ONLY(req);

	switch (wr->generic.level) {
	case RAW_WRITE_WRITEX:
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

	case RAW_WRITE_WRITE:
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
	struct svfs_private *private = req->tcon->ntvfs_private;
	struct svfs_file *f;

	if (io->generic.level != RAW_CLOSE_CLOSE) {
		/* we need a mapping function */
		return NT_STATUS_INVALID_LEVEL;
	}

	f = find_fd(private, io->close.in.fnum);
	if (!f) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if (close(io->close.in.fnum) != 0) {
		return map_nt_error_from_unix(errno);
	}

	DLIST_REMOVE(private->open_files, f);
	talloc_free(f->name);
	talloc_free(f);

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
  set info on a pathname
*/
static NTSTATUS svfs_setpathinfo(struct smbsrv_request *req, union smb_setfileinfo *st)
{
	CHECK_READ_ONLY(req);

	return NT_STATUS_NOT_SUPPORTED;
}

/*
  set info on a open file
*/
static NTSTATUS svfs_setfileinfo(struct smbsrv_request *req, 
				 union smb_setfileinfo *info)
{
	struct utimbuf unix_times;
	int fd;

	CHECK_READ_ONLY(req);
		
	switch (info->generic.level) {
	case RAW_SFILEINFO_END_OF_FILE_INFO:
	case RAW_SFILEINFO_END_OF_FILE_INFORMATION:
		if (ftruncate(info->end_of_file_info.file.fnum, 
			      info->end_of_file_info.in.size) != 0) {
			return map_nt_error_from_unix(errno);
		}
		break;
	case RAW_SFILEINFO_SETATTRE:
		unix_times.actime = info->setattre.in.access_time;
		unix_times.modtime = info->setattre.in.write_time;
  		fd = info->setattre.file.fnum;
	
		if (unix_times.actime == 0 && unix_times.modtime == 0) {
			break;
		} 

		/* set modify time = to access time if modify time was 0 */
		if (unix_times.actime != 0 && unix_times.modtime == 0) {
			unix_times.modtime = unix_times.actime;
		}

		/* Set the date on this file */
		if (svfs_file_utime(fd, &unix_times) != 0) {
			return NT_STATUS_ACCESS_DENIED;
		}
  		break;
	}
	return NT_STATUS_OK;
}


/*
  return filesystem space info
*/
static NTSTATUS svfs_fsinfo(struct smbsrv_request *req, union smb_fsinfo *fs)
{
	struct svfs_private *private = req->tcon->ntvfs_private;
	struct stat st;

	if (fs->generic.level != RAW_QFS_GENERIC) {
		return ntvfs_map_fsinfo(req, fs);
	}

	if (sys_fsusage(private->connectpath, 
			&fs->generic.out.blocks_free, 
			&fs->generic.out.blocks_total) == -1) {
		return map_nt_error_from_unix(errno);
	}

	fs->generic.out.block_size = 512;

	if (stat(private->connectpath, &st) != 0) {
		return NT_STATUS_DISK_CORRUPT_ERROR;
	}
	
	fs->generic.out.fs_id = st.st_ino;
	unix_to_nt_time(&fs->generic.out.create_time, st.st_ctime);
	fs->generic.out.serial_number = st.st_ino;
	fs->generic.out.fs_attr = 0;
	fs->generic.out.max_file_component_length = 255;
	fs->generic.out.device_type = 0;
	fs->generic.out.device_characteristics = 0;
	fs->generic.out.quota_soft = 0;
	fs->generic.out.quota_hard = 0;
	fs->generic.out.quota_flags = 0;
	fs->generic.out.volume_name = talloc_strdup(req, lp_servicename(req->tcon->service));
	fs->generic.out.fs_type = req->tcon->fs_type;

	return NT_STATUS_OK;
}

#if 0
/*
  return filesystem attribute info
*/
static NTSTATUS svfs_fsattr(struct smbsrv_request *req, union smb_fsattr *fs)
{
	struct stat st;
	struct svfs_private *private = req->tcon->ntvfs_private;

	if (fs->generic.level != RAW_FSATTR_GENERIC) {
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
	fs->generic.out.fs_type = talloc_strdup(req, "NTFS");
	fs->generic.out.volume_name = talloc_strdup(req, 
						    lp_servicename(req->tcon->service));

	return NT_STATUS_OK;
}
#endif

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
static NTSTATUS svfs_search_first(struct smbsrv_request *req, union smb_search_first *io, 
				  void *search_private, 
				  BOOL (*callback)(void *, union smb_search_data *))
{
	struct svfs_dir *dir;
	int i;
	struct svfs_private *private = req->tcon->ntvfs_private;
	struct search_state *search;
	union smb_search_data file;
	uint_t max_count;

	if (io->generic.level != RAW_SEARCH_BOTH_DIRECTORY_INFO) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	search = talloc_zero(private, sizeof(struct search_state));
	if (!search) {
		return NT_STATUS_NO_MEMORY;
	}

	max_count = io->t2ffirst.in.max_count;

	dir = svfs_list(private, req, io->t2ffirst.in.pattern);
	if (!dir) {
		return NT_STATUS_FOOBAR;
	}

	search->handle = private->next_search_handle;
	search->dir = dir;

	if (dir->count < max_count) {
		max_count = dir->count;
	}

	for (i=0; i < max_count;i++) {
		ZERO_STRUCT(file);
		unix_to_nt_time(&file.both_directory_info.create_time, dir->files[i].st.st_ctime);
		unix_to_nt_time(&file.both_directory_info.access_time, dir->files[i].st.st_atime);
		unix_to_nt_time(&file.both_directory_info.write_time,  dir->files[i].st.st_mtime);
		unix_to_nt_time(&file.both_directory_info.change_time, dir->files[i].st.st_mtime);
		file.both_directory_info.name.s = dir->files[i].name;
		file.both_directory_info.short_name.s = dir->files[i].name;
		file.both_directory_info.size = dir->files[i].st.st_size;
		file.both_directory_info.attrib = svfs_unix_to_dos_attrib(dir->files[i].st.st_mode);

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
		talloc_free(search);
	} else {
		private->next_search_handle++;
		DLIST_ADD(private->search, search);
	}

	return NT_STATUS_OK;
}

/* continue a search */
static NTSTATUS svfs_search_next(struct smbsrv_request *req, union smb_search_next *io, 
				 void *search_private, 
				 BOOL (*callback)(void *, union smb_search_data *))
{
	struct svfs_dir *dir;
	int i;
	struct svfs_private *private = req->tcon->ntvfs_private;
	struct search_state *search;
	union smb_search_data file;
	uint_t max_count;

	if (io->generic.level != RAW_SEARCH_BOTH_DIRECTORY_INFO) {
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
		unix_to_nt_time(&file.both_directory_info.create_time, dir->files[i].st.st_ctime);
		unix_to_nt_time(&file.both_directory_info.access_time, dir->files[i].st.st_atime);
		unix_to_nt_time(&file.both_directory_info.write_time,  dir->files[i].st.st_mtime);
		unix_to_nt_time(&file.both_directory_info.change_time, dir->files[i].st.st_mtime);
		file.both_directory_info.name.s = dir->files[i].name;
		file.both_directory_info.short_name.s = dir->files[i].name;
		file.both_directory_info.size = dir->files[i].st.st_size;
		file.both_directory_info.attrib = svfs_unix_to_dos_attrib(dir->files[i].st.st_mode);

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
		talloc_free(search);
	}

	return NT_STATUS_OK;
}

/* close a search */
static NTSTATUS svfs_search_close(struct smbsrv_request *req, union smb_search_close *io)
{
	struct svfs_private *private = req->tcon->ntvfs_private;
	struct search_state *search;

	for (search=private->search; search; search = search->next) {
		if (search->handle == io->findclose.in.handle) break;
	}
	
	if (!search) {
		/* we didn't find the search handle */
		return NT_STATUS_FOOBAR;
	}

	DLIST_REMOVE(private->search, search);
	talloc_free(search);

	return NT_STATUS_OK;
}

/* SMBtrans - not used on file shares */
static NTSTATUS svfs_trans(struct smbsrv_request *req, struct smb_trans2 *trans2)
{
	return NT_STATUS_ACCESS_DENIED;
}


/*
  initialialise the POSIX disk backend, registering ourselves with the ntvfs subsystem
 */
NTSTATUS ntvfs_simple_init(void)
{
	NTSTATUS ret;
	struct ntvfs_ops ops;

	ZERO_STRUCT(ops);

	/* fill in the name and type */
	ops.type = NTVFS_DISK;

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
	ops.lpq = svfs_lpq;
	ops.search_first = svfs_search_first;
	ops.search_next = svfs_search_next;
	ops.search_close = svfs_search_close;
	ops.trans = svfs_trans;

	/* register ourselves with the NTVFS subsystem. We register
	   under names 'simple'
	*/
	ops.name = "simple";
	ret = register_backend("ntvfs", &ops);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register simple backend with name: %s!\n",
			 ops.name));
	}

	return ret;
}
