/*
   Unix SMB/CIFS implementation.
   VFS module functions

   Copyright (C) Simo Sorce 2002
   Copyright (C) Eric Lorimer 2002

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
#include "smbd/smbd.h"
#include "system/passwd.h"
#include "system/filesys.h"
#include "vfstest.h"
#include "../lib/util/util_pw.h"
#include "libcli/security/security.h"
#include "passdb/machine_sid.h"

static const char *null_string = "";

static uint32_t ssf_flags(void)
{
	return lp_posix_pathnames() ? SMB_FILENAME_POSIX_PATH : 0;
}

static NTSTATUS cmd_load_module(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	int i;

	if (argc < 2) {
		printf("Usage: load <modules>\n");
		return NT_STATUS_OK;
	}

	for (i=argc-1;i>0;i--) {
		if (!vfs_init_custom(vfs->conn, argv[i])) {
			DEBUG(0, ("load: (vfs_init_custom failed for %s)\n", argv[i]));
			return NT_STATUS_UNSUCCESSFUL;
		}
	}
	printf("load: ok\n");
	return NT_STATUS_OK;
}

static NTSTATUS cmd_populate(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	char c;
	size_t size;
	if (argc != 3) {
		printf("Usage: populate <char> <size>\n");
		return NT_STATUS_OK;
	}
	c = argv[1][0];
	size = atoi(argv[2]);
	vfs->data = talloc_array(mem_ctx, char, size);
	if (vfs->data == NULL) {
		printf("populate: error=-1 (not enough memory)");
		return NT_STATUS_UNSUCCESSFUL;
	}
	memset(vfs->data, c, size);
	vfs->data_size = size;
	return NT_STATUS_OK;
}

static NTSTATUS cmd_show_data(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	size_t offset;
	size_t len;
	if (argc != 1 && argc != 3) {
		printf("Usage: showdata [<offset> <len>]\n");
		return NT_STATUS_OK;
	}
	if (vfs->data == NULL || vfs->data_size == 0) {
		printf("show_data: error=-1 (buffer empty)\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (argc == 3) {
		offset = atoi(argv[1]);
		len = atoi(argv[2]);
	} else {
		offset = 0;
		len = vfs->data_size;
	}
	if ((offset + len) > vfs->data_size) {
		printf("show_data: error=-1 (not enough data in buffer)\n");
		return NT_STATUS_UNSUCCESSFUL;
	}
	dump_data(0, (uint8_t *)(vfs->data) + offset, len);
	return NT_STATUS_OK;
}

static NTSTATUS cmd_connect(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();

	SMB_VFS_CONNECT(vfs->conn, lp_servicename(talloc_tos(), lp_sub, SNUM(vfs->conn)), "vfstest");
	return NT_STATUS_OK;
}

static NTSTATUS cmd_disconnect(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	SMB_VFS_DISCONNECT(vfs->conn);
	return NT_STATUS_OK;
}

static NTSTATUS cmd_disk_free(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	struct smb_filename *smb_fname = NULL;
	uint64_t diskfree, bsize, dfree, dsize;
	if (argc != 2) {
		printf("Usage: disk_free <path>\n");
		return NT_STATUS_OK;
	}

	smb_fname = synthetic_smb_fname(talloc_tos(),
					argv[1],
					NULL,
					NULL,
					0,
					ssf_flags());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	diskfree = SMB_VFS_DISK_FREE(vfs->conn, smb_fname,
				&bsize, &dfree, &dsize);
	printf("disk_free: %lu, bsize = %lu, dfree = %lu, dsize = %lu\n",
			(unsigned long)diskfree,
			(unsigned long)bsize,
			(unsigned long)dfree,
			(unsigned long)dsize);
	return NT_STATUS_OK;
}


static NTSTATUS cmd_opendir(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	struct smb_filename *smb_fname = NULL;

	if (argc != 2) {
		printf("Usage: opendir <fname>\n");
		return NT_STATUS_OK;
	}

	smb_fname = synthetic_smb_fname(talloc_tos(),
					argv[1],
					NULL,
					NULL,
					0,
					ssf_flags());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	vfs->currentdir = OpenDir(vfs->conn, vfs->conn, smb_fname, NULL, 0);
	if (vfs->currentdir == NULL) {
		printf("opendir error=%d (%s)\n", errno, strerror(errno));
		TALLOC_FREE(smb_fname);
		return NT_STATUS_UNSUCCESSFUL;
	}

	vfs->currentdir_offset = 0;

	TALLOC_FREE(smb_fname);
	printf("opendir: ok\n");
	return NT_STATUS_OK;
}


static NTSTATUS cmd_readdir(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	SMB_STRUCT_STAT st;
	const char *dname = NULL;
	char *talloced = NULL;

	if (vfs->currentdir == NULL) {
		printf("readdir: error=-1 (no open directory)\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

        dname = ReadDirName(vfs->currentdir,
			    &vfs->currentdir_offset,
			    &st,
			    &talloced);
	if (dname == NULL) {
		printf("readdir: NULL\n");
		return NT_STATUS_OK;
	}

	printf("readdir: %s\n", dname);
	if (VALID_STAT(st)) {
		time_t tmp_time;
		printf("  stat available");
		if (S_ISREG(st.st_ex_mode)) printf("  Regular File\n");
		else if (S_ISDIR(st.st_ex_mode)) printf("  Directory\n");
		else if (S_ISCHR(st.st_ex_mode)) printf("  Character Device\n");
		else if (S_ISBLK(st.st_ex_mode)) printf("  Block Device\n");
		else if (S_ISFIFO(st.st_ex_mode)) printf("  Fifo\n");
		else if (S_ISLNK(st.st_ex_mode)) printf("  Symbolic Link\n");
		else if (S_ISSOCK(st.st_ex_mode)) printf("  Socket\n");
		printf("  Size: %10u", (unsigned int)st.st_ex_size);
#ifdef HAVE_STAT_ST_BLOCKS
		printf(" Blocks: %9u", (unsigned int)st.st_ex_blocks);
#endif
#ifdef HAVE_STAT_ST_BLKSIZE
		printf(" IO Block: %u\n", (unsigned int)st.st_ex_blksize);
#endif
		printf("  Device: 0x%10x", (unsigned int)st.st_ex_dev);
		printf(" Inode: %10u", (unsigned int)st.st_ex_ino);
		printf(" Links: %10u\n", (unsigned int)st.st_ex_nlink);
		printf("  Access: %05o", (int)((st.st_ex_mode) & 007777));
		printf(" Uid: %5lu Gid: %5lu\n",
		       (unsigned long)st.st_ex_uid,
		       (unsigned long)st.st_ex_gid);
		tmp_time = convert_timespec_to_time_t(st.st_ex_atime);
		printf("  Access: %s", ctime(&tmp_time));
		tmp_time = convert_timespec_to_time_t(st.st_ex_mtime);
		printf("  Modify: %s", ctime(&tmp_time));
		tmp_time = convert_timespec_to_time_t(st.st_ex_ctime);
		printf("  Change: %s", ctime(&tmp_time));
	}

	TALLOC_FREE(talloced);
	return NT_STATUS_OK;
}


static NTSTATUS cmd_mkdir(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	struct smb_filename *smb_fname = NULL;
	int ret;

	if (argc != 2) {
		printf("Usage: mkdir <path>\n");
		return NT_STATUS_OK;
	}

	smb_fname = synthetic_smb_fname(talloc_tos(),
					argv[1],
					NULL,
					NULL,
					0,
					ssf_flags());

	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = SMB_VFS_MKDIRAT(vfs->conn,
				vfs->conn->cwd_fsp,
				smb_fname,
				00755);
	if (ret == -1) {
		printf("mkdir error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("mkdir: ok\n");
	return NT_STATUS_OK;
}


static NTSTATUS cmd_closedir(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	if (vfs->currentdir == NULL) {
		printf("closedir: failure (no directory open)\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	TALLOC_FREE(vfs->currentdir);
	vfs->currentdir_offset = 0;

	printf("closedir: ok\n");
	return NT_STATUS_OK;
}


static NTSTATUS cmd_open(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	int flags;
	mode_t mode;
	const char *flagstr;
	files_struct *fsp;
	struct files_struct *fspcwd = NULL;
	struct smb_filename *smb_fname = NULL;
	NTSTATUS status;
	int ret;

	mode = 00400;

	if (argc < 3 || argc > 5) {
		printf("Usage: open <filename> <flags> <mode>\n");
		printf("  flags: O = O_RDONLY\n");
		printf("         R = O_RDWR\n");
		printf("         W = O_WRONLY\n");
		printf("         C = O_CREAT\n");
	       	printf("         E = O_EXCL\n");
	       	printf("         T = O_TRUNC\n");
	       	printf("         A = O_APPEND\n");
	       	printf("         N = O_NONBLOCK/O_NDELAY\n");
#ifdef O_SYNC
	       	printf("         S = O_SYNC\n");
#endif
#ifdef O_NOFOLLOW
	       	printf("         F = O_NOFOLLOW\n");
#endif
		printf("  mode: see open.2\n");
		printf("        mode is ignored if C flag not present\n");
		printf("        mode defaults to 00400\n");
		return NT_STATUS_OK;
	}
	flags = 0;
	flagstr = argv[2];
	while (*flagstr) {
		switch (*flagstr) {
		case 'O':
			flags |= O_RDONLY;
			break;
		case 'R':
			flags |= O_RDWR;
			break;
		case 'W':
			flags |= O_WRONLY;
			break;
		case 'C':
			flags |= O_CREAT;
			break;
		case 'E':
			flags |= O_EXCL;
			break;
		case 'T':
			flags |= O_TRUNC;
			break;
		case 'A':
			flags |= O_APPEND;
			break;
		case 'N':
			flags |= O_NONBLOCK;
			break;
#ifdef O_SYNC
		case 'S':
			flags |= O_SYNC;
			break;
#endif
#ifdef O_NOFOLLOW
		case 'F':
			flags |= O_NOFOLLOW;
			break;
#endif
		default:
			printf("open: error=-1 (invalid flag!)\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
		flagstr++;
	}
	if ((flags & O_CREAT) && argc == 4) {
		if (sscanf(argv[3], "%ho", (unsigned short *)&mode) == 0) {
			printf("open: error=-1 (invalid mode!)\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	fsp = talloc_zero(vfs, struct files_struct);
	if (fsp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	fsp->fh = talloc_zero(fsp, struct fd_handle);
	if (fsp->fh == NULL) {
		TALLOC_FREE(fsp);
		return NT_STATUS_NO_MEMORY;
	}
	fsp->conn = vfs->conn;

	smb_fname = synthetic_smb_fname_split(NULL,
					argv[1],
					lp_posix_pathnames());
	if (smb_fname == NULL) {
		TALLOC_FREE(fsp);
		return NT_STATUS_NO_MEMORY;
	}

	fsp->fsp_name = smb_fname;

	status = vfs_at_fspcwd(fsp, vfs->conn, &fspcwd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	fsp->fh->fd = SMB_VFS_OPENAT(vfs->conn,
				     fspcwd,
				     smb_fname,
				     fsp,
				     flags,
				     mode);
	if (fsp->fh->fd == -1) {
		printf("open: error=%d (%s)\n", errno, strerror(errno));
		TALLOC_FREE(fsp);
		TALLOC_FREE(smb_fname);
		return NT_STATUS_UNSUCCESSFUL;
	}

	status = NT_STATUS_OK;
	ret = SMB_VFS_FSTAT(fsp, &smb_fname->st);
	if (ret == -1) {
		/* If we have an fd, this stat should succeed. */
		DEBUG(0,("Error doing fstat on open file %s "
			 "(%s)\n",
			 smb_fname_str_dbg(smb_fname),
			 strerror(errno) ));
		status = map_nt_error_from_unix(errno);
	} else if (S_ISDIR(smb_fname->st.st_ex_mode)) {
		errno = EISDIR;
		status = NT_STATUS_FILE_IS_A_DIRECTORY;
	}

	if (!NT_STATUS_IS_OK(status)) {
		SMB_VFS_CLOSE(fsp);
		TALLOC_FREE(fsp);
		TALLOC_FREE(smb_fname);
		return status;
	}

	fsp->file_id = vfs_file_id_from_sbuf(vfs->conn, &smb_fname->st);
	fsp->vuid = UID_FIELD_INVALID;
	fsp->file_pid = 0;
	fsp->fsp_flags.can_lock = true;
	fsp->fsp_flags.can_read = true;
	fsp->fsp_flags.can_write = CAN_WRITE(vfs->conn);
	fsp->print_file = NULL;
	fsp->fsp_flags.modified = false;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->fsp_flags.is_directory = false;

	vfs->files[fsp->fh->fd] = fsp;
	printf("open: fd=%d\n", fsp->fh->fd);
	return NT_STATUS_OK;
}


static NTSTATUS cmd_pathfunc(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	struct smb_filename *smb_fname = NULL;
	int ret = -1;

	if (argc != 2) {
		printf("Usage: %s <path>\n", argv[0]);
		return NT_STATUS_OK;
	}

	smb_fname = synthetic_smb_fname(talloc_tos(),
					argv[1],
					NULL,
					NULL,
					0,
					ssf_flags());

	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (strcmp("rmdir", argv[0]) == 0 ) {
		ret = SMB_VFS_UNLINKAT(vfs->conn,
				vfs->conn->cwd_fsp,
				smb_fname,
				AT_REMOVEDIR);
		TALLOC_FREE(smb_fname);
	} else if (strcmp("unlink", argv[0]) == 0 ) {
		TALLOC_FREE(smb_fname);
		/* unlink can be a stream:name */
		smb_fname = synthetic_smb_fname_split(talloc_tos(),
					argv[1],
					lp_posix_pathnames());
		if (smb_fname == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		ret = SMB_VFS_UNLINKAT(vfs->conn,
				vfs->conn->cwd_fsp,
				smb_fname,
				0);
		TALLOC_FREE(smb_fname);
	} else if (strcmp("chdir", argv[0]) == 0 ) {
		ret = SMB_VFS_CHDIR(vfs->conn, smb_fname);
		TALLOC_FREE(smb_fname);
	} else {
		printf("%s: error=%d (invalid function name!)\n", argv[0], errno);
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (ret == -1) {
		printf("%s: error=%d (%s)\n", argv[0], errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("%s: ok\n", argv[0]);
	return NT_STATUS_OK;
}


static NTSTATUS cmd_close(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	int fd, ret;

	if (argc != 2) {
		printf("Usage: close <fd>\n");
		return NT_STATUS_OK;
	}

	fd = atoi(argv[1]);
	if (vfs->files[fd] == NULL) {
		printf("close: error=-1 (invalid file descriptor)\n");
		return NT_STATUS_OK;
	}

	ret = SMB_VFS_CLOSE(vfs->files[fd]);
	if (ret == -1 )
		printf("close: error=%d (%s)\n", errno, strerror(errno));
	else
		printf("close: ok\n");

	TALLOC_FREE(vfs->files[fd]);
	vfs->files[fd] = NULL;
	return NT_STATUS_OK;
}


static NTSTATUS cmd_read(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	int fd;
	size_t size, rsize;

	if (argc != 3) {
		printf("Usage: read <fd> <size>\n");
		return NT_STATUS_OK;
	}

	/* do some error checking on these */
	fd = atoi(argv[1]);
	size = atoi(argv[2]);
	vfs->data = talloc_array(mem_ctx, char, size);
	if (vfs->data == NULL) {
		printf("read: error=-1 (not enough memory)");
		return NT_STATUS_UNSUCCESSFUL;
	}
	vfs->data_size = size;

	rsize = read_file(vfs->files[fd], vfs->data, 0, size);
	if (rsize == -1) {
		printf("read: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("read: ok\n");
	return NT_STATUS_OK;
}


static NTSTATUS cmd_write(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	int fd, size, wsize;

	if (argc != 3) {
		printf("Usage: write <fd> <size>\n");
		return NT_STATUS_OK;
	}

	/* some error checking should go here */
	fd = atoi(argv[1]);
	size = atoi(argv[2]);
	if (vfs->data == NULL) {
		printf("write: error=-1 (buffer empty, please populate it before writing)");
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (vfs->data_size < size) {
		printf("write: error=-1 (buffer too small, please put some more data in)");
		return NT_STATUS_UNSUCCESSFUL;
	}

	wsize = write_file(NULL, vfs->files[fd], vfs->data, 0, size);

	if (wsize == -1) {
		printf("write: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("write: ok\n");
	return NT_STATUS_OK;
}


static NTSTATUS cmd_lseek(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	int fd, offset, whence;
	off_t pos;

	if (argc != 4) {
		printf("Usage: lseek <fd> <offset> <whence>\n...where whence is 1 => SEEK_SET, 2 => SEEK_CUR, 3 => SEEK_END\n");
		return NT_STATUS_OK;
	}

	fd = atoi(argv[1]);
	offset = atoi(argv[2]);
	whence = atoi(argv[3]);
	switch (whence) {
		case 1:		whence = SEEK_SET; break;
		case 2:		whence = SEEK_CUR; break;
		default:	whence = SEEK_END;
	}

	pos = SMB_VFS_LSEEK(vfs->files[fd], offset, whence);
	if (pos == (off_t)-1) {
		printf("lseek: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("lseek: ok\n");
	return NT_STATUS_OK;
}


static NTSTATUS cmd_rename(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	int ret;
	struct smb_filename *smb_fname_src = NULL;
	struct smb_filename *smb_fname_dst = NULL;

	if (argc != 3) {
		printf("Usage: rename <old> <new>\n");
		return NT_STATUS_OK;
	}

	smb_fname_src = synthetic_smb_fname_split(mem_ctx,
					argv[1],
					lp_posix_pathnames());
	if (smb_fname_src == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	smb_fname_dst = synthetic_smb_fname_split(mem_ctx,
					argv[2],
					lp_posix_pathnames());
	if (smb_fname_dst == NULL) {
		TALLOC_FREE(smb_fname_src);
		return NT_STATUS_NO_MEMORY;
	}

	ret = SMB_VFS_RENAMEAT(vfs->conn,
			vfs->conn->cwd_fsp,
			smb_fname_src,
			vfs->conn->cwd_fsp,
			smb_fname_dst);

	TALLOC_FREE(smb_fname_src);
	TALLOC_FREE(smb_fname_dst);
	if (ret == -1) {
		printf("rename: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("rename: ok\n");
	return NT_STATUS_OK;
}

static NTSTATUS cmd_fsync(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	int ret, fd;
	if (argc != 2) {
		printf("Usage: fsync <fd>\n");
		return NT_STATUS_OK;
	}

	fd = atoi(argv[1]);
	ret = smb_vfs_fsync_sync(vfs->files[fd]);
	if (ret == -1) {
		printf("fsync: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("fsync: ok\n");
	return NT_STATUS_OK;
}


static NTSTATUS cmd_stat(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	int ret;
	const char *user;
	const char *group;
	struct passwd *pwd = NULL;
	struct group *grp = NULL;
	struct smb_filename *smb_fname = NULL;
	SMB_STRUCT_STAT st;
	time_t tmp_time;

	if (argc != 2) {
		printf("Usage: stat <fname>\n");
		return NT_STATUS_OK;
	}

	smb_fname = synthetic_smb_fname_split(mem_ctx,
					argv[1],
					lp_posix_pathnames());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = SMB_VFS_STAT(vfs->conn, smb_fname);
	if (ret == -1) {
		printf("stat: error=%d (%s)\n", errno, strerror(errno));
		TALLOC_FREE(smb_fname);
		return NT_STATUS_UNSUCCESSFUL;
	}
	st = smb_fname->st;
	TALLOC_FREE(smb_fname);

	pwd = getpwuid(st.st_ex_uid);
	if (pwd != NULL) user = pwd->pw_name;
	else user = null_string;
	grp = getgrgid(st.st_ex_gid);
	if (grp != NULL) group = grp->gr_name;
	else group = null_string;

	printf("stat: ok\n");
	printf("  File: %s", argv[1]);
	if (S_ISREG(st.st_ex_mode)) printf("  Regular File\n");
	else if (S_ISDIR(st.st_ex_mode)) printf("  Directory\n");
	else if (S_ISCHR(st.st_ex_mode)) printf("  Character Device\n");
	else if (S_ISBLK(st.st_ex_mode)) printf("  Block Device\n");
	else if (S_ISFIFO(st.st_ex_mode)) printf("  Fifo\n");
	else if (S_ISLNK(st.st_ex_mode)) printf("  Symbolic Link\n");
	else if (S_ISSOCK(st.st_ex_mode)) printf("  Socket\n");
	printf("  Size: %10u", (unsigned int)st.st_ex_size);
#ifdef HAVE_STAT_ST_BLOCKS
	printf(" Blocks: %9u", (unsigned int)st.st_ex_blocks);
#endif
#ifdef HAVE_STAT_ST_BLKSIZE
	printf(" IO Block: %u\n", (unsigned int)st.st_ex_blksize);
#endif
	printf("  Device: 0x%10x", (unsigned int)st.st_ex_dev);
	printf(" Inode: %10u", (unsigned int)st.st_ex_ino);
	printf(" Links: %10u\n", (unsigned int)st.st_ex_nlink);
	printf("  Access: %05o", (int)((st.st_ex_mode) & 007777));
	printf(" Uid: %5lu/%.16s Gid: %5lu/%.16s\n", (unsigned long)st.st_ex_uid, user,
	       (unsigned long)st.st_ex_gid, group);
	tmp_time = convert_timespec_to_time_t(st.st_ex_atime);
	printf("  Access: %s", ctime(&tmp_time));
	tmp_time = convert_timespec_to_time_t(st.st_ex_mtime);
	printf("  Modify: %s", ctime(&tmp_time));
	tmp_time = convert_timespec_to_time_t(st.st_ex_ctime);
	printf("  Change: %s", ctime(&tmp_time));

	return NT_STATUS_OK;
}


static NTSTATUS cmd_fstat(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	int fd;
	const char *user;
	const char *group;
	struct passwd *pwd = NULL;
	struct group *grp = NULL;
	SMB_STRUCT_STAT st;
	time_t tmp_time;

	if (argc != 2) {
		printf("Usage: fstat <fd>\n");
		return NT_STATUS_OK;
	}

	fd = atoi(argv[1]);
	if (fd < 0 || fd >= 1024) {
		printf("fstat: error=%d (file descriptor out of range)\n", EBADF);
		return NT_STATUS_OK;
	}

	if (vfs->files[fd] == NULL) {
		printf("fstat: error=%d (invalid file descriptor)\n", EBADF);
		return NT_STATUS_OK;
	}

	if (SMB_VFS_FSTAT(vfs->files[fd], &st) == -1) {
		printf("fstat: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	pwd = getpwuid(st.st_ex_uid);
	if (pwd != NULL) user = pwd->pw_name;
	else user = null_string;
	grp = getgrgid(st.st_ex_gid);
	if (grp != NULL) group = grp->gr_name;
	else group = null_string;

	printf("fstat: ok\n");
	if (S_ISREG(st.st_ex_mode)) printf("  Regular File\n");
	else if (S_ISDIR(st.st_ex_mode)) printf("  Directory\n");
	else if (S_ISCHR(st.st_ex_mode)) printf("  Character Device\n");
	else if (S_ISBLK(st.st_ex_mode)) printf("  Block Device\n");
	else if (S_ISFIFO(st.st_ex_mode)) printf("  Fifo\n");
	else if (S_ISLNK(st.st_ex_mode)) printf("  Symbolic Link\n");
	else if (S_ISSOCK(st.st_ex_mode)) printf("  Socket\n");
	printf("  Size: %10u", (unsigned int)st.st_ex_size);
#ifdef HAVE_STAT_ST_BLOCKS
	printf(" Blocks: %9u", (unsigned int)st.st_ex_blocks);
#endif
#ifdef HAVE_STAT_ST_BLKSIZE
	printf(" IO Block: %u\n", (unsigned int)st.st_ex_blksize);
#endif
	printf("  Device: 0x%10x", (unsigned int)st.st_ex_dev);
	printf(" Inode: %10u", (unsigned int)st.st_ex_ino);
	printf(" Links: %10u\n", (unsigned int)st.st_ex_nlink);
	printf("  Access: %05o", (int)((st.st_ex_mode) & 007777));
	printf(" Uid: %5lu/%.16s Gid: %5lu/%.16s\n", (unsigned long)st.st_ex_uid, user,
	       (unsigned long)st.st_ex_gid, group);
	tmp_time = convert_timespec_to_time_t(st.st_ex_atime);
	printf("  Access: %s", ctime(&tmp_time));
	tmp_time = convert_timespec_to_time_t(st.st_ex_mtime);
	printf("  Modify: %s", ctime(&tmp_time));
	tmp_time = convert_timespec_to_time_t(st.st_ex_ctime);
	printf("  Change: %s", ctime(&tmp_time));

	return NT_STATUS_OK;
}


static NTSTATUS cmd_lstat(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	const char *user;
	const char *group;
	struct passwd *pwd = NULL;
	struct group *grp = NULL;
	struct smb_filename *smb_fname = NULL;
	SMB_STRUCT_STAT st;
	time_t tmp_time;

	if (argc != 2) {
		printf("Usage: lstat <path>\n");
		return NT_STATUS_OK;
	}

	smb_fname = synthetic_smb_fname_split(mem_ctx,
					argv[1],
					lp_posix_pathnames());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (SMB_VFS_LSTAT(vfs->conn, smb_fname) == -1) {
		printf("lstat: error=%d (%s)\n", errno, strerror(errno));
		TALLOC_FREE(smb_fname);
		return NT_STATUS_UNSUCCESSFUL;
	}
	st = smb_fname->st;
	TALLOC_FREE(smb_fname);

	pwd = getpwuid(st.st_ex_uid);
	if (pwd != NULL) user = pwd->pw_name;
	else user = null_string;
	grp = getgrgid(st.st_ex_gid);
	if (grp != NULL) group = grp->gr_name;
	else group = null_string;

	printf("lstat: ok\n");
	if (S_ISREG(st.st_ex_mode)) printf("  Regular File\n");
	else if (S_ISDIR(st.st_ex_mode)) printf("  Directory\n");
	else if (S_ISCHR(st.st_ex_mode)) printf("  Character Device\n");
	else if (S_ISBLK(st.st_ex_mode)) printf("  Block Device\n");
	else if (S_ISFIFO(st.st_ex_mode)) printf("  Fifo\n");
	else if (S_ISLNK(st.st_ex_mode)) printf("  Symbolic Link\n");
	else if (S_ISSOCK(st.st_ex_mode)) printf("  Socket\n");
	printf("  Size: %10u", (unsigned int)st.st_ex_size);
#ifdef HAVE_STAT_ST_BLOCKS
	printf(" Blocks: %9u", (unsigned int)st.st_ex_blocks);
#endif
#ifdef HAVE_STAT_ST_BLKSIZE
	printf(" IO Block: %u\n", (unsigned int)st.st_ex_blksize);
#endif
	printf("  Device: 0x%10x", (unsigned int)st.st_ex_dev);
	printf(" Inode: %10u", (unsigned int)st.st_ex_ino);
	printf(" Links: %10u\n", (unsigned int)st.st_ex_nlink);
	printf("  Access: %05o", (int)((st.st_ex_mode) & 007777));
	printf(" Uid: %5lu/%.16s Gid: %5lu/%.16s\n", (unsigned long)st.st_ex_uid, user,
	       (unsigned long)st.st_ex_gid, group);
	tmp_time = convert_timespec_to_time_t(st.st_ex_atime);
	printf("  Access: %s", ctime(&tmp_time));
	tmp_time = convert_timespec_to_time_t(st.st_ex_mtime);
	printf("  Modify: %s", ctime(&tmp_time));
	tmp_time = convert_timespec_to_time_t(st.st_ex_ctime);
	printf("  Change: %s", ctime(&tmp_time));

	return NT_STATUS_OK;
}


static NTSTATUS cmd_chmod(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	struct smb_filename *smb_fname = NULL;
	mode_t mode;
	if (argc != 3) {
		printf("Usage: chmod <path> <mode>\n");
		return NT_STATUS_OK;
	}

	mode = atoi(argv[2]);

	smb_fname = synthetic_smb_fname(talloc_tos(),
					argv[1],
					NULL,
					NULL,
					0,
					ssf_flags());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (SMB_VFS_CHMOD(vfs->conn, smb_fname, mode) == -1) {
		printf("chmod: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("chmod: ok\n");
	return NT_STATUS_OK;
}


static NTSTATUS cmd_fchmod(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	int fd;
	mode_t mode;
	if (argc != 3) {
		printf("Usage: fchmod <fd> <mode>\n");
		return NT_STATUS_OK;
	}

	fd = atoi(argv[1]);
	mode = atoi(argv[2]);
	if (fd < 0 || fd >= 1024) {
		printf("fchmod: error=%d (file descriptor out of range)\n", EBADF);
		return NT_STATUS_OK;
	}
	if (vfs->files[fd] == NULL) {
		printf("fchmod: error=%d (invalid file descriptor)\n", EBADF);
		return NT_STATUS_OK;
	}

	if (SMB_VFS_FCHMOD(vfs->files[fd], mode) == -1) {
		printf("fchmod: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("fchmod: ok\n");
	return NT_STATUS_OK;
}

static NTSTATUS cmd_fchown(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	uid_t uid;
	gid_t gid;
	int fd;
	if (argc != 4) {
		printf("Usage: fchown <fd> <uid> <gid>\n");
		return NT_STATUS_OK;
	}

	uid = atoi(argv[2]);
	gid = atoi(argv[3]);
	fd = atoi(argv[1]);
	if (fd < 0 || fd >= 1024) {
		printf("fchown: faliure=%d (file descriptor out of range)\n", EBADF);
		return NT_STATUS_OK;
	}
	if (vfs->files[fd] == NULL) {
		printf("fchown: error=%d (invalid file descriptor)\n", EBADF);
		return NT_STATUS_OK;
	}
	if (SMB_VFS_FCHOWN(vfs->files[fd], uid, gid) == -1) {
		printf("fchown error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("fchown: ok\n");
	return NT_STATUS_OK;
}


static NTSTATUS cmd_getwd(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	struct smb_filename *smb_fname = SMB_VFS_GETWD(vfs->conn, talloc_tos());
	if (smb_fname == NULL) {
		printf("getwd: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("getwd: %s\n", smb_fname->base_name);
	TALLOC_FREE(smb_fname);
	return NT_STATUS_OK;
}

static NTSTATUS cmd_utime(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	struct smb_file_time ft;
	struct smb_filename *smb_fname = NULL;

	if (argc != 4) {
		printf("Usage: utime <path> <access> <modify>\n");
		return NT_STATUS_OK;
	}

	init_smb_file_time(&ft);

	ft.atime = time_t_to_full_timespec(atoi(argv[2]));
	ft.mtime = time_t_to_full_timespec(atoi(argv[3]));

	smb_fname = synthetic_smb_fname_split(mem_ctx,
					argv[1],
					lp_posix_pathnames());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (SMB_VFS_NTIMES(vfs->conn, smb_fname, &ft) != 0) {
		printf("utime: error=%d (%s)\n", errno, strerror(errno));
		TALLOC_FREE(smb_fname);
		return NT_STATUS_UNSUCCESSFUL;
	}

	TALLOC_FREE(smb_fname);
	printf("utime: ok\n");
	return NT_STATUS_OK;
}

static NTSTATUS cmd_ftruncate(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	int fd;
	off_t off;
	if (argc != 3) {
		printf("Usage: ftruncate <fd> <length>\n");
		return NT_STATUS_OK;
	}

	fd = atoi(argv[1]);
	off = atoi(argv[2]);
	if (fd < 0 || fd >= 1024) {
		printf("ftruncate: error=%d (file descriptor out of range)\n", EBADF);
		return NT_STATUS_OK;
	}
	if (vfs->files[fd] == NULL) {
		printf("ftruncate: error=%d (invalid file descriptor)\n", EBADF);
		return NT_STATUS_OK;
	}

	if (SMB_VFS_FTRUNCATE(vfs->files[fd], off) == -1) {
		printf("ftruncate: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("ftruncate: ok\n");
	return NT_STATUS_OK;
}

static NTSTATUS cmd_lock(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	int fd;
	int op;
	long offset;
	long count;
	int type;
	const char *typestr;

	if (argc != 6) {
		printf("Usage: lock <fd> <op> <offset> <count> <type>\n");
                printf("  ops: G = F_GETLK\n");
                printf("       S = F_SETLK\n");
                printf("       W = F_SETLKW\n");
                printf("  type: R = F_RDLCK\n");
                printf("        W = F_WRLCK\n");
                printf("        U = F_UNLCK\n");
		return NT_STATUS_OK;
	}

	if (sscanf(argv[1], "%d", &fd) == 0) {
		printf("lock: error=-1 (error parsing fd)\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	op = 0;
	switch (*argv[2]) {
	case 'G':
		op = F_GETLK;
		break;
	case 'S':
		op = F_SETLK;
		break;
	case 'W':
		op = F_SETLKW;
		break;
	default:
		printf("lock: error=-1 (invalid op flag!)\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (sscanf(argv[3], "%ld", &offset) == 0) {
		printf("lock: error=-1 (error parsing fd)\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (sscanf(argv[4], "%ld", &count) == 0) {
		printf("lock: error=-1 (error parsing fd)\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	type = 0;
	typestr = argv[5];
	while(*typestr) {
		switch (*typestr) {
		case 'R':
			type |= F_RDLCK;
			break;
		case 'W':
			type |= F_WRLCK;
			break;
		case 'U':
			type |= F_UNLCK;
			break;
		default:
			printf("lock: error=-1 (invalid type flag!)\n");
			return NT_STATUS_UNSUCCESSFUL;
		}
		typestr++;
	}

	printf("lock: debug lock(fd=%d, op=%d, offset=%ld, count=%ld, type=%d))\n", fd, op, offset, count, type);

	if (SMB_VFS_LOCK(vfs->files[fd], op, offset, count, type) == False) {
		printf("lock: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("lock: ok\n");
	return NT_STATUS_OK;
}

static NTSTATUS cmd_symlink(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	int ret;
	char *target = NULL;
	struct smb_filename target_fname;
	struct smb_filename *new_smb_fname = NULL;
	NTSTATUS status;

	if (argc != 3) {
		printf("Usage: symlink <path> <link>\n");
		return NT_STATUS_OK;
	}

	new_smb_fname = synthetic_smb_fname_split(mem_ctx,
					argv[2],
					lp_posix_pathnames());
	if (new_smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	target = talloc_strdup(mem_ctx, argv[1]);
	if (target == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	target_fname = (struct smb_filename) {
		.base_name = target,
	};

	/* Removes @GMT tokens if any */
	status = canonicalize_snapshot_path(&target_fname, UCF_GMT_PATHNAME, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ret = SMB_VFS_SYMLINKAT(vfs->conn,
			&target_fname,
			vfs->conn->cwd_fsp,
			new_smb_fname);
	if (ret == -1) {
		printf("symlink: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("symlink: ok\n");
	return NT_STATUS_OK;
}


static NTSTATUS cmd_readlink(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	char buffer[PATH_MAX];
	struct smb_filename *smb_fname = NULL;
	int size;

	if (argc != 2) {
		printf("Usage: readlink <path>\n");
		return NT_STATUS_OK;
	}

	smb_fname = synthetic_smb_fname_split(mem_ctx,
					argv[1],
					lp_posix_pathnames());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	size = SMB_VFS_READLINKAT(vfs->conn,
			vfs->conn->cwd_fsp,
			smb_fname,
			buffer,
			PATH_MAX);

	if (size == -1) {
		printf("readlink: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	buffer[size] = '\0';
	printf("readlink: %s\n", buffer);
	return NT_STATUS_OK;
}


static NTSTATUS cmd_link(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	struct smb_filename *old_smb_fname = NULL;
	struct smb_filename *new_smb_fname = NULL;
	int ret;

	if (argc != 3) {
		printf("Usage: link <path> <link>\n");
		return NT_STATUS_OK;
	}

	old_smb_fname = synthetic_smb_fname_split(mem_ctx,
					argv[1],
					lp_posix_pathnames());
	if (old_smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	new_smb_fname = synthetic_smb_fname_split(mem_ctx,
					argv[2],
					lp_posix_pathnames());
	if (new_smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = SMB_VFS_LINKAT(vfs->conn,
			vfs->conn->cwd_fsp,
			old_smb_fname,
			vfs->conn->cwd_fsp,
			new_smb_fname,
			0);
	if (ret == -1) {
		printf("link: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("link: ok\n");
	return NT_STATUS_OK;
}

static NTSTATUS cmd_mknod(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	mode_t mode;
	unsigned int dev_val;
	SMB_DEV_T dev;
	struct smb_filename *smb_fname = NULL;
	int ret;

	if (argc != 4) {
		printf("Usage: mknod <path> <mode> <dev>\n");
		printf("  mode is octal\n");
		printf("  dev is hex\n");
		return NT_STATUS_OK;
	}

	if (sscanf(argv[2], "%ho", (unsigned short *)&mode) == 0) {
		printf("open: error=-1 (invalid mode!)\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (sscanf(argv[3], "%x", &dev_val) == 0) {
		printf("open: error=-1 (invalid dev!)\n");
		return NT_STATUS_UNSUCCESSFUL;
	}
	dev = (SMB_DEV_T)dev_val;

	smb_fname = synthetic_smb_fname_split(mem_ctx,
					argv[1],
					lp_posix_pathnames());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = SMB_VFS_MKNODAT(vfs->conn,
			vfs->conn->cwd_fsp,
			smb_fname,
			mode,
			dev);

	if (ret == -1) {
		printf("mknod: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("mknod: ok\n");
	return NT_STATUS_OK;
}

static NTSTATUS cmd_realpath(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	struct smb_filename *smb_fname = NULL;

	if (argc != 2) {
		printf("Usage: realpath <path>\n");
		return NT_STATUS_OK;
	}

	smb_fname = synthetic_smb_fname_split(mem_ctx,
					argv[1],
					lp_posix_pathnames());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	if (SMB_VFS_REALPATH(vfs->conn, mem_ctx, smb_fname) == NULL) {
		printf("realpath: error=%d (%s)\n", errno, strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}

	printf("realpath: ok\n");
	return NT_STATUS_OK;
}

static NTSTATUS cmd_getxattr(struct vfs_state *vfs, TALLOC_CTX *mem_ctx,
			     int argc, const char **argv)
{
	uint8_t *buf;
	ssize_t ret;
	struct smb_filename *smb_fname = NULL;

	if (argc != 3) {
		printf("Usage: getxattr <path> <xattr>\n");
		return NT_STATUS_OK;
	}

	buf = NULL;

	smb_fname = synthetic_smb_fname_split(mem_ctx,
					argv[1],
					lp_posix_pathnames());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ret = SMB_VFS_GETXATTR(vfs->conn, smb_fname, argv[2], buf,
			       talloc_get_size(buf));
	if (ret == -1) {
		int err = errno;
		printf("getxattr returned (%s)\n", strerror(err));
		return map_nt_error_from_unix(err);
	}
	buf = talloc_array(mem_ctx, uint8_t, ret);
	if (buf == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ret = SMB_VFS_GETXATTR(vfs->conn, smb_fname, argv[2], buf,
			       talloc_get_size(buf));
	if (ret == -1) {
		int err = errno;
		printf("getxattr returned (%s)\n", strerror(err));
		return map_nt_error_from_unix(err);
	}
	dump_data_file(buf, talloc_get_size(buf), false, stdout);
	return NT_STATUS_OK;
}

static NTSTATUS cmd_listxattr(struct vfs_state *vfs, TALLOC_CTX *mem_ctx,
			      int argc, const char **argv)
{
	char *buf, *p;
	ssize_t ret;
	struct smb_filename *smb_fname = NULL;

	if (argc != 2) {
		printf("Usage: listxattr <path>\n");
		return NT_STATUS_OK;
	}

	buf = NULL;

	smb_fname = synthetic_smb_fname_split(mem_ctx,
					argv[1],
					lp_posix_pathnames());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ret = SMB_VFS_LISTXATTR(vfs->conn, smb_fname,
				buf, talloc_get_size(buf));
	if (ret == -1) {
		int err = errno;
		printf("listxattr returned (%s)\n", strerror(err));
		return map_nt_error_from_unix(err);
	}
	buf = talloc_array(mem_ctx, char, ret);
	if (buf == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ret = SMB_VFS_LISTXATTR(vfs->conn, smb_fname,
				buf, talloc_get_size(buf));
	if (ret == -1) {
		int err = errno;
		printf("listxattr returned (%s)\n", strerror(err));
		return map_nt_error_from_unix(err);
	}
	if (ret == 0) {
		return NT_STATUS_OK;
	}
	if (buf[ret-1] != '\0') {
		printf("listxattr returned non 0-terminated strings\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	p = buf;
	while (p < buf+ret) {
		printf("%s\n", p);
		p = strchr(p, 0);
		p += 1;
	}
	return NT_STATUS_OK;
}

static NTSTATUS cmd_setxattr(struct vfs_state *vfs, TALLOC_CTX *mem_ctx,
			     int argc, const char **argv)
{
	ssize_t ret;
	int flags = 0;
	struct smb_filename *smb_fname = NULL;

	if ((argc < 4) || (argc > 5)) {
		printf("Usage: setxattr <path> <xattr> <value> [flags]\n");
		return NT_STATUS_OK;
	}

	if (argc == 5) {
		flags = atoi(argv[4]);
	}

	smb_fname = synthetic_smb_fname_split(mem_ctx,
					argv[1],
					lp_posix_pathnames());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ret = SMB_VFS_SETXATTR(vfs->conn, smb_fname, argv[2],
			       argv[3], strlen(argv[3]), flags);
	if (ret == -1) {
		int err = errno;
		printf("setxattr returned (%s)\n", strerror(err));
		return map_nt_error_from_unix(err);
	}
	return NT_STATUS_OK;
}

static NTSTATUS cmd_removexattr(struct vfs_state *vfs, TALLOC_CTX *mem_ctx,
				int argc, const char **argv)
{
	ssize_t ret;
	struct smb_filename *smb_fname = NULL;

	if (argc != 3) {
		printf("Usage: removexattr <path> <xattr>\n");
		return NT_STATUS_OK;
	}

	smb_fname = synthetic_smb_fname(talloc_tos(),
					argv[1],
					NULL,
					NULL,
					0,
					ssf_flags());

	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = SMB_VFS_REMOVEXATTR(vfs->conn, smb_fname, argv[2]);
	if (ret == -1) {
		int err = errno;
		printf("removexattr returned (%s)\n", strerror(err));
		return map_nt_error_from_unix(err);
	}
	return NT_STATUS_OK;
}

static NTSTATUS cmd_fget_nt_acl(struct vfs_state *vfs, TALLOC_CTX *mem_ctx,
				int argc, const char **argv)
{
	int fd;
	NTSTATUS status;
	struct security_descriptor *sd;

	if (argc != 2) {
		printf("Usage: fget_nt_acl <fd>\n");
		return NT_STATUS_OK;
	}

	fd = atoi(argv[1]);
	if (fd < 0 || fd >= 1024) {
		printf("fget_nt_acl: error=%d (file descriptor out of range)\n", EBADF);
		return NT_STATUS_OK;
	}
	if (vfs->files[fd] == NULL) {
		printf("fget_nt_acl: error=%d (invalid file descriptor)\n", EBADF);
		return NT_STATUS_OK;
	}

	status = SMB_VFS_FGET_NT_ACL(vfs->files[fd],
				     SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL,
				     talloc_tos(), &sd);
	if (!NT_STATUS_IS_OK(status)) {
		printf("fget_nt_acl returned (%s)\n", nt_errstr(status));
		return status;
	}
	printf("%s\n", sddl_encode(talloc_tos(), sd, get_global_sam_sid()));
	TALLOC_FREE(sd);
	return NT_STATUS_OK;
}

static NTSTATUS cmd_get_nt_acl(struct vfs_state *vfs, TALLOC_CTX *mem_ctx,
			       int argc, const char **argv)
{
	NTSTATUS status;
	struct security_descriptor *sd;
	struct smb_filename *smb_fname = NULL;

	if (argc != 2) {
		printf("Usage: get_nt_acl <path>\n");
		return NT_STATUS_OK;
	}

	smb_fname = synthetic_smb_fname(talloc_tos(),
					argv[1],
					NULL,
					NULL,
					0,
					ssf_flags());

	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = SMB_VFS_GET_NT_ACL_AT(vfs->conn,
				vfs->conn->cwd_fsp,
				smb_fname,
				SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL,
				talloc_tos(),
				&sd);
	if (!NT_STATUS_IS_OK(status)) {
		printf("get_nt_acl returned (%s)\n", nt_errstr(status));
		return status;
	}
	printf("%s\n", sddl_encode(talloc_tos(), sd, get_global_sam_sid()));
	TALLOC_FREE(sd);
	return NT_STATUS_OK;
}

static NTSTATUS cmd_fset_nt_acl(struct vfs_state *vfs, TALLOC_CTX *mem_ctx,
				int argc, const char **argv)
{
	int fd;
	NTSTATUS status;
	struct security_descriptor *sd;

	if (argc != 3) {
		printf("Usage: fset_nt_acl <fd> <sddl>\n");
		return NT_STATUS_OK;
	}

	fd = atoi(argv[1]);
	if (fd < 0 || fd >= 1024) {
		printf("fset_nt_acl: error=%d (file descriptor out of range)\n", EBADF);
		return NT_STATUS_OK;
	}
	if (vfs->files[fd] == NULL) {
		printf("fset_nt_acl: error=%d (invalid file descriptor)\n", EBADF);
		return NT_STATUS_OK;
	}

	sd = sddl_decode(talloc_tos(), argv[2], get_global_sam_sid());
	if (!sd) {
		printf("sddl_decode failed to parse %s as SDDL\n", argv[2]);
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = SMB_VFS_FSET_NT_ACL(vfs->files[fd], SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL, sd);
	if (!NT_STATUS_IS_OK(status)) {
		printf("fset_nt_acl returned (%s)\n", nt_errstr(status));
		return status;
	}
	TALLOC_FREE(sd);
	return NT_STATUS_OK;
}

static NTSTATUS cmd_set_nt_acl(struct vfs_state *vfs, TALLOC_CTX *mem_ctx, int argc, const char **argv)
{
	int flags;
	int ret;
	mode_t mode;
	files_struct *fsp;
	struct files_struct *fspcwd = NULL;
	struct smb_filename *smb_fname = NULL;
	NTSTATUS status;
	struct security_descriptor *sd = NULL;

	if (argc != 3) {
		printf("Usage: set_nt_acl <file> <sddl>\n");
		return NT_STATUS_OK;
	}

	mode = 00400;

	fsp = talloc_zero(vfs, struct files_struct);
	if (fsp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	fsp->fh = talloc_zero(fsp, struct fd_handle);
	if (fsp->fh == NULL) {
		TALLOC_FREE(fsp);
		return NT_STATUS_NO_MEMORY;
	}
	fsp->conn = vfs->conn;

	smb_fname = synthetic_smb_fname_split(NULL,
					argv[1],
					lp_posix_pathnames());
	if (smb_fname == NULL) {
		TALLOC_FREE(fsp);
		return NT_STATUS_NO_MEMORY;
	}

	fsp->fsp_name = smb_fname;

#ifdef O_DIRECTORY
	flags = O_RDONLY|O_DIRECTORY;
#else
	/* POSIX allows us to open a directory with O_RDONLY. */
	flags = O_RDONLY;
#endif

	status = vfs_at_fspcwd(fsp, vfs->conn, &fspcwd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	fsp->fh->fd = SMB_VFS_OPENAT(vfs->conn,
				     fspcwd,
				     smb_fname,
				     fsp,
				     O_RDWR,
				     mode);
	if (fsp->fh->fd == -1 && errno == EISDIR) {
		fsp->fh->fd = SMB_VFS_OPENAT(vfs->conn,
					     fspcwd,
					     smb_fname,
					     fsp,
					     flags,
					     mode);
	}
	if (fsp->fh->fd == -1) {
		printf("open: error=%d (%s)\n", errno, strerror(errno));
		TALLOC_FREE(fsp);
		TALLOC_FREE(smb_fname);
		return NT_STATUS_UNSUCCESSFUL;
	}

	status = NT_STATUS_OK;
	ret = SMB_VFS_FSTAT(fsp, &smb_fname->st);
	if (ret == -1) {
		/* If we have an fd, this stat should succeed. */
		DEBUG(0,("Error doing fstat on open file %s "
			 "(%s)\n",
			 smb_fname_str_dbg(smb_fname),
			 strerror(errno) ));
		status = map_nt_error_from_unix(errno);
	}
	
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	fsp->file_id = vfs_file_id_from_sbuf(vfs->conn, &smb_fname->st);
	fsp->vuid = UID_FIELD_INVALID;
	fsp->file_pid = 0;
	fsp->fsp_flags.can_lock = true;
	fsp->fsp_flags.can_read = true;
	fsp->fsp_flags.can_write = true;
	fsp->print_file = NULL;
	fsp->fsp_flags.modified = false;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->fsp_flags.is_directory = S_ISDIR(smb_fname->st.st_ex_mode);

	sd = sddl_decode(talloc_tos(), argv[2], get_global_sam_sid());
	if (!sd) {
		printf("sddl_decode failed to parse %s as SDDL\n", argv[2]);
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	status = SMB_VFS_FSET_NT_ACL(fsp, SECINFO_OWNER | SECINFO_GROUP | SECINFO_DACL, sd);
	if (!NT_STATUS_IS_OK(status)) {
		printf("fset_nt_acl returned (%s)\n", nt_errstr(status));
		goto out;
	}
out:
	TALLOC_FREE(sd);

	ret = SMB_VFS_CLOSE(fsp);
	if (ret == -1 )
		printf("close: error=%d (%s)\n", errno, strerror(errno));

	TALLOC_FREE(fsp);

	return status;
}



static NTSTATUS cmd_sys_acl_get_fd(struct vfs_state *vfs, TALLOC_CTX *mem_ctx,
				   int argc, const char **argv)
{
	int fd;
	SMB_ACL_T acl;
	char *acl_text;

	if (argc != 2) {
		printf("Usage: sys_acl_get_fd <fd>\n");
		return NT_STATUS_OK;
	}

	fd = atoi(argv[1]);
	if (fd < 0 || fd >= 1024) {
		printf("sys_acl_get_fd: error=%d (file descriptor out of range)\n", EBADF);
		return NT_STATUS_OK;
	}
	if (vfs->files[fd] == NULL) {
		printf("sys_acl_get_fd: error=%d (invalid file descriptor)\n", EBADF);
		return NT_STATUS_OK;
	}

	acl = SMB_VFS_SYS_ACL_GET_FD(vfs->files[fd], talloc_tos());
	if (!acl) {
		printf("sys_acl_get_fd failed (%s)\n", strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}
	acl_text = sys_acl_to_text(acl, NULL);
	printf("%s", acl_text);
	TALLOC_FREE(acl);
	SAFE_FREE(acl_text);
	return NT_STATUS_OK;
}

static NTSTATUS cmd_sys_acl_get_file(struct vfs_state *vfs, TALLOC_CTX *mem_ctx,
				     int argc, const char **argv)
{
	SMB_ACL_T acl;
	char *acl_text;
	int type;
	struct smb_filename *smb_fname = NULL;

	if (argc != 3) {
		printf("Usage: sys_acl_get_file <path> <type>\n");
		return NT_STATUS_OK;
	}

	smb_fname = synthetic_smb_fname_split(talloc_tos(),
					argv[1],
					lp_posix_pathnames());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	type = atoi(argv[2]);
	acl = SMB_VFS_SYS_ACL_GET_FILE(vfs->conn, smb_fname,
				type, talloc_tos());
	if (!acl) {
		printf("sys_acl_get_file failed (%s)\n", strerror(errno));
		return NT_STATUS_UNSUCCESSFUL;
	}
	acl_text = sys_acl_to_text(acl, NULL);
	printf("%s", acl_text);
	TALLOC_FREE(acl);
	SAFE_FREE(acl_text);
	return NT_STATUS_OK;
}

static NTSTATUS cmd_sys_acl_blob_get_file(struct vfs_state *vfs,
					  TALLOC_CTX *mem_ctx,
					  int argc, const char **argv)
{
	char *description;
	DATA_BLOB blob;
	int ret;
	size_t i;
	struct smb_filename *smb_fname = NULL;

	if (argc != 2) {
		printf("Usage: sys_acl_get_file <path>\n");
		return NT_STATUS_OK;
	}

	smb_fname = synthetic_smb_fname_split(talloc_tos(),
					argv[1],
					lp_posix_pathnames());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ret = SMB_VFS_SYS_ACL_BLOB_GET_FILE(vfs->conn, smb_fname, talloc_tos(),
					    &description, &blob);
	if (ret != 0) {
		printf("sys_acl_blob_get_file failed (%s)\n", strerror(errno));
		return map_nt_error_from_unix(errno);
	}
	printf("Description: %s\n", description);
	for (i = 0; i < blob.length; i++) {
		printf("%.2x ", blob.data[i]);
	}
	printf("\n");

	return NT_STATUS_OK;
}

static NTSTATUS cmd_sys_acl_blob_get_fd(struct vfs_state *vfs,
					TALLOC_CTX *mem_ctx,
					int argc, const char **argv)
{
	int fd;
	char *description;
	DATA_BLOB blob;
	int ret;
	size_t i;

	if (argc != 2) {
		printf("Usage: sys_acl_blob_get_fd <fd>\n");
		return NT_STATUS_OK;
	}

	fd = atoi(argv[1]);
	if (fd < 0 || fd >= 1024) {
		printf("sys_acl_blob_get_fd: error=%d "
		       "(file descriptor out of range)\n", EBADF);
		return NT_STATUS_OK;
	}
	if (vfs->files[fd] == NULL) {
		printf("sys_acl_blob_get_fd: error=%d "
		       "(invalid file descriptor)\n", EBADF);
		return NT_STATUS_OK;
	}

	ret = SMB_VFS_SYS_ACL_BLOB_GET_FD(vfs->files[fd], talloc_tos(),
					  &description, &blob);
	if (ret != 0) {
		printf("sys_acl_blob_get_fd failed (%s)\n", strerror(errno));
		return map_nt_error_from_unix(errno);
	}
	printf("Description: %s\n", description);
	for (i = 0; i < blob.length; i++) {
		printf("%.2x ", blob.data[i]);
	}
	printf("\n");

	return NT_STATUS_OK;
}



static NTSTATUS cmd_sys_acl_delete_def_file(struct vfs_state *vfs, TALLOC_CTX *mem_ctx,
					    int argc, const char **argv)
{
	int ret;
	struct smb_filename *smb_fname = NULL;

	if (argc != 2) {
		printf("Usage: sys_acl_delete_def_file <path>\n");
		return NT_STATUS_OK;
	}

	smb_fname = synthetic_smb_fname(talloc_tos(),
					argv[1],
					NULL,
					NULL,
					0,
					ssf_flags());

	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ret = SMB_VFS_SYS_ACL_DELETE_DEF_FILE(vfs->conn, smb_fname);
	if (ret == -1) {
		printf("sys_acl_delete_def_file failed (%s)\n", strerror(errno));
		TALLOC_FREE(smb_fname);
		return NT_STATUS_UNSUCCESSFUL;
	}
	TALLOC_FREE(smb_fname);
	return NT_STATUS_OK;
}

/* Afaik translate name was first introduced with vfs_catia, to be able
   to translate unix file/dir-names, containing invalid windows characters,
   to valid windows names.
   The used translation direction is always unix --> windows
*/
static NTSTATUS cmd_translate_name(struct vfs_state *vfs, TALLOC_CTX *mem_ctx,
					    int argc, const char **argv)
{
	const char *dname = NULL;
	char *dname_talloced = NULL;
	SMB_STRUCT_STAT st;
	bool found = false;
	char *translated = NULL;
	struct smb_filename *smb_fname = NULL;
	NTSTATUS status;

	if (argc != 2) {
		DEBUG(0, ("Usage: translate_name unix_filename\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	smb_fname = synthetic_smb_fname(talloc_tos(),
					".",
					NULL,
					NULL,
					0,
					ssf_flags());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	vfs->currentdir = OpenDir(talloc_tos(),
				  vfs->conn,
				  smb_fname,
				  NULL,
				  0);
	if (vfs->currentdir == NULL) {
		DEBUG(0, ("cmd_translate_name: opendir error=%d (%s)\n",
			  errno, strerror(errno)));
		TALLOC_FREE(smb_fname);
		return NT_STATUS_UNSUCCESSFUL;
	}
	vfs->currentdir_offset = 0;

	while (true) {
		/* ReadDirName() returns Windows "encoding" */
		dname = ReadDirName(vfs->currentdir,
				    &vfs->currentdir_offset,
				    &st,
				    &dname_talloced);
		if (dname == NULL) {
			break;
		}

		/* Convert Windows "encoding" from ReadDirName() to UNIX */
		status = SMB_VFS_TRANSLATE_NAME(vfs->conn,
						dname,
						vfs_translate_to_unix,
						talloc_tos(),
						&translated);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("file '%s' cannot be translated\n", argv[1]);
			goto cleanup;
		}

		/*
		 * argv[1] uses UNIX "encoding", so compare with translation
		 * result.
		 */
		if (strcmp(translated, argv[1]) == 0) {
			found = true;
			break;
		}
		TALLOC_FREE(dname_talloced);
		TALLOC_FREE(translated);
	};

	if (!found) {
		DEBUG(0, ("cmd_translate_name: file '%s' not found.\n", 
			  argv[1]));
		status = NT_STATUS_UNSUCCESSFUL;
		goto cleanup;
	}

	/* translation success. But that could also mean
	   that translating "aaa" to "aaa" was successful :-(
	*/ 
	DBG_ERR("file '%s' --> '%s'\n", argv[1], dname);
	status = NT_STATUS_OK;

cleanup:
	TALLOC_FREE(dname_talloced);
	TALLOC_FREE(translated);
	TALLOC_FREE(smb_fname);
	TALLOC_FREE(vfs->currentdir);
	vfs->currentdir_offset = 0;
	return status;
}


struct cmd_set vfs_commands[] = {

	{ .name = "VFS Commands" },

	{ "load", cmd_load_module, "Load a module", "load <module.so>" },
	{ "populate", cmd_populate, "Populate a data buffer", "populate <char> <size>" },
	{ "showdata", cmd_show_data, "Show data currently in data buffer", "show_data [<offset> <len>]"},
	{ "connect",   cmd_connect,   "VFS connect()",    "connect" },
	{ "disconnect",   cmd_disconnect,   "VFS disconnect()",    "disconnect" },
	{ "disk_free",   cmd_disk_free,   "VFS disk_free()",    "disk_free <path>" },
	{ "opendir",   cmd_opendir,   "VFS opendir()",    "opendir <fname>" },
	{ "readdir",   cmd_readdir,   "VFS readdir()",    "readdir" },
	{ "mkdir",   cmd_mkdir,   "VFS mkdir()",    "mkdir <path>" },
	{ "rmdir",   cmd_pathfunc,   "VFS rmdir()",    "rmdir <path>" },
	{ "closedir",   cmd_closedir,   "VFS closedir()",    "closedir" },
	{ "open",   cmd_open,   "VFS open()",    "open <fname> <flags> <mode>" },
	{ "close",   cmd_close,   "VFS close()",    "close <fd>" },
	{ "read",   cmd_read,   "VFS read()",    "read <fd> <size>" },
	{ "write",   cmd_write,   "VFS write()",    "write <fd> <size>" },
	{ "lseek",   cmd_lseek,   "VFS lseek()",    "lseek <fd> <offset> <whence>" },
	{ "rename",   cmd_rename,   "VFS rename()",    "rename <old> <new>" },
	{ "fsync",   cmd_fsync,   "VFS fsync()",    "fsync <fd>" },
	{ "stat",   cmd_stat,   "VFS stat()",    "stat <fname>" },
	{ "fstat",   cmd_fstat,   "VFS fstat()",    "fstat <fd>" },
	{ "lstat",   cmd_lstat,   "VFS lstat()",    "lstat <fname>" },
	{ "unlink",   cmd_pathfunc,   "VFS unlink()",    "unlink <fname>" },
	{ "chmod",   cmd_chmod,   "VFS chmod()",    "chmod <path> <mode>" },
	{ "fchmod",   cmd_fchmod,   "VFS fchmod()",    "fchmod <fd> <mode>" },
	{ "fchown",   cmd_fchown,   "VFS fchown()",    "fchown <fd> <uid> <gid>" },
	{ "chdir",   cmd_pathfunc,   "VFS chdir()",    "chdir <path>" },
	{ "getwd",   cmd_getwd,   "VFS getwd()",    "getwd" },
	{ "utime",   cmd_utime,   "VFS utime()",    "utime <path> <access> <modify>" },
	{ "ftruncate",   cmd_ftruncate,   "VFS ftruncate()",    "ftruncate <fd> <length>" },
	{ "lock",   cmd_lock,   "VFS lock()",    "lock <f> <op> <offset> <count> <type>" },
	{ "symlink",   cmd_symlink,   "VFS symlink()",    "symlink <old> <new>" },
	{ "readlink",   cmd_readlink,   "VFS readlink()",    "readlink <path>" },
	{ "link",   cmd_link,   "VFS link()",    "link <oldpath> <newpath>" },
	{ "mknod",   cmd_mknod,   "VFS mknod()",    "mknod <path> <mode> <dev>" },
	{ "realpath",   cmd_realpath,   "VFS realpath()",    "realpath <path>" },
	{ "getxattr", cmd_getxattr, "VFS getxattr()",
	  "getxattr <path> <name>" },
	{ "listxattr", cmd_listxattr, "VFS listxattr()",
	  "listxattr <path>" },
	{ "setxattr", cmd_setxattr, "VFS setxattr()",
	  "setxattr <path> <name> <value> [<flags>]" },
	{ "removexattr", cmd_removexattr, "VFS removexattr()",
	  "removexattr <path> <name>\n" },
	{ "fget_nt_acl", cmd_fget_nt_acl, "VFS fget_nt_acl()", 
	  "fget_nt_acl <fd>\n" },
	{ "get_nt_acl", cmd_get_nt_acl, "VFS get_nt_acl()", 
	  "get_nt_acl <path>\n" },
	{ "fset_nt_acl", cmd_fset_nt_acl, "VFS fset_nt_acl()", 
	  "fset_nt_acl <fd>\n" },
	{ "set_nt_acl", cmd_set_nt_acl, "VFS open() and fset_nt_acl()", 
	  "set_nt_acl <file>\n" },
	{ "sys_acl_get_file", cmd_sys_acl_get_file, "VFS sys_acl_get_file()", "sys_acl_get_file <path>" },
	{ "sys_acl_get_fd", cmd_sys_acl_get_fd, "VFS sys_acl_get_fd()", "sys_acl_get_fd <fd>" },
	{ "sys_acl_blob_get_file", cmd_sys_acl_blob_get_file,
	  "VFS sys_acl_blob_get_file()", "sys_acl_blob_get_file <path>" },
	{ "sys_acl_blob_get_fd", cmd_sys_acl_blob_get_fd,
	  "VFS sys_acl_blob_get_fd()", "sys_acl_blob_get_fd <path>" },
	{ "sys_acl_delete_def_file", cmd_sys_acl_delete_def_file, "VFS sys_acl_delete_def_file()", "sys_acl_delete_def_file <path>" },


	{ "test_chain", cmd_test_chain, "test chain code",
	  "test_chain" },
	{ "translate_name", cmd_translate_name, "VFS translate_name()", "translate_name unix_filename" },
	{0}
};
