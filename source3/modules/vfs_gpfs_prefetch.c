/*
   Unix SMB/CIFS implementation.
   Make use of gpfs prefetch functionality

   Copyright (C) Volker Lendecke 2008

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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#include <gpfs.h>
#include <gpfs_fcntl.h>

static int (*gpfs_fcntl_fn)(int fd, void *arg);

static int smbd_gpfs_fcntl(int fd, void *arg)
{
	static void *libgpfs_handle = NULL;

	DEBUG(10, ("smbd_gpfs_fcntl called for %d\n", fd));

	if (gpfs_fcntl_fn == NULL) {
		libgpfs_handle = sys_dlopen("libgpfs.so", RTLD_LAZY);

		if (libgpfs_handle == NULL) {
			DEBUG(10, ("sys_dlopen for libgpfs failed: %s\n",
				   strerror(errno)));
			return;
		}

		gpfs_fcntl_fn = sys_dlsym(libgpfs_handle, "gpfs_fcntl");
		if (gpfs_fcntl_fn == NULL) {
			DEBUG(3, ("libgpfs.so does not contain the symbol "
				  "'gpfs_fcntl'\n"));
			errno = ENOSYS;
			return -1;
		}
	}

	return gpfs_fcntl_fn(fd, arg);
}

struct gpfs_prefetch_config {
	name_compare_entry *namelist;
	size_t size;
};

struct gpfs_prefetch_hints {
	blksize_t st_blksize;
	/*
	 * The current center around which config->size bytes are
	 * prefetched
	 */
	SMB_OFF_T center;
};

static void gpfs_prefetch_recenter(vfs_handle_struct *handle,
				   files_struct *fsp,
				   SMB_OFF_T offset, size_t size,
				   struct gpfs_prefetch_hints *hints)
{
	int ret;
	SMB_OFF_T new_center;

	struct {
		gpfsFcntlHeader_t hdr;
		gpfsMultipleAccessRange_t acc;
	} arg;


	if (hints->st_blksize == 0) {
		SMB_STRUCT_STAT sbuf;

		if (SMB_VFS_NEXT_FSTAT(handle, fsp, &sbuf) == -1) {
			return;
		}
		DEBUG(10, ("gpfs_prefetch_recenter: st_blksize = %d\n",
			   (int)sbuf.st_blksize));
		hints->st_blksize = sbuf.st_blksize;
	}

	new_center = (offset > size) ? offset : 0;

	DEBUG(10, ("gpfs_prefetch_recenter: size=%d, offset=%d, "
		   "old_center=%d, new_center=%d\n", (int)size, (int)offset,
		   (int)hints->center, (int)new_center));

	ZERO_STRUCT(arg);

	arg.hdr.totalLength = sizeof(arg);
	arg.hdr.fcntlVersion = GPFS_FCNTL_CURRENT_VERSION;
	arg.hdr.fcntlReserved = 0;
	arg.acc.structLen = sizeof(arg.acc);
	arg.acc.structType = GPFS_MULTIPLE_ACCESS_RANGE;
	arg.acc.accRangeCnt = 1;
	arg.acc.relRangeCnt = 1;

	arg.acc.accRangeArray[0].blockNumber = new_center/hints->st_blksize;
	arg.acc.accRangeArray[0].start = 0;
	arg.acc.accRangeArray[0].length = size;
	arg.acc.accRangeArray[0].isWrite = 0;

	arg.acc.relRangeArray[0].blockNumber = hints->center/hints->st_blksize;
	arg.acc.relRangeArray[0].start = 0;
	arg.acc.relRangeArray[0].length = size;
	arg.acc.relRangeArray[0].isWrite = 0;

	ret = smbd_gpfs_fcntl(fsp->fh->fd, &arg);
	if (ret == -1) {
		DEBUG(5, ("gpfs_fcntl returned %s\n", strerror(errno)));
	}

	hints->center = new_center;
}

static ssize_t gpfs_prefetch_pread(vfs_handle_struct *handle,
				   files_struct *fsp, void *data,
				   size_t n, SMB_OFF_T offset)
{
	struct gpfs_prefetch_config *config =
		(struct gpfs_prefetch_config *)handle->data;
	struct gpfs_prefetch_hints *hints = (struct gpfs_prefetch_hints *)
		VFS_FETCH_FSP_EXTENSION(handle, fsp);
	SMB_OFF_T out_of_center;

	/*
	 * How far away from the center of the prefetch region is the
	 * request?
	 */

	out_of_center = (offset > hints->center)
		? (offset - hints->center) : (hints->center - offset);

	DEBUG(10, ("gpfs_prefetch_pread: n=%d, offset=%d, center=%d, "
		   "out_of_center=%d, size=%d\n", (int)n, (int)offset,
		   (int)hints->center, (int)out_of_center,
		   (int)config->size));
	/*
	 * Are we completely out of the prefetch range or less than
	 * 10% at its borders?
	 */

	if ((out_of_center > config->size)
	    || ((config->size - out_of_center) * 10 < config->size)) {
		/*
		 * Re-center the prefetch area
		 */
		gpfs_prefetch_recenter(handle, fsp, offset, config->size,
				       hints);
	}

	return SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
}

static int gpfs_prefetch_open(vfs_handle_struct *handle,  const char *fname,
			      files_struct *fsp, int flags, mode_t mode)
{
	int fd, ret;
	struct gpfs_prefetch_hints *hints;
	struct gpfs_prefetch_config *config =
		(struct gpfs_prefetch_config *)handle->data;

	struct {
		gpfsFcntlHeader_t hdr;
		gpfsAccessRange_t acc;
	} arg;

	DEBUG(10, ("gpfs_prefetch_open called for %s, config=%p, "
		   "config->namelist = %p, config->size=%d\n", fname,
		   config, config->namelist, (int)config->size));

	if (!is_in_path(fname, config->namelist,
			handle->conn->case_sensitive)) {
		DEBUG(10, ("gpfs_prefetch_open not in list: %s\n", fname));
		return SMB_VFS_NEXT_OPEN(handle, fname, fsp, flags, mode);
	}

	hints = (struct gpfs_prefetch_hints *)VFS_ADD_FSP_EXTENSION(
		handle, fsp, struct gpfs_prefetch_hints);
	if (hints == NULL) {
		errno = ENOMEM;
		return -1;
	}

	fd = SMB_VFS_NEXT_OPEN(handle, fname, fsp, flags, mode);
	if (fd == -1) {
		VFS_REMOVE_FSP_EXTENSION(handle, fsp);
		return -1;
	}

	arg.hdr.totalLength = sizeof(arg);
	arg.hdr.fcntlVersion = GPFS_FCNTL_CURRENT_VERSION;
	arg.hdr.fcntlReserved = 0;
	arg.acc.structLen = sizeof(arg.acc);
	arg.acc.structType = GPFS_ACCESS_RANGE;
	arg.acc.start = 0;
	arg.acc.length = 1;
	arg.acc.isWrite = 0;

	ret = smbd_gpfs_fcntl(fd, &arg);
	if (ret == -1) {
		DEBUG(5, ("gpfs_fcntl returned %s\n", strerror(errno)));
	}

	hints->st_blksize = 0;
	hints->center = 0;

	return fd;
}

static void gpfs_prefetch_config_free(void **data)
{
	struct gpfs_prefetch_config **config =
		(struct gpfs_prefetch_config **)data;

	free_namearray((*config)->namelist);
	TALLOC_FREE(*config);
}

static int gpfs_prefetch_connect(struct vfs_handle_struct *handle,
				 const char *service,
				 const char *user)
{
	struct gpfs_prefetch_config *config;
	const char *mask;

	config = talloc(handle, struct gpfs_prefetch_config);
	if (config == NULL) {
		DEBUG(0, ("talloc failed\n"));
		errno = ENOMEM;
		return -1;
	}

	mask = lp_parm_const_string(SNUM(handle->conn), "gpfs_prefetch",
				    "mask", "");

	set_namearray(&config->namelist, mask);
	config->size = lp_parm_int(SNUM(handle->conn), "gpfs_prefetch",
				   "size", 1024);

	/*
	 * The size calculations in the core routines assume that
	 * config->size is the size from the center to the border of
	 * the prefetched area. So we need to multiply by 1024/2 here
	 * to get the whole prefetch area in kilobytes.
	 */
	config->size *= 1024/2;

	SMB_VFS_HANDLE_SET_DATA(handle, config, gpfs_prefetch_config_free,
				struct gpfs_prefetch_config, goto fail);

	return SMB_VFS_NEXT_CONNECT(handle, service, user);

fail:
	free_namearray(config->namelist);
	TALLOC_FREE(config);
	return -1;
}

/* VFS operations structure */

static vfs_op_tuple gpfs_prefetch_op_tuples[] = {

	{SMB_VFS_OP(gpfs_prefetch_open),	SMB_VFS_OP_OPEN,
	 SMB_VFS_LAYER_TRANSPARENT },
	{SMB_VFS_OP(gpfs_prefetch_pread),	SMB_VFS_OP_PREAD,
	 SMB_VFS_LAYER_TRANSPARENT },
	{SMB_VFS_OP(gpfs_prefetch_connect),	SMB_VFS_OP_CONNECT,
	 SMB_VFS_LAYER_TRANSPARENT },

        { SMB_VFS_OP(NULL), SMB_VFS_OP_NOOP, SMB_VFS_LAYER_NOOP }
};

/*
 * When done properly upstream (GPL issue resolved), change this
 * routine name to vfs_gpfs_prefetch_init!!
 */

NTSTATUS init_samba_module(void);
NTSTATUS init_samba_module(void)
{
	NTSTATUS status;

	DEBUG(10, ("vfs_gpfs_prefetch_init called\n"));

	status = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "gpfs_prefetch",
				  gpfs_prefetch_op_tuples);
	DEBUG(10, ("smb_register_vfs returned %s\n",
		   nt_errstr(status)));

	return status;
}
