/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   VFS initialisation and support functions
   Copyright (C) Tim Potter 1999
   Copyright (C) Alexander Bokovoy 2002
   Copyright (C) James Peach 2006
   Copyright (C) Volker Lendecke 2009

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

   This work was sponsored by Optifacio Software Services, Inc.
*/

#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../lib/util/memcache.h"
#include "transfer_file.h"
#include "ntioctl.h"
#include "lib/util/tevent_unix.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

static_decl_vfs;

struct vfs_fsp_data {
    struct vfs_fsp_data *next;
    struct vfs_handle_struct *owner;
    void (*destroy)(void *p_data);
    void *_dummy_;
    /* NOTE: This structure contains four pointers so that we can guarantee
     * that the end of the structure is always both 4-byte and 8-byte aligned.
     */
};

struct vfs_init_function_entry {
	char *name;
	struct vfs_init_function_entry *prev, *next;
	const struct vfs_fn_pointers *fns;
};

/****************************************************************************
    maintain the list of available backends
****************************************************************************/

static struct vfs_init_function_entry *vfs_find_backend_entry(const char *name)
{
	struct vfs_init_function_entry *entry = backends;

	DEBUG(10, ("vfs_find_backend_entry called for %s\n", name));

	while(entry) {
		if (strcmp(entry->name, name)==0) return entry;
		entry = entry->next;
	}

	return NULL;
}

NTSTATUS smb_register_vfs(int version, const char *name,
			  const struct vfs_fn_pointers *fns)
{
	struct vfs_init_function_entry *entry = backends;

 	if ((version != SMB_VFS_INTERFACE_VERSION)) {
		DEBUG(0, ("Failed to register vfs module.\n"
		          "The module was compiled against SMB_VFS_INTERFACE_VERSION %d,\n"
		          "current SMB_VFS_INTERFACE_VERSION is %d.\n"
		          "Please recompile against the current Samba Version!\n",  
			  version, SMB_VFS_INTERFACE_VERSION));
		return NT_STATUS_OBJECT_TYPE_MISMATCH;
  	}

	if (!name || !name[0]) {
		DEBUG(0,("smb_register_vfs() called with NULL pointer or empty name!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (vfs_find_backend_entry(name)) {
		DEBUG(0,("VFS module %s already loaded!\n", name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	entry = SMB_XMALLOC_P(struct vfs_init_function_entry);
	entry->name = smb_xstrdup(name);
	entry->fns = fns;

	DLIST_ADD(backends, entry);
	DEBUG(5, ("Successfully added vfs backend '%s'\n", name));
	return NT_STATUS_OK;
}

/****************************************************************************
  initialise default vfs hooks
****************************************************************************/

static void vfs_init_default(connection_struct *conn)
{
	DEBUG(3, ("Initialising default vfs hooks\n"));
	vfs_init_custom(conn, DEFAULT_VFS_MODULE_NAME);
}

/****************************************************************************
  initialise custom vfs hooks
 ****************************************************************************/

bool vfs_init_custom(connection_struct *conn, const char *vfs_object)
{
	char *module_path = NULL;
	char *module_name = NULL;
	char *module_param = NULL, *p;
	vfs_handle_struct *handle;
	const struct vfs_init_function_entry *entry;

	if (!conn||!vfs_object||!vfs_object[0]) {
		DEBUG(0, ("vfs_init_custom() called with NULL pointer or "
			  "empty vfs_object!\n"));
		return False;
	}

	if(!backends) {
		static_init_vfs;
	}

	DEBUG(3, ("Initialising custom vfs hooks from [%s]\n", vfs_object));

	module_path = smb_xstrdup(vfs_object);

	p = strchr_m(module_path, ':');

	if (p) {
		*p = 0;
		module_param = p+1;
		trim_char(module_param, ' ', ' ');
	}

	trim_char(module_path, ' ', ' ');

	module_name = smb_xstrdup(module_path);

	if ((module_name[0] == '/') &&
	    (strcmp(module_path, DEFAULT_VFS_MODULE_NAME) != 0)) {

		/*
		 * Extract the module name from the path. Just use the base
		 * name of the last path component.
		 */

		SAFE_FREE(module_name);
		module_name = smb_xstrdup(strrchr_m(module_path, '/')+1);

		p = strchr_m(module_name, '.');

		if (p != NULL) {
			*p = '\0';
		}
	}

	/* First, try to load the module with the new module system */
	entry = vfs_find_backend_entry(module_name);
	if (!entry) {
		NTSTATUS status;

		DEBUG(5, ("vfs module [%s] not loaded - trying to load...\n",
			  vfs_object));

		status = smb_load_module("vfs", module_path);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("error probing vfs module '%s': %s\n",
				  module_path, nt_errstr(status)));
			goto fail;
		}

		entry = vfs_find_backend_entry(module_name);
		if (!entry) {
			DEBUG(0,("Can't find a vfs module [%s]\n",vfs_object));
			goto fail;
		}
	}

	DEBUGADD(5,("Successfully loaded vfs module [%s] with the new modules system\n", vfs_object));

	handle = talloc_zero(conn, vfs_handle_struct);
	if (!handle) {
		DEBUG(0,("TALLOC_ZERO() failed!\n"));
		goto fail;
	}
	handle->conn = conn;
	handle->fns = entry->fns;
	if (module_param) {
		handle->param = talloc_strdup(conn, module_param);
	}
	DLIST_ADD(conn->vfs_handles, handle);

	SAFE_FREE(module_path);
	SAFE_FREE(module_name);
	return True;

 fail:
	SAFE_FREE(module_path);
	SAFE_FREE(module_name);
	return False;
}

/*****************************************************************
 Allow VFS modules to extend files_struct with VFS-specific state.
 This will be ok for small numbers of extensions, but might need to
 be refactored if it becomes more widely used.
******************************************************************/

#define EXT_DATA_AREA(e) ((uint8 *)(e) + sizeof(struct vfs_fsp_data))

void *vfs_add_fsp_extension_notype(vfs_handle_struct *handle,
				   files_struct *fsp, size_t ext_size,
				   void (*destroy_fn)(void *p_data))
{
	struct vfs_fsp_data *ext;
	void * ext_data;

	/* Prevent VFS modules adding multiple extensions. */
	if ((ext_data = vfs_fetch_fsp_extension(handle, fsp))) {
		return ext_data;
	}

	ext = (struct vfs_fsp_data *)TALLOC_ZERO(
		handle->conn, sizeof(struct vfs_fsp_data) + ext_size);
	if (ext == NULL) {
		return NULL;
	}

	ext->owner = handle;
	ext->next = fsp->vfs_extension;
	ext->destroy = destroy_fn;
	fsp->vfs_extension = ext;
	return EXT_DATA_AREA(ext);
}

void vfs_remove_fsp_extension(vfs_handle_struct *handle, files_struct *fsp)
{
	struct vfs_fsp_data *curr;
	struct vfs_fsp_data *prev;

	for (curr = fsp->vfs_extension, prev = NULL;
	     curr;
	     prev = curr, curr = curr->next) {
		if (curr->owner == handle) {
		    if (prev) {
			    prev->next = curr->next;
		    } else {
			    fsp->vfs_extension = curr->next;
		    }
		    if (curr->destroy) {
			    curr->destroy(EXT_DATA_AREA(curr));
		    }
		    TALLOC_FREE(curr);
		    return;
		}
	}
}

void vfs_remove_all_fsp_extensions(files_struct *fsp)
{
	struct vfs_fsp_data *curr;
	struct vfs_fsp_data *next;

	for (curr = fsp->vfs_extension; curr; curr = next) {

		next = curr->next;
		fsp->vfs_extension = next;

		if (curr->destroy) {
			curr->destroy(EXT_DATA_AREA(curr));
		}
		TALLOC_FREE(curr);
	}
}

void *vfs_memctx_fsp_extension(vfs_handle_struct *handle, files_struct *fsp)
{
	struct vfs_fsp_data *head;

	for (head = fsp->vfs_extension; head; head = head->next) {
		if (head->owner == handle) {
			return head;
		}
	}

	return NULL;
}

void *vfs_fetch_fsp_extension(vfs_handle_struct *handle, files_struct *fsp)
{
	struct vfs_fsp_data *head;

	head = (struct vfs_fsp_data *)vfs_memctx_fsp_extension(handle, fsp);
	if (head != NULL) {
		return EXT_DATA_AREA(head);
	}

	return NULL;
}

#undef EXT_DATA_AREA

/*****************************************************************
 Generic VFS init.
******************************************************************/

bool smbd_vfs_init(connection_struct *conn)
{
	const char **vfs_objects;
	unsigned int i = 0;
	int j = 0;

	/* Normal share - initialise with disk access functions */
	vfs_init_default(conn);

	/* No need to load vfs modules for printer connections */
	if (conn->printer) {
		return True;
	}

	vfs_objects = lp_vfs_objects(SNUM(conn));

	/* Override VFS functions if 'vfs object' was not specified*/
	if (!vfs_objects || !vfs_objects[0])
		return True;

	for (i=0; vfs_objects[i] ;) {
		i++;
	}

	for (j=i-1; j >= 0; j--) {
		if (!vfs_init_custom(conn, vfs_objects[j])) {
			DEBUG(0, ("smbd_vfs_init: vfs_init_custom failed for %s\n", vfs_objects[j]));
			return False;
		}
	}
	return True;
}

/*******************************************************************
 Check if a file exists in the vfs.
********************************************************************/

NTSTATUS vfs_file_exist(connection_struct *conn, struct smb_filename *smb_fname)
{
	/* Only return OK if stat was successful and S_ISREG */
	if ((SMB_VFS_STAT(conn, smb_fname) != -1) &&
	    S_ISREG(smb_fname->st.st_ex_mode)) {
		return NT_STATUS_OK;
	}

	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}

/****************************************************************************
 Read data from fsp on the vfs. (note: EINTR re-read differs from vfs_write_data)
****************************************************************************/

ssize_t vfs_read_data(files_struct *fsp, char *buf, size_t byte_count)
{
	size_t total=0;

	while (total < byte_count)
	{
		ssize_t ret = SMB_VFS_READ(fsp, buf + total,
					   byte_count - total);

		if (ret == 0) return total;
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			else
				return -1;
		}
		total += ret;
	}
	return (ssize_t)total;
}

/****************************************************************************
 Write data to a fd on the vfs.
****************************************************************************/

ssize_t vfs_write_data(struct smb_request *req,
			files_struct *fsp,
			const char *buffer,
			size_t N)
{
	size_t total=0;
	ssize_t ret;

	if (req && req->unread_bytes) {
		int sockfd = req->xconn->transport.sock;
		int old_flags;
		SMB_ASSERT(req->unread_bytes == N);
		/* VFS_RECVFILE must drain the socket
		 * before returning. */
		req->unread_bytes = 0;
		/* Ensure the socket is blocking. */
		old_flags = fcntl(sockfd, F_GETFL, 0);
		if (set_blocking(sockfd, true) == -1) {
			return (ssize_t)-1;
		}
		ret = SMB_VFS_RECVFILE(sockfd,
					fsp,
					(off_t)-1,
					N);
		if (fcntl(sockfd, F_SETFL, old_flags) == -1) {
			return (ssize_t)-1;
		}
		return ret;
	}

	while (total < N) {
		ret = SMB_VFS_WRITE(fsp, buffer + total, N - total);

		if (ret == -1)
			return -1;
		if (ret == 0)
			return total;

		total += ret;
	}
	return (ssize_t)total;
}

ssize_t vfs_pwrite_data(struct smb_request *req,
			files_struct *fsp,
			const char *buffer,
			size_t N,
			off_t offset)
{
	size_t total=0;
	ssize_t ret;

	if (req && req->unread_bytes) {
		int sockfd = req->xconn->transport.sock;
		SMB_ASSERT(req->unread_bytes == N);
		/* VFS_RECVFILE must drain the socket
		 * before returning. */
		req->unread_bytes = 0;
		/*
		 * Leave the socket non-blocking and
		 * use SMB_VFS_RECVFILE. If it returns
		 * EAGAIN || EWOULDBLOCK temporarily set
		 * the socket blocking and retry
		 * the RECVFILE.
		 */
		while (total < N) {
			ret = SMB_VFS_RECVFILE(sockfd,
						fsp,
						offset + total,
						N - total);
			if (ret == 0 || (ret == -1 &&
					 (errno == EAGAIN ||
					  errno == EWOULDBLOCK))) {
				int old_flags;
				/* Ensure the socket is blocking. */
				old_flags = fcntl(sockfd, F_GETFL, 0);
				if (set_blocking(sockfd, true) == -1) {
					return (ssize_t)-1;
				}
				ret = SMB_VFS_RECVFILE(sockfd,
							fsp,
							offset + total,
							N - total);
				if (fcntl(sockfd, F_SETFL, old_flags) == -1) {
					return (ssize_t)-1;
				}
				if (ret == -1) {
					return (ssize_t)-1;
				}
				total += ret;
				return (ssize_t)total;
			}
			/* Any other error case. */
			if (ret == -1) {
				return ret;
			}
			total += ret;
		}
		return (ssize_t)total;
	}

	while (total < N) {
		ret = SMB_VFS_PWRITE(fsp, buffer + total, N - total,
				     offset + total);

		if (ret == -1)
			return -1;
		if (ret == 0)
			return total;

		total += ret;
	}
	return (ssize_t)total;
}
/****************************************************************************
 An allocate file space call using the vfs interface.
 Allocates space for a file from a filedescriptor.
 Returns 0 on success, -1 on failure.
****************************************************************************/

int vfs_allocate_file_space(files_struct *fsp, uint64_t len)
{
	int ret;
	connection_struct *conn = fsp->conn;
	uint64_t space_avail;
	uint64_t bsize,dfree,dsize;
	NTSTATUS status;

	/*
	 * Actually try and commit the space on disk....
	 */

	DEBUG(10,("vfs_allocate_file_space: file %s, len %.0f\n",
		  fsp_str_dbg(fsp), (double)len));

	if (((off_t)len) < 0) {
		DEBUG(0,("vfs_allocate_file_space: %s negative len "
			 "requested.\n", fsp_str_dbg(fsp)));
		errno = EINVAL;
		return -1;
	}

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}

	if (len == (uint64_t)fsp->fsp_name->st.st_ex_size)
		return 0;

	if (len < (uint64_t)fsp->fsp_name->st.st_ex_size) {
		/* Shrink - use ftruncate. */

		DEBUG(10,("vfs_allocate_file_space: file %s, shrink. Current "
			  "size %.0f\n", fsp_str_dbg(fsp),
			  (double)fsp->fsp_name->st.st_ex_size));

		contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_ALLOC_SHRINK);

		flush_write_cache(fsp, SAMBA_SIZECHANGE_FLUSH);
		if ((ret = SMB_VFS_FTRUNCATE(fsp, (off_t)len)) != -1) {
			set_filelen_write_cache(fsp, len);
		}

		contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_ALLOC_SHRINK);

		return ret;
	}

	/* Grow - we need to test if we have enough space. */

	contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_ALLOC_GROW);

	if (lp_strict_allocate(SNUM(fsp->conn))) {
		/* See if we have a syscall that will allocate beyond
		   end-of-file without changing EOF. */
		ret = SMB_VFS_FALLOCATE(fsp, VFS_FALLOCATE_KEEP_SIZE, 0, len);
	} else {
		ret = 0;
	}

	contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_ALLOC_GROW);

	if (ret == 0) {
		/* We changed the allocation size on disk, but not
		   EOF - exactly as required. We're done ! */
		return 0;
	}

	if (ret == -1 && errno == ENOSPC) {
		return -1;
	}

	len -= fsp->fsp_name->st.st_ex_size;
	len /= 1024; /* Len is now number of 1k blocks needed. */
	space_avail = get_dfree_info(conn, fsp->fsp_name->base_name, false,
				     &bsize, &dfree, &dsize);
	if (space_avail == (uint64_t)-1) {
		return -1;
	}

	DEBUG(10,("vfs_allocate_file_space: file %s, grow. Current size %.0f, "
		  "needed blocks = %.0f, space avail = %.0f\n",
		  fsp_str_dbg(fsp), (double)fsp->fsp_name->st.st_ex_size, (double)len,
		  (double)space_avail));

	if (len > space_avail) {
		errno = ENOSPC;
		return -1;
	}

	return 0;
}

/****************************************************************************
 A vfs set_filelen call.
 set the length of a file from a filedescriptor.
 Returns 0 on success, -1 on failure.
****************************************************************************/

int vfs_set_filelen(files_struct *fsp, off_t len)
{
	int ret;

	contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_SET_FILE_LEN);

	DEBUG(10,("vfs_set_filelen: ftruncate %s to len %.0f\n",
		  fsp_str_dbg(fsp), (double)len));
	flush_write_cache(fsp, SAMBA_SIZECHANGE_FLUSH);
	if ((ret = SMB_VFS_FTRUNCATE(fsp, len)) != -1) {
		set_filelen_write_cache(fsp, len);
		notify_fname(fsp->conn, NOTIFY_ACTION_MODIFIED,
			     FILE_NOTIFY_CHANGE_SIZE
			     | FILE_NOTIFY_CHANGE_ATTRIBUTES,
			     fsp->fsp_name->base_name);
	}

	contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_SET_FILE_LEN);

	return ret;
}

/****************************************************************************
 A slow version of fallocate. Fallback code if SMB_VFS_FALLOCATE
 fails. Needs to be outside of the default version of SMB_VFS_FALLOCATE
 as this is also called from the default SMB_VFS_FTRUNCATE code.
 Always extends the file size.
 Returns 0 on success, -1 on failure.
****************************************************************************/

#define SPARSE_BUF_WRITE_SIZE (32*1024)

int vfs_slow_fallocate(files_struct *fsp, off_t offset, off_t len)
{
	ssize_t pwrite_ret;
	size_t total = 0;

	if (!sparse_buf) {
		sparse_buf = SMB_CALLOC_ARRAY(char, SPARSE_BUF_WRITE_SIZE);
		if (!sparse_buf) {
			errno = ENOMEM;
			return -1;
		}
	}

	while (total < len) {
		size_t curr_write_size = MIN(SPARSE_BUF_WRITE_SIZE, (len - total));

		pwrite_ret = SMB_VFS_PWRITE(fsp, sparse_buf, curr_write_size, offset + total);
		if (pwrite_ret == -1) {
			int saved_errno = errno;
			DEBUG(10,("vfs_slow_fallocate: SMB_VFS_PWRITE for file "
				  "%s failed with error %s\n",
				  fsp_str_dbg(fsp), strerror(saved_errno)));
			errno = saved_errno;
			return -1;
		}
		total += pwrite_ret;
	}

	return 0;
}

/****************************************************************************
 A vfs fill sparse call.
 Writes zeros from the end of file to len, if len is greater than EOF.
 Used only by strict_sync.
 Returns 0 on success, -1 on failure.
****************************************************************************/

int vfs_fill_sparse(files_struct *fsp, off_t len)
{
	int ret;
	NTSTATUS status;
	off_t offset;
	size_t num_to_write;

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}

	if (len <= fsp->fsp_name->st.st_ex_size) {
		return 0;
	}

#ifdef S_ISFIFO
	if (S_ISFIFO(fsp->fsp_name->st.st_ex_mode)) {
		return 0;
	}
#endif

	DEBUG(10,("vfs_fill_sparse: write zeros in file %s from len %.0f to "
		  "len %.0f (%.0f bytes)\n", fsp_str_dbg(fsp),
		  (double)fsp->fsp_name->st.st_ex_size, (double)len,
		  (double)(len - fsp->fsp_name->st.st_ex_size)));

	contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_FILL_SPARSE);

	flush_write_cache(fsp, SAMBA_SIZECHANGE_FLUSH);

	offset = fsp->fsp_name->st.st_ex_size;
	num_to_write = len - fsp->fsp_name->st.st_ex_size;

	/* Only do this on non-stream file handles. */
	if (fsp->base_fsp == NULL) {
		/* for allocation try fallocate first. This can fail on some
		 * platforms e.g. when the filesystem doesn't support it and no
		 * emulation is being done by the libc (like on AIX with JFS1). In that
		 * case we do our own emulation. fallocate implementations can
		 * return ENOTSUP or EINVAL in cases like that. */
		ret = SMB_VFS_FALLOCATE(fsp, VFS_FALLOCATE_EXTEND_SIZE,
				offset, num_to_write);
		if (ret == -1 && errno == ENOSPC) {
			goto out;
		}
		if (ret == 0) {
			goto out;
		}
		DEBUG(10,("vfs_fill_sparse: SMB_VFS_FALLOCATE failed with "
			"error %d. Falling back to slow manual allocation\n", ret));
	}

	ret = vfs_slow_fallocate(fsp, offset, num_to_write);

 out:

	if (ret == 0) {
		set_filelen_write_cache(fsp, len);
	}

	contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_FILL_SPARSE);
	return ret;
}

/****************************************************************************
 Transfer some data (n bytes) between two file_struct's.
****************************************************************************/

static ssize_t vfs_read_fn(void *file, void *buf, size_t len)
{
	struct files_struct *fsp = (struct files_struct *)file;

	return SMB_VFS_READ(fsp, buf, len);
}

static ssize_t vfs_write_fn(void *file, const void *buf, size_t len)
{
	struct files_struct *fsp = (struct files_struct *)file;

	return SMB_VFS_WRITE(fsp, buf, len);
}

off_t vfs_transfer_file(files_struct *in, files_struct *out, off_t n)
{
	return transfer_file_internal((void *)in, (void *)out, n,
				      vfs_read_fn, vfs_write_fn);
}

/*******************************************************************
 A vfs_readdir wrapper which just returns the file name.
********************************************************************/

const char *vfs_readdirname(connection_struct *conn, void *p,
			    SMB_STRUCT_STAT *sbuf, char **talloced)
{
	struct dirent *ptr= NULL;
	const char *dname;
	char *translated;
	NTSTATUS status;

	if (!p)
		return(NULL);

	ptr = SMB_VFS_READDIR(conn, (DIR *)p, sbuf);
	if (!ptr)
		return(NULL);

	dname = ptr->d_name;


#ifdef NEXT2
	if (telldir(p) < 0)
		return(NULL);
#endif

#ifdef HAVE_BROKEN_READDIR_NAME
	/* using /usr/ucb/cc is BAD */
	dname = dname - 2;
#endif

	status = SMB_VFS_TRANSLATE_NAME(conn, dname, vfs_translate_to_windows,
					talloc_tos(), &translated);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		*talloced = NULL;
		return dname;
	}
	*talloced = translated;
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}
	return translated;
}

/*******************************************************************
 A wrapper for vfs_chdir().
********************************************************************/

int vfs_ChDir(connection_struct *conn, const char *path)
{
	int ret;

	if (!LastDir) {
		LastDir = SMB_STRDUP("");
	}

	if (ISDOT(path)) {
		return 0;
	}

	if (*path == '/' && strcsequal(LastDir,path)) {
		return 0;
	}

	DEBUG(4,("vfs_ChDir to %s\n",path));

	ret = SMB_VFS_CHDIR(conn,path);
	if (ret == 0) {
		/* Global cache. */
		SAFE_FREE(LastDir);
		LastDir = SMB_STRDUP(path);

		/* conn cache. */
		TALLOC_FREE(conn->cwd);
		conn->cwd = vfs_GetWd(conn, conn);
		DEBUG(4,("vfs_ChDir got %s\n",conn->cwd));
	}
	return ret;
}

/*******************************************************************
 Return the absolute current directory path - given a UNIX pathname.
 Note that this path is returned in DOS format, not UNIX
 format. Note this can be called with conn == NULL.
********************************************************************/

char *vfs_GetWd(TALLOC_CTX *ctx, connection_struct *conn)
{
        char *current_dir = NULL;
	char *result = NULL;
	DATA_BLOB cache_value;
	struct file_id key;
	struct smb_filename *smb_fname_dot = NULL;
	struct smb_filename *smb_fname_full = NULL;

	if (!lp_getwd_cache()) {
		goto nocache;
	}

	smb_fname_dot = synthetic_smb_fname(ctx, ".", NULL, NULL);
	if (smb_fname_dot == NULL) {
		errno = ENOMEM;
		goto out;
	}

	if (SMB_VFS_STAT(conn, smb_fname_dot) == -1) {
		/*
		 * Known to fail for root: the directory may be NFS-mounted
		 * and exported with root_squash (so has no root access).
		 */
		DEBUG(1,("vfs_GetWd: couldn't stat \".\" error %s "
			 "(NFS problem ?)\n", strerror(errno) ));
		goto nocache;
	}

	key = vfs_file_id_from_sbuf(conn, &smb_fname_dot->st);

	if (!memcache_lookup(smbd_memcache(), GETWD_CACHE,
			     data_blob_const(&key, sizeof(key)),
			     &cache_value)) {
		goto nocache;
	}

	SMB_ASSERT((cache_value.length > 0)
		   && (cache_value.data[cache_value.length-1] == '\0'));

	smb_fname_full = synthetic_smb_fname(ctx, (char *)cache_value.data,
					     NULL, NULL);
	if (smb_fname_full == NULL) {
		errno = ENOMEM;
		goto out;
	}

	if ((SMB_VFS_STAT(conn, smb_fname_full) == 0) &&
	    (smb_fname_dot->st.st_ex_dev == smb_fname_full->st.st_ex_dev) &&
	    (smb_fname_dot->st.st_ex_ino == smb_fname_full->st.st_ex_ino) &&
	    (S_ISDIR(smb_fname_dot->st.st_ex_mode))) {
		/*
		 * Ok, we're done
		 */
		result = talloc_strdup(ctx, smb_fname_full->base_name);
		if (result == NULL) {
			errno = ENOMEM;
		}
		goto out;
	}

 nocache:

	/*
	 * We don't have the information to hand so rely on traditional
	 * methods. The very slow getcwd, which spawns a process on some
	 * systems, or the not quite so bad getwd.
	 */

	current_dir = SMB_VFS_GETWD(conn);
	if (current_dir == NULL) {
		DEBUG(0, ("vfs_GetWd: SMB_VFS_GETWD call failed: %s\n",
			  strerror(errno)));
		goto out;
	}

	if (lp_getwd_cache() && VALID_STAT(smb_fname_dot->st)) {
		key = vfs_file_id_from_sbuf(conn, &smb_fname_dot->st);

		memcache_add(smbd_memcache(), GETWD_CACHE,
			     data_blob_const(&key, sizeof(key)),
			     data_blob_const(current_dir,
						strlen(current_dir)+1));
	}

	result = talloc_strdup(ctx, current_dir);
	if (result == NULL) {
		errno = ENOMEM;
	}

 out:
	TALLOC_FREE(smb_fname_dot);
	TALLOC_FREE(smb_fname_full);
	SAFE_FREE(current_dir);
	return result;
}

/*******************************************************************
 Reduce a file name, removing .. elements and checking that
 it is below dir in the heirachy. This uses realpath.
 This function must run as root, and will return names
 and valid stat structs that can be checked on open.
********************************************************************/

NTSTATUS check_reduced_name_with_privilege(connection_struct *conn,
			const char *fname,
			struct smb_request *smbreq)
{
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();
	const char *conn_rootdir;
	size_t rootdir_len;
	char *dir_name = NULL;
	const char *last_component = NULL;
	char *resolved_name = NULL;
	char *saved_dir = NULL;
	struct smb_filename *smb_fname_cwd = NULL;
	struct privilege_paths *priv_paths = NULL;
	int ret;

	DEBUG(3,("check_reduced_name_with_privilege [%s] [%s]\n",
			fname,
			conn->connectpath));


	priv_paths = talloc_zero(smbreq, struct privilege_paths);
	if (!priv_paths) {
		status = NT_STATUS_NO_MEMORY;
		goto err;
	}

	if (!parent_dirname(ctx, fname, &dir_name, &last_component)) {
		status = NT_STATUS_NO_MEMORY;
		goto err;
	}

	priv_paths->parent_name.base_name = talloc_strdup(priv_paths, dir_name);
	priv_paths->file_name.base_name = talloc_strdup(priv_paths, last_component);

	if (priv_paths->parent_name.base_name == NULL ||
			priv_paths->file_name.base_name == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err;
	}

	if (SMB_VFS_STAT(conn, &priv_paths->parent_name) != 0) {
		status = map_nt_error_from_unix(errno);
		goto err;
	}
	/* Remember where we were. */
	saved_dir = vfs_GetWd(ctx, conn);
	if (!saved_dir) {
		status = map_nt_error_from_unix(errno);
		goto err;
	}

	/* Go to the parent directory to lock in memory. */
	if (vfs_ChDir(conn, priv_paths->parent_name.base_name) == -1) {
		status = map_nt_error_from_unix(errno);
		goto err;
	}

	/* Get the absolute path of the parent directory. */
	resolved_name = SMB_VFS_REALPATH(conn,".");
	if (!resolved_name) {
		status = map_nt_error_from_unix(errno);
		goto err;
	}

	if (*resolved_name != '/') {
		DEBUG(0,("check_reduced_name_with_privilege: realpath "
			"doesn't return absolute paths !\n"));
		status = NT_STATUS_OBJECT_NAME_INVALID;
		goto err;
	}

	DEBUG(10,("check_reduced_name_with_privilege: realpath [%s] -> [%s]\n",
		priv_paths->parent_name.base_name,
		resolved_name));

	/* Now check the stat value is the same. */
	smb_fname_cwd = synthetic_smb_fname(talloc_tos(), ".", NULL, NULL);
	if (smb_fname_cwd == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err;
	}

	if (SMB_VFS_LSTAT(conn, smb_fname_cwd) != 0) {
		status = map_nt_error_from_unix(errno);
		goto err;
	}

	/* Ensure we're pointing at the same place. */
	if (!check_same_stat(&smb_fname_cwd->st, &priv_paths->parent_name.st)) {
		DEBUG(0,("check_reduced_name_with_privilege: "
			"device/inode/uid/gid on directory %s changed. "
			"Denying access !\n",
			priv_paths->parent_name.base_name));
		status = NT_STATUS_ACCESS_DENIED;
		goto err;
	}

	/* Ensure we're below the connect path. */

	conn_rootdir = SMB_VFS_CONNECTPATH(conn, fname);
	if (conn_rootdir == NULL) {
		DEBUG(2, ("check_reduced_name_with_privilege: Could not get "
			"conn_rootdir\n"));
		status = NT_STATUS_ACCESS_DENIED;
		goto err;
	}

	rootdir_len = strlen(conn_rootdir);
	if (strncmp(conn_rootdir, resolved_name, rootdir_len) != 0) {
		DEBUG(2, ("check_reduced_name_with_privilege: Bad access "
			"attempt: %s is a symlink outside the "
			"share path\n",
			dir_name));
		DEBUGADD(2, ("conn_rootdir =%s\n", conn_rootdir));
		DEBUGADD(2, ("resolved_name=%s\n", resolved_name));
		status = NT_STATUS_ACCESS_DENIED;
		goto err;
	}

	/* Now ensure that the last component either doesn't
	   exist, or is *NOT* a symlink. */

	ret = SMB_VFS_LSTAT(conn, &priv_paths->file_name);
	if (ret == -1) {
		/* Errno must be ENOENT for this be ok. */
		if (errno != ENOENT) {
			status = map_nt_error_from_unix(errno);
			DEBUG(2, ("check_reduced_name_with_privilege: "
				"LSTAT on %s failed with %s\n",
				priv_paths->file_name.base_name,
				nt_errstr(status)));
			goto err;
		}
	}

	if (VALID_STAT(priv_paths->file_name.st) &&
			S_ISLNK(priv_paths->file_name.st.st_ex_mode)) {
		DEBUG(2, ("check_reduced_name_with_privilege: "
			"Last component %s is a symlink. Denying"
			"access.\n",
			priv_paths->file_name.base_name));
		status = NT_STATUS_ACCESS_DENIED;
		goto err;
	}

	smbreq->priv_paths = priv_paths;
	status = NT_STATUS_OK;

  err:

	if (saved_dir) {
		vfs_ChDir(conn, saved_dir);
	}
	SAFE_FREE(resolved_name);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(priv_paths);
	}
	TALLOC_FREE(dir_name);
	return status;
}

/*******************************************************************
 Reduce a file name, removing .. elements and checking that
 it is below dir in the heirachy. This uses realpath.
********************************************************************/

NTSTATUS check_reduced_name(connection_struct *conn, const char *fname)
{
	char *resolved_name = NULL;
	bool allow_symlinks = true;
	bool allow_widelinks = false;

	DEBUG(3,("check_reduced_name [%s] [%s]\n", fname, conn->connectpath));

	resolved_name = SMB_VFS_REALPATH(conn,fname);

	if (!resolved_name) {
		switch (errno) {
			case ENOTDIR:
				DEBUG(3,("check_reduced_name: Component not a "
					 "directory in getting realpath for "
					 "%s\n", fname));
				return NT_STATUS_OBJECT_PATH_NOT_FOUND;
			case ENOENT:
			{
				TALLOC_CTX *ctx = talloc_tos();
				char *dir_name = NULL;
				const char *last_component = NULL;
				char *new_name = NULL;
				int ret;

				/* Last component didn't exist.
				   Remove it and try and canonicalise
				   the directory name. */
				if (!parent_dirname(ctx, fname,
						&dir_name,
						&last_component)) {
					return NT_STATUS_NO_MEMORY;
				}

				resolved_name = SMB_VFS_REALPATH(conn,dir_name);
				if (!resolved_name) {
					NTSTATUS status = map_nt_error_from_unix(errno);

					if (errno == ENOENT || errno == ENOTDIR) {
						status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
					}

					DEBUG(3,("check_reduce_name: "
						 "couldn't get realpath for "
						 "%s (%s)\n",
						fname,
						nt_errstr(status)));
					return status;
				}
				ret = asprintf(&new_name, "%s/%s",
					       resolved_name, last_component);
				SAFE_FREE(resolved_name);
				if (ret == -1) {
					return NT_STATUS_NO_MEMORY;
				}
				resolved_name = new_name;
				break;
			}
			default:
				DEBUG(3,("check_reduced_name: couldn't get "
					 "realpath for %s\n", fname));
				return map_nt_error_from_unix(errno);
		}
	}

	DEBUG(10,("check_reduced_name realpath [%s] -> [%s]\n", fname,
		  resolved_name));

	if (*resolved_name != '/') {
		DEBUG(0,("check_reduced_name: realpath doesn't return "
			 "absolute paths !\n"));
		SAFE_FREE(resolved_name);
		return NT_STATUS_OBJECT_NAME_INVALID;
	}

	allow_widelinks = lp_widelinks(SNUM(conn));
	allow_symlinks = lp_follow_symlinks(SNUM(conn));

	/* Common widelinks and symlinks checks. */
	if (!allow_widelinks || !allow_symlinks) {
		const char *conn_rootdir;
		size_t rootdir_len;

		conn_rootdir = SMB_VFS_CONNECTPATH(conn, fname);
		if (conn_rootdir == NULL) {
			DEBUG(2, ("check_reduced_name: Could not get "
				"conn_rootdir\n"));
			SAFE_FREE(resolved_name);
			return NT_STATUS_ACCESS_DENIED;
		}

		rootdir_len = strlen(conn_rootdir);
		if (strncmp(conn_rootdir, resolved_name,
				rootdir_len) != 0) {
			DEBUG(2, ("check_reduced_name: Bad access "
				"attempt: %s is a symlink outside the "
				"share path\n", fname));
			DEBUGADD(2, ("conn_rootdir =%s\n", conn_rootdir));
			DEBUGADD(2, ("resolved_name=%s\n", resolved_name));
			SAFE_FREE(resolved_name);
			return NT_STATUS_ACCESS_DENIED;
		}

		/* Extra checks if all symlinks are disallowed. */
		if (!allow_symlinks) {
			/* fname can't have changed in resolved_path. */
			const char *p = &resolved_name[rootdir_len];

			/* *p can be '\0' if fname was "." */
			if (*p == '\0' && ISDOT(fname)) {
				goto out;
			}

			if (*p != '/') {
				DEBUG(2, ("check_reduced_name: logic error (%c) "
					"in resolved_name: %s\n",
					*p,
					fname));
				SAFE_FREE(resolved_name);
				return NT_STATUS_ACCESS_DENIED;
			}

			p++;
			if (strcmp(fname, p)!=0) {
				DEBUG(2, ("check_reduced_name: Bad access "
					"attempt: %s is a symlink to %s\n",
					  fname, p));
				SAFE_FREE(resolved_name);
				return NT_STATUS_ACCESS_DENIED;
			}
		}
	}

  out:

	DEBUG(3,("check_reduced_name: %s reduced to %s\n", fname,
		 resolved_name));
	SAFE_FREE(resolved_name);
	return NT_STATUS_OK;
}

/**
 * XXX: This is temporary and there should be no callers of this once
 * smb_filename is plumbed through all path based operations.
 */
int vfs_stat_smb_fname(struct connection_struct *conn, const char *fname,
		       SMB_STRUCT_STAT *psbuf)
{
	struct smb_filename *smb_fname;
	int ret;

	smb_fname = synthetic_smb_fname_split(talloc_tos(), fname, NULL);
	if (smb_fname == NULL) {
		errno = ENOMEM;
		return -1;
	}

	if (lp_posix_pathnames()) {
		ret = SMB_VFS_LSTAT(conn, smb_fname);
	} else {
		ret = SMB_VFS_STAT(conn, smb_fname);
	}

	if (ret != -1) {
		*psbuf = smb_fname->st;
	}

	TALLOC_FREE(smb_fname);
	return ret;
}

/**
 * XXX: This is temporary and there should be no callers of this once
 * smb_filename is plumbed through all path based operations.
 */
int vfs_lstat_smb_fname(struct connection_struct *conn, const char *fname,
			SMB_STRUCT_STAT *psbuf)
{
	struct smb_filename *smb_fname;
	int ret;

	smb_fname = synthetic_smb_fname_split(talloc_tos(), fname, NULL);
	if (smb_fname == NULL) {
		errno = ENOMEM;
		return -1;
	}

	ret = SMB_VFS_LSTAT(conn, smb_fname);
	if (ret != -1) {
		*psbuf = smb_fname->st;
	}

	TALLOC_FREE(smb_fname);
	return ret;
}

/**
 * XXX: This is temporary and there should be no callers of this once
 * smb_filename is plumbed through all path based operations.
 *
 * Called when we know stream name parsing has already been done.
 */
int vfs_stat_smb_basename(struct connection_struct *conn, const char *fname,
		       SMB_STRUCT_STAT *psbuf)
{
	struct smb_filename smb_fname = {
			.base_name = discard_const_p(char, fname)
	};
	int ret;

	if (lp_posix_pathnames()) {
		ret = SMB_VFS_LSTAT(conn, &smb_fname);
	} else {
		ret = SMB_VFS_STAT(conn, &smb_fname);
	}

	if (ret != -1) {
		*psbuf = smb_fname.st;
	}
	return ret;
}

/**
 * Ensure LSTAT is called for POSIX paths.
 */

NTSTATUS vfs_stat_fsp(files_struct *fsp)
{
	int ret;

	if(fsp->fh->fd == -1) {
		if (fsp->posix_open) {
			ret = SMB_VFS_LSTAT(fsp->conn, fsp->fsp_name);
		} else {
			ret = SMB_VFS_STAT(fsp->conn, fsp->fsp_name);
		}
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
	} else {
		if(SMB_VFS_FSTAT(fsp, &fsp->fsp_name->st) != 0) {
			return map_nt_error_from_unix(errno);
		}
	}
	return NT_STATUS_OK;
}

/**
 * Initialize num_streams and streams, then call VFS op streaminfo
 */
NTSTATUS vfs_streaminfo(connection_struct *conn,
			struct files_struct *fsp,
			const char *fname,
			TALLOC_CTX *mem_ctx,
			unsigned int *num_streams,
			struct stream_struct **streams)
{
	*num_streams = 0;
	*streams = NULL;
	return SMB_VFS_STREAMINFO(conn, fsp, fname, mem_ctx, num_streams, streams);
}

/*
  generate a file_id from a stat structure
 */
struct file_id vfs_file_id_from_sbuf(connection_struct *conn, const SMB_STRUCT_STAT *sbuf)
{
	return SMB_VFS_FILE_ID_CREATE(conn, sbuf);
}

int smb_vfs_call_connect(struct vfs_handle_struct *handle,
			 const char *service, const char *user)
{
	VFS_FIND(connect);
	return handle->fns->connect_fn(handle, service, user);
}

void smb_vfs_call_disconnect(struct vfs_handle_struct *handle)
{
	VFS_FIND(disconnect);
	handle->fns->disconnect_fn(handle);
}

uint64_t smb_vfs_call_disk_free(struct vfs_handle_struct *handle,
				const char *path, bool small_query,
				uint64_t *bsize, uint64_t *dfree,
				uint64_t *dsize)
{
	VFS_FIND(disk_free);
	return handle->fns->disk_free_fn(handle, path, small_query, bsize, 
					 dfree, dsize);
}

int smb_vfs_call_get_quota(struct vfs_handle_struct *handle,
			   enum SMB_QUOTA_TYPE qtype, unid_t id,
			   SMB_DISK_QUOTA *qt)
{
	VFS_FIND(get_quota);
	return handle->fns->get_quota_fn(handle, qtype, id, qt);
}

int smb_vfs_call_set_quota(struct vfs_handle_struct *handle,
			   enum SMB_QUOTA_TYPE qtype, unid_t id,
			   SMB_DISK_QUOTA *qt)
{
	VFS_FIND(set_quota);
	return handle->fns->set_quota_fn(handle, qtype, id, qt);
}

int smb_vfs_call_get_shadow_copy_data(struct vfs_handle_struct *handle,
				      struct files_struct *fsp,
				      struct shadow_copy_data *shadow_copy_data,
				      bool labels)
{
	VFS_FIND(get_shadow_copy_data);
	return handle->fns->get_shadow_copy_data_fn(handle, fsp, 
						    shadow_copy_data,
						    labels);
}
int smb_vfs_call_statvfs(struct vfs_handle_struct *handle, const char *path,
			 struct vfs_statvfs_struct *statbuf)
{
	VFS_FIND(statvfs);
	return handle->fns->statvfs_fn(handle, path, statbuf);
}

uint32_t smb_vfs_call_fs_capabilities(struct vfs_handle_struct *handle,
			enum timestamp_set_resolution *p_ts_res)
{
	VFS_FIND(fs_capabilities);
	return handle->fns->fs_capabilities_fn(handle, p_ts_res);
}

NTSTATUS smb_vfs_call_get_dfs_referrals(struct vfs_handle_struct *handle,
					struct dfs_GetDFSReferral *r)
{
	VFS_FIND(get_dfs_referrals);
	return handle->fns->get_dfs_referrals_fn(handle, r);
}

DIR *smb_vfs_call_opendir(struct vfs_handle_struct *handle,
				     const char *fname, const char *mask,
				     uint32 attributes)
{
	VFS_FIND(opendir);
	return handle->fns->opendir_fn(handle, fname, mask, attributes);
}

DIR *smb_vfs_call_fdopendir(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					const char *mask,
					uint32 attributes)
{
	VFS_FIND(fdopendir);
	return handle->fns->fdopendir_fn(handle, fsp, mask, attributes);
}

struct dirent *smb_vfs_call_readdir(struct vfs_handle_struct *handle,
					      DIR *dirp,
					      SMB_STRUCT_STAT *sbuf)
{
	VFS_FIND(readdir);
	return handle->fns->readdir_fn(handle, dirp, sbuf);
}

void smb_vfs_call_seekdir(struct vfs_handle_struct *handle,
			  DIR *dirp, long offset)
{
	VFS_FIND(seekdir);
	handle->fns->seekdir_fn(handle, dirp, offset);
}

long smb_vfs_call_telldir(struct vfs_handle_struct *handle,
			  DIR *dirp)
{
	VFS_FIND(telldir);
	return handle->fns->telldir_fn(handle, dirp);
}

void smb_vfs_call_rewind_dir(struct vfs_handle_struct *handle,
			     DIR *dirp)
{
	VFS_FIND(rewind_dir);
	handle->fns->rewind_dir_fn(handle, dirp);
}

int smb_vfs_call_mkdir(struct vfs_handle_struct *handle, const char *path,
		       mode_t mode)
{
	VFS_FIND(mkdir);
	return handle->fns->mkdir_fn(handle, path, mode);
}

int smb_vfs_call_rmdir(struct vfs_handle_struct *handle, const char *path)
{
	VFS_FIND(rmdir);
	return handle->fns->rmdir_fn(handle, path);
}

int smb_vfs_call_closedir(struct vfs_handle_struct *handle,
			  DIR *dir)
{
	VFS_FIND(closedir);
	return handle->fns->closedir_fn(handle, dir);
}

void smb_vfs_call_init_search_op(struct vfs_handle_struct *handle,
				 DIR *dirp)
{
	VFS_FIND(init_search_op);
	handle->fns->init_search_op_fn(handle, dirp);
}

int smb_vfs_call_open(struct vfs_handle_struct *handle,
		      struct smb_filename *smb_fname, struct files_struct *fsp,
		      int flags, mode_t mode)
{
	VFS_FIND(open);
	return handle->fns->open_fn(handle, smb_fname, fsp, flags, mode);
}

NTSTATUS smb_vfs_call_create_file(struct vfs_handle_struct *handle,
				  struct smb_request *req,
				  uint16_t root_dir_fid,
				  struct smb_filename *smb_fname,
				  uint32_t access_mask,
				  uint32_t share_access,
				  uint32_t create_disposition,
				  uint32_t create_options,
				  uint32_t file_attributes,
				  uint32_t oplock_request,
				  struct smb2_lease *lease,
				  uint64_t allocation_size,
				  uint32_t private_flags,
				  struct security_descriptor *sd,
				  struct ea_list *ea_list,
				  files_struct **result,
				  int *pinfo,
				  const struct smb2_create_blobs *in_context_blobs,
				  struct smb2_create_blobs *out_context_blobs)
{
	VFS_FIND(create_file);
	return handle->fns->create_file_fn(
		handle, req, root_dir_fid, smb_fname, access_mask,
		share_access, create_disposition, create_options,
		file_attributes, oplock_request, lease, allocation_size,
		private_flags, sd, ea_list,
		result, pinfo, in_context_blobs, out_context_blobs);
}

int smb_vfs_call_close(struct vfs_handle_struct *handle,
		       struct files_struct *fsp)
{
	VFS_FIND(close);
	return handle->fns->close_fn(handle, fsp);
}

ssize_t smb_vfs_call_read(struct vfs_handle_struct *handle,
			  struct files_struct *fsp, void *data, size_t n)
{
	VFS_FIND(read);
	return handle->fns->read_fn(handle, fsp, data, n);
}

ssize_t smb_vfs_call_pread(struct vfs_handle_struct *handle,
			   struct files_struct *fsp, void *data, size_t n,
			   off_t offset)
{
	VFS_FIND(pread);
	return handle->fns->pread_fn(handle, fsp, data, n, offset);
}

struct smb_vfs_call_pread_state {
	ssize_t (*recv_fn)(struct tevent_req *req, int *err);
	ssize_t retval;
};

static void smb_vfs_call_pread_done(struct tevent_req *subreq);

struct tevent_req *smb_vfs_call_pread_send(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct files_struct *fsp,
					   void *data,
					   size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct smb_vfs_call_pread_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_vfs_call_pread_state);
	if (req == NULL) {
		return NULL;
	}
	VFS_FIND(pread_send);
	state->recv_fn = handle->fns->pread_recv_fn;

	subreq = handle->fns->pread_send_fn(handle, state, ev, fsp, data, n,
					    offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb_vfs_call_pread_done, req);
	return req;
}

static void smb_vfs_call_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb_vfs_call_pread_state *state = tevent_req_data(
		req, struct smb_vfs_call_pread_state);
	int err;

	state->retval = state->recv_fn(subreq, &err);
	TALLOC_FREE(subreq);
	if (state->retval == -1) {
		tevent_req_error(req, err);
		return;
	}
	tevent_req_done(req);
}

ssize_t SMB_VFS_PREAD_RECV(struct tevent_req *req, int *perrno)
{
	struct smb_vfs_call_pread_state *state = tevent_req_data(
		req, struct smb_vfs_call_pread_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		*perrno = err;
		return -1;
	}
	return state->retval;
}

ssize_t smb_vfs_call_write(struct vfs_handle_struct *handle,
			   struct files_struct *fsp, const void *data,
			   size_t n)
{
	VFS_FIND(write);
	return handle->fns->write_fn(handle, fsp, data, n);
}

ssize_t smb_vfs_call_pwrite(struct vfs_handle_struct *handle,
			    struct files_struct *fsp, const void *data,
			    size_t n, off_t offset)
{
	VFS_FIND(pwrite);
	return handle->fns->pwrite_fn(handle, fsp, data, n, offset);
}

struct smb_vfs_call_pwrite_state {
	ssize_t (*recv_fn)(struct tevent_req *req, int *err);
	ssize_t retval;
};

static void smb_vfs_call_pwrite_done(struct tevent_req *subreq);

struct tevent_req *smb_vfs_call_pwrite_send(struct vfs_handle_struct *handle,
					    TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct files_struct *fsp,
					    const void *data,
					    size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct smb_vfs_call_pwrite_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_vfs_call_pwrite_state);
	if (req == NULL) {
		return NULL;
	}
	VFS_FIND(pwrite_send);
	state->recv_fn = handle->fns->pwrite_recv_fn;

	subreq = handle->fns->pwrite_send_fn(handle, state, ev, fsp, data, n,
					     offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb_vfs_call_pwrite_done, req);
	return req;
}

static void smb_vfs_call_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb_vfs_call_pwrite_state *state = tevent_req_data(
		req, struct smb_vfs_call_pwrite_state);
	int err;

	state->retval = state->recv_fn(subreq, &err);
	TALLOC_FREE(subreq);
	if (state->retval == -1) {
		tevent_req_error(req, err);
		return;
	}
	tevent_req_done(req);
}

ssize_t SMB_VFS_PWRITE_RECV(struct tevent_req *req, int *perrno)
{
	struct smb_vfs_call_pwrite_state *state = tevent_req_data(
		req, struct smb_vfs_call_pwrite_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		*perrno = err;
		return -1;
	}
	return state->retval;
}

off_t smb_vfs_call_lseek(struct vfs_handle_struct *handle,
			     struct files_struct *fsp, off_t offset,
			     int whence)
{
	VFS_FIND(lseek);
	return handle->fns->lseek_fn(handle, fsp, offset, whence);
}

ssize_t smb_vfs_call_sendfile(struct vfs_handle_struct *handle, int tofd,
			      files_struct *fromfsp, const DATA_BLOB *header,
			      off_t offset, size_t count)
{
	VFS_FIND(sendfile);
	return handle->fns->sendfile_fn(handle, tofd, fromfsp, header, offset,
					count);
}

ssize_t smb_vfs_call_recvfile(struct vfs_handle_struct *handle, int fromfd,
			      files_struct *tofsp, off_t offset,
			      size_t count)
{
	VFS_FIND(recvfile);
	return handle->fns->recvfile_fn(handle, fromfd, tofsp, offset, count);
}

int smb_vfs_call_rename(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname_src,
			const struct smb_filename *smb_fname_dst)
{
	VFS_FIND(rename);
	return handle->fns->rename_fn(handle, smb_fname_src, smb_fname_dst);
}

int smb_vfs_call_fsync(struct vfs_handle_struct *handle,
		       struct files_struct *fsp)
{
	VFS_FIND(fsync);
	return handle->fns->fsync_fn(handle, fsp);
}

struct smb_vfs_call_fsync_state {
	int (*recv_fn)(struct tevent_req *req, int *err);
	int retval;
};

static void smb_vfs_call_fsync_done(struct tevent_req *subreq);

struct tevent_req *smb_vfs_call_fsync_send(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct files_struct *fsp)
{
	struct tevent_req *req, *subreq;
	struct smb_vfs_call_fsync_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_vfs_call_fsync_state);
	if (req == NULL) {
		return NULL;
	}
	VFS_FIND(fsync_send);
	state->recv_fn = handle->fns->fsync_recv_fn;

	subreq = handle->fns->fsync_send_fn(handle, state, ev, fsp);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb_vfs_call_fsync_done, req);
	return req;
}

static void smb_vfs_call_fsync_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb_vfs_call_fsync_state *state = tevent_req_data(
		req, struct smb_vfs_call_fsync_state);
	int err;

	state->retval = state->recv_fn(subreq, &err);
	TALLOC_FREE(subreq);
	if (state->retval == -1) {
		tevent_req_error(req, err);
		return;
	}
	tevent_req_done(req);
}

int SMB_VFS_FSYNC_RECV(struct tevent_req *req, int *perrno)
{
	struct smb_vfs_call_fsync_state *state = tevent_req_data(
		req, struct smb_vfs_call_fsync_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		*perrno = err;
		return -1;
	}
	return state->retval;
}


int smb_vfs_call_stat(struct vfs_handle_struct *handle,
		      struct smb_filename *smb_fname)
{
	VFS_FIND(stat);
	return handle->fns->stat_fn(handle, smb_fname);
}

int smb_vfs_call_fstat(struct vfs_handle_struct *handle,
		       struct files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	VFS_FIND(fstat);
	return handle->fns->fstat_fn(handle, fsp, sbuf);
}

int smb_vfs_call_lstat(struct vfs_handle_struct *handle,
		       struct smb_filename *smb_filename)
{
	VFS_FIND(lstat);
	return handle->fns->lstat_fn(handle, smb_filename);
}

uint64_t smb_vfs_call_get_alloc_size(struct vfs_handle_struct *handle,
				     struct files_struct *fsp,
				     const SMB_STRUCT_STAT *sbuf)
{
	VFS_FIND(get_alloc_size);
	return handle->fns->get_alloc_size_fn(handle, fsp, sbuf);
}

int smb_vfs_call_unlink(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	VFS_FIND(unlink);
	return handle->fns->unlink_fn(handle, smb_fname);
}

int smb_vfs_call_chmod(struct vfs_handle_struct *handle, const char *path,
		       mode_t mode)
{
	VFS_FIND(chmod);
	return handle->fns->chmod_fn(handle, path, mode);
}

int smb_vfs_call_fchmod(struct vfs_handle_struct *handle,
			struct files_struct *fsp, mode_t mode)
{
	VFS_FIND(fchmod);
	return handle->fns->fchmod_fn(handle, fsp, mode);
}

int smb_vfs_call_chown(struct vfs_handle_struct *handle, const char *path,
		       uid_t uid, gid_t gid)
{
	VFS_FIND(chown);
	return handle->fns->chown_fn(handle, path, uid, gid);
}

int smb_vfs_call_fchown(struct vfs_handle_struct *handle,
			struct files_struct *fsp, uid_t uid, gid_t gid)
{
	VFS_FIND(fchown);
	return handle->fns->fchown_fn(handle, fsp, uid, gid);
}

int smb_vfs_call_lchown(struct vfs_handle_struct *handle, const char *path,
			uid_t uid, gid_t gid)
{
	VFS_FIND(lchown);
	return handle->fns->lchown_fn(handle, path, uid, gid);
}

NTSTATUS vfs_chown_fsp(files_struct *fsp, uid_t uid, gid_t gid)
{
	int ret;
	bool as_root = false;
	const char *path;
	char *saved_dir = NULL;
	char *parent_dir = NULL;
	NTSTATUS status;

	if (fsp->fh->fd != -1) {
		/* Try fchown. */
		ret = SMB_VFS_FCHOWN(fsp, uid, gid);
		if (ret == 0) {
			return NT_STATUS_OK;
		}
		if (ret == -1 && errno != ENOSYS) {
			return map_nt_error_from_unix(errno);
		}
	}

	as_root = (geteuid() == 0);

	if (as_root) {
		/*
		 * We are being asked to chown as root. Make
		 * sure we chdir() into the path to pin it,
		 * and always act using lchown to ensure we
		 * don't deref any symbolic links.
		 */
		const char *final_component = NULL;
		struct smb_filename local_fname;

		saved_dir = vfs_GetWd(talloc_tos(),fsp->conn);
		if (!saved_dir) {
			status = map_nt_error_from_unix(errno);
			DEBUG(0,("vfs_chown_fsp: failed to get "
				"current working directory. Error was %s\n",
				strerror(errno)));
			return status;
		}

		if (!parent_dirname(talloc_tos(),
				fsp->fsp_name->base_name,
				&parent_dir,
				&final_component)) {
			return NT_STATUS_NO_MEMORY;
		}

		/* cd into the parent dir to pin it. */
		ret = vfs_ChDir(fsp->conn, parent_dir);
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}

		ZERO_STRUCT(local_fname);
		local_fname.base_name = discard_const_p(char, final_component);

		/* Must use lstat here. */
		ret = SMB_VFS_LSTAT(fsp->conn, &local_fname);
		if (ret == -1) {
			status = map_nt_error_from_unix(errno);
			goto out;
		}

		/* Ensure it matches the fsp stat. */
		if (!check_same_stat(&local_fname.st, &fsp->fsp_name->st)) {
                        status = NT_STATUS_ACCESS_DENIED;
			goto out;
                }
                path = final_component;
        } else {
                path = fsp->fsp_name->base_name;
        }

	if (fsp->posix_open || as_root) {
		ret = SMB_VFS_LCHOWN(fsp->conn,
			path,
			uid, gid);
	} else {
		ret = SMB_VFS_CHOWN(fsp->conn,
			path,
			uid, gid);
	}

	if (ret == 0) {
		status = NT_STATUS_OK;
	} else {
		status = map_nt_error_from_unix(errno);
	}

  out:

	if (as_root) {
		vfs_ChDir(fsp->conn,saved_dir);
		TALLOC_FREE(saved_dir);
		TALLOC_FREE(parent_dir);
	}
	return status;
}

int smb_vfs_call_chdir(struct vfs_handle_struct *handle, const char *path)
{
	VFS_FIND(chdir);
	return handle->fns->chdir_fn(handle, path);
}

char *smb_vfs_call_getwd(struct vfs_handle_struct *handle)
{
	VFS_FIND(getwd);
	return handle->fns->getwd_fn(handle);
}

int smb_vfs_call_ntimes(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			struct smb_file_time *ft)
{
	VFS_FIND(ntimes);
	return handle->fns->ntimes_fn(handle, smb_fname, ft);
}

int smb_vfs_call_ftruncate(struct vfs_handle_struct *handle,
			   struct files_struct *fsp, off_t offset)
{
	VFS_FIND(ftruncate);
	return handle->fns->ftruncate_fn(handle, fsp, offset);
}

int smb_vfs_call_fallocate(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				enum vfs_fallocate_mode mode,
				off_t offset,
				off_t len)
{
	VFS_FIND(fallocate);
	return handle->fns->fallocate_fn(handle, fsp, mode, offset, len);
}

int smb_vfs_call_kernel_flock(struct vfs_handle_struct *handle,
			      struct files_struct *fsp, uint32 share_mode,
			      uint32_t access_mask)
{
	VFS_FIND(kernel_flock);
	return handle->fns->kernel_flock_fn(handle, fsp, share_mode,
					 access_mask);
}

int smb_vfs_call_linux_setlease(struct vfs_handle_struct *handle,
				struct files_struct *fsp, int leasetype)
{
	VFS_FIND(linux_setlease);
	return handle->fns->linux_setlease_fn(handle, fsp, leasetype);
}

int smb_vfs_call_symlink(struct vfs_handle_struct *handle, const char *oldpath,
			 const char *newpath)
{
	VFS_FIND(symlink);
	return handle->fns->symlink_fn(handle, oldpath, newpath);
}

int smb_vfs_call_readlink(struct vfs_handle_struct *handle,
			      const char *path, char *buf, size_t bufsiz)
{
	VFS_FIND(readlink);
	return handle->fns->readlink_fn(handle, path, buf, bufsiz);
}

int smb_vfs_call_link(struct vfs_handle_struct *handle, const char *oldpath,
		      const char *newpath)
{
	VFS_FIND(link);
	return handle->fns->link_fn(handle, oldpath, newpath);
}

int smb_vfs_call_mknod(struct vfs_handle_struct *handle, const char *path,
		       mode_t mode, SMB_DEV_T dev)
{
	VFS_FIND(mknod);
	return handle->fns->mknod_fn(handle, path, mode, dev);
}

char *smb_vfs_call_realpath(struct vfs_handle_struct *handle, const char *path)
{
	VFS_FIND(realpath);
	return handle->fns->realpath_fn(handle, path);
}

NTSTATUS smb_vfs_call_notify_watch(struct vfs_handle_struct *handle,
				   struct sys_notify_context *ctx,
				   const char *path,
				   uint32_t *filter,
				   uint32_t *subdir_filter,
				   void (*callback)(struct sys_notify_context *ctx,
						    void *private_data,
						    struct notify_event *ev),
				   void *private_data, void *handle_p)
{
	VFS_FIND(notify_watch);
	return handle->fns->notify_watch_fn(handle, ctx, path,
					    filter, subdir_filter, callback,
					    private_data, handle_p);
}

int smb_vfs_call_chflags(struct vfs_handle_struct *handle, const char *path,
			 unsigned int flags)
{
	VFS_FIND(chflags);
	return handle->fns->chflags_fn(handle, path, flags);
}

struct file_id smb_vfs_call_file_id_create(struct vfs_handle_struct *handle,
					   const SMB_STRUCT_STAT *sbuf)
{
	VFS_FIND(file_id_create);
	return handle->fns->file_id_create_fn(handle, sbuf);
}

NTSTATUS smb_vfs_call_streaminfo(struct vfs_handle_struct *handle,
				 struct files_struct *fsp,
				 const char *fname,
				 TALLOC_CTX *mem_ctx,
				 unsigned int *num_streams,
				 struct stream_struct **streams)
{
	VFS_FIND(streaminfo);
	return handle->fns->streaminfo_fn(handle, fsp, fname, mem_ctx,
					  num_streams, streams);
}

int smb_vfs_call_get_real_filename(struct vfs_handle_struct *handle,
				   const char *path, const char *name,
				   TALLOC_CTX *mem_ctx, char **found_name)
{
	VFS_FIND(get_real_filename);
	return handle->fns->get_real_filename_fn(handle, path, name, mem_ctx,
						 found_name);
}

const char *smb_vfs_call_connectpath(struct vfs_handle_struct *handle,
				     const char *filename)
{
	VFS_FIND(connectpath);
	return handle->fns->connectpath_fn(handle, filename);
}

bool smb_vfs_call_strict_lock(struct vfs_handle_struct *handle,
			      struct files_struct *fsp,
			      struct lock_struct *plock)
{
	VFS_FIND(strict_lock);
	return handle->fns->strict_lock_fn(handle, fsp, plock);
}

void smb_vfs_call_strict_unlock(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				struct lock_struct *plock)
{
	VFS_FIND(strict_unlock);
	handle->fns->strict_unlock_fn(handle, fsp, plock);
}

NTSTATUS smb_vfs_call_translate_name(struct vfs_handle_struct *handle,
				     const char *name,
				     enum vfs_translate_direction direction,
				     TALLOC_CTX *mem_ctx,
				     char **mapped_name)
{
	VFS_FIND(translate_name);
	return handle->fns->translate_name_fn(handle, name, direction, mem_ctx,
					      mapped_name);
}

NTSTATUS smb_vfs_call_fsctl(struct vfs_handle_struct *handle,
			    struct files_struct *fsp,
			    TALLOC_CTX *ctx,
			    uint32_t function,
			    uint16_t req_flags,
			    const uint8_t *in_data,
			    uint32_t in_len,
			    uint8_t **out_data,
			    uint32_t max_out_len,
			    uint32_t *out_len)
{
	VFS_FIND(fsctl);
	return handle->fns->fsctl_fn(handle, fsp, ctx, function, req_flags,
				     in_data, in_len, out_data, max_out_len,
				     out_len);
}

struct tevent_req *smb_vfs_call_copy_chunk_send(struct vfs_handle_struct *handle,
						TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct files_struct *src_fsp,
						off_t src_off,
						struct files_struct *dest_fsp,
						off_t dest_off,
						off_t num)
{
	VFS_FIND(copy_chunk_send);
	return handle->fns->copy_chunk_send_fn(handle, mem_ctx, ev, src_fsp,
					       src_off, dest_fsp, dest_off, num);
}

NTSTATUS smb_vfs_call_copy_chunk_recv(struct vfs_handle_struct *handle,
				      struct tevent_req *req,
				      off_t *copied)
{
	VFS_FIND(copy_chunk_recv);
	return handle->fns->copy_chunk_recv_fn(handle, req, copied);
}

NTSTATUS smb_vfs_call_get_compression(vfs_handle_struct *handle,
				      TALLOC_CTX *mem_ctx,
				      struct files_struct *fsp,
				      struct smb_filename *smb_fname,
				      uint16_t *_compression_fmt)
{
	VFS_FIND(get_compression);
	return handle->fns->get_compression_fn(handle, mem_ctx, fsp, smb_fname,
					       _compression_fmt);
}

NTSTATUS smb_vfs_call_set_compression(vfs_handle_struct *handle,
				      TALLOC_CTX *mem_ctx,
				      struct files_struct *fsp,
				      uint16_t compression_fmt)
{
	VFS_FIND(set_compression);
	return handle->fns->set_compression_fn(handle, mem_ctx, fsp,
					       compression_fmt);
}

NTSTATUS smb_vfs_call_fget_nt_acl(struct vfs_handle_struct *handle,
				  struct files_struct *fsp,
				  uint32 security_info,
				  TALLOC_CTX *mem_ctx,
				  struct security_descriptor **ppdesc)
{
	VFS_FIND(fget_nt_acl);
	return handle->fns->fget_nt_acl_fn(handle, fsp, security_info,
					   mem_ctx, ppdesc);
}

NTSTATUS smb_vfs_call_get_nt_acl(struct vfs_handle_struct *handle,
				 const char *name,
				 uint32 security_info,
				 TALLOC_CTX *mem_ctx,
				 struct security_descriptor **ppdesc)
{
	VFS_FIND(get_nt_acl);
	return handle->fns->get_nt_acl_fn(handle, name, security_info, mem_ctx, ppdesc);
}

NTSTATUS smb_vfs_call_fset_nt_acl(struct vfs_handle_struct *handle,
				  struct files_struct *fsp,
				  uint32 security_info_sent,
				  const struct security_descriptor *psd)
{
	VFS_FIND(fset_nt_acl);
	return handle->fns->fset_nt_acl_fn(handle, fsp, security_info_sent, 
					   psd);
}

NTSTATUS smb_vfs_call_audit_file(struct vfs_handle_struct *handle,
				 struct smb_filename *file,
				 struct security_acl *sacl,
				 uint32_t access_requested,
				 uint32_t access_denied)
{
	VFS_FIND(audit_file);
	return handle->fns->audit_file_fn(handle, 
					  file, 
					  sacl, 
					  access_requested, 
					  access_denied);
}

int smb_vfs_call_chmod_acl(struct vfs_handle_struct *handle, const char *name,
			   mode_t mode)
{
	VFS_FIND(chmod_acl);
	return handle->fns->chmod_acl_fn(handle, name, mode);
}

int smb_vfs_call_fchmod_acl(struct vfs_handle_struct *handle,
			    struct files_struct *fsp, mode_t mode)
{
	VFS_FIND(fchmod_acl);
	return handle->fns->fchmod_acl_fn(handle, fsp, mode);
}

SMB_ACL_T smb_vfs_call_sys_acl_get_file(struct vfs_handle_struct *handle,
					const char *path_p,
					SMB_ACL_TYPE_T type,
					TALLOC_CTX *mem_ctx)
{
	VFS_FIND(sys_acl_get_file);
	return handle->fns->sys_acl_get_file_fn(handle, path_p, type, mem_ctx);
}

SMB_ACL_T smb_vfs_call_sys_acl_get_fd(struct vfs_handle_struct *handle,
				      struct files_struct *fsp,
				      TALLOC_CTX *mem_ctx)
{
	VFS_FIND(sys_acl_get_fd);
	return handle->fns->sys_acl_get_fd_fn(handle, fsp, mem_ctx);
}

int smb_vfs_call_sys_acl_blob_get_file(struct vfs_handle_struct *handle,
				       const char *path_p,
				       TALLOC_CTX *mem_ctx, 
				       char **blob_description,
				       DATA_BLOB *blob)
{
	VFS_FIND(sys_acl_blob_get_file);
	return handle->fns->sys_acl_blob_get_file_fn(handle, path_p, mem_ctx, blob_description, blob);
}

int smb_vfs_call_sys_acl_blob_get_fd(struct vfs_handle_struct *handle,
				     struct files_struct *fsp,
				     TALLOC_CTX *mem_ctx, 
				     char **blob_description,
				     DATA_BLOB *blob)
{
	VFS_FIND(sys_acl_blob_get_fd);
	return handle->fns->sys_acl_blob_get_fd_fn(handle, fsp, mem_ctx, blob_description, blob);
}

int smb_vfs_call_sys_acl_set_file(struct vfs_handle_struct *handle,
				  const char *name, SMB_ACL_TYPE_T acltype,
				  SMB_ACL_T theacl)
{
	VFS_FIND(sys_acl_set_file);
	return handle->fns->sys_acl_set_file_fn(handle, name, acltype, theacl);
}

int smb_vfs_call_sys_acl_set_fd(struct vfs_handle_struct *handle,
				struct files_struct *fsp, SMB_ACL_T theacl)
{
	VFS_FIND(sys_acl_set_fd);
	return handle->fns->sys_acl_set_fd_fn(handle, fsp, theacl);
}

int smb_vfs_call_sys_acl_delete_def_file(struct vfs_handle_struct *handle,
					 const char *path)
{
	VFS_FIND(sys_acl_delete_def_file);
	return handle->fns->sys_acl_delete_def_file_fn(handle, path);
}

ssize_t smb_vfs_call_getxattr(struct vfs_handle_struct *handle,
			      const char *path, const char *name, void *value,
			      size_t size)
{
	VFS_FIND(getxattr);
	return handle->fns->getxattr_fn(handle, path, name, value, size);
}

ssize_t smb_vfs_call_fgetxattr(struct vfs_handle_struct *handle,
			       struct files_struct *fsp, const char *name,
			       void *value, size_t size)
{
	VFS_FIND(fgetxattr);
	return handle->fns->fgetxattr_fn(handle, fsp, name, value, size);
}

ssize_t smb_vfs_call_listxattr(struct vfs_handle_struct *handle,
			       const char *path, char *list, size_t size)
{
	VFS_FIND(listxattr);
	return handle->fns->listxattr_fn(handle, path, list, size);
}

ssize_t smb_vfs_call_flistxattr(struct vfs_handle_struct *handle,
				struct files_struct *fsp, char *list,
				size_t size)
{
	VFS_FIND(flistxattr);
	return handle->fns->flistxattr_fn(handle, fsp, list, size);
}

int smb_vfs_call_removexattr(struct vfs_handle_struct *handle,
			     const char *path, const char *name)
{
	VFS_FIND(removexattr);
	return handle->fns->removexattr_fn(handle, path, name);
}

int smb_vfs_call_fremovexattr(struct vfs_handle_struct *handle,
			      struct files_struct *fsp, const char *name)
{
	VFS_FIND(fremovexattr);
	return handle->fns->fremovexattr_fn(handle, fsp, name);
}

int smb_vfs_call_setxattr(struct vfs_handle_struct *handle, const char *path,
			  const char *name, const void *value, size_t size,
			  int flags)
{
	VFS_FIND(setxattr);
	return handle->fns->setxattr_fn(handle, path, name, value, size, flags);
}

int smb_vfs_call_fsetxattr(struct vfs_handle_struct *handle,
			   struct files_struct *fsp, const char *name,
			   const void *value, size_t size, int flags)
{
	VFS_FIND(fsetxattr);
	return handle->fns->fsetxattr_fn(handle, fsp, name, value, size, flags);
}

bool smb_vfs_call_aio_force(struct vfs_handle_struct *handle,
			    struct files_struct *fsp)
{
	VFS_FIND(aio_force);
	return handle->fns->aio_force_fn(handle, fsp);
}

bool smb_vfs_call_is_offline(struct vfs_handle_struct *handle,
			     const struct smb_filename *fname,
			     SMB_STRUCT_STAT *sbuf)
{
	VFS_FIND(is_offline);
	return handle->fns->is_offline_fn(handle, fname, sbuf);
}

int smb_vfs_call_set_offline(struct vfs_handle_struct *handle,
                             const struct smb_filename *fname)
{
	VFS_FIND(set_offline);
	return handle->fns->set_offline_fn(handle, fname);
}

NTSTATUS smb_vfs_call_durable_cookie(struct vfs_handle_struct *handle,
				     struct files_struct *fsp,
				     TALLOC_CTX *mem_ctx,
				     DATA_BLOB *cookie)
{
	VFS_FIND(durable_cookie);
	return handle->fns->durable_cookie_fn(handle, fsp, mem_ctx, cookie);
}

NTSTATUS smb_vfs_call_durable_disconnect(struct vfs_handle_struct *handle,
					 struct files_struct *fsp,
					 const DATA_BLOB old_cookie,
					 TALLOC_CTX *mem_ctx,
					 DATA_BLOB *new_cookie)
{
	VFS_FIND(durable_disconnect);
	return handle->fns->durable_disconnect_fn(handle, fsp, old_cookie,
					          mem_ctx, new_cookie);
}

NTSTATUS smb_vfs_call_durable_reconnect(struct vfs_handle_struct *handle,
					struct smb_request *smb1req,
					struct smbXsrv_open *op,
					const DATA_BLOB old_cookie,
					TALLOC_CTX *mem_ctx,
					struct files_struct **fsp,
					DATA_BLOB *new_cookie)
{
	VFS_FIND(durable_reconnect);
	return handle->fns->durable_reconnect_fn(handle, smb1req, op,
					         old_cookie, mem_ctx, fsp,
					         new_cookie);
}

NTSTATUS smb_vfs_call_readdir_attr(struct vfs_handle_struct *handle,
				   const struct smb_filename *fname,
				   TALLOC_CTX *mem_ctx,
				   struct readdir_attr_data **attr_data)
{
	VFS_FIND(readdir_attr);
	return handle->fns->readdir_attr_fn(handle, fname, mem_ctx, attr_data);
}
