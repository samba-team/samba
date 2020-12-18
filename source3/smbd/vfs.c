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
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/sys_rw.h"

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
		static_init_vfs(NULL);
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

#define EXT_DATA_AREA(e) ((uint8_t *)(e) + sizeof(struct vfs_fsp_data))

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

/*
 * Ensure this module catches all VFS functions.
 */
#ifdef DEVELOPER
void smb_vfs_assert_all_fns(const struct vfs_fn_pointers* fns,
			    const char *module)
{
	bool missing_fn = false;
	unsigned int idx;
	const uintptr_t *end = (const uintptr_t *)(fns + 1);

	for (idx = 0; ((const uintptr_t *)fns + idx) < end; idx++) {
		if (*((const uintptr_t *)fns + idx) == 0) {
			DBG_ERR("VFS function at index %d not implemented "
				"in module %s\n", idx, module);
			missing_fn = true;
		}
	}

	if (missing_fn) {
		smb_panic("Required VFS function not implemented in module.\n");
	}
}
#else
void smb_vfs_assert_all_fns(const struct vfs_fn_pointers* fns,
			    const char *module)
{
}
#endif

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

	if (lp_widelinks(SNUM(conn))) {
		/*
		 * As the widelinks logic is now moving into a
		 * vfs_widelinks module, we need to custom load
		 * it after the default module is initialized.
		 * That way no changes to smb.conf files are
		 * needed.
		 */
		bool ok = vfs_init_custom(conn, "widelinks");
		if (!ok) {
			DBG_ERR("widelinks enabled and vfs_init_custom "
				"failed for vfs_widelinks module\n");
			return false;
		}
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

bool vfs_valid_pread_range(off_t offset, size_t length)
{
	return sys_valid_io_range(offset, length);
}

bool vfs_valid_pwrite_range(off_t offset, size_t length)
{
	/*
	 * See MAXFILESIZE in [MS-FSA] 2.1.5.3 Server Requests a Write
	 */
	static const uint64_t maxfilesize = 0xfffffff0000;
	uint64_t last_byte_ofs;
	bool ok;

	ok = sys_valid_io_range(offset, length);
	if (!ok) {
		return false;
	}

	if (length == 0) {
		return true;
	}

	last_byte_ofs = offset + length;
	if (last_byte_ofs > maxfilesize) {
		return false;
	}

	return true;
}

ssize_t vfs_pwrite_data(struct smb_request *req,
			files_struct *fsp,
			const char *buffer,
			size_t N,
			off_t offset)
{
	size_t total=0;
	ssize_t ret;
	bool ok;

	ok = vfs_valid_pwrite_range(offset, N);
	if (!ok) {
		errno = EINVAL;
		return -1;
	}

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
	bool ok;

	/*
	 * Actually try and commit the space on disk....
	 */

	DEBUG(10,("vfs_allocate_file_space: file %s, len %.0f\n",
		  fsp_str_dbg(fsp), (double)len));

	ok = vfs_valid_pwrite_range((off_t)len, 0);
	if (!ok) {
		DEBUG(0,("vfs_allocate_file_space: %s negative/invalid len "
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

		ret = SMB_VFS_FTRUNCATE(fsp, (off_t)len);

		contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_ALLOC_SHRINK);

		return ret;
	}

	/* Grow - we need to test if we have enough space. */

	contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_ALLOC_GROW);

	if (lp_strict_allocate(SNUM(fsp->conn))) {
		/* See if we have a syscall that will allocate beyond
		   end-of-file without changing EOF. */
		ret = SMB_VFS_FALLOCATE(fsp, VFS_FALLOCATE_FL_KEEP_SIZE,
					0, len);
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
	space_avail =
	    get_dfree_info(conn, fsp->fsp_name, &bsize, &dfree, &dsize);
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
	bool ok;

	ok = vfs_valid_pwrite_range(len, 0);
	if (!ok) {
		errno = EINVAL;
		return -1;
	}

	contend_level2_oplocks_begin(fsp, LEVEL2_CONTEND_SET_FILE_LEN);

	DEBUG(10,("vfs_set_filelen: ftruncate %s to len %.0f\n",
		  fsp_str_dbg(fsp), (double)len));
	if ((ret = SMB_VFS_FTRUNCATE(fsp, len)) != -1) {
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
	bool ok;

	ok = vfs_valid_pwrite_range(offset, len);
	if (!ok) {
		errno = EINVAL;
		return -1;
	}

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
	bool ok;

	ok = vfs_valid_pwrite_range(len, 0);
	if (!ok) {
		errno = EINVAL;
		return -1;
	}

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

	offset = fsp->fsp_name->st.st_ex_size;
	num_to_write = len - fsp->fsp_name->st.st_ex_size;

	/* Only do this on non-stream file handles. */
	if (fsp->base_fsp == NULL) {
		/* for allocation try fallocate first. This can fail on some
		 * platforms e.g. when the filesystem doesn't support it and no
		 * emulation is being done by the libc (like on AIX with JFS1). In that
		 * case we do our own emulation. fallocate implementations can
		 * return ENOTSUP or EINVAL in cases like that. */
		ret = SMB_VFS_FALLOCATE(fsp, 0, offset, num_to_write);
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

	contend_level2_oplocks_end(fsp, LEVEL2_CONTEND_FILL_SPARSE);
	return ret;
}

/*******************************************************************************
 Set a fd into blocking/nonblocking mode through VFS
*******************************************************************************/

int vfs_set_blocking(files_struct *fsp, bool set)
{
	int val;
#ifdef O_NONBLOCK
#define FLAG_TO_SET O_NONBLOCK
#else
#ifdef SYSV
#define FLAG_TO_SET O_NDELAY
#else /* BSD */
#define FLAG_TO_SET FNDELAY
#endif
#endif
	val = SMB_VFS_FCNTL(fsp, F_GETFL, 0);
	if (val == -1) {
		return -1;
	}

	if (set) {
		val &= ~FLAG_TO_SET;
	} else {
		val |= FLAG_TO_SET;
	}

	return SMB_VFS_FCNTL(fsp, F_SETFL, val);
#undef FLAG_TO_SET
}

/****************************************************************************
 Transfer some data (n bytes) between two file_struct's.
****************************************************************************/

static ssize_t vfs_pread_fn(void *file, void *buf, size_t len, off_t offset)
{
	struct files_struct *fsp = (struct files_struct *)file;

	return SMB_VFS_PREAD(fsp, buf, len, offset);
}

static ssize_t vfs_pwrite_fn(void *file, const void *buf, size_t len, off_t offset)
{
	struct files_struct *fsp = (struct files_struct *)file;

	return SMB_VFS_PWRITE(fsp, buf, len, offset);
}

off_t vfs_transfer_file(files_struct *in, files_struct *out, off_t n)
{
	return transfer_file_internal((void *)in, (void *)out, n,
				      vfs_pread_fn, vfs_pwrite_fn);
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

int vfs_ChDir(connection_struct *conn, const struct smb_filename *smb_fname)
{
	int ret;
	struct smb_filename *cwd = NULL;

	if (!LastDir) {
		LastDir = SMB_STRDUP("");
	}

	if (ISDOT(smb_fname->base_name)) {
		/*
		 * passing a '.' is a noop,
		 * and we only expect this after
		 * everything is initialized.
		 *
		 * So the first vfs_ChDir() on a given
		 * connection_struct must not be '.'.
		 *
		 * Note: conn_new() sets
		 * conn->cwd_fsp->fh->fd = -1
		 * and vfs_ChDir() leaves with
		 * conn->cwd_fsp->fh->fd = AT_FDCWD
		 * on success!
		 */
		if (conn->cwd_fsp->fh->fd != AT_FDCWD) {
			/*
			 * This should never happen and
			 * we might change this to
			 * SMB_ASSERT() in future.
			 */
			DBG_ERR("Called with '.' as first operation!\n");
			log_stack_trace();
			errno = EINVAL;
			return -1;
		}
		return 0;
	}

	if (smb_fname->base_name[0] == '/' &&
	    strcsequal(LastDir,smb_fname->base_name))
	{
		/*
		 * conn->cwd_fsp->fsp_name and the kernel
		 * are already correct, but conn->cwd_fsp->fh->fd
		 * might still be -1 as initialized in conn_new().
		 *
		 * This can happen when a client made a 2nd
		 * tree connect to a share with the same underlying
		 * path (may or may not the same share).
		 */
		conn->cwd_fsp->fh->fd = AT_FDCWD;
		return 0;
	}

	DEBUG(4,("vfs_ChDir to %s\n", smb_fname->base_name));

	ret = SMB_VFS_CHDIR(conn, smb_fname);
	if (ret != 0) {
		return -1;
	}

	/*
	 * Always replace conn->cwd_fsp. We
	 * don't know if it's been modified by
	 * VFS modules in the stack.
	 */

	/* conn cache. */
	cwd = vfs_GetWd(conn, conn);
	if (cwd == NULL) {
		/*
		 * vfs_GetWd() failed.
		 * We must be able to read cwd.
		 * Return to original directory
		 * and return -1.
		 */
		int saved_errno = errno;

		if (conn->cwd_fsp->fsp_name == NULL) {
			/*
			 * Failed on the very first chdir()+getwd()
			 * for this connection. We can't
			 * continue.
			 */
			smb_panic("conn->cwd getwd failed\n");
			/* NOTREACHED */
			return -1;
		}

		/* Return to the previous $cwd. */
		ret = SMB_VFS_CHDIR(conn, conn->cwd_fsp->fsp_name);
		if (ret != 0) {
			smb_panic("conn->cwd getwd failed\n");
			/* NOTREACHED */
			return -1;
		}
		errno = saved_errno;
		/* And fail the chdir(). */
		return -1;
	}

	/* vfs_GetWd() succeeded. */
	/* Replace global cache. */
	SAFE_FREE(LastDir);
	LastDir = SMB_STRDUP(smb_fname->base_name);

	/*
	 * (Indirect) Callers of vfs_ChDir() may still hold references to the
	 * old conn->cwd_fsp->fsp_name. Move it to talloc_tos(), that way
	 * callers can use it for the lifetime of the SMB request.
	 */
	talloc_move(talloc_tos(), &conn->cwd_fsp->fsp_name);

	conn->cwd_fsp->fsp_name = talloc_move(conn->cwd_fsp, &cwd);
	conn->cwd_fsp->fh->fd = AT_FDCWD;

	DBG_INFO("vfs_ChDir got %s\n", fsp_str_dbg(conn->cwd_fsp));

	return ret;
}

/*******************************************************************
 Return the absolute current directory path - given a UNIX pathname.
 Note that this path is returned in DOS format, not UNIX
 format. Note this can be called with conn == NULL.
********************************************************************/

struct smb_filename *vfs_GetWd(TALLOC_CTX *ctx, connection_struct *conn)
{
        struct smb_filename *current_dir_fname = NULL;
	struct file_id key;
	struct smb_filename *smb_fname_dot = NULL;
	struct smb_filename *smb_fname_full = NULL;
	struct smb_filename *result = NULL;

	if (!lp_getwd_cache()) {
		goto nocache;
	}

	smb_fname_dot = synthetic_smb_fname(ctx,
					    ".",
					    NULL,
					    NULL,
					    0,
					    0);
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

	smb_fname_full = (struct smb_filename *)memcache_lookup_talloc(
					smbd_memcache(),
					GETWD_CACHE,
					data_blob_const(&key, sizeof(key)));

	if (smb_fname_full == NULL) {
		goto nocache;
	}

	if ((SMB_VFS_STAT(conn, smb_fname_full) == 0) &&
	    (smb_fname_dot->st.st_ex_dev == smb_fname_full->st.st_ex_dev) &&
	    (smb_fname_dot->st.st_ex_ino == smb_fname_full->st.st_ex_ino) &&
	    (S_ISDIR(smb_fname_dot->st.st_ex_mode))) {
		/*
		 * Ok, we're done
		 * Note: smb_fname_full is owned by smbd_memcache()
		 * so we must make a copy to return.
		 */
		result = cp_smb_filename(ctx, smb_fname_full);
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

	current_dir_fname = SMB_VFS_GETWD(conn, ctx);
	if (current_dir_fname == NULL) {
		DEBUG(0, ("vfs_GetWd: SMB_VFS_GETWD call failed: %s\n",
			  strerror(errno)));
		goto out;
	}

	if (lp_getwd_cache() && VALID_STAT(smb_fname_dot->st)) {
		key = vfs_file_id_from_sbuf(conn, &smb_fname_dot->st);

		/*
		 * smbd_memcache() will own current_dir_fname after the
		 * memcache_add_talloc call, so we must make
		 * a copy on ctx to return.
		 */
		result = cp_smb_filename(ctx, current_dir_fname);
		if (result == NULL) {
			errno = ENOMEM;
		}

		/*
		 * Ensure the memory going into the cache
		 * doesn't have a destructor so it can be
		 * cleanly freed.
		 */
		talloc_set_destructor(current_dir_fname, NULL);

		memcache_add_talloc(smbd_memcache(),
				GETWD_CACHE,
				data_blob_const(&key, sizeof(key)),
				&current_dir_fname);
		/* current_dir_fname is now == NULL here. */
	} else {
		/* current_dir_fname is already allocated on ctx. */
		result = current_dir_fname;
	}

 out:
	TALLOC_FREE(smb_fname_dot);
	/*
	 * Don't free current_dir_fname here. It's either been moved
	 * to the memcache or is being returned in result.
	 */
	return result;
}

/*******************************************************************
 Reduce a file name, removing .. elements and checking that
 it is below dir in the hierarchy. This uses realpath.
 This function must run as root, and will return names
 and valid stat structs that can be checked on open.
********************************************************************/

NTSTATUS check_reduced_name_with_privilege(connection_struct *conn,
			const struct smb_filename *smb_fname,
			struct smb_request *smbreq)
{
	NTSTATUS status;
	TALLOC_CTX *ctx = talloc_tos();
	const char *conn_rootdir;
	size_t rootdir_len;
	char *resolved_name = NULL;
	struct smb_filename *resolved_fname = NULL;
	struct smb_filename *saved_dir_fname = NULL;
	struct smb_filename *smb_fname_cwd = NULL;
	int ret;
	struct smb_filename *parent_name = NULL;
	struct smb_filename *file_name = NULL;
	bool ok;

	DEBUG(3,("check_reduced_name_with_privilege [%s] [%s]\n",
			smb_fname->base_name,
			conn->connectpath));


	ok = parent_smb_fname(ctx,
			      smb_fname,
			      &parent_name,
			      &file_name);
	if (!ok) {
		status = NT_STATUS_NO_MEMORY;
		goto err;
	}

	if (SMB_VFS_STAT(conn, parent_name) != 0) {
		status = map_nt_error_from_unix(errno);
		goto err;
	}
	/* Remember where we were. */
	saved_dir_fname = vfs_GetWd(ctx, conn);
	if (!saved_dir_fname) {
		status = map_nt_error_from_unix(errno);
		goto err;
	}

	if (vfs_ChDir(conn, parent_name) == -1) {
		status = map_nt_error_from_unix(errno);
		goto err;
	}

	smb_fname_cwd = synthetic_smb_fname(talloc_tos(),
					    ".",
					    NULL,
					    NULL,
					    parent_name->twrp,
					    0);
	if (smb_fname_cwd == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err;
	}

	/* Get the absolute path of the parent directory. */
	resolved_fname = SMB_VFS_REALPATH(conn, ctx, smb_fname_cwd);
	if (resolved_fname == NULL) {
		status = map_nt_error_from_unix(errno);
		goto err;
	}
	resolved_name = resolved_fname->base_name;

	if (*resolved_name != '/') {
		DEBUG(0,("check_reduced_name_with_privilege: realpath "
			"doesn't return absolute paths !\n"));
		status = NT_STATUS_OBJECT_NAME_INVALID;
		goto err;
	}

	DBG_DEBUG("realpath [%s] -> [%s]\n",
		  smb_fname_str_dbg(parent_name),
		  resolved_name);

	/* Now check the stat value is the same. */
	if (SMB_VFS_LSTAT(conn, smb_fname_cwd) != 0) {
		status = map_nt_error_from_unix(errno);
		goto err;
	}

	/* Ensure we're pointing at the same place. */
	if (!check_same_stat(&smb_fname_cwd->st, &parent_name->st)) {
		DBG_ERR("device/inode/uid/gid on directory %s changed. "
			"Denying access !\n",
			smb_fname_str_dbg(parent_name));
		status = NT_STATUS_ACCESS_DENIED;
		goto err;
	}

	/* Ensure we're below the connect path. */

	conn_rootdir = SMB_VFS_CONNECTPATH(conn, smb_fname);
	if (conn_rootdir == NULL) {
		DEBUG(2, ("check_reduced_name_with_privilege: Could not get "
			"conn_rootdir\n"));
		status = NT_STATUS_ACCESS_DENIED;
		goto err;
	}

	rootdir_len = strlen(conn_rootdir);

	/*
	 * In the case of rootdir_len == 1, we know that conn_rootdir is
	 * "/", and we also know that resolved_name starts with a slash.
	 * So, in this corner case, resolved_name is automatically a
	 * sub-directory of the conn_rootdir. Thus we can skip the string
	 * comparison and the next character checks (which are even
	 * wrong in this case).
	 */
	if (rootdir_len != 1) {
		bool matched;

		matched = (strncmp(conn_rootdir, resolved_name,
				rootdir_len) == 0);

		if (!matched || (resolved_name[rootdir_len] != '/' &&
				 resolved_name[rootdir_len] != '\0')) {
			DBG_WARNING("%s is a symlink outside the "
				    "share path\n",
				    smb_fname_str_dbg(parent_name));
			DEBUGADD(1, ("conn_rootdir =%s\n", conn_rootdir));
			DEBUGADD(1, ("resolved_name=%s\n", resolved_name));
			status = NT_STATUS_ACCESS_DENIED;
			goto err;
		}
	}

	/* Now ensure that the last component either doesn't
	   exist, or is *NOT* a symlink. */

	ret = SMB_VFS_LSTAT(conn, file_name);
	if (ret == -1) {
		/* Errno must be ENOENT for this be ok. */
		if (errno != ENOENT) {
			status = map_nt_error_from_unix(errno);
			DBG_WARNING("LSTAT on %s failed with %s\n",
				    smb_fname_str_dbg(file_name),
				    nt_errstr(status));
			goto err;
		}
	}

	if (VALID_STAT(file_name->st) &&
	    S_ISLNK(file_name->st.st_ex_mode))
	{
		DBG_WARNING("Last component %s is a symlink. Denying"
			    "access.\n",
			    smb_fname_str_dbg(file_name));
		status = NT_STATUS_ACCESS_DENIED;
		goto err;
	}

	status = NT_STATUS_OK;

  err:

	if (saved_dir_fname != NULL) {
		vfs_ChDir(conn, saved_dir_fname);
		TALLOC_FREE(saved_dir_fname);
	}
	TALLOC_FREE(resolved_fname);
	TALLOC_FREE(parent_name);
	return status;
}

/*******************************************************************
 Reduce a file name, removing .. elements and checking that
 it is below dir in the hierarchy. This uses realpath.

 If cwd_name == NULL then fname is a client given path relative
 to the root path of the share.

 If cwd_name != NULL then fname is a client given path relative
 to cwd_name. cwd_name is relative to the root path of the share.
********************************************************************/

NTSTATUS check_reduced_name(connection_struct *conn,
				const struct smb_filename *cwd_fname,
				const struct smb_filename *smb_fname)
{
	TALLOC_CTX *ctx = talloc_tos();
	const char *cwd_name = cwd_fname ? cwd_fname->base_name : NULL;
	const char *fname = smb_fname->base_name;
	struct smb_filename *resolved_fname;
	char *resolved_name = NULL;
	char *new_fname = NULL;
	bool allow_symlinks = true;
	const char *conn_rootdir;
	size_t rootdir_len;
	bool ok;

	DBG_DEBUG("check_reduced_name [%s] [%s]\n", fname, conn->connectpath);

	resolved_fname = SMB_VFS_REALPATH(conn, ctx, smb_fname);

	if (resolved_fname == NULL) {
		struct smb_filename *dir_fname = NULL;
		struct smb_filename *last_component = NULL;

		if (errno == ENOTDIR) {
			DBG_NOTICE("Component not a directory in getting "
				   "realpath for %s\n",
				   fname);
			return NT_STATUS_OBJECT_PATH_NOT_FOUND;
		}
		if (errno != ENOENT) {
			NTSTATUS status = map_nt_error_from_unix(errno);
			DBG_NOTICE("couldn't get realpath for %s: %s\n",
				   fname,
				   strerror(errno));
			return status;
		}

		/* errno == ENOENT */

		/*
		 * Last component didn't exist. Remove it and try and
		 * canonicalise the directory name.
		 */

		ok = parent_smb_fname(ctx,
				      smb_fname,
				      &dir_fname,
				      &last_component);
		if (!ok) {
			return NT_STATUS_NO_MEMORY;
		}

		resolved_fname = SMB_VFS_REALPATH(conn, ctx, dir_fname);
		if (resolved_fname == NULL) {
			NTSTATUS status = map_nt_error_from_unix(errno);

			if (errno == ENOENT || errno == ENOTDIR) {
				status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
			}

			DBG_NOTICE("couldn't get realpath for "
				   "%s (%s)\n",
				   smb_fname_str_dbg(dir_fname),
				   nt_errstr(status));
			return status;
		}
		resolved_name = talloc_asprintf(ctx,
						"%s/%s",
						resolved_fname->base_name,
						last_component->base_name);
		if (resolved_name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		resolved_name = resolved_fname->base_name;
	}

	DEBUG(10,("check_reduced_name realpath [%s] -> [%s]\n", fname,
		  resolved_name));

	if (*resolved_name != '/') {
		DEBUG(0,("check_reduced_name: realpath doesn't return "
			 "absolute paths !\n"));
		TALLOC_FREE(resolved_fname);
		return NT_STATUS_OBJECT_NAME_INVALID;
	}

	/* Common widelinks and symlinks checks. */
	conn_rootdir = SMB_VFS_CONNECTPATH(conn, smb_fname);
	if (conn_rootdir == NULL) {
		DBG_NOTICE("Could not get conn_rootdir\n");
		TALLOC_FREE(resolved_fname);
		return NT_STATUS_ACCESS_DENIED;
	}

	rootdir_len = strlen(conn_rootdir);

	/*
	 * In the case of rootdir_len == 1, we know that
	 * conn_rootdir is "/", and we also know that
	 * resolved_name starts with a slash.  So, in this
	 * corner case, resolved_name is automatically a
	 * sub-directory of the conn_rootdir. Thus we can skip
	 * the string comparison and the next character checks
	 * (which are even wrong in this case).
	 */
	if (rootdir_len != 1) {
		bool matched;

		matched = (strncmp(conn_rootdir, resolved_name,
				rootdir_len) == 0);
		if (!matched || (resolved_name[rootdir_len] != '/' &&
				 resolved_name[rootdir_len] != '\0')) {
			DBG_NOTICE("Bad access attempt: %s is a symlink "
				"outside the "
				"share path\n"
				"conn_rootdir =%s\n"
				"resolved_name=%s\n",
				fname,
				conn_rootdir,
				resolved_name);
			TALLOC_FREE(resolved_fname);
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	/* Extra checks if all symlinks are disallowed. */
	allow_symlinks = lp_follow_symlinks(SNUM(conn));
	if (!allow_symlinks) {
		/* fname can't have changed in resolved_path. */
		const char *p = &resolved_name[rootdir_len];

		/*
		 * UNIX filesystem semantics, names consisting
		 * only of "." or ".." CANNOT be symlinks.
		 */
		if (ISDOT(fname) || ISDOTDOT(fname)) {
			goto out;
		}

		if (*p != '/') {
			DBG_NOTICE("logic error (%c) "
				"in resolved_name: %s\n",
				*p,
				fname);
			TALLOC_FREE(resolved_fname);
			return NT_STATUS_ACCESS_DENIED;
		}

		p++;

		/*
		 * If cwd_name is present and not ".",
		 * then fname is relative to that, not
		 * the root of the share. Make sure the
		 * path we check is the one the client
		 * sent (cwd_name+fname).
		 */
		if (cwd_name != NULL && !ISDOT(cwd_name)) {
			new_fname = talloc_asprintf(ctx,
						"%s/%s",
						cwd_name,
						fname);
			if (new_fname == NULL) {
				TALLOC_FREE(resolved_fname);
				return NT_STATUS_NO_MEMORY;
			}
			fname = new_fname;
		}

		if (strcmp(fname, p)!=0) {
			DBG_NOTICE("Bad access "
				"attempt: %s is a symlink to %s\n",
				fname,
				p);
			TALLOC_FREE(resolved_fname);
			TALLOC_FREE(new_fname);
			return NT_STATUS_ACCESS_DENIED;
		}
	}

  out:

	DBG_INFO("%s reduced to %s\n", fname, resolved_name);
	TALLOC_FREE(resolved_fname);
	TALLOC_FREE(new_fname);
	return NT_STATUS_OK;
}

/**
 * XXX: This is temporary and there should be no callers of this once
 * smb_filename is plumbed through all path based operations.
 *
 * Called when we know stream name parsing has already been done.
 */
int vfs_stat_smb_basename(struct connection_struct *conn,
			const struct smb_filename *smb_fname_in,
			SMB_STRUCT_STAT *psbuf)
{
	struct smb_filename smb_fname = {
		.base_name = discard_const_p(char, smb_fname_in->base_name),
		.flags = smb_fname_in->flags,
		.twrp = smb_fname_in->twrp,
	};
	int ret;

	if (smb_fname.flags & SMB_FILENAME_POSIX_PATH) {
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
	struct stat_ex saved_stat = fsp->fsp_name->st;

	if(fsp->fh->fd == -1) {
		if (fsp->posix_flags & FSP_POSIX_FLAGS_OPEN) {
			ret = SMB_VFS_LSTAT(fsp->conn, fsp->fsp_name);
		} else {
			ret = SMB_VFS_STAT(fsp->conn, fsp->fsp_name);
		}
	} else {
		ret = SMB_VFS_FSTAT(fsp, &fsp->fsp_name->st);
	}
	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}
	update_stat_ex_from_saved_stat(&fsp->fsp_name->st, &saved_stat);
	return NT_STATUS_OK;
}

void init_smb_file_time(struct smb_file_time *ft)
{
	*ft = (struct smb_file_time) {
		.atime = make_omit_timespec(),
		.ctime = make_omit_timespec(),
		.mtime = make_omit_timespec(),
		.create_time = make_omit_timespec()
	};
}

/**
 * Initialize num_streams and streams, then call VFS op streaminfo
 */
NTSTATUS vfs_streaminfo(connection_struct *conn,
			struct files_struct *fsp,
			const struct smb_filename *smb_fname,
			TALLOC_CTX *mem_ctx,
			unsigned int *num_streams,
			struct stream_struct **streams)
{
	*num_streams = 0;
	*streams = NULL;
	return SMB_VFS_STREAMINFO(conn,
			fsp,
			smb_fname,
			mem_ctx,
			num_streams,
			streams);
}

/*
 * This is just a helper to make
 * users of vfs_fake_fd() more symetric
 */
int vfs_fake_fd_close(int fd)
{
	return close(fd);
}

/*
  generate a file_id from a stat structure
 */
struct file_id vfs_file_id_from_sbuf(connection_struct *conn, const SMB_STRUCT_STAT *sbuf)
{
	return SMB_VFS_FILE_ID_CREATE(conn, sbuf);
}

NTSTATUS vfs_at_fspcwd(TALLOC_CTX *mem_ctx,
		       struct connection_struct *conn,
		       struct files_struct **_fsp)
{
	struct files_struct *fsp = NULL;

	fsp = talloc_zero(mem_ctx, struct files_struct);
	if (fsp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	fsp->fsp_name = synthetic_smb_fname(fsp, ".", NULL, NULL, 0, 0);
	if (fsp->fsp_name == NULL) {
		TALLOC_FREE(fsp);
		return NT_STATUS_NO_MEMORY;
	}

	fsp->fh = talloc_zero(fsp, struct fd_handle);
	if (fsp->fh == NULL) {
		TALLOC_FREE(fsp);
		return NT_STATUS_NO_MEMORY;
	}

	fsp->fh->fd = AT_FDCWD;
	fsp->fnum = FNUM_FIELD_INVALID;
	fsp->conn = conn;

	*_fsp = fsp;
	return NT_STATUS_OK;
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
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	VFS_FIND(disk_free);
	return handle->fns->disk_free_fn(handle, smb_fname,
			bsize, dfree, dsize);
}

int smb_vfs_call_get_quota(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *qt)
{
	VFS_FIND(get_quota);
	return handle->fns->get_quota_fn(handle, smb_fname, qtype, id, qt);
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
int smb_vfs_call_statvfs(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			struct vfs_statvfs_struct *statbuf)
{
	VFS_FIND(statvfs);
	return handle->fns->statvfs_fn(handle, smb_fname, statbuf);
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

NTSTATUS smb_vfs_call_create_dfs_pathat(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				const struct referral *reflist,
				size_t referral_count)
{
	VFS_FIND(create_dfs_pathat);
	return handle->fns->create_dfs_pathat_fn(handle,
						dirfsp,
						smb_fname,
						reflist,
						referral_count);
}

NTSTATUS smb_vfs_call_read_dfs_pathat(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct files_struct *dirfsp,
				struct smb_filename *smb_fname,
				struct referral **ppreflist,
				size_t *preferral_count)
{
	VFS_FIND(read_dfs_pathat);
	return handle->fns->read_dfs_pathat_fn(handle,
						mem_ctx,
						dirfsp,
						smb_fname,
						ppreflist,
						preferral_count);
}

DIR *smb_vfs_call_fdopendir(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					const char *mask,
					uint32_t attributes)
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

int smb_vfs_call_mkdirat(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	VFS_FIND(mkdirat);
	return handle->fns->mkdirat_fn(handle,
			dirfsp,
			smb_fname,
			mode);
}

int smb_vfs_call_closedir(struct vfs_handle_struct *handle,
			  DIR *dir)
{
	VFS_FIND(closedir);
	return handle->fns->closedir_fn(handle, dir);
}

int smb_vfs_call_openat(struct vfs_handle_struct *handle,
			const struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			struct files_struct *fsp,
			int flags,
			mode_t mode)
{
	VFS_FIND(openat);
	return handle->fns->openat_fn(handle,
				      dirfsp,
				      smb_fname,
				      fsp,
				      flags,
				      mode);
}

NTSTATUS smb_vfs_call_create_file(struct vfs_handle_struct *handle,
				  struct smb_request *req,
				  struct files_struct **dirfsp,
				  struct smb_filename *smb_fname,
				  uint32_t access_mask,
				  uint32_t share_access,
				  uint32_t create_disposition,
				  uint32_t create_options,
				  uint32_t file_attributes,
				  uint32_t oplock_request,
				  const struct smb2_lease *lease,
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
		handle, req, dirfsp, smb_fname,
		access_mask, share_access, create_disposition, create_options,
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

ssize_t smb_vfs_call_pread(struct vfs_handle_struct *handle,
			   struct files_struct *fsp, void *data, size_t n,
			   off_t offset)
{
	VFS_FIND(pread);
	return handle->fns->pread_fn(handle, fsp, data, n, offset);
}

struct smb_vfs_call_pread_state {
	ssize_t (*recv_fn)(struct tevent_req *req, struct vfs_aio_state *vfs_aio_state);
	ssize_t retval;
	struct vfs_aio_state vfs_aio_state;
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

	state->retval = state->recv_fn(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	if (state->retval == -1) {
		tevent_req_error(req, state->vfs_aio_state.error);
		return;
	}
	tevent_req_done(req);
}

ssize_t SMB_VFS_PREAD_RECV(struct tevent_req *req,
			   struct vfs_aio_state *vfs_aio_state)
{
	struct smb_vfs_call_pread_state *state = tevent_req_data(
		req, struct smb_vfs_call_pread_state);
	ssize_t retval;

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	retval = state->retval;
	tevent_req_received(req);
	return retval;
}

ssize_t smb_vfs_call_pwrite(struct vfs_handle_struct *handle,
			    struct files_struct *fsp, const void *data,
			    size_t n, off_t offset)
{
	VFS_FIND(pwrite);
	return handle->fns->pwrite_fn(handle, fsp, data, n, offset);
}

struct smb_vfs_call_pwrite_state {
	ssize_t (*recv_fn)(struct tevent_req *req, struct vfs_aio_state *vfs_aio_state);
	ssize_t retval;
	struct vfs_aio_state vfs_aio_state;
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

	state->retval = state->recv_fn(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	if (state->retval == -1) {
		tevent_req_error(req, state->vfs_aio_state.error);
		return;
	}
	tevent_req_done(req);
}

ssize_t SMB_VFS_PWRITE_RECV(struct tevent_req *req,
			    struct vfs_aio_state *vfs_aio_state)
{
	struct smb_vfs_call_pwrite_state *state = tevent_req_data(
		req, struct smb_vfs_call_pwrite_state);
	ssize_t retval;

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	retval = state->retval;
	tevent_req_received(req);
	return retval;
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

int smb_vfs_call_renameat(struct vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *smb_fname_src,
			files_struct *dstfsp,
			const struct smb_filename *smb_fname_dst)
{
	VFS_FIND(renameat);
	return handle->fns->renameat_fn(handle,
				srcfsp,
				smb_fname_src,
				dstfsp,
				smb_fname_dst);
}

struct smb_vfs_call_fsync_state {
	int (*recv_fn)(struct tevent_req *req, struct vfs_aio_state *vfs_aio_state);
	int retval;
	struct vfs_aio_state vfs_aio_state;
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

	state->retval = state->recv_fn(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	if (state->retval == -1) {
		tevent_req_error(req, state->vfs_aio_state.error);
		return;
	}
	tevent_req_done(req);
}

int SMB_VFS_FSYNC_RECV(struct tevent_req *req, struct vfs_aio_state *vfs_aio_state)
{
	struct smb_vfs_call_fsync_state *state = tevent_req_data(
		req, struct smb_vfs_call_fsync_state);
	ssize_t retval;

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	retval = state->retval;
	tevent_req_received(req);
	return retval;
}

/*
 * Synchronous version of fsync, built from backend
 * async VFS primitives. Uses a temporary sub-event
 * context (NOT NESTED).
 */

int smb_vfs_fsync_sync(files_struct *fsp)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_req *req = NULL;
	struct vfs_aio_state aio_state = { 0 };
	int ret = -1;
	bool ok;
	struct tevent_context *ev = samba_tevent_context_init(frame);

	if (ev == NULL) {
		goto out;
	}

	req = SMB_VFS_FSYNC_SEND(talloc_tos(), ev, fsp);
	if (req == NULL) {
		goto out;
	}

	ok = tevent_req_poll(req, ev);
	if (!ok) {
		goto out;
	}

	ret = SMB_VFS_FSYNC_RECV(req, &aio_state);

  out:

	TALLOC_FREE(frame);
	if (aio_state.error != 0) {
		errno = aio_state.error;
	}
	return ret;
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

int smb_vfs_call_unlinkat(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	VFS_FIND(unlinkat);
	return handle->fns->unlinkat_fn(handle,
			dirfsp,
			smb_fname,
			flags);
}

int smb_vfs_call_chmod(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	VFS_FIND(chmod);
	return handle->fns->chmod_fn(handle, smb_fname, mode);
}

int smb_vfs_call_fchmod(struct vfs_handle_struct *handle,
			struct files_struct *fsp, mode_t mode)
{
	VFS_FIND(fchmod);
	return handle->fns->fchmod_fn(handle, fsp, mode);
}

int smb_vfs_call_fchown(struct vfs_handle_struct *handle,
			struct files_struct *fsp, uid_t uid, gid_t gid)
{
	VFS_FIND(fchown);
	return handle->fns->fchown_fn(handle, fsp, uid, gid);
}

int smb_vfs_call_lchown(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	VFS_FIND(lchown);
	return handle->fns->lchown_fn(handle, smb_fname, uid, gid);
}

int smb_vfs_call_chdir(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	VFS_FIND(chdir);
	return handle->fns->chdir_fn(handle, smb_fname);
}

struct smb_filename *smb_vfs_call_getwd(struct vfs_handle_struct *handle,
				TALLOC_CTX *ctx)
{
	VFS_FIND(getwd);
	return handle->fns->getwd_fn(handle, ctx);
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
			   uint32_t mode,
			   off_t offset,
			   off_t len)
{
	VFS_FIND(fallocate);
	return handle->fns->fallocate_fn(handle, fsp, mode, offset, len);
}

int smb_vfs_call_kernel_flock(struct vfs_handle_struct *handle,
			      struct files_struct *fsp, uint32_t share_mode,
			      uint32_t access_mask)
{
	VFS_FIND(kernel_flock);
	return handle->fns->kernel_flock_fn(handle, fsp, share_mode,
					 access_mask);
}

int smb_vfs_call_fcntl(struct vfs_handle_struct *handle,
		       struct files_struct *fsp, int cmd, ...)
{
	int result;
	va_list cmd_arg;

	VFS_FIND(fcntl);

	va_start(cmd_arg, cmd);
	result = handle->fns->fcntl_fn(handle, fsp, cmd, cmd_arg);
	va_end(cmd_arg);

	return result;
}

int smb_vfs_call_linux_setlease(struct vfs_handle_struct *handle,
				struct files_struct *fsp, int leasetype)
{
	VFS_FIND(linux_setlease);
	return handle->fns->linux_setlease_fn(handle, fsp, leasetype);
}

int smb_vfs_call_symlinkat(struct vfs_handle_struct *handle,
			const struct smb_filename *link_target,
			struct files_struct *dirfsp,
			const struct smb_filename *new_smb_fname)
{
	VFS_FIND(symlinkat);
	return handle->fns->symlinkat_fn(handle,
				link_target,
				dirfsp,
				new_smb_fname);
}

int smb_vfs_call_readlinkat(struct vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			char *buf,
			size_t bufsiz)
{
	VFS_FIND(readlinkat);
	return handle->fns->readlinkat_fn(handle,
				dirfsp,
				smb_fname,
				buf,
				bufsiz);
}

int smb_vfs_call_linkat(struct vfs_handle_struct *handle,
			struct files_struct *srcfsp,
			const struct smb_filename *old_smb_fname,
			struct files_struct *dstfsp,
			const struct smb_filename *new_smb_fname,
			int flags)
{
	VFS_FIND(linkat);
	return handle->fns->linkat_fn(handle,
				srcfsp,
				old_smb_fname,
				dstfsp,
				new_smb_fname,
				flags);
}

int smb_vfs_call_mknodat(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode,
			SMB_DEV_T dev)
{
	VFS_FIND(mknodat);
	return handle->fns->mknodat_fn(handle,
				dirfsp,
				smb_fname,
				mode,
				dev);
}

struct smb_filename *smb_vfs_call_realpath(struct vfs_handle_struct *handle,
			TALLOC_CTX *ctx,
			const struct smb_filename *smb_fname)
{
	VFS_FIND(realpath);
	return handle->fns->realpath_fn(handle, ctx, smb_fname);
}

int smb_vfs_call_chflags(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			unsigned int flags)
{
	VFS_FIND(chflags);
	return handle->fns->chflags_fn(handle, smb_fname, flags);
}

struct file_id smb_vfs_call_file_id_create(struct vfs_handle_struct *handle,
					   const SMB_STRUCT_STAT *sbuf)
{
	VFS_FIND(file_id_create);
	return handle->fns->file_id_create_fn(handle, sbuf);
}

uint64_t smb_vfs_call_fs_file_id(struct vfs_handle_struct *handle,
				 const SMB_STRUCT_STAT *sbuf)
{
	VFS_FIND(fs_file_id);
	return handle->fns->fs_file_id_fn(handle, sbuf);
}

NTSTATUS smb_vfs_call_streaminfo(struct vfs_handle_struct *handle,
				 struct files_struct *fsp,
				 const struct smb_filename *smb_fname,
				 TALLOC_CTX *mem_ctx,
				 unsigned int *num_streams,
				 struct stream_struct **streams)
{
	VFS_FIND(streaminfo);
	return handle->fns->streaminfo_fn(handle, fsp, smb_fname, mem_ctx,
					  num_streams, streams);
}

int smb_vfs_call_get_real_filename(struct vfs_handle_struct *handle,
				   const struct smb_filename *path,
				   const char *name,
				   TALLOC_CTX *mem_ctx,
				   char **found_name)
{
	VFS_FIND(get_real_filename);
	return handle->fns->get_real_filename_fn(handle, path, name, mem_ctx,
						 found_name);
}

const char *smb_vfs_call_connectpath(struct vfs_handle_struct *handle,
				 const struct smb_filename *smb_fname)
{
	VFS_FIND(connectpath);
	return handle->fns->connectpath_fn(handle, smb_fname);
}

bool smb_vfs_call_strict_lock_check(struct vfs_handle_struct *handle,
				    struct files_struct *fsp,
				    struct lock_struct *plock)
{
	VFS_FIND(strict_lock_check);
	return handle->fns->strict_lock_check_fn(handle, fsp, plock);
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

NTSTATUS smb_vfs_call_get_dos_attributes(struct vfs_handle_struct *handle,
					 struct smb_filename *smb_fname,
					 uint32_t *dosmode)
{
	VFS_FIND(get_dos_attributes);
	return handle->fns->get_dos_attributes_fn(handle, smb_fname, dosmode);
}

NTSTATUS smb_vfs_call_fget_dos_attributes(struct vfs_handle_struct *handle,
					  struct files_struct *fsp,
					  uint32_t *dosmode)
{
	VFS_FIND(fget_dos_attributes);
	return handle->fns->fget_dos_attributes_fn(handle, fsp, dosmode);
}

NTSTATUS smb_vfs_call_set_dos_attributes(struct vfs_handle_struct *handle,
					 const struct smb_filename *smb_fname,
					 uint32_t dosmode)
{
	VFS_FIND(set_dos_attributes);
	return handle->fns->set_dos_attributes_fn(handle, smb_fname, dosmode);
}

NTSTATUS smb_vfs_call_fset_dos_attributes(struct vfs_handle_struct *handle,
					  struct files_struct *fsp,
					  uint32_t dosmode)
{
	VFS_FIND(set_dos_attributes);
	return handle->fns->fset_dos_attributes_fn(handle, fsp, dosmode);
}

struct tevent_req *smb_vfs_call_offload_read_send(TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct vfs_handle_struct *handle,
						  struct files_struct *fsp,
						  uint32_t fsctl,
						  uint32_t ttl,
						  off_t offset,
						  size_t to_copy)
{
	VFS_FIND(offload_read_send);
	return handle->fns->offload_read_send_fn(mem_ctx, ev, handle,
						 fsp, fsctl,
						 ttl, offset, to_copy);
}

NTSTATUS smb_vfs_call_offload_read_recv(struct tevent_req *req,
					struct vfs_handle_struct *handle,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *token_blob)
{
	VFS_FIND(offload_read_recv);
	return handle->fns->offload_read_recv_fn(req, handle, mem_ctx, token_blob);
}

struct tevent_req *smb_vfs_call_offload_write_send(struct vfs_handle_struct *handle,
						   TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   uint32_t fsctl,
						   DATA_BLOB *token,
						   off_t transfer_offset,
						   struct files_struct *dest_fsp,
						   off_t dest_off,
						   off_t num)
{
	VFS_FIND(offload_write_send);
	return handle->fns->offload_write_send_fn(handle, mem_ctx, ev, fsctl,
					       token, transfer_offset,
					       dest_fsp, dest_off, num);
}

NTSTATUS smb_vfs_call_offload_write_recv(struct vfs_handle_struct *handle,
					 struct tevent_req *req,
					 off_t *copied)
{
	VFS_FIND(offload_write_recv);
	return handle->fns->offload_write_recv_fn(handle, req, copied);
}

struct smb_vfs_call_get_dos_attributes_state {
	files_struct *dir_fsp;
	NTSTATUS (*recv_fn)(struct tevent_req *req,
			    struct vfs_aio_state *aio_state,
			    uint32_t *dosmode);
	struct vfs_aio_state aio_state;
	uint32_t dos_attributes;
};

static void smb_vfs_call_get_dos_attributes_done(struct tevent_req *subreq);

struct tevent_req *smb_vfs_call_get_dos_attributes_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			struct smb_filename *smb_fname)
{
	struct tevent_req *req = NULL;
	struct smb_vfs_call_get_dos_attributes_state *state = NULL;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_vfs_call_get_dos_attributes_state);
	if (req == NULL) {
		return NULL;
	}

	VFS_FIND(get_dos_attributes_send);

	*state = (struct smb_vfs_call_get_dos_attributes_state) {
		.dir_fsp = dir_fsp,
		.recv_fn = handle->fns->get_dos_attributes_recv_fn,
	};

	subreq = handle->fns->get_dos_attributes_send_fn(mem_ctx,
							 ev,
							 handle,
							 dir_fsp,
							 smb_fname);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_defer_callback(req, ev);

	tevent_req_set_callback(subreq,
				smb_vfs_call_get_dos_attributes_done,
				req);

	return req;
}

static void smb_vfs_call_get_dos_attributes_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb_vfs_call_get_dos_attributes_state *state =
		tevent_req_data(req,
		struct smb_vfs_call_get_dos_attributes_state);
	NTSTATUS status;
	bool ok;

	/*
	 * Make sure we run as the user again
	 */
	ok = change_to_user_and_service_by_fsp(state->dir_fsp);
	SMB_ASSERT(ok);

	status = state->recv_fn(subreq,
				&state->aio_state,
				&state->dos_attributes);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS smb_vfs_call_get_dos_attributes_recv(
		struct tevent_req *req,
		struct vfs_aio_state *aio_state,
		uint32_t *dos_attributes)
{
	struct smb_vfs_call_get_dos_attributes_state *state =
		tevent_req_data(req,
		struct smb_vfs_call_get_dos_attributes_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*aio_state = state->aio_state;
	*dos_attributes = state->dos_attributes;
	tevent_req_received(req);
	return NT_STATUS_OK;
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

NTSTATUS smb_vfs_call_snap_check_path(vfs_handle_struct *handle,
				      TALLOC_CTX *mem_ctx,
				      const char *service_path,
				      char **base_volume)
{
	VFS_FIND(snap_check_path);
	return handle->fns->snap_check_path_fn(handle, mem_ctx, service_path,
					       base_volume);
}

NTSTATUS smb_vfs_call_snap_create(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  const char *base_volume,
				  time_t *tstamp,
				  bool rw,
				  char **base_path,
				  char **snap_path)
{
	VFS_FIND(snap_create);
	return handle->fns->snap_create_fn(handle, mem_ctx, base_volume, tstamp,
					   rw, base_path, snap_path);
}

NTSTATUS smb_vfs_call_snap_delete(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  char *base_path,
				  char *snap_path)
{
	VFS_FIND(snap_delete);
	return handle->fns->snap_delete_fn(handle, mem_ctx, base_path,
					   snap_path);
}

NTSTATUS smb_vfs_call_fget_nt_acl(struct vfs_handle_struct *handle,
				  struct files_struct *fsp,
				  uint32_t security_info,
				  TALLOC_CTX *mem_ctx,
				  struct security_descriptor **ppdesc)
{
	VFS_FIND(fget_nt_acl);
	return handle->fns->fget_nt_acl_fn(handle, fsp, security_info,
					   mem_ctx, ppdesc);
}

NTSTATUS smb_vfs_call_get_nt_acl_at(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			uint32_t security_info,
			TALLOC_CTX *mem_ctx,
			struct security_descriptor **ppdesc)
{
	VFS_FIND(get_nt_acl_at);
	return handle->fns->get_nt_acl_at_fn(handle,
				dirfsp,
				smb_fname,
				security_info,
				mem_ctx,
				ppdesc);
}

NTSTATUS smb_vfs_call_fset_nt_acl(struct vfs_handle_struct *handle,
				  struct files_struct *fsp,
				  uint32_t security_info_sent,
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

SMB_ACL_T smb_vfs_call_sys_acl_get_file(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					SMB_ACL_TYPE_T type,
					TALLOC_CTX *mem_ctx)
{
	VFS_FIND(sys_acl_get_file);
	return handle->fns->sys_acl_get_file_fn(handle, smb_fname, type, mem_ctx);
}

SMB_ACL_T smb_vfs_call_sys_acl_get_fd(struct vfs_handle_struct *handle,
				      struct files_struct *fsp,
				      TALLOC_CTX *mem_ctx)
{
	VFS_FIND(sys_acl_get_fd);
	return handle->fns->sys_acl_get_fd_fn(handle, fsp, mem_ctx);
}

int smb_vfs_call_sys_acl_blob_get_file(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				char **blob_description,
				DATA_BLOB *blob)
{
	VFS_FIND(sys_acl_blob_get_file);
	return handle->fns->sys_acl_blob_get_file_fn(handle, smb_fname,
			mem_ctx, blob_description, blob);
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
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T acltype,
				SMB_ACL_T theacl)
{
	VFS_FIND(sys_acl_set_file);
	return handle->fns->sys_acl_set_file_fn(handle, smb_fname,
				acltype, theacl);
}

int smb_vfs_call_sys_acl_set_fd(struct vfs_handle_struct *handle,
				struct files_struct *fsp, SMB_ACL_T theacl)
{
	VFS_FIND(sys_acl_set_fd);
	return handle->fns->sys_acl_set_fd_fn(handle, fsp, theacl);
}

int smb_vfs_call_sys_acl_delete_def_file(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname)
{
	VFS_FIND(sys_acl_delete_def_file);
	return handle->fns->sys_acl_delete_def_file_fn(handle, smb_fname);
}

ssize_t smb_vfs_call_getxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				void *value,
				size_t size)
{
	VFS_FIND(getxattr);
	return handle->fns->getxattr_fn(handle, smb_fname, name, value, size);
}


struct smb_vfs_call_getxattrat_state {
	files_struct *dir_fsp;
	ssize_t (*recv_fn)(struct tevent_req *req,
			   struct vfs_aio_state *aio_state,
			   TALLOC_CTX *mem_ctx,
			   uint8_t **xattr_value);
	ssize_t retval;
	uint8_t *xattr_value;
	struct vfs_aio_state aio_state;
};

static void smb_vfs_call_getxattrat_done(struct tevent_req *subreq);

struct tevent_req *smb_vfs_call_getxattrat_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			const struct smb_filename *smb_fname,
			const char *xattr_name,
			size_t alloc_hint)
{
	struct tevent_req *req = NULL;
	struct smb_vfs_call_getxattrat_state *state = NULL;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_vfs_call_getxattrat_state);
	if (req == NULL) {
		return NULL;
	}

	VFS_FIND(getxattrat_send);

	*state = (struct smb_vfs_call_getxattrat_state) {
		.dir_fsp = dir_fsp,
		.recv_fn = handle->fns->getxattrat_recv_fn,
	};

	subreq = handle->fns->getxattrat_send_fn(mem_ctx,
						 ev,
						 handle,
						 dir_fsp,
						 smb_fname,
						 xattr_name,
						 alloc_hint);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_defer_callback(req, ev);

	tevent_req_set_callback(subreq, smb_vfs_call_getxattrat_done, req);
	return req;
}

static void smb_vfs_call_getxattrat_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb_vfs_call_getxattrat_state *state = tevent_req_data(
		req, struct smb_vfs_call_getxattrat_state);
	bool ok;

	/*
	 * Make sure we run as the user again
	 */
	ok = change_to_user_and_service_by_fsp(state->dir_fsp);
	SMB_ASSERT(ok);

	state->retval = state->recv_fn(subreq,
				       &state->aio_state,
				       state,
				       &state->xattr_value);
	TALLOC_FREE(subreq);
	if (state->retval == -1) {
		tevent_req_error(req, state->aio_state.error);
		return;
	}

	tevent_req_done(req);
}

ssize_t smb_vfs_call_getxattrat_recv(struct tevent_req *req,
				     struct vfs_aio_state *aio_state,
				     TALLOC_CTX *mem_ctx,
				     uint8_t **xattr_value)
{
	struct smb_vfs_call_getxattrat_state *state = tevent_req_data(
		req, struct smb_vfs_call_getxattrat_state);
	size_t xattr_size;

	if (tevent_req_is_unix_error(req, &aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	*aio_state = state->aio_state;
	xattr_size = state->retval;
	if (xattr_value != NULL) {
		*xattr_value = talloc_move(mem_ctx, &state->xattr_value);
	}

	tevent_req_received(req);
	return xattr_size;
}

ssize_t smb_vfs_call_fgetxattr(struct vfs_handle_struct *handle,
			       struct files_struct *fsp, const char *name,
			       void *value, size_t size)
{
	VFS_FIND(fgetxattr);
	return handle->fns->fgetxattr_fn(handle, fsp, name, value, size);
}

ssize_t smb_vfs_call_listxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				char *list,
				size_t size)
{
	VFS_FIND(listxattr);
	return handle->fns->listxattr_fn(handle, smb_fname, list, size);
}

ssize_t smb_vfs_call_flistxattr(struct vfs_handle_struct *handle,
				struct files_struct *fsp, char *list,
				size_t size)
{
	VFS_FIND(flistxattr);
	return handle->fns->flistxattr_fn(handle, fsp, list, size);
}

int smb_vfs_call_removexattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name)
{
	VFS_FIND(removexattr);
	return handle->fns->removexattr_fn(handle, smb_fname, name);
}

int smb_vfs_call_fremovexattr(struct vfs_handle_struct *handle,
			      struct files_struct *fsp, const char *name)
{
	VFS_FIND(fremovexattr);
	return handle->fns->fremovexattr_fn(handle, fsp, name);
}

int smb_vfs_call_setxattr(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *name,
			const void *value,
			size_t size,
			int flags)
{
	VFS_FIND(setxattr);
	return handle->fns->setxattr_fn(handle, smb_fname,
			name, value, size, flags);
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
