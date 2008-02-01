/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   VFS initialisation and support functions
   Copyright (C) Tim Potter 1999
   Copyright (C) Alexander Bokovoy 2002
   Copyright (C) James Peach 2006

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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

static_decl_vfs;

struct vfs_init_function_entry {
	char *name;
	const vfs_op_tuple *vfs_op_tuples;
	struct vfs_init_function_entry *prev, *next;
};

static struct vfs_init_function_entry *backends = NULL;

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

NTSTATUS smb_register_vfs(int version, const char *name, const vfs_op_tuple *vfs_op_tuples)
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

	if (!name || !name[0] || !vfs_op_tuples) {
		DEBUG(0,("smb_register_vfs() called with NULL pointer or empty name!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (vfs_find_backend_entry(name)) {
		DEBUG(0,("VFS module %s already loaded!\n", name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	entry = SMB_XMALLOC_P(struct vfs_init_function_entry);
	entry->name = smb_xstrdup(name);
	entry->vfs_op_tuples = vfs_op_tuples;

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

static inline void vfs_set_operation(struct vfs_ops * vfs, vfs_op_type which,
				struct vfs_handle_struct * handle, void * op)
{
	((struct vfs_handle_struct **)&vfs->handles)[which] = handle;
	((void **)(void *)&vfs->ops)[which] = op;
}

bool vfs_init_custom(connection_struct *conn, const char *vfs_object)
{
	const vfs_op_tuple *ops;
	char *module_path = NULL;
	char *module_name = NULL;
	char *module_param = NULL, *p;
	int i;
	vfs_handle_struct *handle;
	const struct vfs_init_function_entry *entry;
	
	if (!conn||!vfs_object||!vfs_object[0]) {
		DEBUG(0,("vfs_init_custon() called with NULL pointer or emtpy vfs_object!\n"));
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
	if((entry = vfs_find_backend_entry(module_name)) || 
	   (NT_STATUS_IS_OK(smb_probe_module("vfs", module_path)) &&
		(entry = vfs_find_backend_entry(module_name)))) {

		DEBUGADD(5,("Successfully loaded vfs module [%s] with the new modules system\n", vfs_object));
		
	 	if ((ops = entry->vfs_op_tuples) == NULL) {
	 		DEBUG(0, ("entry->vfs_op_tuples==NULL for [%s] failed\n", vfs_object));
			goto fail;
	 	}
	} else {
		DEBUG(0,("Can't find a vfs module [%s]\n",vfs_object));
		goto fail;
	}

	handle = TALLOC_ZERO_P(conn->mem_ctx,vfs_handle_struct);
	if (!handle) {
		DEBUG(0,("TALLOC_ZERO() failed!\n"));
		goto fail;
	}
	memcpy(&handle->vfs_next, &conn->vfs, sizeof(struct vfs_ops));
	handle->conn = conn;
	if (module_param) {
		handle->param = talloc_strdup(conn->mem_ctx, module_param);
	}
	DLIST_ADD(conn->vfs_handles, handle);

 	for(i=0; ops[i].op != NULL; i++) {
		DEBUG(5, ("Checking operation #%d (type %d, layer %d)\n", i, ops[i].type, ops[i].layer));
		if(ops[i].layer == SMB_VFS_LAYER_OPAQUE) {
			/* If this operation was already made opaque by different module, it
			 * will be overridden here.
			 */
			DEBUGADD(5, ("Making operation type %d opaque [module %s]\n", ops[i].type, vfs_object));
			vfs_set_operation(&conn->vfs_opaque, ops[i].type, handle, ops[i].op);
		}
		/* Change current VFS disposition*/
		DEBUGADD(5, ("Accepting operation type %d from module %s\n", ops[i].type, vfs_object));
		vfs_set_operation(&conn->vfs, ops[i].type, handle, ops[i].op);
	}

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

void *vfs_add_fsp_extension_notype(vfs_handle_struct *handle, files_struct *fsp, size_t ext_size)
{
	struct vfs_fsp_data *ext;
	void * ext_data;

	/* Prevent VFS modules adding multiple extensions. */
	if ((ext_data = vfs_fetch_fsp_extension(handle, fsp))) {
		return ext_data;
	}

	ext = (struct vfs_fsp_data *)TALLOC_ZERO(
		handle->conn->mem_ctx, sizeof(struct vfs_fsp_data) + ext_size);
	if (ext == NULL) {
		return NULL;
	}

	ext->owner = handle;
	ext->next = fsp->vfs_extension;
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
		    TALLOC_FREE(curr);
		    return;
		}
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
 Check if directory exists.
********************************************************************/

bool vfs_directory_exist(connection_struct *conn, const char *dname, SMB_STRUCT_STAT *st)
{
	SMB_STRUCT_STAT st2;
	bool ret;

	if (!st)
		st = &st2;

	if (SMB_VFS_STAT(conn,dname,st) != 0)
		return(False);

	ret = S_ISDIR(st->st_mode);
	if(!ret)
		errno = ENOTDIR;

	return ret;
}

/*******************************************************************
 Check if an object exists in the vfs.
********************************************************************/

bool vfs_object_exist(connection_struct *conn,const char *fname,SMB_STRUCT_STAT *sbuf)
{
	SMB_STRUCT_STAT st;

	if (!sbuf)
		sbuf = &st;

	ZERO_STRUCTP(sbuf);

	if (SMB_VFS_STAT(conn,fname,sbuf) == -1)
		return(False);
	return True;
}

/*******************************************************************
 Check if a file exists in the vfs.
********************************************************************/

bool vfs_file_exist(connection_struct *conn, const char *fname,SMB_STRUCT_STAT *sbuf)
{
	SMB_STRUCT_STAT st;

	if (!sbuf)
		sbuf = &st;

	ZERO_STRUCTP(sbuf);

	if (SMB_VFS_STAT(conn,fname,sbuf) == -1)
		return False;
	return(S_ISREG(sbuf->st_mode));
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

ssize_t vfs_pread_data(files_struct *fsp, char *buf,
                size_t byte_count, SMB_OFF_T offset)
{
	size_t total=0;

	while (total < byte_count)
	{
		ssize_t ret = SMB_VFS_PREAD(fsp, buf + total,
					byte_count - total, offset + total);

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
		SMB_ASSERT(req->unread_bytes == N);
		/* VFS_RECVFILE must drain the socket
		 * before returning. */
		req->unread_bytes = 0;
		return SMB_VFS_RECVFILE(smbd_server_fd(),
					fsp,
					(SMB_OFF_T)-1,
					N);
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
			SMB_OFF_T offset)
{
	size_t total=0;
	ssize_t ret;

	if (req && req->unread_bytes) {
		SMB_ASSERT(req->unread_bytes == N);
		/* VFS_RECVFILE must drain the socket
		 * before returning. */
		req->unread_bytes = 0;
		return SMB_VFS_RECVFILE(smbd_server_fd(),
					fsp,
					offset,
					N);
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

int vfs_allocate_file_space(files_struct *fsp, SMB_BIG_UINT len)
{
	int ret;
	SMB_STRUCT_STAT st;
	connection_struct *conn = fsp->conn;
	SMB_BIG_UINT space_avail;
	SMB_BIG_UINT bsize,dfree,dsize;

	release_level_2_oplocks_on_change(fsp);

	/*
	 * Actually try and commit the space on disk....
	 */

	DEBUG(10,("vfs_allocate_file_space: file %s, len %.0f\n", fsp->fsp_name, (double)len ));

	if (((SMB_OFF_T)len) < 0) {
		DEBUG(0,("vfs_allocate_file_space: %s negative len requested.\n", fsp->fsp_name ));
		errno = EINVAL;
		return -1;
	}

	ret = SMB_VFS_FSTAT(fsp, &st);
	if (ret == -1)
		return ret;

	if (len == (SMB_BIG_UINT)st.st_size)
		return 0;

	if (len < (SMB_BIG_UINT)st.st_size) {
		/* Shrink - use ftruncate. */

		DEBUG(10,("vfs_allocate_file_space: file %s, shrink. Current size %.0f\n",
				fsp->fsp_name, (double)st.st_size ));

		flush_write_cache(fsp, SIZECHANGE_FLUSH);
		if ((ret = SMB_VFS_FTRUNCATE(fsp, (SMB_OFF_T)len)) != -1) {
			set_filelen_write_cache(fsp, len);
		}
		return ret;
	}

	/* Grow - we need to test if we have enough space. */

	if (!lp_strict_allocate(SNUM(fsp->conn)))
		return 0;

	len -= st.st_size;
	len /= 1024; /* Len is now number of 1k blocks needed. */
	space_avail = get_dfree_info(conn,fsp->fsp_name,False,&bsize,&dfree,&dsize);
	if (space_avail == (SMB_BIG_UINT)-1) {
		return -1;
	}

	DEBUG(10,("vfs_allocate_file_space: file %s, grow. Current size %.0f, needed blocks = %.0f, space avail = %.0f\n",
			fsp->fsp_name, (double)st.st_size, (double)len, (double)space_avail ));

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

int vfs_set_filelen(files_struct *fsp, SMB_OFF_T len)
{
	int ret;

	release_level_2_oplocks_on_change(fsp);
	DEBUG(10,("vfs_set_filelen: ftruncate %s to len %.0f\n", fsp->fsp_name, (double)len));
	flush_write_cache(fsp, SIZECHANGE_FLUSH);
	if ((ret = SMB_VFS_FTRUNCATE(fsp, len)) != -1) {
		set_filelen_write_cache(fsp, len);
		notify_fname(fsp->conn, NOTIFY_ACTION_MODIFIED,
			     FILE_NOTIFY_CHANGE_SIZE
			     | FILE_NOTIFY_CHANGE_ATTRIBUTES,
			     fsp->fsp_name);
	}

	return ret;
}

/****************************************************************************
 A vfs fill sparse call.
 Writes zeros from the end of file to len, if len is greater than EOF.
 Used only by strict_sync.
 Returns 0 on success, -1 on failure.
****************************************************************************/

static char *sparse_buf;
#define SPARSE_BUF_WRITE_SIZE (32*1024)

int vfs_fill_sparse(files_struct *fsp, SMB_OFF_T len)
{
	int ret;
	SMB_STRUCT_STAT st;
	SMB_OFF_T offset;
	size_t total;
	size_t num_to_write;
	ssize_t pwrite_ret;

	release_level_2_oplocks_on_change(fsp);
	ret = SMB_VFS_FSTAT(fsp, &st);
	if (ret == -1) {
		return ret;
	}

	if (len <= st.st_size) {
		return 0;
	}

	DEBUG(10,("vfs_fill_sparse: write zeros in file %s from len %.0f to len %.0f (%.0f bytes)\n",
		fsp->fsp_name, (double)st.st_size, (double)len, (double)(len - st.st_size)));

	flush_write_cache(fsp, SIZECHANGE_FLUSH);

	if (!sparse_buf) {
		sparse_buf = SMB_CALLOC_ARRAY(char, SPARSE_BUF_WRITE_SIZE);
		if (!sparse_buf) {
			errno = ENOMEM;
			return -1;
		}
	}

	offset = st.st_size;
	num_to_write = len - st.st_size;
	total = 0;

	while (total < num_to_write) {
		size_t curr_write_size = MIN(SPARSE_BUF_WRITE_SIZE, (num_to_write - total));

		pwrite_ret = SMB_VFS_PWRITE(fsp, sparse_buf, curr_write_size, offset + total);
		if (pwrite_ret == -1) {
			DEBUG(10,("vfs_fill_sparse: SMB_VFS_PWRITE for file %s failed with error %s\n",
				fsp->fsp_name, strerror(errno) ));
			return -1;
		}
		if (pwrite_ret == 0) {
			return 0;
		}

		total += pwrite_ret;
	}

	set_filelen_write_cache(fsp, len);
	return 0;
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

SMB_OFF_T vfs_transfer_file(files_struct *in, files_struct *out, SMB_OFF_T n)
{
	return transfer_file_internal((void *)in, (void *)out, n,
				      vfs_read_fn, vfs_write_fn);
}

/*******************************************************************
 A vfs_readdir wrapper which just returns the file name.
********************************************************************/

char *vfs_readdirname(connection_struct *conn, void *p)
{
	SMB_STRUCT_DIRENT *ptr= NULL;
	char *dname;

	if (!p)
		return(NULL);

	ptr = SMB_VFS_READDIR(conn, (DIR *)p);
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

	return(dname);
}

/*******************************************************************
 A wrapper for vfs_chdir().
********************************************************************/

int vfs_ChDir(connection_struct *conn, const char *path)
{
	int res;
	static char *LastDir = NULL;

	if (!LastDir) {
		LastDir = SMB_STRDUP("");
	}

	if (strcsequal(path,"."))
		return(0);

	if (*path == '/' && strcsequal(LastDir,path))
		return(0);

	DEBUG(4,("vfs_ChDir to %s\n",path));

	res = SMB_VFS_CHDIR(conn,path);
	if (!res) {
		SAFE_FREE(LastDir);
		LastDir = SMB_STRDUP(path);
	}
	return(res);
}

/*******************************************************************
 Return the absolute current directory path - given a UNIX pathname.
 Note that this path is returned in DOS format, not UNIX
 format. Note this can be called with conn == NULL.
********************************************************************/

struct getwd_cache_key {
	SMB_DEV_T dev;
	SMB_INO_T ino;
};

char *vfs_GetWd(TALLOC_CTX *ctx, connection_struct *conn)
{
        char s[PATH_MAX+1];
	SMB_STRUCT_STAT st, st2;
	char *result;
	DATA_BLOB cache_value;
	struct getwd_cache_key key;

	*s = 0;

	if (!lp_getwd_cache()) {
		goto nocache;
	}

	SET_STAT_INVALID(st);

	if (SMB_VFS_STAT(conn, ".",&st) == -1) {
		/*
		 * Known to fail for root: the directory may be NFS-mounted
		 * and exported with root_squash (so has no root access).
		 */
		DEBUG(1,("vfs_GetWd: couldn't stat \".\" error %s "
			 "(NFS problem ?)\n", strerror(errno) ));
		goto nocache;
	}

	ZERO_STRUCT(key); /* unlikely, but possible padding */
	key.dev = st.st_dev;
	key.ino = st.st_ino;

	if (!memcache_lookup(smbd_memcache(), GETWD_CACHE,
			     data_blob_const(&key, sizeof(key)),
			     &cache_value)) {
		goto nocache;
	}

	SMB_ASSERT((cache_value.length > 0)
		   && (cache_value.data[cache_value.length-1] == '\0'));

	if ((SMB_VFS_STAT(conn, (char *)cache_value.data, &st2) == 0)
	    && (st.st_dev == st2.st_dev) && (st.st_ino == st2.st_ino)
	    && (S_ISDIR(st.st_mode))) {
		/*
		 * Ok, we're done
		 */
		result = talloc_strdup(ctx, (char *)cache_value.data);
		if (result == NULL) {
			errno = ENOMEM;
		}
		return result;
	}

 nocache:

	/*
	 * We don't have the information to hand so rely on traditional
	 * methods. The very slow getcwd, which spawns a process on some
	 * systems, or the not quite so bad getwd.
	 */

	if (!SMB_VFS_GETWD(conn,s)) {
		DEBUG(0, ("vfs_GetWd: SMB_VFS_GETWD call failed: %s\n",
			  strerror(errno)));
		return NULL;
	}

	if (lp_getwd_cache() && VALID_STAT(st)) {
		ZERO_STRUCT(key); /* unlikely, but possible padding */
		key.dev = st.st_dev;
		key.ino = st.st_ino;

		memcache_add(smbd_memcache(), GETWD_CACHE,
			     data_blob_const(&key, sizeof(key)),
			     data_blob_const(s, strlen(s)+1));
	}

	result = talloc_strdup(ctx, s);
	if (result == NULL) {
		errno = ENOMEM;
	}
	return result;
}

/*******************************************************************
 Reduce a file name, removing .. elements and checking that
 it is below dir in the heirachy. This uses realpath.
********************************************************************/

NTSTATUS check_reduced_name(connection_struct *conn, const char *fname)
{
#ifdef REALPATH_TAKES_NULL
	bool free_resolved_name = True;
#else
        char resolved_name_buf[PATH_MAX+1];
	bool free_resolved_name = False;
#endif
	char *resolved_name = NULL;
	size_t con_path_len = strlen(conn->connectpath);
	char *p = NULL;

	DEBUG(3,("reduce_name [%s] [%s]\n", fname, conn->connectpath));

#ifdef REALPATH_TAKES_NULL
	resolved_name = SMB_VFS_REALPATH(conn,fname,NULL);
#else
	resolved_name = SMB_VFS_REALPATH(conn,fname,resolved_name_buf);
#endif

	if (!resolved_name) {
		switch (errno) {
			case ENOTDIR:
				DEBUG(3,("reduce_name: Component not a directory in getting realpath for %s\n", fname));
				return map_nt_error_from_unix(errno);
			case ENOENT:
			{
				TALLOC_CTX *ctx = talloc_tos();
				char *tmp_fname = NULL;
				char *last_component = NULL;
				/* Last component didn't exist. Remove it and try and canonicalise the directory. */

				tmp_fname = talloc_strdup(ctx, fname);
				if (!tmp_fname) {
					return NT_STATUS_NO_MEMORY;
				}
				p = strrchr_m(tmp_fname, '/');
				if (p) {
					*p++ = '\0';
					last_component = p;
				} else {
					last_component = tmp_fname;
					tmp_fname = talloc_strdup(ctx,
							".");
					if (!tmp_fname) {
						return NT_STATUS_NO_MEMORY;
					}
				}

#ifdef REALPATH_TAKES_NULL
				resolved_name = SMB_VFS_REALPATH(conn,tmp_fname,NULL);
#else
				resolved_name = SMB_VFS_REALPATH(conn,tmp_fname,resolved_name_buf);
#endif
				if (!resolved_name) {
					DEBUG(3,("reduce_name: couldn't get realpath for %s\n", fname));
					return map_nt_error_from_unix(errno);
				}
				tmp_fname = talloc_asprintf(ctx,
						"%s/%s",
						resolved_name,
						last_component);
				if (!tmp_fname) {
					return NT_STATUS_NO_MEMORY;
				}
#ifdef REALPATH_TAKES_NULL
				SAFE_FREE(resolved_name);
				resolved_name = SMB_STRDUP(tmp_fname);
				if (!resolved_name) {
					DEBUG(0,("reduce_name: malloc fail for %s\n", tmp_fname));
					return NT_STATUS_NO_MEMORY;
				}
#else
				safe_strcpy(resolved_name_buf, tmp_fname, PATH_MAX);
				resolved_name = resolved_name_buf;
#endif
				break;
			}
			default:
				DEBUG(1,("reduce_name: couldn't get realpath for %s\n", fname));
				return map_nt_error_from_unix(errno);
		}
	}

	DEBUG(10,("reduce_name realpath [%s] -> [%s]\n", fname, resolved_name));

	if (*resolved_name != '/') {
		DEBUG(0,("reduce_name: realpath doesn't return absolute paths !\n"));
		if (free_resolved_name) {
			SAFE_FREE(resolved_name);
		}
		return NT_STATUS_OBJECT_NAME_INVALID;
	}

	/* Check for widelinks allowed. */
	if (!lp_widelinks(SNUM(conn)) && (strncmp(conn->connectpath, resolved_name, con_path_len) != 0)) {
		DEBUG(2, ("reduce_name: Bad access attempt: %s is a symlink outside the share path", fname));
		if (free_resolved_name) {
			SAFE_FREE(resolved_name);
		}
		return NT_STATUS_ACCESS_DENIED;
	}

        /* Check if we are allowing users to follow symlinks */
        /* Patch from David Clerc <David.Clerc@cui.unige.ch>
                University of Geneva */

#ifdef S_ISLNK
        if (!lp_symlinks(SNUM(conn))) {
                SMB_STRUCT_STAT statbuf;
                if ( (SMB_VFS_LSTAT(conn,fname,&statbuf) != -1) &&
                                (S_ISLNK(statbuf.st_mode)) ) {
			if (free_resolved_name) {
				SAFE_FREE(resolved_name);
			}
                        DEBUG(3,("reduce_name: denied: file path name %s is a symlink\n",resolved_name));
			return NT_STATUS_ACCESS_DENIED;
                }
        }
#endif

	DEBUG(3,("reduce_name: %s reduced to %s\n", fname, resolved_name));
	if (free_resolved_name) {
		SAFE_FREE(resolved_name);
	}
	return NT_STATUS_OK;
}
