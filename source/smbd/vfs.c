/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   VFS initialisation and support functions
   Copyright (C) Tim Potter 1999
   Copyright (C) Alexander Bokovoy 2002

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

   This work was sponsored by Optifacio Software Services, Inc.
*/

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

struct vfs_init_function_entry {
	char *name;
 	vfs_op_tuple *vfs_op_tuples;
	struct vfs_init_function_entry *prev, *next;
};

static struct vfs_init_function_entry *backends = NULL;

/* Some structures to help us initialise the vfs operations table */

struct vfs_syminfo {
	char *name;
	void *fptr;
};

/* Default vfs hooks.  WARNING: The order of these initialisers is
   very important.  They must be in the same order as defined in
   vfs.h.  Change at your own peril. */

static struct vfs_ops default_vfs = {

	{
		/* Disk operations */
	
		vfswrap_dummy_connect,
		vfswrap_dummy_disconnect,
		vfswrap_disk_free,
		vfswrap_get_quota,
		vfswrap_set_quota,
		vfswrap_get_shadow_copy_data,
	
		/* Directory operations */
	
		vfswrap_opendir,
		vfswrap_readdir,
		vfswrap_mkdir,
		vfswrap_rmdir,
		vfswrap_closedir,
	
		/* File operations */
	
		vfswrap_open,
		vfswrap_close,
		vfswrap_read,
		vfswrap_pread,
		vfswrap_write,
		vfswrap_pwrite,
		vfswrap_lseek,
		vfswrap_sendfile,
		vfswrap_rename,
		vfswrap_fsync,
		vfswrap_stat,
		vfswrap_fstat,
		vfswrap_lstat,
		vfswrap_unlink,
		vfswrap_chmod,
		vfswrap_fchmod,
		vfswrap_chown,
		vfswrap_fchown,
		vfswrap_chdir,
		vfswrap_getwd,
		vfswrap_utime,
		vfswrap_ftruncate,
		vfswrap_lock,
		vfswrap_symlink,
		vfswrap_readlink,
		vfswrap_link,
		vfswrap_mknod,
		vfswrap_realpath,
	
		/* Windows ACL operations. */
		vfswrap_fget_nt_acl,
		vfswrap_get_nt_acl,
		vfswrap_fset_nt_acl,
		vfswrap_set_nt_acl,
	
		/* POSIX ACL operations. */
		vfswrap_chmod_acl,
		vfswrap_fchmod_acl,

		vfswrap_sys_acl_get_entry,
		vfswrap_sys_acl_get_tag_type,
		vfswrap_sys_acl_get_permset,
		vfswrap_sys_acl_get_qualifier,
		vfswrap_sys_acl_get_file,
		vfswrap_sys_acl_get_fd,
		vfswrap_sys_acl_clear_perms,
		vfswrap_sys_acl_add_perm,
		vfswrap_sys_acl_to_text,
		vfswrap_sys_acl_init,
		vfswrap_sys_acl_create_entry,
		vfswrap_sys_acl_set_tag_type,
		vfswrap_sys_acl_set_qualifier,
		vfswrap_sys_acl_set_permset,
		vfswrap_sys_acl_valid,
		vfswrap_sys_acl_set_file,
		vfswrap_sys_acl_set_fd,
		vfswrap_sys_acl_delete_def_file,
		vfswrap_sys_acl_get_perm,
		vfswrap_sys_acl_free_text,
		vfswrap_sys_acl_free_acl,
		vfswrap_sys_acl_free_qualifier,

		/* EA operations. */
		vfswrap_getxattr,
		vfswrap_lgetxattr,
		vfswrap_fgetxattr,
		vfswrap_listxattr,
		vfswrap_llistxattr,
		vfswrap_flistxattr,
		vfswrap_removexattr,
		vfswrap_lremovexattr,
		vfswrap_fremovexattr,
		vfswrap_setxattr,
		vfswrap_lsetxattr,
		vfswrap_fsetxattr
	}
};

/****************************************************************************
    maintain the list of available backends
****************************************************************************/

static struct vfs_init_function_entry *vfs_find_backend_entry(const char *name)
{
	struct vfs_init_function_entry *entry = backends;
 
	while(entry) {
		if (strcmp(entry->name, name)==0) return entry;
		entry = entry->next;
	}

	return NULL;
}

NTSTATUS smb_register_vfs(int version, const char *name, vfs_op_tuple *vfs_op_tuples)
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

	entry = smb_xmalloc(sizeof(struct vfs_init_function_entry));
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

	memcpy(&conn->vfs.ops, &default_vfs.ops, sizeof(default_vfs.ops));
	memcpy(&conn->vfs_opaque.ops, &default_vfs.ops, sizeof(default_vfs.ops));
}

/****************************************************************************
  initialise custom vfs hooks
 ****************************************************************************/

BOOL vfs_init_custom(connection_struct *conn, const char *vfs_object)
{
	vfs_op_tuple *ops;
	char *module_name = NULL;
	char *module_param = NULL, *p;
	int i;
	vfs_handle_struct *handle;
	struct vfs_init_function_entry *entry;
	
	if (!conn||!vfs_object||!vfs_object[0]) {
		DEBUG(0,("vfs_init_custon() called with NULL pointer or emtpy vfs_object!\n"));
		return False;
	}

	if(!backends) static_init_vfs;

	DEBUG(3, ("Initialising custom vfs hooks from [%s]\n", vfs_object));

	module_name = smb_xstrdup(vfs_object);

	p = strchr(module_name, ':');

	if (p) {
		*p = 0;
		module_param = p+1;
		trim_char(module_param, ' ', ' ');
	}

	trim_char(module_name, ' ', ' ');

	/* First, try to load the module with the new module system */
	if((entry = vfs_find_backend_entry(module_name)) || 
	   (NT_STATUS_IS_OK(smb_probe_module("vfs", module_name)) && 
		(entry = vfs_find_backend_entry(module_name)))) {

		DEBUGADD(5,("Successfully loaded vfs module [%s] with the new modules system\n", vfs_object));
		
	 	if ((ops = entry->vfs_op_tuples) == NULL) {
	 		DEBUG(0, ("entry->vfs_op_tuples==NULL for [%s] failed\n", vfs_object));
	 		SAFE_FREE(module_name);
	 		return False;
	 	}
	} else {
		DEBUG(0,("Can't find a vfs module [%s]\n",vfs_object));
		SAFE_FREE(module_name);
		return False;
	}

	handle = (vfs_handle_struct *)talloc_zero(conn->mem_ctx,sizeof(vfs_handle_struct));
	if (!handle) {
		DEBUG(0,("talloc_zero() failed!\n"));
		SAFE_FREE(module_name);
		return False;
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
 	    /* Check whether this operation was already made opaque by different module */
 	    if(((void**)&conn->vfs_opaque.ops)[ops[i].type] == ((void**)&default_vfs.ops)[ops[i].type]) {
 	      /* No, it isn't overloaded yet. Overload. */
 	      DEBUGADD(5, ("Making operation type %d opaque [module %s]\n", ops[i].type, vfs_object));
 	      ((void**)&conn->vfs_opaque.ops)[ops[i].type] = ops[i].op;
 	      ((vfs_handle_struct **)&conn->vfs_opaque.handles)[ops[i].type] = handle;
 	    }
 	  }
 	  /* Change current VFS disposition*/
 	  DEBUGADD(5, ("Accepting operation type %d from module %s\n", ops[i].type, vfs_object));
 	  ((void**)&conn->vfs.ops)[ops[i].type] = ops[i].op;
 	  ((vfs_handle_struct **)&conn->vfs.handles)[ops[i].type] = handle;
	}

	SAFE_FREE(module_name);
	return True;
}

/*****************************************************************
 Generic VFS init.
******************************************************************/

BOOL smbd_vfs_init(connection_struct *conn)
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

BOOL vfs_directory_exist(connection_struct *conn, const char *dname, SMB_STRUCT_STAT *st)
{
	SMB_STRUCT_STAT st2;
	BOOL ret;

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
 vfs mkdir wrapper 
********************************************************************/

int vfs_MkDir(connection_struct *conn, const char *name, mode_t mode)
{
	int ret;
	SMB_STRUCT_STAT sbuf;

	if(!(ret=SMB_VFS_MKDIR(conn, name, mode))) {

		inherit_access_acl(conn, name, mode);

		/*
		 * Check if high bits should have been set,
		 * then (if bits are missing): add them.
		 * Consider bits automagically set by UNIX, i.e. SGID bit from parent dir.
		 */
		if(mode & ~(S_IRWXU|S_IRWXG|S_IRWXO) &&
				!SMB_VFS_STAT(conn,name,&sbuf) && (mode & ~sbuf.st_mode))
			SMB_VFS_CHMOD(conn,name,sbuf.st_mode | (mode & ~sbuf.st_mode));
	}
	return ret;
}

/*******************************************************************
 Check if an object exists in the vfs.
********************************************************************/

BOOL vfs_object_exist(connection_struct *conn,const char *fname,SMB_STRUCT_STAT *sbuf)
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

BOOL vfs_file_exist(connection_struct *conn, const char *fname,SMB_STRUCT_STAT *sbuf)
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
		ssize_t ret = SMB_VFS_READ(fsp, fsp->fd, buf + total,
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
		ssize_t ret = SMB_VFS_PREAD(fsp, fsp->fd, buf + total,
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

ssize_t vfs_write_data(files_struct *fsp,const char *buffer,size_t N)
{
	size_t total=0;
	ssize_t ret;

	while (total < N) {
		ret = SMB_VFS_WRITE(fsp,fsp->fd,buffer + total,N - total);

		if (ret == -1)
			return -1;
		if (ret == 0)
			return total;

		total += ret;
	}
	return (ssize_t)total;
}

ssize_t vfs_pwrite_data(files_struct *fsp,const char *buffer,
                size_t N, SMB_OFF_T offset)
{
	size_t total=0;
	ssize_t ret;

	while (total < N) {
		ret = SMB_VFS_PWRITE(fsp, fsp->fd, buffer + total,
                                N - total, offset + total);

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
		return -1;
	}

	ret = SMB_VFS_FSTAT(fsp,fsp->fd,&st);
	if (ret == -1)
		return ret;

	if (len == (SMB_BIG_UINT)st.st_size)
		return 0;

	if (len < (SMB_BIG_UINT)st.st_size) {
		/* Shrink - use ftruncate. */

		DEBUG(10,("vfs_allocate_file_space: file %s, shrink. Current size %.0f\n",
				fsp->fsp_name, (double)st.st_size ));

		flush_write_cache(fsp, SIZECHANGE_FLUSH);
		if ((ret = SMB_VFS_FTRUNCATE(fsp, fsp->fd, (SMB_OFF_T)len)) != -1) {
			set_filelen_write_cache(fsp, len);
		}
		return ret;
	}

	/* Grow - we need to test if we have enough space. */

	if (!lp_strict_allocate(SNUM(fsp->conn)))
		return 0;

	len -= st.st_size;
	len /= 1024; /* Len is now number of 1k blocks needed. */
	space_avail = SMB_VFS_DISK_FREE(conn,fsp->fsp_name,False,&bsize,&dfree,&dsize);

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
	if ((ret = SMB_VFS_FTRUNCATE(fsp, fsp->fd, len)) != -1)
		set_filelen_write_cache(fsp, len);

	return ret;
}

/****************************************************************************
 Transfer some data (n bytes) between two file_struct's.
****************************************************************************/

static files_struct *in_fsp;
static files_struct *out_fsp;

static ssize_t read_fn(int fd, void *buf, size_t len)
{
	return SMB_VFS_READ(in_fsp, fd, buf, len);
}

static ssize_t write_fn(int fd, const void *buf, size_t len)
{
	return SMB_VFS_WRITE(out_fsp, fd, buf, len);
}

SMB_OFF_T vfs_transfer_file(files_struct *in, files_struct *out, SMB_OFF_T n)
{
	in_fsp = in;
	out_fsp = out;

	return transfer_file_internal(in_fsp->fd, out_fsp->fd, n, read_fn, write_fn);
}

/*******************************************************************
 A vfs_readdir wrapper which just returns the file name.
********************************************************************/

char *vfs_readdirname(connection_struct *conn, void *p)
{
	struct dirent *ptr= NULL;
	char *dname;

	if (!p)
		return(NULL);

	ptr = (struct dirent *)SMB_VFS_READDIR(conn,p);
	if (!ptr)
		return(NULL);

	dname = ptr->d_name;

#ifdef NEXT2
	if (telldir(p) < 0)
		return(NULL);
#endif

#ifdef HAVE_BROKEN_READDIR
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
	static pstring LastDir="";

	if (strcsequal(path,"."))
		return(0);

	if (*path == '/' && strcsequal(LastDir,path))
		return(0);

	DEBUG(4,("vfs_ChDir to %s\n",path));

	res = SMB_VFS_CHDIR(conn,path);
	if (!res)
		pstrcpy(LastDir,path);
	return(res);
}

/* number of list structures for a caching GetWd function. */
#define MAX_GETWDCACHE (50)

static struct {
	SMB_DEV_T dev; /* These *must* be compatible with the types returned in a stat() call. */
	SMB_INO_T inode; /* These *must* be compatible with the types returned in a stat() call. */
	char *dos_path; /* The pathname in DOS format. */
	BOOL valid;
} ino_list[MAX_GETWDCACHE];

extern BOOL use_getwd_cache;

/****************************************************************************
 Prompte a ptr (to make it recently used)
****************************************************************************/

static void array_promote(char *array,int elsize,int element)
{
	char *p;
	if (element == 0)
		return;

	p = (char *)malloc(elsize);

	if (!p) {
		DEBUG(5,("array_promote: malloc fail\n"));
		return;
	}

	memcpy(p,array + element * elsize, elsize);
	memmove(array + elsize,array,elsize*element);
	memcpy(array,p,elsize);
	SAFE_FREE(p);
}

/*******************************************************************
 Return the absolute current directory path - given a UNIX pathname.
 Note that this path is returned in DOS format, not UNIX
 format. Note this can be called with conn == NULL.
********************************************************************/

char *vfs_GetWd(connection_struct *conn, char *path)
{
	pstring s;
	static BOOL getwd_cache_init = False;
	SMB_STRUCT_STAT st, st2;
	int i;

	*s = 0;

	if (!use_getwd_cache)
		return(SMB_VFS_GETWD(conn,path));

	/* init the cache */
	if (!getwd_cache_init) {
		getwd_cache_init = True;
		for (i=0;i<MAX_GETWDCACHE;i++) {
			string_set(&ino_list[i].dos_path,"");
			ino_list[i].valid = False;
		}
	}

	/*  Get the inode of the current directory, if this doesn't work we're
		in trouble :-) */

	if (SMB_VFS_STAT(conn, ".",&st) == -1) {
		DEBUG(0,("Very strange, couldn't stat \".\" path=%s\n", path));
		return(SMB_VFS_GETWD(conn,path));
	}


	for (i=0; i<MAX_GETWDCACHE; i++) {
		if (ino_list[i].valid) {

			/*  If we have found an entry with a matching inode and dev number
				then find the inode number for the directory in the cached string.
				If this agrees with that returned by the stat for the current
				directory then all is o.k. (but make sure it is a directory all
				the same...) */

			if (st.st_ino == ino_list[i].inode && st.st_dev == ino_list[i].dev) {
				if (SMB_VFS_STAT(conn,ino_list[i].dos_path,&st2) == 0) {
					if (st.st_ino == st2.st_ino && st.st_dev == st2.st_dev &&
							(st2.st_mode & S_IFMT) == S_IFDIR) {
						pstrcpy (path, ino_list[i].dos_path);

						/* promote it for future use */
						array_promote((char *)&ino_list[0],sizeof(ino_list[0]),i);
						return (path);
					} else {
						/*  If the inode is different then something's changed,
							scrub the entry and start from scratch. */
						ino_list[i].valid = False;
					}
				}
			}
		}
	}

	/*  We don't have the information to hand so rely on traditional methods.
		The very slow getcwd, which spawns a process on some systems, or the
		not quite so bad getwd. */

	if (!SMB_VFS_GETWD(conn,s)) {
		DEBUG(0,("vfs_GetWd: SMB_VFS_GETWD call failed, errno %s\n",strerror(errno)));
		return (NULL);
	}

	pstrcpy(path,s);

	DEBUG(5,("vfs_GetWd %s, inode %.0f, dev %.0f\n",s,(double)st.st_ino,(double)st.st_dev));

	/* add it to the cache */
	i = MAX_GETWDCACHE - 1;
	string_set(&ino_list[i].dos_path,s);
	ino_list[i].dev = st.st_dev;
	ino_list[i].inode = st.st_ino;
	ino_list[i].valid = True;

	/* put it at the top of the list */
	array_promote((char *)&ino_list[0],sizeof(ino_list[0]),i);

	return (path);
}


/* check if the file 'nmae' is a symlink, in that case check that it point to
   a file that reside under the 'dir' tree */

static BOOL readlink_check(connection_struct *conn, const char *dir, char *name)
{
	BOOL ret = True;
	pstring flink;
	pstring cleanlink;
	pstring savedir;
	pstring realdir;
	size_t reallen;

	if (!vfs_GetWd(conn, savedir)) {
		DEBUG(0,("couldn't vfs_GetWd for %s %s\n", name, dir));
		return False;
	}

	if (vfs_ChDir(conn, dir) != 0) {
		DEBUG(0,("couldn't vfs_ChDir to %s\n", dir));
		return False;
	}

	if (!vfs_GetWd(conn, realdir)) {
		DEBUG(0,("couldn't vfs_GetWd for %s\n", dir));
		vfs_ChDir(conn, savedir);
		return(False);
	}
	
	reallen = strlen(realdir);
	if (realdir[reallen -1] == '/') {
		reallen--;
		realdir[reallen] = 0;
	}

	if (SMB_VFS_READLINK(conn, name, flink, sizeof(pstring) -1) != -1) {
		DEBUG(3,("reduce_name: file path name %s is a symlink\nChecking it's path\n", name));
		if (*flink == '/') {
			pstrcpy(cleanlink, flink);
		} else {
			pstrcpy(cleanlink, realdir);
			pstrcat(cleanlink, "/");
			pstrcat(cleanlink, flink);
		}
		unix_clean_name(cleanlink);

		if (strncmp(cleanlink, realdir, reallen) != 0) {
			DEBUG(2,("Bad access attempt? s=%s dir=%s newname=%s l=%d\n", name, realdir, cleanlink, (int)reallen));
			ret = False;
		}
	}

	vfs_ChDir(conn, savedir);
	
	return ret;
}

/*******************************************************************
 Reduce a file name, removing .. elements and checking that
 it is below dir in the heirachy. This uses vfs_GetWd() and so must be run
 on the system that has the referenced file system.
********************************************************************/

BOOL reduce_name(connection_struct *conn, pstring s, const char *dir)
{
#ifndef REDUCE_PATHS
	return True;
#else
	pstring dir2;
	pstring wd;
	pstring base_name;
	pstring newname;
	char *p=NULL;
	BOOL relative = (*s != '/');

	*dir2 = *wd = *base_name = *newname = 0;

	DEBUG(3,("reduce_name [%s] [%s]\n",s,dir));

	/* We know there are no double slashes as this comes from srvstr_get_path().
	   and has gone through check_path_syntax(). JRA */

	pstrcpy(base_name,s);
	p = strrchr_m(base_name,'/');

	if (!p)
		return readlink_check(conn, dir, s);

	if (!vfs_GetWd(conn,wd)) {
		DEBUG(0,("couldn't vfs_GetWd for %s %s\n",s,dir));
		return(False);
	}

	if (vfs_ChDir(conn,dir) != 0) {
		DEBUG(0,("couldn't vfs_ChDir to %s\n",dir));
		return(False);
	}

	if (!vfs_GetWd(conn,dir2)) {
		DEBUG(0,("couldn't vfs_GetWd for %s\n",dir));
		vfs_ChDir(conn,wd);
		return(False);
	}

	if (p && (p != base_name)) {
		*p = 0;
		if (strcmp(p+1,".")==0)
			p[1]=0;
		if (strcmp(p+1,"..")==0)
			*p = '/';
	}

	if (vfs_ChDir(conn,base_name) != 0) {
		vfs_ChDir(conn,wd);
		DEBUG(3,("couldn't vfs_ChDir for %s %s basename=%s\n",s,dir,base_name));
		return(False);
	}

	if (!vfs_GetWd(conn,newname)) {
		vfs_ChDir(conn,wd);
		DEBUG(2,("couldn't get vfs_GetWd for %s %s\n",s,base_name));
		return(False);
	}

	if (p && (p != base_name)) {
		pstrcat(newname,"/");
		pstrcat(newname,p+1);
	}

	{
		size_t l = strlen(dir2);
		char *last_slash = strrchr_m(dir2, '/');

		if (last_slash && (last_slash[1] == '\0'))
			l--;

		if (strncmp(newname,dir2,l) != 0) {
			vfs_ChDir(conn,wd);
			DEBUG(2,("Bad access attempt: s=%s dir=%s newname=%s l=%d\n",s,dir2,newname,(int)l));
			return(False);
		}

		if (!readlink_check(conn, dir, newname)) {
			DEBUG(2, ("Bad access attemt: %s is a symlink outside the share path", s));
			return(False);
		}

		if (relative) {
			if (newname[l] == '/')
				pstrcpy(s,newname + l + 1);
			else
				pstrcpy(s,newname+l);
		} else
			pstrcpy(s,newname);
	}

	vfs_ChDir(conn,wd);

	if (strlen(s) == 0)
		pstrcpy(s,"./");

	DEBUG(3,("reduced to %s\n",s));
	return(True);
#endif
}
