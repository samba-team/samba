/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   VFS initialisation and support functions
   Copyright (C) Tim Potter 1999
   
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

#include "includes.h"

extern int DEBUGLEVEL;

/* Some structures to help us initialise the vfs operations table */

struct vfs_syminfo {
    char *name;
    void *fptr;
};

/* Default vfs hooks.  WARNING: The order of these initialisers is
   very important.  They must be in the same order as defined in
   vfs.h.  Change at your own peril. */

struct vfs_ops default_vfs_ops = {

    /* Disk operations */        

    vfswrap_dummy_connect,
    vfswrap_dummy_disconnect,
    vfswrap_disk_free,

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
    vfswrap_write,
    vfswrap_lseek,
    vfswrap_rename,
    vfswrap_fsync,
    vfswrap_stat,
    vfswrap_fstat,
    vfswrap_lstat,
    vfswrap_unlink,
    vfswrap_chmod,
    vfswrap_utime,
    vfswrap_ftruncate,
	vfswrap_lock
};

/****************************************************************************
  initialise default vfs hooks
****************************************************************************/
int vfs_init_default(connection_struct *conn)
{
    DEBUG(3, ("Initialising default vfs hooks\n"));

    memcpy(&conn->vfs_ops, &default_vfs_ops, sizeof(conn->vfs_ops));
    return True;
}

/****************************************************************************
  initialise custom vfs hooks
****************************************************************************/
#ifdef HAVE_LIBDL
BOOL vfs_init_custom(connection_struct *conn)
{
    void *handle;
    struct vfs_ops *ops, *(*fptr)(struct vfs_options *options);

    DEBUG(3, ("Initialising custom vfs hooks from %s\n",
	      lp_vfsobj(SNUM(conn))));

    /* Open object file */

    handle = dlopen(lp_vfsobj(SNUM(conn)), RTLD_NOW | RTLD_GLOBAL);
    conn->vfs_conn->dl_handle = handle;

    if (!handle) {
	DEBUG(0, ("Error opening %s: %s\n", lp_vfsobj(SNUM(conn)),
		  dlerror()));
	return False;
    }

    /* Get handle on vfs_init() symbol */

    fptr = dlsym(handle, "vfs_init");

    if (fptr == NULL) {
	DEBUG(0, ("No vfs_init() symbol found in %s\n", 
		  lp_vfsobj(SNUM(conn))));
	return False;
    }

    /* Initialise vfs_ops structure */

    if ((ops = fptr(NULL)) == NULL) {
        DEBUG(0, ("vfs_init function from %s failed\n", lp_vfsobj(SNUM(conn))));
	return False;
    }

    /* Fill in unused operations with default (disk based) ones.
       There's probably a neater way to do this then a whole bunch of
       if statements. */ 

    memcpy(&conn->vfs_ops, ops, sizeof(conn->vfs_ops));
    
    if (conn->vfs_ops.connect == NULL) {
	conn->vfs_ops.connect = default_vfs_ops.connect;
    }

    if (conn->vfs_ops.disconnect == NULL) {
	conn->vfs_ops.disconnect = default_vfs_ops.disconnect;
    }

    if (conn->vfs_ops.disk_free == NULL) {
	conn->vfs_ops.disk_free = default_vfs_ops.disk_free;
    }

    if (conn->vfs_ops.opendir == NULL) {
	conn->vfs_ops.opendir = default_vfs_ops.opendir;
    }

    if (conn->vfs_ops.readdir == NULL) {
	conn->vfs_ops.readdir = default_vfs_ops.readdir;
    }

    if (conn->vfs_ops.mkdir == NULL) {
	conn->vfs_ops.mkdir = default_vfs_ops.mkdir;
    }

    if (conn->vfs_ops.rmdir == NULL) {
	conn->vfs_ops.rmdir = default_vfs_ops.rmdir;
    }

    if (conn->vfs_ops.closedir == NULL) {
	conn->vfs_ops.closedir = default_vfs_ops.closedir;
    }

    if (conn->vfs_ops.open == NULL) {
	conn->vfs_ops.open = default_vfs_ops.open;
    }

    if (conn->vfs_ops.close == NULL) {
	conn->vfs_ops.close = default_vfs_ops.close;
    }

    if (conn->vfs_ops.read == NULL) {
	conn->vfs_ops.read = default_vfs_ops.read;
    }
    
    if (conn->vfs_ops.write == NULL) {
	conn->vfs_ops.write = default_vfs_ops.write;
    }
    
    if (conn->vfs_ops.lseek == NULL) {
	conn->vfs_ops.lseek = default_vfs_ops.lseek;
    }
    
    if (conn->vfs_ops.rename == NULL) {
	conn->vfs_ops.rename = default_vfs_ops.rename;
    }
    
    if (conn->vfs_ops.fsync == NULL) {
	conn->vfs_ops.fsync = default_vfs_ops.fsync;
    }
    
    if (conn->vfs_ops.stat == NULL) {
	conn->vfs_ops.stat = default_vfs_ops.stat;
    }
    
    if (conn->vfs_ops.fstat == NULL) {
	conn->vfs_ops.fstat = default_vfs_ops.fstat;
    }
    
    if (conn->vfs_ops.lstat == NULL) {
	conn->vfs_ops.lstat = default_vfs_ops.lstat;
    }
    
    if (conn->vfs_ops.unlink == NULL) {
	conn->vfs_ops.unlink = default_vfs_ops.unlink;
    }
    
    if (conn->vfs_ops.chmod == NULL) {
	conn->vfs_ops.chmod = default_vfs_ops.chmod;
    }
    
    if (conn->vfs_ops.utime == NULL) {
	conn->vfs_ops.utime = default_vfs_ops.utime;
    }
    
    if (conn->vfs_ops.ftruncate == NULL) {
	conn->vfs_ops.ftruncate = default_vfs_ops.ftruncate;
    }
    
    if (conn->vfs_ops.lock == NULL) {
	conn->vfs_ops.lock = default_vfs_ops.lock;
    }
    
    return True;
}
#endif

BOOL vfs_directory_exist(connection_struct *conn, char *dname,
                         SMB_STRUCT_STAT *st)
{
  SMB_STRUCT_STAT st2;
  BOOL ret;

  if (!st) st = &st2;

  if (conn->vfs_ops.stat(dos_to_unix(dname,False),st) != 0) 
    return(False);

  ret = S_ISDIR(st->st_mode);
  if(!ret)
    errno = ENOTDIR;

  return ret;
}

/*******************************************************************
  check if a vfs file exists
********************************************************************/
BOOL vfs_file_exist(connection_struct *conn,char *fname,SMB_STRUCT_STAT *sbuf)
{
  SMB_STRUCT_STAT st;
  if (!sbuf) sbuf = &st;
  
  if (conn->vfs_ops.stat(dos_to_unix(fname,False),sbuf) != 0) 
    return(False);

  return(S_ISREG(sbuf->st_mode));
}

/****************************************************************************
  write data to a fd on the vfs
****************************************************************************/
ssize_t vfs_write_data(files_struct *fsp,char *buffer,size_t N)
{
  size_t total=0;
  ssize_t ret;

  while (total < N)
  {
    ret = fsp->conn->vfs_ops.write(fsp->fd,buffer + total,N - total);

    if (ret == -1) return -1;
    if (ret == 0) return total;

    total += ret;
  }
  return (ssize_t)total;
}

/****************************************************************************
transfer some data between two file_struct's
****************************************************************************/
SMB_OFF_T vfs_transfer_file(int in_fd, files_struct *in_fsp, 
			    int out_fd, files_struct *out_fsp,
			    SMB_OFF_T n, char *header, int headlen, int align)
{
  static char *buf=NULL;  
  static int size=0;
  char *buf1,*abuf;
  SMB_OFF_T total = 0;

  DEBUG(4,("vfs_transfer_file n=%.0f  (head=%d) called\n",(double)n,headlen));

  /* Check we have at least somewhere to read from */

  SMB_ASSERT((in_fd != -1) || (in_fsp != NULL));

  if (size == 0) {
    size = lp_readsize();
    size = MAX(size,1024);
  }

  while (!buf && size>0) {
    buf = (char *)Realloc(buf,size+8);
    if (!buf) size /= 2;
  }

  if (!buf) {
    DEBUG(0,("Can't allocate transfer buffer!\n"));
    exit(1);
  }

  abuf = buf + (align%8);

  if (header)
    n += headlen;

  while (n > 0)
  {
    int s = (int)MIN(n,(SMB_OFF_T)size);
    int ret,ret2=0;

    ret = 0;

    if (header && (headlen >= MIN(s,1024))) {
      buf1 = header;
      s = headlen;
      ret = headlen;
      headlen = 0;
      header = NULL;
    } else {
      buf1 = abuf;
    }

    if (header && headlen > 0)
    {
      ret = MIN(headlen,size);
      memcpy(buf1,header,ret);
      headlen -= ret;
      header += ret;
      if (headlen <= 0) header = NULL;
    }

    if (s > ret) {
      ret += in_fsp ? 
	  in_fsp->conn->vfs_ops.read(in_fsp->fd,buf1+ret,s-ret) : read(in_fd,buf1+ret,s-ret);
    }

    if (ret > 0)
    {
	if (out_fsp) {
	    ret2 = out_fsp->conn->vfs_ops.write(out_fsp->fd,buf1,ret);
	} else {
	    ret2= (out_fd != -1) ? write_data(out_fd,buf1,ret) : ret;
	}
    }

      if (ret2 > 0) total += ret2;
      /* if we can't write then dump excess data */
      if (ret2 != ret)
        vfs_transfer_file(in_fd, in_fsp, -1,NULL,n-(ret+headlen),NULL,0,0);

    if (ret <= 0 || ret2 != ret)
      return(total);
    n -= ret;
  }
  return(total);
}

/*******************************************************************
a vfs_readdir wrapper which just returns the file name
********************************************************************/
char *vfs_readdirname(connection_struct *conn, void *p)
{
	struct dirent *ptr;
	char *dname;

	if (!p) return(NULL);
  
	ptr = (struct dirent *)conn->vfs_ops.readdir(p);
	if (!ptr) return(NULL);

	dname = ptr->d_name;

#ifdef NEXT2
	if (telldir(p) < 0) return(NULL);
#endif

#ifdef HAVE_BROKEN_READDIR
	/* using /usr/ucb/cc is BAD */
	dname = dname - 2;
#endif

	{
		static pstring buf;
		memcpy(buf, dname, NAMLEN(ptr)+1);
		unix_to_dos(buf, True);
		dname = buf;
	}

	unix_to_dos(dname, True);
	return(dname);
}

/* VFS options not quite working yet */

#if 0

/***************************************************************************
  handle the interpretation of the vfs option parameter
 *************************************************************************/
static BOOL handle_vfs_option(char *pszParmValue, char **ptr)
{
    struct vfs_options *new_option, **options = (struct vfs_options **)ptr;
    int i;
    
    /* Create new vfs option */

    new_option = (struct vfs_options *)malloc(sizeof(*new_option));
    if (new_option == NULL) {
	return False;
    }

    ZERO_STRUCTP(new_option);

    /* Get name and value */
    
    new_option->name = strtok(pszParmValue, "=");

    if (new_option->name == NULL) {
	return False;
    }

    while(isspace(*new_option->name)) {
	new_option->name++;
    }

    for (i = strlen(new_option->name); i > 0; i--) {
	if (!isspace(new_option->name[i - 1])) break;
    }

    new_option->name[i] = '\0';
    new_option->name = strdup(new_option->name);

    new_option->value = strtok(NULL, "=");

    if (new_option->value != NULL) {

	while(isspace(*new_option->value)) {
	    new_option->value++;
	}
	
	for (i = strlen(new_option->value); i > 0; i--) {
	    if (!isspace(new_option->value[i - 1])) break;
	}
	
	new_option->value[i] = '\0';
	new_option->value = strdup(new_option->value);
    }

    /* Add to list */

    DLIST_ADD(*options, new_option);

    return True;
}

#endif

