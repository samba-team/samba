/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   vfs initialisation and support functions
   Copyright (C) Tim Potter 1992-1998
   
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
#ifdef HAVE_LIBDL
#include <dlfcn.h>
#endif

extern int DEBUGLEVEL;

/* Some structures to help us initialise the vfs operations table */

struct vfs_syminfo {
    char *name;
    void *fptr;
};

struct vfs_ops dl_ops;

struct vfs_syminfo vfs_syminfo[] = {

    /* Global operations */

    {"vfs_init",       &dl_ops.init},

    /* Disk operations */

    {"vfs_connect",    &dl_ops.connect},
    {"vfs_disconnect", &dl_ops.disconnect},
    {"vfs_disk_free",  &dl_ops.disk_free},

    /* Directory operations */

    {"vfs_opendir",    &dl_ops.opendir},
    {"vfs_readdir",    &dl_ops.readdir},
    {"vfs_mkdir",      &dl_ops.mkdir},
    {"vfs_rmdir",      &dl_ops.rmdir},

    /* File operations */

    {"vfs_open",       &dl_ops.open},
    {"vfs_close",      &dl_ops.close},
    {"vfs_read",       &dl_ops.read},
    {"vfs_write",      &dl_ops.write},
    {"vfs_lseek",      &dl_ops.lseek},
    {"vfs_rename",     &dl_ops.rename},
    {"vfs_sync",       &dl_ops.sync},
    {"vfs_stat",       &dl_ops.stat},
    {"vfs_fstat",      &dl_ops.fstat},
    {"vfs_lstat",      &dl_ops.lstat},
    {"vfs_lock",       &dl_ops.lock},
    {"vfs_unlink",     &dl_ops.unlink},
    {"vfs_chmod",      &dl_ops.chmod},
    {"vfs_utime",      &dl_ops.utime},
    
    {NULL, 0}
};

/* Default vfs hooks.  WARNING: The order of these initialisers is
   very important.  Change at your own peril. */

struct vfs_ops default_vfs_ops = {

    /* Global operations */

    NULL,                         /* init */

    /* Disk operations */        

    NULL,                         /* connect */
    NULL,                         /* disconnect */
    vfswrap_disk_free,

    /* Directory operations */

    vfswrap_opendir,
    vfswrap_readdir,
    vfswrap_mkdir,
    vfswrap_rmdir,

    /* File operations */

    vfswrap_open,
    vfswrap_close,
    vfswrap_read,
    vfswrap_write,
    vfswrap_lseek,
    vfswrap_rename,
    vfswrap_sync_file,
    vfswrap_stat,
    vfswrap_fstat,
    vfswrap_lstat,
    vfswrap_fcntl_lock,
    vfswrap_unlink,
    vfswrap_chmod,
    vfswrap_utime
};

/****************************************************************************
  call vfs_init function of loadable module
****************************************************************************/
#ifdef HAVE_LIBDL
BOOL do_vfs_init(char *vfs_object)
{
    void *handle, (*fptr)(void);

    DEBUG(3, ("Calling vfs_init for module %s\n", vfs_object));

    handle = dlopen(vfs_object, RTLD_NOW);
    if (!handle) {
	DEBUG(0, ("Error opening %s: %s\n", vfs_object, dlerror()));
	return False;
    }

    fptr = dlsym(handle, "vfs_init");

    /* Call initialisation function */

    if (fptr != NULL) {
	fptr();
    }

    dlclose(handle);

    return True;
}
#endif

/****************************************************************************
  initialise default vfs hooks
****************************************************************************/
int vfs_init_default(connection_struct *conn)
{
    DEBUG(3, ("Initialising default vfs hooks\n"));

    bcopy(&default_vfs_ops, &conn->vfs_ops, sizeof(conn->vfs_ops));
    return 0;
}

/****************************************************************************
  initialise custom vfs hooks
****************************************************************************/
#ifdef HAVE_LIBDL
int vfs_init_custom(connection_struct *conn)
{
    void *handle, *fptr;
    int index;

    DEBUG(3, ("Initialising custom vfs hooks from %s\n",
	      lp_vfsobj(SNUM(conn))));

    /* Open object file */

    handle = dlopen(lp_vfsobj(SNUM(conn)), RTLD_NOW);
    if (!handle) {
	DEBUG(0, ("Error opening %s: %s\n", lp_vfsobj(SNUM(conn)),
		  dlerror()));
	return -1;
    }

    /* Read list of symbols */

    for(index = 0; vfs_syminfo[index].name; index++) {
	fptr = dlsym(handle, vfs_syminfo[index].name);
	if (fptr == NULL) {
	    DEBUG(0, ("Symbol %s not found in %s\n", vfs_syminfo[index].name,
		      lp_vfsobj(SNUM(conn))));
	    return -1;
	}

	*((void **)vfs_syminfo[index].fptr) = fptr;
    }

    /* Copy loaded symbols into connection struct */

    bcopy(&dl_ops, &conn->vfs_ops, sizeof(dl_ops));
    dlclose(handle);

    do_vfs_init(lp_vfsobj(SNUM(conn)));

    return 0;
}
#endif

/*******************************************************************
  check if a vfs file exists
********************************************************************/
BOOL vfs_file_exist(connection_struct *conn,char *fname,SMB_STRUCT_STAT *sbuf)
{
  SMB_STRUCT_STAT st;
  if (!sbuf) sbuf = &st;
  
  if (conn->vfs_ops.stat(fname,sbuf) != 0) 
    return(False);

  return(S_ISREG(sbuf->st_mode));
}

/****************************************************************************
  read data from the client vfs, reading exactly N bytes. 
****************************************************************************/
ssize_t vfs_read_data(files_struct *fsp,char *buffer,size_t N)
{
  ssize_t  ret;
  size_t total=0;  
  int fd = fsp->fd_ptr->fd;
  extern int smb_read_error;
 
  smb_read_error = 0;

  while (total < N)
  {
#ifdef WITH_SSL
      DEBUG(0, ("WARNING: read_data() called with SSL enabled\n"));
    if(fd == sslFd){
      ret = SSL_read(ssl, buffer + total, N - total);
    }else{
      ret = read(fd,buffer + total,N - total);
    }
#else /* WITH_SSL */
    ret = fsp->conn->vfs_ops.read(fd,buffer + total,N - total);
#endif /* WITH_SSL */

    if (ret == 0)
    {
      smb_read_error = READ_EOF;
      return 0;
    }
    if (ret == -1)
    {
      smb_read_error = READ_ERROR;
      return -1;
    }
    total += ret;
  }
  return (ssize_t)total;
}

/****************************************************************************
  write data to a fd on the vfs
****************************************************************************/
ssize_t vfs_write_data(files_struct *fsp,char *buffer,size_t N)
{
  size_t total=0;
  ssize_t ret;
  int fd = fsp->fd_ptr->fd;

  while (total < N)
  {
#ifdef WITH_SSL
      DEBUG(0, ("WARNING: write_data called with SSL enabled\n"));
    if(fd == sslFd){
      ret = SSL_write(ssl,buffer + total,N - total);
    }else{
      ret = write(fd,buffer + total,N - total);
    }
#else /* WITH_SSL */
    ret = fsp->conn->vfs_ops.write(fd,buffer + total,N - total);
#endif /* WITH_SSL */

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
	  in_fsp->conn->vfs_ops.read(in_fsp->fd_ptr->fd,buf1+ret,s-ret) : read(in_fd,buf1+ret,s-ret);
    }

    if (ret > 0)
    {
	if (out_fsp) {
	    ret2 = out_fsp->conn->vfs_ops.write(out_fsp->fd_ptr->fd,buf1,ret);
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
