/* 
 * Recycle bin VFS module for Samba.
 *
 * Copyright (C) 2001, Brandon Stone, Amherst College, <bbstone@amherst.edu>.
 * Copyright (C) 2002, Jeremy Allison - modified to make a VFS module.
 * Copyright (C) 2002, Juergen Hasch - added some options.
  *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "config.h"
#include <stdio.h>
#include <sys/stat.h>
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <errno.h>
#include <string.h>
#include <includes.h>
#include <vfs.h>

const char delimiter = '|';		/* delimiter for options */

/* One per connection */

typedef struct recycle_bin_struct
{
	TALLOC_CTX *ctx;
	char	*recycle_bin;		/* name of the recycle bin directory */
	BOOL	keep_directories;	/* keep directory structure of deleted file in recycle bin */
	BOOL	versions;		/* create versions of deleted files with identical name */
	BOOL	touch;			/* touch access date of deleted file */
	char	*exclude;		/* which files to exclude */
	char	*exclude_dir;		/* which directories to exclude */
	char	*noversions;		/* which files to exclude from versioning */
	SMB_OFF_T max_size;		/* maximum file size to be saved */
} recycle_bin_struct;

/* Global Variables */
static recycle_bin_struct *current;

/* VFS operations */

extern struct vfs_ops default_vfs_ops;   /* For passthrough operation */

static int recycle_unlink(connection_struct *, const char *);
static int recycle_connect(struct connection_struct *conn, const char *service, const char *user);
static void recycle_disconnect(struct connection_struct *conn);

BOOL checkparam(char *haystack,char *needle);

struct vfs_ops recycle_ops = {
    
	/* Disk operations */

	recycle_connect,		/* connect */
	recycle_disconnect,		/* disconnect */
	NULL,				/* disk free */

	/* Directory operations */

	NULL,				/* opendir */
	NULL,				/* readdir */
	NULL,				/* mkdir */
	NULL,				/* rmdir */
	NULL,				/* closedir */

	/* File operations */

	NULL,				/* open */
	NULL,				/* close */
	NULL,				/* read  */
	NULL,				/* write */
	NULL,				/* lseek */
	NULL,				/* sendfile */
	NULL,				/* rename */
	NULL,				/* fsync */
	NULL,				/* stat  */
	NULL,				/* fstat */
	NULL,				/* lstat */
	recycle_unlink,
	NULL,				/* chmod */
	NULL,				/* fchmod */
	NULL,				/* chown */
	NULL,				/* fchown */
	NULL,				/* chdir */
	NULL,				/* getwd */
	NULL,				/* utime */
	NULL,				/* ftruncate */
	NULL,				/* lock */
	NULL,				/* symlink */
	NULL,				/* readlink */
	NULL,				/* link */
	NULL,				/* mknod */
	NULL,				/* realpath */
	NULL,				/* fget_nt_acl */
	NULL,				/* get_nt_acl */
	NULL,				/* fset_nt_acl */
	NULL,				/* set_nt_acl */

	NULL,				/* chmod_acl */
	NULL,				/* fchmod_acl */

	NULL,				/* sys_acl_get_entry */
	NULL,				/* sys_acl_get_tag_type */
	NULL,				/* sys_acl_get_permset */
	NULL,				/* sys_acl_get_qualifier */
	NULL,				/* sys_acl_get_file */
	NULL,				/* sys_acl_get_fd */
	NULL,				/* sys_acl_clear_perms */
	NULL,				/* sys_acl_add_perm */
	NULL,				/* sys_acl_to_text */
	NULL,				/* sys_acl_init */
	NULL,				/* sys_acl_create_entry */
	NULL,				/* sys_acl_set_tag_type */
	NULL,				/* sys_acl_set_qualifier */
	NULL,				/* sys_acl_set_permset */
	NULL,				/* sys_acl_valid */
	NULL,				/* sys_acl_set_file */
	NULL,				/* sys_acl_set_fd */
	NULL,				/* sys_acl_delete_def_file */
	NULL,				/* sys_acl_get_perm */
	NULL,				/* sys_acl_free_text */
	NULL,				/* sys_acl_free_acl */
	NULL				/* sys_acl_free_qualifier */
};

/**
 * Parse recycle bin configuration parameters
 *
 * @retval False if out of memory
 **/
static BOOL do_parameter(char *pszParmName, char *pszParmValue)
{
	if (StrCaseCmp("name",pszParmName)==0) {
		current->recycle_bin = (char *)talloc(current->ctx,sizeof(pstring));
		if (current->recycle_bin == NULL)
			return False;
		current->recycle_bin = safe_strcpy(current->recycle_bin,pszParmValue,sizeof(pstring));
		DEBUG(10, ("name=%s\n", current->recycle_bin));
	} else if (StrCaseCmp("mode",pszParmName)==0) {
		if (checkparam(pszParmValue,"KEEP_DIRECTORIES") == True)
			current->keep_directories = True;
		if (checkparam(pszParmValue,"VERSIONS") == True)
			current->versions = True;
		if (checkparam(pszParmValue,"TOUCH") == True)
			current->touch = True;
		DEBUG(10, ("mode=%s\n", pszParmValue));
	} else if (StrCaseCmp("maxsize",pszParmName)==0) {
		current->max_size = strtoul(pszParmValue,NULL,10);
		DEBUG(10, ("max_size=%ld\n", (long int)current->max_size));
	} else if (StrCaseCmp("exclude",pszParmName)==0) {
		current->exclude = talloc_strdup(current->ctx, pszParmValue);
		if (current->exclude == NULL)
			return False;
		DEBUG(10, ("exclude=%s\n", current->exclude));
	} else if (StrCaseCmp("excludedir",pszParmName)==0) {
		current->exclude_dir = talloc_strdup(current->ctx, pszParmValue);
		if (current->exclude_dir == NULL)
			return False;
		DEBUG(10, ("exclude_dir=%s\n", current->exclude_dir));
	} else if (StrCaseCmp("noversions",pszParmName)==0) {
		current->noversions = talloc_strdup(current->ctx, pszParmValue);
		if (current->noversions == NULL)
			return False;
		DEBUG(10, ("noversions=%s\n", current->noversions));
	}
	return True;
}

/**
 * We don't care for sections in configuration file
 *
 **/
static BOOL do_section(char *pszSectionName)
{
	return True;
}

/**
 * VFS initialisation function.
 *
 * @retval initialised vfs_ops structure
 **/
struct vfs_ops *vfs_init(int *vfs_version, struct vfs_ops *def_vfs_ops)
{
	struct vfs_ops tmp_ops;
	DEBUG(3, ("Initializing VFS module recycle\n"));

	*vfs_version = SMB_VFS_INTERFACE_VERSION;
	memcpy(&tmp_ops, def_vfs_ops, sizeof(struct vfs_ops));
	tmp_ops.unlink = recycle_unlink;
	tmp_ops.connect = recycle_connect;
	tmp_ops.disconnect = recycle_disconnect;
	memcpy(&recycle_ops, &tmp_ops, sizeof(struct vfs_ops));
	return &recycle_ops;
}

static int recycle_connect(struct connection_struct *conn, const char *service, const char *user)
{
	const char *p;
	pstring conf_file;
	int rc;
	TALLOC_CTX *ctx=NULL;

	DEBUG(3,("Called for service %s (%d) as user %s\n", service, SNUM(conn), user));
	
	if (!(ctx = talloc_init_named("recycle bin"))) {
		DEBUG(0, ("Failed to allocate memory in VFS module recycle_bin\n"));
		return 0;
	}
	
	/* read configuration file */
	*conf_file='\0';
	p = (const char *)lp_vfs_options(SNUM(conn));
	if (p != NULL && strlen(p) > 0) {
		pstrcpy(conf_file,p);
		DEBUG(10,("Using configuration file %s\n",conf_file));
	}
	
	current = talloc(ctx,sizeof(recycle_bin_struct));
	if ( current == NULL) {
		DEBUG(0, ("Failed to allocate memory in VFS module recycle_bin\n"));
		return -1;
	}
	current->ctx = ctx;
	/* Set defaults */
	current->recycle_bin = talloc_strdup(ctx,".recycle");
	current->keep_directories = False;
	current->versions = False;
	current->touch = False;
	current->exclude = "";
	current->exclude_dir = "";
	current->noversions = "";
	current->max_size = 0;
	if (strlen(conf_file) > 0) {
		rc=pm_process( conf_file, do_section, do_parameter);
		DEBUG(10, ("pm_process returned %d\n", rc));
	}
	standard_sub_conn( conn , current->recycle_bin,sizeof(pstring));
	trim_string(current->recycle_bin,"/","/");
	conn->vfs_private= (void *)current;
	return 0;
}

static void recycle_disconnect(struct connection_struct *conn)
{
	DEBUG(3, ("Disconnecting VFS module recycle_bin\n"));
	talloc_destroy(((recycle_bin_struct*)conn->vfs_private)->ctx);
	default_vfs_ops.disconnect(conn);
}

static BOOL recycle_XXX_exist(connection_struct *conn, const char *dname, BOOL isdir)
{
	SMB_STRUCT_STAT st;

	if (default_vfs_ops.stat(conn,dname,&st) != 0)
		return(False);

	if (isdir)
		return S_ISDIR(st.st_mode) ? True : False;
	else
		return S_ISREG(st.st_mode) ? True : False;
}

static BOOL recycle_directory_exist(connection_struct *conn, const char *dname)
{
	return recycle_XXX_exist(conn, dname, True);
}

static BOOL recycle_file_exist(connection_struct *conn, const char *fname)
{
	return recycle_XXX_exist(conn, fname, False);
}

/**
 * Return file size
 * @param conn connection
 * @param fname file name
 * @return size in bytes
 **/
static SMB_OFF_T recycle_get_file_size(connection_struct *conn, const char *fname)
{
	SMB_STRUCT_STAT st;
	if (default_vfs_ops.stat(conn,fname,&st) != 0) {
		DEBUG(0,("stat for %s returned %s\n",fname,strerror(errno)));
		return (SMB_OFF_T)0;
	}
	return(st.st_size);
}

/**
 * Create directory tree
 * @param conn connection
 * @param dname Directory tree to be created
 * @return Returns True for success
 **/
static BOOL recycle_create_dir(connection_struct *conn, const char *dname)
{
	char *c,*y;
	int i;
	
	mode_t mode;
	pstring tempstr;
	pstring newdir;
	
	*newdir='\0';
	mode=S_IREAD|S_IWRITE|S_IEXEC;
	pstrcpy(tempstr,dname);
	y=tempstr;
	/* Create directory tree if neccessary */
	for(c = strtok(y,"/"); c; c= strtok(NULL,"/")) {
		pstrcat(newdir,c);
		if (recycle_directory_exist(conn,newdir))
			DEBUG(3, ("dir %s already exists\n",newdir));
		else {
			DEBUG(3, ("creating new dir %s\n",newdir));
			i=default_vfs_ops.mkdir(conn,newdir,mode);
			if (i) {
				DEBUG(3,("mkdir failed for %s with error %s\n",newdir,strerror(errno)));
				return False;
			}
		}
		pstrcat(newdir,"/");	
		}
	return True;
}

/**
 * Check if needle is contained exactly in haystack
 * @param haystack list of parameters separated by delimimiter character
 * @param needle string to be matched exactly to haystack
 * @return True if found
 **/
BOOL checkparam(char *haystack,char *needle)
{
	char *p,*c;
	pstring str;
	int i,len;
	
	if (haystack==NULL || strlen(haystack)==0 || needle == NULL || strlen(needle)== 0)
		return False;
		
	pstrcpy(str,haystack);
	len=strlen(str)+1;
	p=c=str;

	for (i=0; i < len; i++, p++) {
		if (*p == delimiter || *p == '\0') {
			*p='\0';
			if(strncmp(c,needle,c-p) == 0)
				return True;
			c=p+1;
		}
	}
	return False;
}

/**
 * Check if needle is contained in haystack, * and ? patterns are resolved
 * @param haystack list of parameters separated by delimimiter character
 * @param needle string to be matched exectly to haystack including pattern matching
 * @return True if found
 **/
BOOL matchparam(char *haystack,char *needle)
{
	char *p,*c;
	pstring str;
	int i,len;
	
	if (haystack==NULL || strlen(haystack)==0 || needle == NULL || strlen(needle)== 0)
		return False;
		
	pstrcpy(str,haystack);
	len=strlen(str)+1;
	p=c=str;

	for (i=0; i < len; i++, p++) {
		if (*p == delimiter || *p == '\0') {
			*p='\0';
			if (!unix_wild_match(c,needle))
				return True;
			c=p+1;
		}
	}
	return False;
}

/**
 * Touch access date
 **/
void recycle_touch(connection_struct *conn, const char *fname)
{
	SMB_STRUCT_STAT st;
	struct utimbuf tb;
	time_t current;

	if (default_vfs_ops.stat(conn,fname,&st) != 0) {
		DEBUG(0,("stat for %s returned %s\n",fname,strerror(errno)));
		return;
	}
	current = time(&current);
	tb.actime = current;
	tb.modtime = st.st_mtime;	

	if (default_vfs_ops.utime(conn, fname, &tb) == -1 )
		DEBUG(0, ("Touching %s failed, reason = %s\n",fname,strerror(errno)));
	}

/**
 * Check if file should be recycled
 **/
static int recycle_unlink(connection_struct *conn, const char *inname)
{
	pstring fname,fpath, bin;
	char *base, *ext;
	int i=1, len, addlen;
	SMB_BIG_UINT dfree,dsize,bsize,space_avail;
	SMB_OFF_T fsize;
	BOOL exist;
	int rc;

	pstrcpy(fname,inname);
	if (conn->vfs_private)
		current = (recycle_bin_struct *)conn->vfs_private;
	else {
		DEBUG(0,("Recycle bin not initialized!\n"));
		return default_vfs_ops.unlink(conn,fname);
	}
		
	if(!current->recycle_bin || !*(current->recycle_bin)) {
		DEBUG(3, ("Recycle path not set, purging %s...\n", fname));
		return default_vfs_ops.unlink(conn,fname);
	}
	
	/* we don't recycle the recycle bin... */
	if (strstr(fname,current->recycle_bin)==fname) {
		DEBUG(3, ("File is within recycling bin\n"));
		return default_vfs_ops.unlink(conn,fname);
	}
	
	fsize = recycle_get_file_size(conn,fname);
	if(fsize == 0) {
		DEBUG(3, ("File %s is empty, purging...\n", fname));
		return default_vfs_ops.unlink(conn,fname);
	}
	
	if(current->max_size > 0 && fsize > current->max_size) {
		DEBUG(3, ("File %s exceeds maximum recycle size, purging... \n", fname));
		return default_vfs_ops.unlink(conn,fname);
	} 
	
	space_avail = default_vfs_ops.disk_free(conn,".",True,&bsize,&dfree,&dsize)*1024L;
	DEBUG(10,("space_avail = %Lu, fsize = %Lu\n",space_avail,fsize));
	if(space_avail < (SMB_BIG_UINT)fsize) {
		DEBUG(3, ("Not enough diskspace, purging file %s\n",fname));
		return default_vfs_ops.unlink(conn,fname);
	}

	/* extract filename and path */
	pstrcpy(fpath,"/");
	pstrcat(fpath, fname);
	base = strrchr(fpath, '/');
	if (base == NULL) {
		ext = strrchr(fname, '.');
		base = (char *)fname;
		pstrcpy(fpath,"/");
	}
	else {
		ext = strrchr(base, '.');
		*(base++) = '\0';
	}

	DEBUG(10, ("fname:%s\n", fname));	/* original filename with path */
	DEBUG(10, ("fpath:%s\n", fpath));	/* original path */
	DEBUG(10, ("base:%s\n", base));		/* filename without path */
	DEBUG(10, ("ext:%s\n", ext));		/* filename extension */
	
	if (matchparam(current->exclude,base)) {
		DEBUG(3, ("file %s is excluded \n",base));
		return default_vfs_ops.unlink(conn,fname);
	}

	if (checkparam(current->exclude_dir,fpath)) {
		DEBUG(3, ("directory %s is excluded \n",fpath));
		return default_vfs_ops.unlink(conn,fname);
	} 

	pstrcpy(bin, current->recycle_bin);

	/* see if we need to recreate the original directory structure in the recycle bin */
	if (current->keep_directories == True)
		pstrcat(bin, fpath);

	exist=recycle_directory_exist(conn,bin);
	if (exist)
		DEBUG(10, ("Directory already exists\n"));
	else {
		DEBUG(10, ("Creating directory %s\n",bin));
		rc=recycle_create_dir(conn,bin);
		if (rc == False)
			{
			DEBUG(3, ("Could not create directory, purging %s...\n", fname));
			return default_vfs_ops.unlink(conn,fname);			
			}
	}

	pstrcat(bin, "/");
	pstrcat(bin,base);
	DEBUG(10, ("bin:%s\n", bin));		/* new filename with path */	
	
	/* check if we should delete file from recycle bin */
	if (recycle_file_exist(conn,bin)) {
		if (current->versions == False || matchparam(current->noversions,base) == True) {
			DEBUG(3, ("Removing old file %s from recycle bin\n",bin));
			default_vfs_ops.unlink(conn,bin);
		}
	}

	/* rename file we move to recycle bin */
	len = strlen(bin);
	addlen = sizeof(pstring)-len-1;
	while(recycle_file_exist(conn,bin)) {
		slprintf(bin+len, addlen, " (Copy #%d)", i++);
		pstrcat(bin, ext);
	}
	
	DEBUG(10, ("Moving source=%s to dest=%s\n", fname, bin));
	rc = default_vfs_ops.rename(conn, fname, bin);
	if (rc == -1) {
		DEBUG(3, ("Move error %d (%s), purging file %s (%s)\n", errno, strerror(errno),fname,bin));
		return default_vfs_ops.unlink(conn,fname);
	}

	/* touch access date of moved file */
	if (current->touch == True )
		recycle_touch(conn,bin);
	return rc;
}
