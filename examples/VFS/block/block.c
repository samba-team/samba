/* 
 * 
 * Block access from links to dev mount points specified in PARAMCONF file
 *
 * Copyright (C) Ronald Kuetemeier, 2001
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
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>


#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#include <syslog.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif


#include <includes.h>
#include <vfs.h>



DIR *block_opendir(struct connection_struct *conn, const char *fname);
int block_connect(struct connection_struct *conn, const char *service, const char *user);    
void block_disconnect(struct connection_struct *conn);    


/* VFS operations */


extern struct vfs_ops default_vfs_ops;   /* For passthrough operation */

struct vfs_ops execute_vfs_ops = {
    
	/* Disk operations */

	block_connect,
	block_disconnect,
	NULL,					/* disk free */

	/* Directory operations */

	block_opendir,
	NULL,					/* readdir */
	NULL,					/* mkdir */
	NULL,					/* rmdir */
	NULL,					/* closedir */

	/* File operations */

	NULL,					/* open */
	NULL,					/* close */
	NULL,					/* read  */
	NULL,					/* write */
	NULL,					/* lseek */
	NULL,					/* rename */
	NULL,					/* fsync */
	NULL,					/* stat  */
	NULL,					/* fstat */
	NULL,					/* lstat */
	NULL,					/* unlink */
	NULL,					/* chmod */
	NULL,					/* fchmod */
	NULL,					/* chown */
	NULL,					/* fchown */
	NULL,					/* chdir */
	NULL,					/* getwd */
	NULL,					/* utime */
	NULL,					/* ftruncate */
	NULL,					/* lock */
	NULL,					/* symlink */
	NULL,					/* readlink */
	NULL,					/* link */
	NULL,					/* mknod */
	NULL,					/* realpath */

	/* NT ACL operations */

	NULL,					/* fget_nt_acl */
	NULL,					/* get_nt_acl */
	NULL,					/* fset_nt_acl */
	NULL,					/* set_nt_acl */

	/* POSIX ACL operations. */

	NULL,					/* chmod_acl */
	NULL,					/* fchmod_acl */
	NULL,					/* sys_acl_get_entry */
	NULL,					/* sys_acl_get_tag_type */
	NULL,					/* sys_acl_get_permset */
	NULL,					/* sys_acl_get_qualifier */
	NULL,					/* sys_acl_get_file */
	NULL,					/* sys_acl_get_fd */
	NULL,					/* sys_acl_clear_perms */
	NULL,					/* sys_acl_add_perm */
	NULL,					/* sys_acl_to_text */
	NULL,					/* sys_acl_init */
	NULL,					/* sys_acl_create_entry */
	NULL,					/* sys_acl_set_tag_type */
	NULL,					/* sys_acl_set_qualifier */
	NULL,					/* sys_acl_set_permset */
	NULL,					/* sys_acl_valid */
	NULL,					/* sys_acl_set_file */
	NULL,					/* sys_acl_set_fd */
	NULL,					/* sys_acl_delete_def_file */
	NULL,					/* sys_acl_get_perm */
	NULL,					/* sys_acl_free_text */
	NULL,					/* sys_acl_free_acl */
	NULL					/* sys_acl_free_qualifier */
};


#ifndef PARAMCONF
#define PARAMCONF "/etc/samba/samba-block.conf"
#endif

extern BOOL pm_process(char *FileName, BOOL (*sfunc)(char *), BOOL(*pfunc)(char * , char *));

//functions

BOOL enter_pblock_mount(char *dir);
BOOL get_section(char *sect);
BOOL get_parameter_value(char *param, char *value);
BOOL load_param(void);
BOOL search(struct stat *stat_buf);
BOOL dir_search(char *link, const char *dir);
BOOL enter_pblock_dir(char *dir);



typedef struct block_dir
{
	dev_t st_dev;
	int str_len;	
	char *dir_name;
	struct block_dir *next;
} block_dir;


static char *params[] = {"mount_point","dir_name"};
enum                    { MOUNT_POINT , DIR_NAME };

static struct block_dir *pblock_mountp = NULL;
static struct block_dir *pblock_dir = NULL;



/*
 * Load the conf file into a table
 */

BOOL load_param(void)
{

	if ((pm_process(PARAMCONF,&get_section,&get_parameter_value)) == TRUE)
	{
		return TRUE;
		
	}
	return FALSE;	
}



/*
 * Enter the key and data into the list
 * 
 */

BOOL enter_pblock_mount(char *dir)
{
	struct stat stat_buf;
	static struct block_dir *tmp_pblock;
	

	if((stat(dir,&stat_buf)) != 0)
	{
		return FALSE;
	}
	
	if(pblock_mountp == NULL)
	{
		pblock_mountp = calloc(1, sizeof(block_dir));
		if( pblock_mountp == NULL)
		{
			return FALSE;
		}
		tmp_pblock = pblock_mountp;
		tmp_pblock->next = NULL;
		
	}else
	{
		tmp_pblock->next = calloc(1, sizeof(block_dir));
		if(tmp_pblock->next == NULL)
		{
			return FALSE;
		}
		tmp_pblock = tmp_pblock->next;
		tmp_pblock->next = NULL;
		
	}
	

	tmp_pblock->st_dev = stat_buf.st_dev;
	tmp_pblock->dir_name = strdup(dir);
	

      return TRUE;
		
}


/*
 * Enter the key and data into the list
 * 
 */

BOOL enter_pblock_dir(char *dir)
{
	static struct block_dir *tmp_pblock;
	

	if(pblock_dir == NULL)
	{
		pblock_dir = calloc(1, sizeof(block_dir));
		if( pblock_dir == NULL)
		{
			return FALSE;
		}
		tmp_pblock = pblock_dir;
		tmp_pblock->next = NULL;
		
	}else
	{
		tmp_pblock->next = calloc(1, sizeof(block_dir));
		if(tmp_pblock->next == NULL)
		{
			return FALSE;
		}
		tmp_pblock = tmp_pblock->next;
		tmp_pblock->next = NULL;
		
	}
	

	tmp_pblock->dir_name = strdup(dir);
	tmp_pblock->str_len = strlen(dir);
	

      return TRUE;
		
}




/*
 * Function callback for config section names 
 */

BOOL get_section(char *sect)
{
	return TRUE;	
}



/* 
 * Function callback for config parameter value pairs
 *
 */

BOOL get_parameter_value(char *param, char *value)
{
	int i = 0, maxargs = sizeof(params) / sizeof(char *);

	
	for( i= 0; i < maxargs; i++)
	{
		if (strcmp(param,params[i]) == 0)
		{
			switch(i)
			{
			case MOUNT_POINT :				
				enter_pblock_mount(value);				
				break;
			case DIR_NAME :				
				enter_pblock_dir(value);				
				break;
			default :
				break;
			}
		}
	}
       				
	return TRUE;
	
}




/* VFS initialisation function.  Return initialised vfs_ops structure
   back to SAMBA. */

struct vfs_ops *vfs_init(int *vfs_version, struct vfs_ops *def_vfs_ops)
{
	struct vfs_ops tmp_ops;

	*vfs_version = SMB_VFS_INTERFACE_VERSION;
	
	memcpy(&tmp_ops, def_vfs_ops, sizeof(struct vfs_ops));

	/* Override the ones we want. */
	tmp_ops.connect = block_connect;
	tmp_ops.disconnect = block_disconnect;
	tmp_ops.opendir = block_opendir;

	memcpy(&execute_vfs_ops, &tmp_ops, sizeof(struct vfs_ops));
	return(&execute_vfs_ops);
}


/*
 * VFS connect and param file loading
 */

int block_connect(struct connection_struct *conn, const char *service, const char *user)
{
	if((load_param()) == FALSE)
	{

		return -1;
		
	}	

        DEBUG(0,("%s connecting \n",conn->user));
	
	return (default_vfs_ops.connect(conn, service,user));
}

/*
 * Free allocated structures and disconnect
 *
 */


void block_disconnect(struct connection_struct *conn)
{
	
	struct block_dir *tmp_pblock = (pblock_mountp == NULL ? pblock_dir : pblock_mountp);
	struct block_dir *free_pblock = NULL;

	while(tmp_pblock != NULL)
	{
		free(tmp_pblock->dir_name);		
		free_pblock = tmp_pblock;		
		tmp_pblock = tmp_pblock->next;
		free(free_pblock);	

		if(tmp_pblock == NULL && pblock_dir != NULL)
		{
			tmp_pblock = (pblock_mountp == NULL ? pblock_dir : NULL);
			pblock_dir = NULL;
			
		}
		
	}
		
	

	default_vfs_ops.disconnect(conn);
}

/*
 * VFS opendir
 */

DIR *block_opendir(struct connection_struct *conn, const char *fname)
{

	char *dir_name = NULL; 
	struct stat stat_buf;

	dir_name = alloca((strlen(conn->origpath) + strlen(fname) + 2) * sizeof(char));

	pstrcpy(dir_name,conn->origpath);
	pstrcat(dir_name, "/");	
	strncat(dir_name, fname, strcspn(fname,"/"));

	if((lstat(dir_name,&stat_buf)) == 0)
	{
		if((S_ISLNK(stat_buf.st_mode)) == 1)
		{
			stat(dir_name,&stat_buf);			
			if((search(&stat_buf) || dir_search(dir_name, fname) ) == TRUE)			
			{			
				DEBUG(0,("%s used link to blocked dir: %s \n", conn->user, dir_name));				
				errno = EACCES;				
				return NULL;
			}
		}
	} 
		
	return (default_vfs_ops.opendir(conn, fname));	
}


/*
 * Find mount point to block in list
 */

BOOL search(struct stat *stat_buf)
{
	struct block_dir *tmp_pblock = pblock_mountp;

	while(tmp_pblock != NULL)
	{

		if(tmp_pblock->st_dev == stat_buf->st_dev)
		{
			return TRUE;
		}
		tmp_pblock = tmp_pblock->next;
	}
		
	return FALSE;	
	
}

/*
 * Find dir in list to block id the starting point is link from a share
 */

BOOL dir_search(char *link, const char *dir)
{
	char buf[PATH_MAX +1], *ext_path;
	int len = 0;
	struct block_dir *tmp_pblock = pblock_dir;
	
	if((len = readlink(link,buf,sizeof(buf))) == -1)
	{
		return TRUE;

	}else
	{
		buf[len] = '\0';
	}
	
	
        if((ext_path = strchr(dir,'/')) != NULL)
	{
		pstrcat(buf,&ext_path[1]);
		len = strlen(buf);		
	}
	
	while(tmp_pblock != NULL)
	{
		if(len < tmp_pblock->str_len)
		{
			tmp_pblock = tmp_pblock->next;
			continue;
		}
		
		if((strstr(buf,tmp_pblock->dir_name)) != NULL)
		{
			return TRUE;
		}
		tmp_pblock = tmp_pblock->next;
	}


	return FALSE;
	
}
