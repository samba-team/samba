/* 
 * 
 * Block access from links to dev mount points specified in PARAMCONF file
 *
 * Copyright (C) Ronald Kuetemeier, 2001
 * Copyright (C) Alexander Bokovoy, 2002
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



static DIR *block_opendir(connection_struct *conn, char *fname);
static int block_connect(connection_struct *conn, const char *service, const char *user);    
static void block_disconnect(connection_struct *conn);    

static struct smb_vfs_handle_struct *block_handle;

/* VFS operations */


static struct vfs_ops default_vfs_ops;   /* For passthrough operation */

static vfs_op_tuple block_vfs_ops[] = {
    
	/* Disk operations */

	{block_connect,		SMB_VFS_OP_CONNECT,	SMB_VFS_LAYER_TRANSPARENT},
	{block_disconnect,	SMB_VFS_OP_DISCONNECT,	SMB_VFS_LAYER_TRANSPARENT},

	/* Directory operations */

	{block_opendir,		SMB_VFS_OP_OPENDIR,	SMB_VFS_LAYER_TRANSPARENT},
	
	{NULL,			SMB_VFS_OP_NOOP,	SMB_VFS_LAYER_NOOP}
};


#ifndef PARAMCONF
#define PARAMCONF "/etc/samba-block.conf"
#endif

extern BOOL pm_process(char *FileName, BOOL (*sfunc)(char *), BOOL(*pfunc)(char * , char *));

//functions

static BOOL enter_pblock_mount(char *dir);
static BOOL get_section(char *sect);
static BOOL get_parameter_value(char *param, char *value);
static BOOL load_param(void);
static BOOL search(struct stat *stat_buf);
static BOOL dir_search(char *link, char *dir);
static BOOL enter_pblock_dir(char *dir);



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

static BOOL load_param(void)
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

static BOOL enter_pblock_mount(char *dir)
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

static BOOL enter_pblock_dir(char *dir)
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

static BOOL get_section(char *sect)
{
	return TRUE;	
}



/* 
 * Function callback for config parameter value pairs
 *
 */

static BOOL get_parameter_value(char *param, char *value)
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




/* VFS initialisation function.  Return initialised vfs_op_tuple array
   back to SAMBA. */

vfs_op_tuple *vfs_init(int *vfs_version, struct vfs_ops *def_vfs_ops,
			struct smb_vfs_handle_struct *vfs_handle)
{
	*vfs_version = SMB_VFS_INTERFACE_VERSION;
	
	memcpy(&default_vfs_ops, def_vfs_ops, sizeof(struct vfs_ops));
	
	block_handle = vfs_handle;

	return block_vfs_ops;
}


/* VFS finalization function. */
void vfs_done(connection_struct *conn)
{
}


/*
 * VFS connect and param file loading
 */

static int block_connect(connection_struct *conn, const char *service, const char *user)
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


static void block_disconnect(struct connection_struct *conn)
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

static DIR *block_opendir(struct connection_struct *conn, char *fname)
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

static BOOL search(struct stat *stat_buf)
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

static BOOL dir_search(char *link, char *dir)
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
