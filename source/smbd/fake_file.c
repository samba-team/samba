/* 
   Unix SMB/CIFS implementation.
   FAKE FILE suppport, for faking up special files windows want access to
   Copyright (C) Stefan (metze) Metzmacher	2003
   
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

/****************************************************************************
 Open a file with a share mode.
****************************************************************************/
files_struct *open_fake_file_shared1(enum FAKE_FILE_TYPE fake_file_type, connection_struct *conn,char *fname,
				SMB_STRUCT_STAT *psbuf, 
				uint32 desired_access, 
				int share_mode,int ofun, uint32 new_dos_attr, int oplock_request, 
				int *Access,int *action)
{
	extern struct current_user current_user;
	int flags=0;
	files_struct *fsp = NULL;

	if (fake_file_type == 0) {
		return open_file_shared1(conn,fname,psbuf,desired_access,
					share_mode,ofun,new_dos_attr,
					oplock_request,Access,action);	
	}

	/* access check */
	if (conn->admin_user != True) {
		DEBUG(1,("access_denied to service[%s] file[%s] user[%s]\n",
			lp_servicename(SNUM(conn)),fname,conn->user));
		errno = EACCES;
		return NULL;
	}

	fsp = file_new(conn);
	if(!fsp)
		return NULL;

	DEBUG(5,("open_fake_file_shared1: fname = %s, FID = %d, share_mode = %x, ofun = %x, oplock request = %d\n",
		fname, fsp->fnum, share_mode, ofun, oplock_request ));

	if (!check_name(fname,conn)) {
		file_free(fsp);
		return NULL;
	} 

	fsp->fd = -1;
	fsp->mode = psbuf->st_mode;
	fsp->inode = psbuf->st_ino;
	fsp->dev = psbuf->st_dev;
	fsp->vuid = current_user.vuid;
	fsp->size = psbuf->st_size;
	fsp->pos = -1;
	fsp->can_lock = True;
	fsp->can_read = ((flags & O_WRONLY)==0);
	fsp->can_write = ((flags & (O_WRONLY|O_RDWR))!=0);
	fsp->share_mode = 0;
	fsp->desired_access = desired_access;
	fsp->print_file = False;
	fsp->modified = False;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->is_directory = False;
	fsp->is_stat = False;
	fsp->directory_delete_on_close = False;
	fsp->conn = conn;
	string_set(&fsp->fsp_name,fname);
	fsp->wcp = NULL; /* Write cache pointer. */
	
	fsp->fake_file_handle = init_fake_file_handle(fake_file_type);
	
	if (fsp->fake_file_handle==NULL) {
		file_free(fsp);
		return NULL;
	}

	conn->num_files_open++;
	return fsp;
}

static FAKE_FILE fake_files[] = {
#ifdef WITH_QUOTAS
	{FAKE_FILE_NAME_QUOTA,	FAKE_FILE_TYPE_QUOTA,	init_quota_handle,	destroy_quota_handle},
#endif /* WITH_QUOTAS */
	{NULL,			FAKE_FILE_TYPE_NONE,	NULL,			NULL }
};

int is_fake_file(char *fname)
{
	int i;

	if (!fname)
		return 0;

	for (i=0;fake_files[i].name!=NULL;i++) {
		if (strncmp(fname,fake_files[i].name,strlen(fake_files[i].name))==0) {
			DEBUG(5,("is_fake_file: [%s] is a fake file\n",fname));
			return fake_files[i].type;
		}
	}

	return FAKE_FILE_TYPE_NONE;
}

struct _FAKE_FILE_HANDLE *init_fake_file_handle(enum FAKE_FILE_TYPE type)
{
	TALLOC_CTX *mem_ctx = NULL;
	FAKE_FILE_HANDLE *fh = NULL;
	int i;

	for (i=0;fake_files[i].name!=NULL;i++) {
		if (fake_files[i].type==type) {
			DEBUG(5,("init_fake_file_handle: for [%s]\n",fake_files[i].name));

			if ((mem_ctx=talloc_init("fake_file_handle"))==NULL) {
				DEBUG(0,("talloc_init(fake_file_handle) failed.\n"));
				return NULL;	
			}

			if ((fh =(FAKE_FILE_HANDLE *)talloc_zero(mem_ctx, sizeof(FAKE_FILE_HANDLE)))==NULL) {
				DEBUG(0,("talloc_zero() failed.\n"));
				talloc_destroy(mem_ctx);
				return NULL;
			}

			fh->type = type;
			fh->mem_ctx = mem_ctx;

			if (fake_files[i].init_pd)
				fh->pd = fake_files[i].init_pd(fh->mem_ctx);

			fh->free_pd = fake_files[i].free_pd;

			return fh;
		}
	}

	return NULL;	
}

void destroy_fake_file_handle(FAKE_FILE_HANDLE **fh)
{
	if (!fh||!(*fh))
		return ;

	if ((*fh)->free_pd)
		(*fh)->free_pd(&(*fh)->pd);		

	talloc_destroy((*fh)->mem_ctx);
	(*fh) = NULL;
}
