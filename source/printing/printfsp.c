/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   printing backend routines for smbd - using files_struct rather
   than only snum
   Copyright (C) Andrew Tridgell 1992-2000
   
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

/***************************************************************************
open a print file and setup a fsp for it. This is a wrapper around
print_job_start().
***************************************************************************/

files_struct *print_fsp_open(connection_struct *conn, char *fname)
{
	int jobid;
	SMB_STRUCT_STAT sbuf;
	extern struct current_user current_user;
	files_struct *fsp = file_new(conn);
	fstring name;

	if(!fsp)
		return NULL;

	fstrcpy( name, "Remote Downlevel Document");
	if (fname) {
		char *p = strrchr(fname, '/');
		fstrcat(name, " ");
		if (!p)
			p = fname;
		fstrcat(name, p);
	}

	jobid = print_job_start(&current_user, SNUM(conn), name);
	if (jobid == -1) {
		file_free(fsp);
		return NULL;
	}

	/* setup a full fsp */
	fsp->print_jobid = jobid;
	fsp->fd = print_job_fd(jobid);
	GetTimeOfDay(&fsp->open_time);
	fsp->vuid = current_user.vuid;
	fsp->size = 0;
	fsp->pos = -1;
	fsp->can_lock = True;
	fsp->can_read = False;
	fsp->can_write = True;
	fsp->share_mode = 0;
	fsp->print_file = True;
	fsp->modified = False;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->is_directory = False;
	fsp->directory_delete_on_close = False;
	fsp->conn = conn;
	string_set(&fsp->fsp_name,print_job_fname(jobid));
	fsp->wbmpx_ptr = NULL;      
	fsp->wcp = NULL; 
	conn->vfs_ops.fstat(fsp,fsp->fd, &sbuf);
	fsp->mode = sbuf.st_mode;
	fsp->inode = sbuf.st_ino;
	fsp->dev = sbuf.st_dev;

	conn->num_files_open++;

	return fsp;
}

/****************************************************************************
print a file - called on closing the file
****************************************************************************/
void print_fsp_end(files_struct *fsp, BOOL normal_close)
{
	if (fsp->share_mode == FILE_DELETE_ON_CLOSE) {
		/*
		 * Truncate the job. print_job_end will take
		 * care of deleting it for us. JRA.
		 */
		sys_ftruncate(fsp->fd, 0);
	}

	print_job_end(fsp->print_jobid, normal_close);

	if (fsp->fsp_name) {
		string_free(&fsp->fsp_name);
	}
}
