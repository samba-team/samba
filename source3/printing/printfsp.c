/* 
   Unix SMB/CIFS implementation.
   printing backend routines for smbd - using files_struct rather
   than only snum
   Copyright (C) Andrew Tridgell 1992-2000
   
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
*/

#include "includes.h"

/***************************************************************************
open a print file and setup a fsp for it. This is a wrapper around
print_job_start().
***************************************************************************/

NTSTATUS print_fsp_open(struct smb_request *req, connection_struct *conn,
			const char *fname,
			uint16_t current_vuid, files_struct *fsp)
{
	const char *svcname = lp_const_servicename(SNUM(conn));
	uint32_t jobid;
	fstring name;
	NTSTATUS status;
	WERROR werr;

	fstrcpy( name, "Remote Downlevel Document");
	if (fname) {
		const char *p = strrchr(fname, '/');
		fstrcat(name, " ");
		if (!p) {
			p = fname;
		}
		fstrcat(name, p);
	}

	werr = print_job_start(conn->server_info, SNUM(conn),
				 name, fname, NULL, &jobid);
	if (!W_ERROR_IS_OK(werr)) {
		return werror_to_ntstatus(werr);
	}

	fsp->print_file = talloc(fsp, struct print_file_data);
	if (!fsp->print_file) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Convert to RAP id. */
	fsp->print_file->rap_jobid = pjobid_to_rap(svcname, jobid);
	if (fsp->print_file->rap_jobid == 0) {
		/* We need to delete the entry in the tdb. */
		pjob_delete(svcname, jobid);
		return NT_STATUS_ACCESS_DENIED;	/* No errno around here */
	}

	status = create_synthetic_smb_fname(fsp,
	    print_job_fname(svcname, jobid), NULL,
	    NULL, &fsp->fsp_name);
	if (!NT_STATUS_IS_OK(status)) {
		pjob_delete(svcname, jobid);
		return status;
	}
	/* setup a full fsp */
	fsp->fh->fd = print_job_fd(svcname, jobid);
	GetTimeOfDay(&fsp->open_time);
	fsp->vuid = current_vuid;
	fsp->fh->pos = -1;
	fsp->can_lock = False;
	fsp->can_read = False;
	fsp->access_mask = FILE_GENERIC_WRITE;
	fsp->can_write = True;
	fsp->modified = False;
	fsp->oplock_type = NO_OPLOCK;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->is_directory = False;
	fsp->wcp = NULL;
	SMB_VFS_FSTAT(fsp, &fsp->fsp_name->st);
	fsp->mode = fsp->fsp_name->st.st_ex_mode;
	fsp->file_id = vfs_file_id_from_sbuf(conn, &fsp->fsp_name->st);

	return NT_STATUS_OK;
}

/****************************************************************************
 Print a file - called on closing the file.
****************************************************************************/

void print_fsp_end(files_struct *fsp, enum file_close_type close_type)
{
	uint32 jobid;

	if (fsp->fh->private_options & NTCREATEX_OPTIONS_PRIVATE_DELETE_ON_CLOSE) {
		/*
		 * Truncate the job. print_job_end will take
		 * care of deleting it for us. JRA.
		 */
		sys_ftruncate(fsp->fh->fd, 0);
	}

	if (fsp->fsp_name) {
		TALLOC_FREE(fsp->fsp_name);
	}

	if (!rap_to_pjobid(fsp->print_file->rap_jobid, NULL, &jobid)) {
		DEBUG(3,("print_fsp_end: Unable to convert RAP jobid %u to print jobid.\n",
			(unsigned int)fsp->print_file->rap_jobid ));
		return;
	}

	print_job_end(SNUM(fsp->conn),jobid, close_type);
}

/****************************************************************************
 Discovered by Sebastian Kloska <oncaphillis@snafu.de>. When print files
 go beyond 4GB, the 32-bit offset sent in old SMBwrite calls is relative
 to the current 4GB chunk we're writing to.
****************************************************************************/

SMB_OFF_T printfile_offset(files_struct *fsp, SMB_OFF_T offset)
{
	SMB_STRUCT_STAT st;

	if (offset & 0xffffffff00000000LL) {
		/* offset is > 4G, skip */
		return offset;
	}

	if (sys_fstat(fsp->fh->fd, &st, false) == -1) {
		DEBUG(3,("printfile_offset: sys_fstat failed on %s (%s)\n",
			fsp_str_dbg(fsp),
			strerror(errno) ));
		return offset;
	}

	return (st.st_ex_size & 0xffffffff00000000LL) + offset;
}
