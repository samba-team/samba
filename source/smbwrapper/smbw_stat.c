/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   SMB wrapper stat functions
   Copyright (C) Andrew Tridgell 1998
   
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
#include "wrapper.h"

extern int DEBUGLEVEL;

extern int smbw_busy;


/***************************************************** 
setup basic info in a stat structure
*******************************************************/
void smbw_setup_stat(struct stat *st, char *fname, size_t size, int mode)
{
	ZERO_STRUCTP(st);

	if (IS_DOS_DIR(mode)) {
		st->st_mode = SMBW_DIR_MODE;
	} else {
		st->st_mode = SMBW_FILE_MODE;
	}

	st->st_size = size;
	st->st_blksize = 512;
	st->st_blocks = (size+511)/512;
	st->st_uid = getuid();
	st->st_gid = getgid();
	st->st_ino = smbw_inode(fname);
}


/***************************************************** 
try to do a QPATHINFO and if that fails then do a getatr
this is needed because win95 sometimes refuses the qpathinfo
*******************************************************/
BOOL smbw_getatr(struct smbw_server *srv, char *path, 
		 uint32 *mode, size_t *size, 
		 time_t *c_time, time_t *a_time, time_t *m_time)
{
	DEBUG(5,("sending qpathinfo\n"));

	if (cli_qpathinfo(&srv->cli, path, c_time, a_time, m_time,
			  size, mode)) return True;

	DEBUG(5,("qpathinfo OK\n"));

	/* if this is NT then don't bother with the getatr */
	if (srv->cli.capabilities & CAP_NT_SMBS) return False;

	if (cli_getatr(&srv->cli, path, mode, size, m_time)) {
		a_time = c_time = m_time;
		return True;
	}
	return False;
}


static struct print_job_info printjob;

/***************************************************** 
gather info from a printjob listing
*******************************************************/
static void smbw_printjob_stat(struct print_job_info *job)
{
	if (strcmp(job->name, printjob.name) == 0) {
		printjob = *job;
	}
}

/***************************************************** 
stat a printjob
*******************************************************/
int smbw_stat_printjob(struct smbw_server *srv,char *path,
		       size_t *size, time_t *m_time)
{
	if (path[0] == '\\') path++;

	ZERO_STRUCT(printjob);

	fstrcpy(printjob.name, path);
	cli_print_queue(&srv->cli, smbw_printjob_stat);

	if (size) {
		*size = printjob.size;
	}
	if (m_time) {
		*m_time = printjob.t;
	}
	return printjob.id;
}


/***************************************************** 
a wrapper for fstat()
*******************************************************/
int smbw_fstat(int fd, struct stat *st)
{
	struct smbw_file *file;
	time_t c_time, a_time, m_time;
	uint32 size;
	uint32 mode;

	smbw_busy++;

	file = smbw_file(fd);
	if (!file) {
		int ret = smbw_dir_fstat(fd, st);
		smbw_busy--;
		return ret;
	}

	if (!cli_qfileinfo(&file->srv->cli, file->f->cli_fd, 
			  &mode, &size, &c_time, &a_time, &m_time) &&
	    !cli_getattrE(&file->srv->cli, file->f->cli_fd, 
			  &mode, &size, &c_time, &a_time, &m_time)) {
		errno = EINVAL;
		smbw_busy--;
		return -1;
	}

	smbw_setup_stat(st, file->f->fname, size, mode);

	st->st_atime = a_time;
	st->st_ctime = c_time;
	st->st_mtime = m_time;
	st->st_dev = file->srv->dev;

	smbw_busy--;
	return 0;
}


/***************************************************** 
a wrapper for stat()
*******************************************************/
int smbw_stat(const char *fname, struct stat *st)
{
	struct smbw_server *srv;
	fstring server, share;
	pstring path;
	time_t m_time=0, a_time=0, c_time=0;
	size_t size=0;
	uint32 mode=0;

	if (!fname) {
		errno = EINVAL;
		return -1;
	}

	smbw_init();

	smbw_busy++;

	/* work out what server they are after */
	smbw_parse_path(fname, server, share, path);

	/* get a connection to the server */
	srv = smbw_server(server, share);
	if (!srv) {
		/* smbw_server sets errno */
		goto failed;
	}

	if (strncmp(srv->cli.dev,"IPC",3) == 0) {
		mode = aDIR | aRONLY;
	} else if (strncmp(srv->cli.dev,"LPT",3) == 0) {
		if (strcmp(path,"\\") == 0) {
			mode = aDIR | aRONLY;
		} else {
			mode = aRONLY;
			smbw_stat_printjob(srv, path, &size, &m_time);
			c_time = a_time = m_time;
		}
	} else {
		if (!smbw_getatr(srv, path, 
				 &mode, &size, &c_time, &a_time, &m_time)) {
			errno = smbw_errno(&srv->cli);
			goto failed;
		}
	}

	smbw_setup_stat(st, path, size, mode);

	st->st_atime = a_time;
	st->st_ctime = c_time;
	st->st_mtime = m_time;
	st->st_dev = srv->dev;

	smbw_busy--;
	return 0;

 failed:
	smbw_busy--;
	return -1;
}


