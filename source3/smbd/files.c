/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Files[] structure handling
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

extern int DEBUGLEVEL;

#define MAX_OPEN_FILES 100

#define MAX_FNUMS (MAX_OPEN_FILES+MAX_OPEN_DIRECTORIES)
#define VALID_FNUM(fnum)   (((fnum) >= 0) && ((fnum) < MAX_FNUMS))

static files_struct Files[MAX_FNUMS];

/*
 * Indirection for file fd's. Needed as POSIX locking
 * is based on file/process, not fd/process.
 */
static file_fd_struct FileFd[MAX_OPEN_FILES];
static int max_file_fd_used = 0;


/****************************************************************************
  find first available file slot
****************************************************************************/
files_struct *file_new(void )
{
	int i;
	static int first_file;

	/* we want to give out file handles differently on each new
	   connection because of a common bug in MS clients where they try to
	   reuse a file descriptor from an earlier smb connection. This code
	   increases the chance that the errant client will get an error rather
	   than causing corruption */
	if (first_file == 0) {
		first_file = (getpid() ^ (int)time(NULL)) % MAX_FNUMS;
		if (first_file == 0) first_file = 1;
	}

	if (first_file >= MAX_FNUMS)
		first_file = 1;

	for (i=first_file;i<MAX_FNUMS;i++)
		if (!Files[i].open && !Files[i].reserved) {
			memset(&Files[i], 0, sizeof(Files[i]));
			first_file = i+1;
			Files[i].reserved = True;
			Files[i].fnum = i;
			return &Files[i];
		}

	/* returning a file handle of 0 is a bad idea - so we start at 1 */
	for (i=1;i<first_file;i++)
		if (!Files[i].open && !Files[i].reserved) {
			memset(&Files[i], 0, sizeof(Files[i]));
			first_file = i+1;
			Files[i].reserved = True;
			Files[i].fnum = i;
			return &Files[i];
		}

        /* 
         * Before we give up, go through the open files 
         * and see if there are any files opened with a
         * batch oplock. If so break the oplock and then
         * re-use that entry (if it becomes closed).
         * This may help as NT/95 clients tend to keep
         * files batch oplocked for quite a long time
         * after they have finished with them.
         */
        for (i=first_file;i<MAX_FNUMS;i++) {
          if(attempt_close_oplocked_file( &Files[i])) {
            memset(&Files[i], 0, sizeof(Files[i]));
            first_file = i+1;
            Files[i].reserved = True;
	    Files[i].fnum = i;
	    return &Files[i];
          }
        }

        for (i=1;i<MAX_FNUMS;i++) {
          if(attempt_close_oplocked_file( &Files[i])) {
            memset(&Files[i], 0, sizeof(Files[i]));
            first_file = i+1;
            Files[i].reserved = True;
	    Files[i].fnum = i;
	    return &Files[i];
          }
        }

	DEBUG(1,("ERROR! Out of file structures - perhaps increase MAX_OPEN_FILES?\n"));
	return NULL;
}



/****************************************************************************
fd support routines - attempt to find an already open file by dev
and inode - increments the ref_count of the returned file_fd_struct *.
****************************************************************************/
file_fd_struct *fd_get_already_open(struct stat *sbuf)
{
  int i;
  file_fd_struct *fd_ptr;

  if(sbuf == 0)
    return 0;

  for(i = 0; i <= max_file_fd_used; i++) {
    fd_ptr = &FileFd[i];
    if((fd_ptr->ref_count > 0) &&
       (((uint32)sbuf->st_dev) == fd_ptr->dev) &&
       (((uint32)sbuf->st_ino) == fd_ptr->inode)) {
      fd_ptr->ref_count++;
      DEBUG(3,
       ("Re-used file_fd_struct %d, dev = %x, inode = %x, ref_count = %d\n",
        i, fd_ptr->dev, fd_ptr->inode, fd_ptr->ref_count));
      return fd_ptr;
    }
  }
  return 0;
}

/****************************************************************************
fd support routines - attempt to find a empty slot in the FileFd array.
Increments the ref_count of the returned entry.
****************************************************************************/
file_fd_struct *fd_get_new(void)
{
  extern struct current_user current_user;
  int i;
  file_fd_struct *fd_ptr;

  for(i = 0; i < MAX_OPEN_FILES; i++) {
    fd_ptr = &FileFd[i];
    if(fd_ptr->ref_count == 0) {
      fd_ptr->dev = (uint32)-1;
      fd_ptr->inode = (uint32)-1;
      fd_ptr->fd = -1;
      fd_ptr->fd_readonly = -1;
      fd_ptr->fd_writeonly = -1;
      fd_ptr->real_open_flags = -1;
      fd_ptr->uid_cache_count = 0;
      fd_add_to_uid_cache(fd_ptr, (uid_t)current_user.uid);
      fd_ptr->ref_count++;
      /* Increment max used counter if neccessary, cuts down
         on search time when re-using */
      if(i > max_file_fd_used)
        max_file_fd_used = i;
      DEBUG(3,("Allocated new file_fd_struct %d, dev = %x, inode = %x\n",
               i, fd_ptr->dev, fd_ptr->inode));
      return fd_ptr;
    }
  }
  DEBUG(1,("ERROR! Out of file_fd structures - perhaps increase MAX_OPEN_FILES?\n"));
  return 0;
}


/****************************************************************************
close all open files for a connection
****************************************************************************/
void file_close_conn(connection_struct *conn)
{
  int i;
  for (i=0;i<MAX_FNUMS;i++)
    if (Files[i].conn == conn && Files[i].open) {
      if(Files[i].is_directory)
        close_directory(&Files[i]); 
      else                  
        close_file(&Files[i],False); 
    }
}

/****************************************************************************
initialise file structures
****************************************************************************/
void file_init(void)
{
	int i;

#ifdef HAVE_GETRLIMIT
#ifdef RLIMIT_NOFILE
	{
		struct rlimit rlp;
		getrlimit(RLIMIT_NOFILE, &rlp);
		/* Set the fd limit to be MAX_OPEN_FILES + 10 to
		 * account for the extra fd we need to read
		 * directories, as well as the log files and standard
		 * handles etc.  */
		rlp.rlim_cur = (MAX_FNUMS+10>rlp.rlim_max)? 
			rlp.rlim_max:MAX_FNUMS+10;
		setrlimit(RLIMIT_NOFILE, &rlp);
		getrlimit(RLIMIT_NOFILE, &rlp);
		DEBUG(3,("Maximum number of open files per session is %d\n",
			 (int)rlp.rlim_cur));
	}
#endif
#endif

  

	for (i=0;i<MAX_FNUMS;i++) {
		Files[i].open = False;
		string_init(&Files[i].fsp_name,"");
	}

	for (i=0;i<MAX_OPEN_FILES;i++) {
		file_fd_struct *fd_ptr = &FileFd[i];
		fd_ptr->ref_count = 0;
		fd_ptr->dev = (int32)-1;
		fd_ptr->inode = (int32)-1;
		fd_ptr->fd = -1;
		fd_ptr->fd_readonly = -1;
		fd_ptr->fd_writeonly = -1;
		fd_ptr->real_open_flags = -1;
	}
}

/****************************************************************************
find a fsp given a fnum
****************************************************************************/
files_struct *file_fsp(int fnum)
{
	if (!VALID_FNUM(fnum)) return NULL;
	return &Files[fnum];
}


/****************************************************************************
close files open by a specified vuid
****************************************************************************/
void file_close_user(int vuid)
{
	int i;
	for (i=0;i<MAX_FNUMS;i++) {
		files_struct *fsp = &Files[i];
		if ((fsp->vuid == vuid) && fsp->open) {
			if(!fsp->is_directory)
				close_file(fsp,False);
			else
				close_directory(fsp);
		}
	}
}


/****************************************************************************
find a fsp given a device, inode and timevalue
****************************************************************************/
files_struct *file_find_dit(int dev, int inode, struct timeval *tval)
{
	int i;
	for (i=0;i<MAX_FNUMS;i++) {
		files_struct *fsp = &Files[i];
		if (fsp->open && 
		    fsp->fd_ptr->dev == dev && 
		    fsp->fd_ptr->inode == inode &&
		    fsp->open_time.tv_sec == tval->tv_sec &&
		    fsp->open_time.tv_usec == tval->tv_usec) {
			return fsp;
		}
	} 
	return NULL;
}

/****************************************************************************
find a fsp that is open for printing
****************************************************************************/
files_struct *file_find_print(void)
{
	int i;

	for (i=0;i<MAX_FNUMS;i++) {
		files_struct *fsp = &Files[i];
		if (fsp->open && fsp->print_file) {
			return fsp;
		}
	} 
	return NULL;
}


/****************************************************************************
sync open files on a connection
****************************************************************************/
void file_sync_all(connection_struct *conn)
{
	int i;
	for (i=0;i<MAX_FNUMS;i++) {
		files_struct *fsp = &Files[i];
		if (fsp->open && conn == fsp->conn) {
			sync_file(conn,fsp);
		}
	}
}


void file_free(files_struct *fsp)
{
	memset(fsp, 0, sizeof(*fsp));
}
