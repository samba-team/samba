/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   read/write to a files_struct
   Copyright (C) Andrew Tridgell 1992-1998
   
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


/****************************************************************************
seek a file. Try to avoid the seek if possible
****************************************************************************/

SMB_OFF_T seek_file(files_struct *fsp,SMB_OFF_T pos)
{
  SMB_OFF_T offset = 0;
  SMB_OFF_T seek_ret;

  if (fsp->print_file && lp_postscript(fsp->conn->service))
    offset = 3;

  seek_ret = sys_lseek(fsp->fd_ptr->fd,pos+offset,SEEK_SET);

  /*
   * We want to maintain the fiction that we can seek
   * on a fifo for file system purposes. This allows 
   * people to set up UNIX fifo's that feed data to Windows
   * applications. JRA.
   */

  if((seek_ret == -1) && (errno == ESPIPE)) {
    seek_ret = pos+offset;
    errno = 0;
  }

  if((seek_ret == -1) || (seek_ret != pos+offset)) {
    DEBUG(0,("seek_file: sys_lseek failed. Error was %s\n", strerror(errno) ));
    fsp->pos = -1;
    return -1;
  }

  fsp->pos = seek_ret - offset;

  DEBUG(10,("seek_file: requested pos = %.0f, new pos = %.0f\n",
        (double)(pos+offset), (double)fsp->pos ));

  return(fsp->pos);
}

/****************************************************************************
read from a file
****************************************************************************/

ssize_t read_file(files_struct *fsp,char *data,SMB_OFF_T pos,size_t n)
{
  ssize_t ret=0,readret;

#if USE_READ_PREDICTION
  if (!fsp->can_write) {
    ret = read_predict(fsp->fd_ptr->fd,pos,data,NULL,n);

    data += ret;
    n -= ret;
    pos += ret;
  }
#endif

#if WITH_MMAP
  if (fsp->mmap_ptr) {
	  SMB_OFF_T num = (fsp->mmap_size > pos) ? (fsp->mmap_size - pos) : 0;
	  num = MIN(n,num);
	  if (num > 0) {
		  memcpy(data,fsp->mmap_ptr+pos,num);
		  data += num;
		  pos += num;
		  n -= num;
		  ret += num;
	  }
  }
#endif

  if (seek_file(fsp,pos) == -1) {
    DEBUG(3,("read_file: Failed to seek to %.0f\n",(double)pos));
    return(ret);
  }
  
  if (n > 0) {
    readret = read(fsp->fd_ptr->fd,data,n);
    if (readret > 0) ret += readret;
  }

  return(ret);
}


/****************************************************************************
write to a file
****************************************************************************/

ssize_t write_file(files_struct *fsp, char *data, SMB_OFF_T pos, size_t n)
{

  if (!fsp->can_write) {
    errno = EPERM;
    return(0);
  }

  if (!fsp->modified) {
    SMB_STRUCT_STAT st;
    fsp->modified = True;
    if (sys_fstat(fsp->fd_ptr->fd,&st) == 0) {
      int dosmode = dos_mode(fsp->conn,fsp->fsp_name,&st);
      if (MAP_ARCHIVE(fsp->conn) && !IS_DOS_ARCHIVE(dosmode)) {	
        file_chmod(fsp->conn,fsp->fsp_name,dosmode | aARCH,&st);
      }
    }  
  }

  /*
   * If this file is level II oplocked then we need
   * to grab the shared memory lock and inform all
   * other files with a level II lock that they need
   * to flush their read caches. We keep the lock over
   * the shared memory area whilst doing this.
   */

  if (LEVEL_II_OPLOCK_TYPE(fsp->oplock_type)) {
    SMB_DEV_T dev = fsp->fd_ptr->dev;
    SMB_INO_T inode = fsp->fd_ptr->inode;
    share_mode_entry *share_list = NULL;
    pid_t pid = getpid();
    int token = -1;
    int num_share_modes = 0;
    int i;

    if (lock_share_entry(fsp->conn, dev, inode, &token) == False) {
      DEBUG(0,("write_file: failed to lock share mode entry for file %s.\n", fsp->fsp_name ));
    }

    num_share_modes = get_share_modes(fsp->conn, token, dev, inode, &share_list);

    for(i = 0; i < num_share_modes; i++) {
      share_mode_entry *share_entry = &share_list[i];

      /*
       * As there could have been multiple writes waiting at the lock_share_entry
       * gate we may not be the first to enter. Hence the state of the op_types
       * in the share mode entries may be partly NO_OPLOCK and partly LEVEL_II
       * oplock. It will do no harm to re-send break messages to those smbd's
       * that are still waiting their turn to remove their LEVEL_II state, and
       * also no harm to ignore existing NO_OPLOCK states. JRA.
       */

      if (share_entry->op_type == NO_OPLOCK)
        continue;

      /* Paranoia .... */
      if (EXCLUSIVE_OPLOCK_TYPE(share_entry->op_type)) {
        DEBUG(0,("write_file: PANIC. share mode entry %d is an exlusive oplock !\n", i ));
        abort();
      }

      /*
       * Check if this is a file we have open (including the
       * file we've been called to do write_file on. If so
       * then break it directly without releasing the lock.
       */

      if (pid == share_entry->pid) {
        files_struct *new_fsp = file_find_dit(dev, inode, &share_entry->time);

        /* Paranoia check... */
        if(new_fsp == NULL) {
          DEBUG(0,("write_file: PANIC. share mode entry %d is not a local file !\n", i ));
          abort();
        }
        oplock_break_level2(new_fsp, True, token);

      } else {

        /*
         * This is a remote file and so we send an asynchronous
         * message.
         */

        request_oplock_break(share_entry, dev, inode);
      }
    }
 
    free((char *)share_list);
    unlock_share_entry(fsp->conn, dev, inode, token);
  }

  /* Paranoia check... */
  if (LEVEL_II_OPLOCK_TYPE(fsp->oplock_type)) {
    DEBUG(0,("write_file: PANIC. File %s still has a level II oplock.\n", fsp->fsp_name));
    abort();
  }

  if ((pos != -1) && (seek_file(fsp,pos) == -1))
    return -1;

  return(write_data(fsp->fd_ptr->fd,data,n));
}


/*******************************************************************
sync a file
********************************************************************/

void sync_file(connection_struct *conn, files_struct *fsp)
{
#ifdef HAVE_FSYNC
    if(lp_strict_sync(SNUM(conn)) && fsp->fd_ptr != NULL)
      fsync(fsp->fd_ptr->fd);
#endif
}
