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
int seek_file(files_struct *fsp,uint32 pos)
{
  uint32 offset = 0;

  if (fsp->print_file && lp_postscript(fsp->conn->service))
    offset = 3;

  fsp->pos = (int)(lseek(fsp->fd_ptr->fd,pos+offset,SEEK_SET) - offset);
  return(fsp->pos);
}

/****************************************************************************
read from a file
****************************************************************************/
int read_file(files_struct *fsp,char *data,uint32 pos,int n)
{
  int ret=0,readret;

#if USE_READ_PREDICTION
  if (!fsp->can_write)
    {
      ret = read_predict(fsp->fd_ptr->fd,pos,data,NULL,n);

      data += ret;
      n -= ret;
      pos += ret;
    }
#endif

#if WITH_MMAP
  if (fsp->mmap_ptr)
    {
      int num = (fsp->mmap_size > pos) ? (fsp->mmap_size - pos) : -1;
      num = MIN(n,num);
      if (num > 0)
	{
	  memcpy(data,fsp->mmap_ptr+pos,num);
	  data += num;
	  pos += num;
	  n -= num;
	  ret += num;
	}
    }
#endif

  if (n <= 0)
    return(ret);

  if (seek_file(fsp,pos) != pos)
    {
      DEBUG(3,("Failed to seek to %d\n",pos));
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
int write_file(files_struct *fsp,char *data,int n)
{

  if (!fsp->can_write) {
    errno = EPERM;
    return(0);
  }

  if (!fsp->modified) {
    SMB_STRUCT_STAT st;
    fsp->modified = True;
    if (fstat(fsp->fd_ptr->fd,&st) == 0) {
      int dosmode = dos_mode(fsp->conn,fsp->fsp_name,&st);
      if (MAP_ARCHIVE(fsp->conn) && !IS_DOS_ARCHIVE(dosmode)) {	
        file_chmod(fsp->conn,fsp->fsp_name,dosmode | aARCH,&st);
      }
    }  
  }

  return(write_data(fsp->fd_ptr->fd,data,n));
}


/*******************************************************************
sync a file
********************************************************************/
void sync_file(connection_struct *conn, files_struct *fsp)
{
#ifdef HAVE_FSYNC
    if(lp_strict_sync(SNUM(conn)))
      fsync(fsp->fd_ptr->fd);
#endif
}

