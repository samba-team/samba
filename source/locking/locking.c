/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Locking functions
   Copyright (C) Andrew Tridgell 1992-1995
   
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
#include "loadparm.h"
extern int DEBUGLEVEL;
extern connection_struct Connections[];
extern files_struct Files[];

pstring share_del_pending="";


/****************************************************************************
  utility function called to see if a file region is locked
****************************************************************************/
BOOL is_locked(int fnum,int cnum,uint32 count,uint32 offset)
{
  int snum = SNUM(cnum);

  if (count == 0)
    return(False);

  if (!lp_locking(snum) || !lp_strict_locking(snum))
    return(False);

  return(fcntl_lock(Files[fnum].fd,F_GETLK,offset,count,
		    (Files[fnum].can_write?F_WRLCK:F_RDLCK)));
}


/****************************************************************************
  utility function called by locking requests
****************************************************************************/
BOOL do_lock(int fnum,int cnum,uint32 count,uint32 offset,int *eclass,uint32 *ecode)
{
  BOOL ok = False;

  if (!lp_locking(SNUM(cnum)))
    return(True);

  if (count == 0) {
    *eclass = ERRDOS;
    *ecode = ERRnoaccess;
    return False;
  }

  if (Files[fnum].can_lock && OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
    ok = fcntl_lock(Files[fnum].fd,F_SETLK,offset,count,
		    (Files[fnum].can_write?F_WRLCK:F_RDLCK));

  if (!ok) {
    *eclass = ERRDOS;
    *ecode = ERRlock;
    return False;
  }
  return True; /* Got lock */
}


/****************************************************************************
  utility function called by unlocking requests
****************************************************************************/
BOOL do_unlock(int fnum,int cnum,uint32 count,uint32 offset,int *eclass,uint32 *ecode)
{
  BOOL ok = False;

  if (!lp_locking(SNUM(cnum)))
    return(True);

  if (Files[fnum].can_lock && OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
    ok = fcntl_lock(Files[fnum].fd,F_SETLK,offset,count,F_UNLCK);
   
  if (!ok) {
    *eclass = ERRDOS;
    *ecode = ERRlock;
    return False;
  }
  return True; /* Did unlock */
}

/*******************************************************************
  name a share file
  ******************************************************************/
static BOOL share_name(int cnum,struct stat *st,char *name)
{
  strcpy(name,lp_lockdir());
  standard_sub(cnum,name);
  trim_string(name,"","/");
  if (!*name) return(False);
  name += strlen(name);
  
  sprintf(name,"/share.%d.%d",(int)st->st_dev,(int)st->st_ino);
  return(True);
}

/*******************************************************************
  use the fnum to get the share file name
  ******************************************************************/
static BOOL share_name_fnum(int fnum,char *name)
{
  struct stat st;
  if (fstat(Files[fnum].fd,&st) != 0) return(False);
  return(share_name(Files[fnum].cnum,&st,name));
}


/*******************************************************************
  get the share mode of a file using the fnum
  ******************************************************************/
int get_share_mode_by_fnum(int cnum,int fnum,int *pid)
{
  struct stat sbuf;
  if (fstat(Files[fnum].fd,&sbuf) == -1) return(0);
  return(get_share_mode(cnum,&sbuf,pid));
}

/*******************************************************************
  get the share mode of a file using the files name
  ******************************************************************/
int get_share_mode_byname(int cnum,char *fname,int *pid)
{
  struct stat sbuf;
  if (stat(fname,&sbuf) == -1) return(0);
  return(get_share_mode(cnum,&sbuf,pid));
}  


/*******************************************************************
get the share mode of a file
********************************************************************/
int get_share_mode(int cnum,struct stat *sbuf,int *pid)
{
  pstring fname;
  int fd2;
  char buf[16];
  int ret;
  time_t t;

  *pid = 0;

  if (!share_name(cnum,sbuf,fname)) return(0);

  fd2 = open(fname,O_RDONLY,0);
  if (fd2 < 0) return(0);

  if (read(fd2,buf,16) != 16) {
    close(fd2);
    unlink(fname);
    return(0);
  }
  close(fd2);

  t = IVAL(buf,0);
  ret = IVAL(buf,4);
  *pid = IVAL(buf,8);
  
  if (IVAL(buf,12) != LOCKING_VERSION) {    
    if (!unlink(fname)) DEBUG(2,("Deleted old locking file %s",fname));
    *pid = 0;
    return(0);
  }

  if (*pid && !process_exists(*pid)) {
    ret=0;
    *pid = 0;
  }

  if (! *pid) unlink(fname); /* XXXXX race, race */

  if (*pid)
    DEBUG(5,("Read share file %s mode 0x%X pid=%d\n",fname,ret,*pid));

  return(ret);
}


/*******************************************************************
del the share mode of a file, if we set it last
********************************************************************/
void del_share_mode(int fnum)
{
  pstring fname;
  int fd2;
  char buf[16];
  time_t t=0;
  int pid=0;
  BOOL del = False;

  if (!share_name_fnum(fnum,fname)) return;

  fd2 = open(fname,O_RDONLY,0);
  if (fd2 < 0) return;
  if (read(fd2,buf,16) != 16)
    del = True;
  close(fd2);

  if (!del) {
    t = IVAL(buf,0);
    pid = IVAL(buf,8);
  }

  if (!del)
    if (IVAL(buf,12) != LOCKING_VERSION || !pid || !process_exists(pid))
      del = True;

  if (!del && t == Files[fnum].open_time && pid==(int)getpid())
    del = True;

  if (del) {
    if (!unlink(fname)) 
      DEBUG(2,("Deleted share file %s\n",fname));
    else {
      DEBUG(3,("Pending delete share file %s\n",fname));
      if (*share_del_pending) DEBUG(0,("Share del clash!\n"));
      strcpy(share_del_pending,fname);
    }
  }
}
  

/*******************************************************************
set the share mode of a file
********************************************************************/
BOOL set_share_mode(int fnum,int mode)
{
  pstring fname;
  int fd2;
  char buf[16];
  int pid = (int)getpid();

  if (!share_name_fnum(fnum,fname)) return(False);

  {
    int old_umask = umask(0);
    fd2 = open(fname,O_WRONLY|O_CREAT|O_TRUNC,0644);
    umask(old_umask);
  }
  if (fd2 < 0) {
    DEBUG(2,("Failed to create share file %s\n",fname));
    return(False);
  }

  SIVAL(buf,0,Files[fnum].open_time);
  SIVAL(buf,4,mode);
  SIVAL(buf,8,pid);
  SIVAL(buf,12,LOCKING_VERSION);

  if (write(fd2,buf,16) != 16) {
    close(fd2);
    unlink(fname);
    return(False);
  }

  write(fd2,Files[fnum].name,strlen(Files[fnum].name)+1);

  close(fd2);

  DEBUG(3,("Created share file %s with mode 0x%X pid=%d\n",fname,mode,pid));

  return(True);
}
  

/*******************************************************************
cleanup any stale share files
********************************************************************/
void clean_share_files(void)
{
  char *lockdir = lp_lockdir();
  void *dir;
  char *s;

  if (!*lockdir) return;

  dir = opendir(lockdir);
  if (!dir) return;

  while ((s=readdirname(dir))) {
    char buf[16];
    int pid;
    int fd;
    pstring lname;
    int dev,inode;

    if (sscanf(s,"share.%d.%d",&dev,&inode)!=2) continue;

    strcpy(lname,lp_lockdir());
    trim_string(lname,NULL,"/");
    strcat(lname,"/");
    strcat(lname,s);

    fd = open(lname,O_RDONLY,0);
    if (fd < 0) continue;

    if (read(fd,buf,16) != 16) {
      close(fd);
      if (!unlink(lname))
	printf("Deleted corrupt share file %s\n",s);
      continue;
    }
    close(fd);

    pid = IVAL(buf,8);

    if (IVAL(buf,12) != LOCKING_VERSION || !process_exists(pid)) {
      if (!unlink(lname))
	printf("Deleted stale share file %s\n",s);
    }
  }

  closedir(dir);
}
