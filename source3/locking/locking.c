/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Locking functions
   Copyright (C) Andrew Tridgell 1992-1996
   
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

   Revision History:

   12 aug 96: Erik.Devriendt@te6.siemens.be
   added support for shared memory implementation of share mode locking
*/

#include "includes.h"
extern int DEBUGLEVEL;
extern connection_struct Connections[];
extern files_struct Files[];

pstring share_del_pending="";


/****************************************************************************
routine to do file locking
****************************************************************************/
BOOL fcntl_lock(int fd,int op,uint32 offset,uint32 count,int type)
{
#if HAVE_FCNTL_LOCK
  struct flock lock;
  int ret;

#if 1
  uint32 mask = 0xC0000000;

  /* make sure the count is reasonable, we might kill the lockd otherwise */
  count &= ~mask;

  /* the offset is often strange - remove 2 of its bits if either of
     the top two bits are set. Shift the top ones by two bits. This
     still allows OLE2 apps to operate, but should stop lockd from
     dieing */
  if ((offset & mask) != 0)
    offset = (offset & ~mask) | ((offset & mask) >> 2);
#else
  uint32 mask = ((unsigned)1<<31);

  /* interpret negative counts as large numbers */
  if (count < 0)
    count &= ~mask;

  /* no negative offsets */
  offset &= ~mask;

  /* count + offset must be in range */
  while ((offset < 0 || (offset + count < 0)) && mask)
    {
      offset &= ~mask;
      mask = mask >> 1;
    }
#endif


  DEBUG(5,("fcntl_lock %d %d %d %d %d\n",fd,op,(int)offset,(int)count,type));

  lock.l_type = type;
  lock.l_whence = SEEK_SET;
  lock.l_start = (int)offset;
  lock.l_len = (int)count;
  lock.l_pid = 0;

  errno = 0;

  ret = fcntl(fd,op,&lock);

  if (errno != 0)
    DEBUG(3,("fcntl lock gave errno %d (%s)\n",errno,strerror(errno)));

  /* a lock query */
  if (op == F_GETLK)
    {
      if ((ret != -1) &&
	  (lock.l_type != F_UNLCK) && 
	  (lock.l_pid != 0) && 
	  (lock.l_pid != getpid()))
	{
	  DEBUG(3,("fd %d is locked by pid %d\n",fd,lock.l_pid));
	  return(True);
	}

      /* it must be not locked or locked by me */
      return(False);
    }

  /* a lock set or unset */
  if (ret == -1)
    {
      DEBUG(3,("lock failed at offset %d count %d op %d type %d (%s)\n",
	       offset,count,op,type,strerror(errno)));

      /* perhaps it doesn't support this sort of locking?? */
      if (errno == EINVAL)
	{
	  DEBUG(3,("locking not supported? returning True\n"));
	  return(True);
	}

      return(False);
    }

  /* everything went OK */
  DEBUG(5,("Lock call successful\n"));

  return(True);
#else
  return(False);
#endif
}

/*******************************************************************
lock a file - returning a open file descriptor or -1 on failure
The timeout is in seconds. 0 means no timeout
********************************************************************/
int file_lock(char *name,int timeout)
{  
  int fd = open(name,O_RDWR|O_CREAT,0666);
  time_t t=0;
  if (fd < 0) return(-1);

#if HAVE_FCNTL_LOCK
  if (timeout) t = time(NULL);
  while (!timeout || (time(NULL)-t < timeout)) {
    if (fcntl_lock(fd,F_SETLK,0,1,F_WRLCK)) return(fd);    
    msleep(LOCK_RETRY_TIMEOUT);
  }
  return(-1);
#else
  return(fd);
#endif
}

/*******************************************************************
unlock a file locked by file_lock
********************************************************************/
void file_unlock(int fd)
{
  if (fd<0) return;
#if HAVE_FCNTL_LOCK
  fcntl_lock(fd,F_SETLK,0,1,F_UNLCK);
#endif
  close(fd);
}


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

#if FAST_SHARE_MODES
/*******************************************************************
  initialize the shared memory for share_mode management 
  ******************************************************************/
BOOL start_share_mode_mgmt(void)
{
   pstring shmem_file_name;
   
  strcpy(shmem_file_name,lp_lockdir());
  if (!directory_exist(shmem_file_name,NULL))
    mkdir(shmem_file_name,0755);
  trim_string(shmem_file_name,"","/");
  if (!*shmem_file_name) return(False);
  strcat(shmem_file_name, "/SHARE_MEM_FILE");
  return shm_open(shmem_file_name, SHMEM_SIZE);
}


/*******************************************************************
  deinitialize the shared memory for share_mode management 
  ******************************************************************/
BOOL stop_share_mode_mgmt(void)
{
   return shm_close();
}

#else

/* SHARE MODE LOCKS USING SLOW DESCRIPTION FILES */

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

#endif

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
#if FAST_SHARE_MODES
  share_mode_record *scanner_p;
  share_mode_record *prev_p;
  int ret;
  BOOL found = False;

  *pid = 0;

  if(!shm_lock()) return (0);

  scanner_p = (share_mode_record *)shm_offset2addr(shm_get_userdef_off());
  prev_p = scanner_p;
  while(scanner_p)
  {
     if( (scanner_p->st_dev == sbuf->st_dev) && (scanner_p->st_ino == sbuf->st_ino) )
     {
	found = True;
	break;
     }
     else
     {
	prev_p = scanner_p ;
	scanner_p = (share_mode_record *)shm_offset2addr(scanner_p->next_offset);
     }
  }
  
  if(!found)
  {
     shm_unlock();
     return (0);
  }
  
  if(scanner_p->locking_version != LOCKING_VERSION)
  {
     DEBUG(2,("Deleting old share mode record due to old locking version %d",scanner_p->locking_version));
     if(prev_p == scanner_p)
	shm_set_userdef_off(scanner_p->next_offset);
     else
	prev_p->next_offset = scanner_p->next_offset;
     shm_free(shm_addr2offset(scanner_p));
     *pid = 0;
	
     shm_unlock();
     return (0);
  }
  
  *pid = scanner_p->pid;
  ret = scanner_p->share_mode;

  if (*pid && !process_exists(*pid))
  {
    ret = 0;
    *pid = 0;
  }
  
  if (! *pid)
  {
     if(prev_p == scanner_p)
	shm_set_userdef_off(scanner_p->next_offset);
     else
	prev_p->next_offset = scanner_p->next_offset;
     shm_free(shm_addr2offset(scanner_p));
  }
  
  if (*pid)
    DEBUG(5,("Read share mode record mode 0x%X pid=%d\n",ret,*pid));

  if(!shm_unlock()) return (0);
  
  return(ret);
  
#else
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
#endif
}


/*******************************************************************
del the share mode of a file, if we set it last
********************************************************************/
void del_share_mode(int fnum)
{
#if FAST_SHARE_MODES
  struct stat st;
  time_t t=0;
  int pid=0;
  BOOL del = False;
  share_mode_record *scanner_p;
  share_mode_record *prev_p;
  BOOL found = False;

  
  
  if (fstat(Files[fnum].fd,&st) != 0) return;
  
  if (!shm_lock()) return;
  
  scanner_p = (share_mode_record *)shm_offset2addr(shm_get_userdef_off());
  prev_p = scanner_p;
  while(scanner_p)
  {
     if( (scanner_p->st_dev == st.st_dev) && (scanner_p->st_ino == st.st_ino) )
     {
	found = True;
	break;
     }
     else
     {
	prev_p = scanner_p ;
	scanner_p = (share_mode_record *)shm_offset2addr(scanner_p->next_offset);
     }
  }
    
  if(!found)
  {
     shm_unlock();
     return;
  }
  
  t = scanner_p->time;
  pid = scanner_p->pid;
  
  if( (scanner_p->locking_version != LOCKING_VERSION) || !pid || !process_exists(pid))
    del = True;

  if (!del && t == Files[fnum].open_time && pid==(int)getpid())
    del = True;

  if (del)
  {
     DEBUG(2,("Deleting share mode record\n"));
     if(prev_p == scanner_p)
	shm_set_userdef_off(scanner_p->next_offset);
     else
	prev_p->next_offset = scanner_p->next_offset;
     shm_free(shm_addr2offset(scanner_p));
	
  }

  shm_unlock();
  return;

#else
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
#endif
}
  

/*******************************************************************
set the share mode of a file
********************************************************************/
BOOL set_share_mode(int fnum,int mode)
{
#if FAST_SHARE_MODES
  int pid = (int)getpid();
  struct stat st;
  shm_offset_t new_off;
  share_mode_record *new_p;
  
  
  if (fstat(Files[fnum].fd,&st) != 0) return(False);
  
  if (!shm_lock()) return (False);
  new_off = shm_alloc(sizeof(share_mode_record) + strlen(Files[fnum].name) );
  if (new_off == NULL_OFFSET) return (False);
  new_p = (share_mode_record *)shm_offset2addr(new_off);
  new_p->locking_version = LOCKING_VERSION;
  new_p->share_mode = mode;
  new_p->time = Files[fnum].open_time;
  new_p->pid = pid;
  new_p->st_dev = st.st_dev;
  new_p->st_ino = st.st_ino;
  strcpy(new_p->file_name,Files[fnum].name);
  new_p->next_offset = shm_get_userdef_off();
  shm_set_userdef_off(new_off);


  DEBUG(3,("Created share record for %s with mode 0x%X pid=%d\n",Files[fnum].name,mode,pid));

  if (!shm_unlock()) return (False);
  return(True);

#else
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
#endif
}
  

/*******************************************************************
cleanup any stale share files
********************************************************************/
void clean_share_modes(void)
{
#ifdef USE_SHMEM
  share_mode_record *scanner_p;
  share_mode_record *prev_p;
  int pid;
  
  if (!shm_lock()) return;
  
  scanner_p = (share_mode_record *)shm_offset2addr(shm_get_userdef_off());
  prev_p = scanner_p;
  while(scanner_p)
  {
     pid = scanner_p->pid;
     
     if( (scanner_p->locking_version != LOCKING_VERSION) || !process_exists(pid))
     {
	DEBUG(2,("Deleting stale share mode record"));
	if(prev_p == scanner_p)
	{
	   shm_set_userdef_off(scanner_p->next_offset);
	   shm_free(shm_addr2offset(scanner_p));
           scanner_p = (share_mode_record *)shm_offset2addr(shm_get_userdef_off());
           prev_p = scanner_p;
	}
	else
	{
	   prev_p->next_offset = scanner_p->next_offset;
  	   shm_free(shm_addr2offset(scanner_p));
           scanner_p = (share_mode_record *)shm_offset2addr(prev_p->next_offset);
	}
	
     }
     else
     {
	prev_p = scanner_p ;
	scanner_p = (share_mode_record *)shm_offset2addr(scanner_p->next_offset);
     }
  }
    

  shm_unlock();
  return;
  
#else
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
#endif
}
