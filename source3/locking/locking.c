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
  utility function called to see if a file region is locked
****************************************************************************/
BOOL is_locked(int fnum,int cnum,uint32 count,uint32 offset)
{
  int snum = SNUM(cnum);

  if (count == 0)
    return(False);

  if (!lp_locking(snum) || !lp_strict_locking(snum))
    return(False);

  return(fcntl_lock(Files[fnum].fd_ptr->fd,F_GETLK,offset,count,
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
    ok = fcntl_lock(Files[fnum].fd_ptr->fd,F_SETLK,offset,count,
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
    ok = fcntl_lock(Files[fnum].fd_ptr->fd,F_SETLK,offset,count,F_UNLCK);
   
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
  if (fstat(Files[fnum].fd_ptr->fd,&st) != 0) return(False);
  return(share_name(Files[fnum].cnum,&st,name));
}

#endif

/*******************************************************************
  get the share mode of a file using the fnum
  ******************************************************************/
int get_share_mode_by_fnum(int cnum,int fnum,int *pid)
{
  struct stat sbuf;
  if (fstat(Files[fnum].fd_ptr->fd,&sbuf) == -1) return(0);
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
  char buf[20];
  int ret;
  struct timeval t;

  *pid = 0;

  if (!share_name(cnum,sbuf,fname)) return(0);

  fd2 = open(fname,O_RDONLY,0);
  if (fd2 < 0) return(0);

  if (read(fd2,buf,20) != 20) {
    DEBUG(2,("Failed to read share file %s\n",fname));
    close(fd2);
    unlink(fname);
    return(0);
  }
  close(fd2);

  t.tv_sec = IVAL(buf,4);
  t.tv_usec = IVAL(buf,8);
  ret = IVAL(buf,12);
  *pid = IVAL(buf,16);
  
  if (IVAL(buf,0) != LOCKING_VERSION) {    
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
  char buf[20];
  struct timeval t;
  int pid=0;
  BOOL del = False;

  t.tv_sec = t.tv_usec = 0;
  if (!share_name_fnum(fnum,fname)) return;

  fd2 = open(fname,O_RDONLY,0);
  if (fd2 < 0) return;
  if (read(fd2,buf,20) != 20)
    del = True;
  close(fd2);

  if (!del) {
    t.tv_sec = IVAL(buf,4);
    t.tv_usec = IVAL(buf,8);
    pid = IVAL(buf,16);
  }

  if (!del)
    if (IVAL(buf,0) != LOCKING_VERSION || !pid || !process_exists(pid))
      del = True;

  if (!del && (memcmp(&t,&Files[fnum].open_time,sizeof(t)) == 0) && (pid==(int)getpid()))
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
  char buf[20];
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

  SIVAL(buf,0,LOCKING_VERSION);
  SIVAL(buf,4,Files[fnum].open_time.tv_sec);
  SIVAL(buf,8,Files[fnum].open_time.tv_usec);
  SIVAL(buf,12,mode);
  SIVAL(buf,16,pid);

  if (write(fd2,buf,20) != 20) {
    DEBUG(2,("Failed to write share file %s\n",fname));
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
    char buf[20];
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

    if (read(fd,buf,20) != 20) {
      close(fd);
      if (!unlink(lname))
	printf("Deleted corrupt share file %s\n",s);
      continue;
    }
    close(fd);

    pid = IVAL(buf,16);

    if (IVAL(buf,0) != LOCKING_VERSION || !process_exists(pid)) {
      if (!unlink(lname))
	printf("Deleted stale share file %s\n",s);
    }
  }

  closedir(dir);
#endif
}
