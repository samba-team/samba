/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   slow (lockfile) locking implementation
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

   Revision History:

   12 aug 96: Erik.Devriendt@te6.siemens.be
   added support for shared memory implementation of share mode locking

   May 1997. Jeremy Allison (jallison@whistle.com). Modified share mode
   locking to deal with multiple share modes per open file.

   September 1997. Jeremy Allison (jallison@whistle.com). Added oplock
   support.

   October 1997 - split into separate file (tridge)
*/

#include "includes.h"
extern int DEBUGLEVEL;
extern connection_struct Connections[];
extern files_struct Files[];

/* 
 * Locking file header lengths & offsets. 
 */
#define SMF_VERSION_OFFSET 0
#define SMF_NUM_ENTRIES_OFFSET 4
#define SMF_FILENAME_LEN_OFFSET 8
#define SMF_HEADER_LENGTH 10

#define SMF_ENTRY_LENGTH 20

/*
 * Share mode record offsets.
 */

#define SME_SEC_OFFSET 0
#define SME_USEC_OFFSET 4
#define SME_SHAREMODE_OFFSET 8
#define SME_PID_OFFSET 12
#define SME_PORT_OFFSET 16
#define SME_OPLOCK_TYPE_OFFSET 18

/* we need world read for smbstatus to function correctly */
#ifdef SECURE_SHARE_MODES
#define SHARE_FILE_MODE 0600
#else
#define SHARE_FILE_MODE 0644
#endif

static int read_only;

/*******************************************************************
  deinitialize share_mode management 
  ******************************************************************/
static BOOL slow_stop_share_mode_mgmt(void)
{
   return True;
}


/*******************************************************************
  name a share file
  ******************************************************************/
static BOOL share_name(int cnum, uint32 dev, uint32 inode, char *name)
{
  int len;
  pstrcpy(name,lp_lockdir());
  trim_string(name,"","/");
  if (!*name) return(False);
  len = strlen(name);
  name += len;
  
  slprintf(name,sizeof(pstring) - len - 1,"/share.%u.%u",dev,inode);
  return(True);
}

/*******************************************************************
Force a share file to be deleted.
********************************************************************/
static int delete_share_file( int cnum, char *fname )
{
  if (read_only) return -1;

  /* the share file could be owned by anyone, so do this as root */
  become_root(False);

  if(unlink(fname) != 0)
  {
    DEBUG(0,("delete_share_file: Can't delete share file %s (%s)\n",
            fname, strerror(errno)));
  } 
  else 
  {
    DEBUG(5,("delete_share_file: Deleted share file %s\n", fname));
  }

  /* return to our previous privilage level */
  unbecome_root(False);

  return 0;
}

/*******************************************************************
  lock a share mode file.
  ******************************************************************/
static BOOL slow_lock_share_entry(int cnum, uint32 dev, uint32 inode, int *ptok)
{
  pstring fname;
  int fd;
  int ret = True;

  *ptok = (int)-1;

  if(!share_name(cnum, dev, inode, fname))
    return False;

  if (read_only) return True;

  /* we need to do this as root */
  become_root(False);

  {
    BOOL gotlock = False;
    /*
     * There was a race condition in the original slow share mode code.
     * A smbd could open a share mode file, and before getting
     * the lock, another smbd could delete the last entry for
     * the share mode file and delete the file entry from the
     * directory. Thus this smbd would be left with a locked
     * share mode fd attached to a file that no longer had a
     * directory entry. Thus another smbd would think that
     * there were no outstanding opens on the file. To fix
     * this we now check we can do a stat() call on the filename
     * before allowing the lock to proceed, and back out completely
     * and try the open again if we cannot.
     * Jeremy Allison (jallison@whistle.com).
     */

    do
    {
      struct stat dummy_stat;

      fd = (int)open(fname,read_only?O_RDONLY:(O_RDWR|O_CREAT),
		     SHARE_FILE_MODE);

      if(fd < 0)
      {
        DEBUG(0,("ERROR lock_share_entry: failed to open share file %s. Error was %s\n",
                  fname, strerror(errno)));
        ret = False;
        break;
      }

       /* At this point we have an open fd to the share mode file. 
         Lock the first byte exclusively to signify a lock. */
      if(fcntl_lock(fd, F_SETLKW, 0, 1, F_WRLCK) == False)
      {
        DEBUG(0,("ERROR lock_share_entry: fcntl_lock on file %s failed with %s\n",
                  fname, strerror(errno)));   
        close(fd);
        ret = False;
        break;
      }

      /* 
       * If we cannot stat the filename, the file was deleted between
       * the open and the lock call. Back out and try again.
       */

      if(stat(fname, &dummy_stat)!=0)
      {
        DEBUG(2,("lock_share_entry: Re-issuing open on %s to fix race. Error was %s\n",
                fname, strerror(errno)));
        close(fd);
      }
      else
        gotlock = True;
    } while(!gotlock);

    /*
     * We have to come here if any of the above calls fail
     * as we don't want to return and leave ourselves running
     * as root !
     */
  }

  *ptok = (int)fd;

  /* return to our previous privilage level */
  unbecome_root(False);

  return ret;
}

/*******************************************************************
  unlock a share mode file.
  ******************************************************************/
static BOOL slow_unlock_share_entry(int cnum, uint32 dev, uint32 inode, int token)
{
  int fd = (int)token;
  int ret = True;
  struct stat sb;
  pstring fname;

  if (read_only) return True;

  /* Fix for zero length share files from
     Gerald Werner <wernerg@mfldclin.edu> */
    
  share_name(cnum, dev, inode, fname);

  /* get the share mode file size */
  if(fstat((int)token, &sb) != 0)
  {
    DEBUG(0,("ERROR: unlock_share_entry: Failed to do stat on share file %s (%s)\n",
              fname, strerror(errno)));
    sb.st_size = 1;
    ret = False;
  }

  /* If the file was zero length, we must delete before
     doing the unlock to avoid a race condition (see
     the code in lock_share_mode_entry for details.
   */

  /* remove the share file if zero length */    
  if(sb.st_size == 0)  
    delete_share_file(cnum, fname);

  /* token is the fd of the open share mode file. */
  /* Unlock the first byte. */
  if(fcntl_lock(fd, F_SETLKW, 0, 1, F_UNLCK) == False)
   { 
      DEBUG(0,("ERROR unlock_share_entry: fcntl_lock failed with %s\n",
                      strerror(errno)));   
      ret = False;
   }
 
  close(fd);
  return ret;
}

/*******************************************************************
Read a share file into a buffer.
********************************************************************/
static int read_share_file(int cnum, int fd, char *fname, char **out, BOOL *p_new_file)
{
  struct stat sb;
  char *buf;
  int size;

  *out = 0;
  *p_new_file = False;

  if(fstat(fd, &sb) != 0)
  {
    DEBUG(0,("ERROR: read_share_file: Failed to do stat on share file %s (%s)\n",
                  fname, strerror(errno)));
    return -1;
  }

  if(sb.st_size == 0)
  {
     *p_new_file = True;
     return 0;
  }

  /* Allocate space for the file */
  if((buf = (char *)malloc(sb.st_size)) == NULL)
  {
    DEBUG(0,("read_share_file: malloc for file size %d fail !\n", sb.st_size));
    return -1;
  }
  
  if(lseek(fd, 0, SEEK_SET) != 0)
  {
    DEBUG(0,("ERROR: read_share_file: Failed to reset position to 0 \
for share file %s (%s)\n", fname, strerror(errno)));
    if(buf)
      free(buf);
    return -1;
  }
  
  if (read(fd,buf,sb.st_size) != sb.st_size)
  {
    DEBUG(0,("ERROR: read_share_file: Failed to read share file %s (%s)\n",
               fname, strerror(errno)));
    if(buf)
      free(buf);
    return -1;
  }
  
  if (IVAL(buf,SMF_VERSION_OFFSET) != LOCKING_VERSION) {
    DEBUG(0,("ERROR: read_share_file: share file %s has incorrect \
locking version (was %d, should be %d).\n",fname, 
                    IVAL(buf,SMF_VERSION_OFFSET), LOCKING_VERSION));
   if(buf)
      free(buf);
    delete_share_file(cnum, fname);
    return -1;
  }

  /* Sanity check for file contents */
  size = sb.st_size;
  size -= SMF_HEADER_LENGTH; /* Remove the header */

  /* Remove the filename component. */
  size -= SVAL(buf, SMF_FILENAME_LEN_OFFSET);

  /* The remaining size must be a multiple of SMF_ENTRY_LENGTH - error if not. */
  if((size % SMF_ENTRY_LENGTH) != 0)
  {
    DEBUG(0,("ERROR: read_share_file: share file %s is an incorrect length - \
deleting it.\n", fname));
    if(buf)
      free(buf);
    delete_share_file(cnum, fname);
    return -1;
  }

  *out = buf;
  return 0;
}

/*******************************************************************
get all share mode entries in a share file for a dev/inode pair.
********************************************************************/
static int slow_get_share_modes(int cnum, int token, uint32 dev, uint32 inode, 
				share_mode_entry **old_shares)
{
  int fd = (int)token;
  pstring fname;
  int i;
  int num_entries;
  int num_entries_copied;
  int newsize;
  share_mode_entry *share_array;
  char *buf = 0;
  char *base = 0;
  BOOL new_file;

  *old_shares = 0;

  /* Read the share file header - this is of the form:
     0   -  locking version.
     4   -  number of share mode entries.
     8   -  2 byte name length
     [n bytes] file name (zero terminated).

   Followed by <n> share mode entries of the form :

     0   -  tv_sec
     4   -  tv_usec
     8   -  share_mode
    12   -  pid
    16   -  oplock port (if oplocks in use) - 2 bytes.
  */

  share_name(cnum, dev, inode, fname);

  if(read_share_file( cnum, fd, fname, &buf, &new_file) != 0)
  {
    DEBUG(0,("ERROR: get_share_modes: Failed to read share file %s\n",
                  fname));
    return 0;
  }

  if(new_file == True)
    return 0;

  num_entries = IVAL(buf,SMF_NUM_ENTRIES_OFFSET);

  DEBUG(5,("get_share_modes: share file %s has %d share mode entries.\n",
            fname, num_entries));

  /* PARANOIA TEST */
  if(num_entries < 0)
  {
    DEBUG(0,("PANIC ERROR:get_share_mode: num_share_mode_entries < 0 (%d) \
for share file %d\n", num_entries, fname));
    return 0;
  }

  if(num_entries)
  {
    *old_shares = share_array = (share_mode_entry *)
                 malloc(num_entries * sizeof(share_mode_entry));
    if(*old_shares == 0)
    {
      DEBUG(0,("get_share_modes: malloc fail !\n"));
      return 0;
    }
  } 
  else
  {
    /* No entries - just delete the file. */
    DEBUG(0,("get_share_modes: share file %s has no share mode entries - deleting.\n",
              fname));
    if(buf)
      free(buf);
    delete_share_file(cnum, fname);
    return 0;
  }

  num_entries_copied = 0;
  base = buf + SMF_HEADER_LENGTH + SVAL(buf,SMF_FILENAME_LEN_OFFSET);

  for( i = 0; i < num_entries; i++)
  {
    int pid;
    char *p = base + (i*SMF_ENTRY_LENGTH);

    pid = IVAL(p,SME_PID_OFFSET);

    if(!process_exists(pid))
    {
      DEBUG(0,("get_share_modes: process %d no longer exists and \
it left a share mode entry with mode 0x%X in share file %s\n",
            pid, IVAL(p,SME_SHAREMODE_OFFSET), fname));
      continue;
    }
    share_array[num_entries_copied].time.tv_sec = IVAL(p,SME_SEC_OFFSET);
    share_array[num_entries_copied].time.tv_usec = IVAL(p,SME_USEC_OFFSET);
    share_array[num_entries_copied].share_mode = IVAL(p,SME_SHAREMODE_OFFSET);
    share_array[num_entries_copied].pid = pid;
    share_array[num_entries_copied].op_port = SVAL(p,SME_PORT_OFFSET);
    share_array[num_entries_copied].op_type = SVAL(p,SME_OPLOCK_TYPE_OFFSET);

    num_entries_copied++;
  }

  if(num_entries_copied == 0)
  {
    /* Delete the whole file. */
    DEBUG(0,("get_share_modes: share file %s had no valid entries - deleting it !\n",
             fname));
    if(*old_shares)
      free((char *)*old_shares);
    *old_shares = 0;
    if(buf)
      free(buf);
    delete_share_file(cnum, fname);
    return 0;
  }

  /* If we deleted some entries we need to re-write the whole number of
     share mode entries back into the file. */

  if(num_entries_copied != num_entries)
  {
    if(lseek(fd, 0, SEEK_SET) != 0)
    {
      DEBUG(0,("ERROR: get_share_modes: lseek failed to reset to \
position 0 for share mode file %s (%s)\n", fname, strerror(errno)));
      if(*old_shares)
        free((char *)*old_shares);
      *old_shares = 0;
      if(buf)
        free(buf);
      return 0;
    }

    SIVAL(buf, SMF_NUM_ENTRIES_OFFSET, num_entries_copied);
    for( i = 0; i < num_entries_copied; i++)
    {
      char *p = base + (i*SMF_ENTRY_LENGTH);

      SIVAL(p,SME_PID_OFFSET,share_array[i].pid);
      SIVAL(p,SME_SHAREMODE_OFFSET,share_array[i].share_mode);
      SIVAL(p,SME_SEC_OFFSET,share_array[i].time.tv_sec);
      SIVAL(p,SME_USEC_OFFSET,share_array[i].time.tv_usec);
      SSVAL(p,SME_PORT_OFFSET,share_array[i].op_port);
      SSVAL(p,SME_OPLOCK_TYPE_OFFSET,share_array[i].op_type);
    }

    newsize = (base - buf) + (SMF_ENTRY_LENGTH*num_entries_copied);
    if(write(fd, buf, newsize) != newsize)
    {
      DEBUG(0,("ERROR: get_share_modes: failed to re-write share \
mode file %s (%s)\n", fname, strerror(errno)));
      if(*old_shares)
        free((char *)*old_shares);
      *old_shares = 0;
      if(buf)
        free(buf);
      return 0;
    }
    /* Now truncate the file at this point. */
#ifdef FTRUNCATE_NEEDS_ROOT
    become_root(False);
#endif /* FTRUNCATE_NEEDS_ROOT */

    if(ftruncate(fd, newsize)!= 0)
    {

#ifdef FTRUNCATE_NEEDS_ROOT
      unbecome_root(False);
#endif /* FTRUNCATE_NEEDS_ROOT */

      DEBUG(0,("ERROR: get_share_modes: failed to ftruncate share \
mode file %s to size %d (%s)\n", fname, newsize, strerror(errno)));
      if(*old_shares)
        free((char *)*old_shares);
      *old_shares = 0;
      if(buf)
        free(buf);
      return 0;
    }
  }

#ifdef FTRUNCATE_NEEDS_ROOT
      unbecome_root(False);
#endif /* FTRUNCATE_NEEDS_ROOT */

  if(buf)
    free(buf);

  DEBUG(5,("get_share_modes: Read share file %s returning %d entries\n",fname,
            num_entries_copied));

  return num_entries_copied;
}

/*******************************************************************
del a share mode from a share mode file.
********************************************************************/
static void slow_del_share_mode(int token, int fnum)
{
  pstring fname;
  int fd = (int)token;
  char *buf = 0;
  char *base = 0;
  int num_entries;
  int newsize;
  int i;
  files_struct *fs_p = &Files[fnum];
  int pid;
  BOOL deleted = False;
  BOOL new_file;

  share_name(fs_p->cnum, fs_p->fd_ptr->dev, 
                       fs_p->fd_ptr->inode, fname);

  if(read_share_file( fs_p->cnum, fd, fname, &buf, &new_file) != 0)
  {
    DEBUG(0,("ERROR: del_share_mode: Failed to read share file %s\n",
                  fname));
    return;
  }

  if(new_file == True)
  {
    DEBUG(0,("ERROR:del_share_mode: share file %s is new (size zero), deleting it.\n",
              fname));
    delete_share_file(fs_p->cnum, fname);
    return;
  }

  num_entries = IVAL(buf,SMF_NUM_ENTRIES_OFFSET);

  DEBUG(5,("del_share_mode: share file %s has %d share mode entries.\n",
            fname, num_entries));

  /* PARANOIA TEST */
  if(num_entries < 0)
  {
    DEBUG(0,("PANIC ERROR:del_share_mode: num_share_mode_entries < 0 (%d) \
for share file %d\n", num_entries, fname));
    return;
  }

  if(num_entries == 0)
  {
    /* No entries - just delete the file. */
    DEBUG(0,("del_share_mode: share file %s has no share mode entries - deleting.\n",
              fname));
    if(buf)
      free(buf);
    delete_share_file(fs_p->cnum, fname);
    return;
  }

  pid = getpid();

  /* Go through the entries looking for the particular one
     we have set - delete it.
  */

  base = buf + SMF_HEADER_LENGTH + SVAL(buf,SMF_FILENAME_LEN_OFFSET);

  for(i = 0; i < num_entries; i++)
  {
    char *p = base + (i*SMF_ENTRY_LENGTH);

    if((IVAL(p,SME_SEC_OFFSET) != fs_p->open_time.tv_sec) || 
       (IVAL(p,SME_USEC_OFFSET) != fs_p->open_time.tv_usec) ||
       (IVAL(p,SME_SHAREMODE_OFFSET) != fs_p->share_mode) || 
       (IVAL(p,SME_PID_OFFSET) != pid))
      continue;

    DEBUG(5,("del_share_mode: deleting entry number %d (of %d) from the share file %s\n",
             i, num_entries, fname));

    /* Remove this entry. */
    if(i != num_entries - 1)
      memcpy(p, p + SMF_ENTRY_LENGTH, (num_entries - i - 1)*SMF_ENTRY_LENGTH);

    deleted = True;
    break;
  }

  if(!deleted)
  {
    DEBUG(0,("del_share_mode: entry not found in share file %s\n", fname));
    if(buf)
      free(buf);
    return;
  }

  num_entries--;
  SIVAL(buf,SMF_NUM_ENTRIES_OFFSET, num_entries);

  if(num_entries == 0)
  {
    /* Deleted the last entry - remove the file. */
    DEBUG(5,("del_share_mode: removed last entry in share file - deleting share file %s\n",
             fname));
    if(buf)
      free(buf);
    delete_share_file(fs_p->cnum,fname);
    return;
  }

  /* Re-write the file - and truncate it at the correct point. */
  if(lseek(fd, 0, SEEK_SET) != 0)
  {
    DEBUG(0,("ERROR: del_share_mode: lseek failed to reset to \
position 0 for share mode file %s (%s)\n", fname, strerror(errno)));
    if(buf)
      free(buf);
    return;
  }

  newsize = (base - buf) + (SMF_ENTRY_LENGTH*num_entries);
  if(write(fd, buf, newsize) != newsize)
  {
    DEBUG(0,("ERROR: del_share_mode: failed to re-write share \
mode file %s (%s)\n", fname, strerror(errno)));
    if(buf)
      free(buf);
    return;
  }

  /* Now truncate the file at this point. */
#ifdef FTRUNCATE_NEEDS_ROOT
  become_root(False);
#endif /* FTRUNCATE_NEEDS_ROOT */

  if(ftruncate(fd, newsize) != 0)
  {

#ifdef FTRUNCATE_NEEDS_ROOT
    unbecome_root(False);
#endif /* FTRUNCATE_NEEDS_ROOT */

    DEBUG(0,("ERROR: del_share_mode: failed to ftruncate share \
mode file %s to size %d (%s)\n", fname, newsize, strerror(errno)));
    if(buf)
      free(buf);
    return;
  }

#ifdef FTRUNCATE_NEEDS_ROOT
  unbecome_root(False);
#endif /* FTRUNCATE_NEEDS_ROOT */
}
  
/*******************************************************************
set the share mode of a file
********************************************************************/
static BOOL slow_set_share_mode(int token,int fnum, uint16 port, uint16 op_type)
{
  files_struct *fs_p = &Files[fnum];
  pstring fname;
  int fd = (int)token;
  int pid = (int)getpid();
  struct stat sb;
  char *buf;
  int num_entries;
  int header_size;
  char *p;

  share_name(fs_p->cnum, fs_p->fd_ptr->dev,
                       fs_p->fd_ptr->inode, fname);

  if(fstat(fd, &sb) != 0)
  {
    DEBUG(0,("ERROR: set_share_mode: Failed to do stat on share file %s\n",
                  fname));
    return False;
  }

  /* Sanity check for file contents (if it's not a new share file). */
  if(sb.st_size != 0)
  {
    int size = sb.st_size;

    /* Allocate space for the file plus one extra entry */
    if((buf = (char *)malloc(sb.st_size + SMF_ENTRY_LENGTH)) == NULL)
    {
      DEBUG(0,("set_share_mode: malloc for file size %d fail !\n", 
                  sb.st_size + SMF_ENTRY_LENGTH));
      return False;
    }
 
    if(lseek(fd, 0, SEEK_SET) != 0)
    {
      DEBUG(0,("ERROR: set_share_mode: Failed to reset position \
to 0 for share file %s (%s)\n", fname, strerror(errno)));
      if(buf)
        free(buf);
      return False;
    }

    if (read(fd,buf,sb.st_size) != sb.st_size)
    {
      DEBUG(0,("ERROR: set_share_mode: Failed to read share file %s (%s)\n",
                  fname, strerror(errno)));
      if(buf)
        free(buf);
      return False;
    }   
  
    if (IVAL(buf,SMF_VERSION_OFFSET) != LOCKING_VERSION) 
    {
      DEBUG(0,("ERROR: set_share_mode: share file %s has incorrect \
locking version (was %d, should be %d).\n",fname, IVAL(buf,SMF_VERSION_OFFSET), 
                    LOCKING_VERSION));
      if(buf)
        free(buf);
      delete_share_file(fs_p->cnum, fname);
      return False;
    }   

    size -= (SMF_HEADER_LENGTH + SVAL(buf, SMF_FILENAME_LEN_OFFSET)); /* Remove the header */

    /* The remaining size must be a multiple of SMF_ENTRY_LENGTH - error if not. */
    if((size % SMF_ENTRY_LENGTH) != 0)
    {
      DEBUG(0,("ERROR: set_share_mode: share file %s is an incorrect length - \
deleting it.\n", fname));
      if(buf)
        free(buf);
      delete_share_file(fs_p->cnum, fname);
      return False;
    }

  }
  else
  {
    /* New file - just use a single_entry. */
    if((buf = (char *)malloc(SMF_HEADER_LENGTH + 
                  strlen(fs_p->name) + 1 + SMF_ENTRY_LENGTH)) == NULL)
    {
      DEBUG(0,("ERROR: set_share_mode: malloc failed for single entry.\n"));
      return False;
    }
    SIVAL(buf,SMF_VERSION_OFFSET,LOCKING_VERSION);
    SIVAL(buf,SMF_NUM_ENTRIES_OFFSET,0);
    SSVAL(buf,SMF_FILENAME_LEN_OFFSET,strlen(fs_p->name) + 1);
    pstrcpy(buf + SMF_HEADER_LENGTH, fs_p->name);
  }

  num_entries = IVAL(buf,SMF_NUM_ENTRIES_OFFSET);
  header_size = SMF_HEADER_LENGTH + SVAL(buf,SMF_FILENAME_LEN_OFFSET);
  p = buf + header_size + (num_entries * SMF_ENTRY_LENGTH);
  SIVAL(p,SME_SEC_OFFSET,fs_p->open_time.tv_sec);
  SIVAL(p,SME_USEC_OFFSET,fs_p->open_time.tv_usec);
  SIVAL(p,SME_SHAREMODE_OFFSET,fs_p->share_mode);
  SIVAL(p,SME_PID_OFFSET,pid);
  SSVAL(p,SME_PORT_OFFSET,port);
  SSVAL(p,SME_OPLOCK_TYPE_OFFSET,op_type);

  num_entries++;

  SIVAL(buf,SMF_NUM_ENTRIES_OFFSET,num_entries);

  if(lseek(fd, 0, SEEK_SET) != 0)
  {
    DEBUG(0,("ERROR: set_share_mode: (1) Failed to reset position to \
0 for share file %s (%s)\n", fname, strerror(errno)));
    if(buf)
      free(buf);
    return False;
  }

  if (write(fd,buf,header_size + (num_entries*SMF_ENTRY_LENGTH)) != 
                       (header_size + (num_entries*SMF_ENTRY_LENGTH))) 
  {
    DEBUG(2,("ERROR: set_share_mode: Failed to write share file %s - \
deleting it (%s).\n",fname, strerror(errno)));
    delete_share_file(fs_p->cnum, fname);
    if(buf)
      free(buf);
    return False;
  }

  /* Now truncate the file at this point - just for safety. */

#ifdef FTRUNCATE_NEEDS_ROOT
  become_root(False);
#endif /* FTRUNCATE_NEEDS_ROOT */

  if(ftruncate(fd, header_size + (SMF_ENTRY_LENGTH*num_entries))!= 0)
  {

#ifdef FTRUNCATE_NEEDS_ROOT
    unbecome_root(False);
#endif /* FTRUNCATE_NEEDS_ROOT */

    DEBUG(0,("ERROR: set_share_mode: failed to ftruncate share \
mode file %s to size %d (%s)\n", fname, header_size + (SMF_ENTRY_LENGTH*num_entries), 
                strerror(errno)));
    if(buf)
      free(buf);
    return False;
  }

#ifdef FTRUNCATE_NEEDS_ROOT
  unbecome_root(False);
#endif /* FTRUNCATE_NEEDS_ROOT */

  if(buf)
    free(buf);

  DEBUG(3,("set_share_mode: Created share file %s with \
mode 0x%X pid=%d\n",fname,fs_p->share_mode,pid));

  return True;
}

/*******************************************************************
Remove an oplock port and mode entry from a share mode.
********************************************************************/
static BOOL slow_remove_share_oplock(int fnum, int token)
{
  pstring fname;
  int fd = (int)token;
  char *buf = 0;
  char *base = 0;
  int num_entries;
  int fsize;
  int i;
  files_struct *fs_p = &Files[fnum];
  int pid;
  BOOL found = False;
  BOOL new_file;

  share_name(fs_p->cnum, fs_p->fd_ptr->dev, 
                       fs_p->fd_ptr->inode, fname);

  if(read_share_file( fs_p->cnum, fd, fname, &buf, &new_file) != 0)
  {
    DEBUG(0,("ERROR: remove_share_oplock: Failed to read share file %s\n",
                  fname));
    return False;
  }

  if(new_file == True)
  {
    DEBUG(0,("ERROR: remove_share_oplock: share file %s is new (size zero), \
deleting it.\n", fname));
    delete_share_file(fs_p->cnum, fname);
    return False;
  }

  num_entries = IVAL(buf,SMF_NUM_ENTRIES_OFFSET);

  DEBUG(5,("remove_share_oplock: share file %s has %d share mode entries.\n",
            fname, num_entries));

  /* PARANOIA TEST */
  if(num_entries < 0)
  {
    DEBUG(0,("PANIC ERROR:remove_share_oplock: num_share_mode_entries < 0 (%d) \
for share file %d\n", num_entries, fname));
    return False;
  }

  if(num_entries == 0)
  {
    /* No entries - just delete the file. */
    DEBUG(0,("remove_share_oplock: share file %s has no share mode entries - deleting.\n",
              fname));
    if(buf)
      free(buf);
    delete_share_file(fs_p->cnum, fname);
    return False;
  }

  pid = getpid();

  /* Go through the entries looking for the particular one
     we have set - remove the oplock settings on it.
  */

  base = buf + SMF_HEADER_LENGTH + SVAL(buf,SMF_FILENAME_LEN_OFFSET);

  for(i = 0; i < num_entries; i++)
  {
    char *p = base + (i*SMF_ENTRY_LENGTH);

    if((IVAL(p,SME_SEC_OFFSET) != fs_p->open_time.tv_sec) || 
       (IVAL(p,SME_USEC_OFFSET) != fs_p->open_time.tv_usec) ||
       (IVAL(p,SME_SHAREMODE_OFFSET) != fs_p->share_mode) || 
       (IVAL(p,SME_PID_OFFSET) != pid))
      continue;

    DEBUG(5,("remove_share_oplock: clearing oplock on entry number %d (of %d) \
from the share file %s\n", i, num_entries, fname));

    SSVAL(p,SME_PORT_OFFSET,0);
    SSVAL(p,SME_OPLOCK_TYPE_OFFSET,0);
    found = True;
    break;
  }

  if(!found)
  {
    DEBUG(0,("remove_share_oplock: entry not found in share file %s\n", fname));
    if(buf)
      free(buf);
    return False;
  }

  /* Re-write the file - and truncate it at the correct point. */
  if(lseek(fd, 0, SEEK_SET) != 0)
  {
    DEBUG(0,("ERROR: remove_share_oplock: lseek failed to reset to \
position 0 for share mode file %s (%s)\n", fname, strerror(errno)));
    if(buf)
      free(buf);
    return False;
  }

  fsize = (base - buf) + (SMF_ENTRY_LENGTH*num_entries);
  if(write(fd, buf, fsize) != fsize)
  {
    DEBUG(0,("ERROR: remove_share_oplock: failed to re-write share \
mode file %s (%s)\n", fname, strerror(errno)));
    if(buf)
      free(buf);
    return False;
  }

  return True;
}



/*******************************************************************
call the specified function on each entry under management by the
share ode system
********************************************************************/
static int slow_share_forall(void (*fn)(share_mode_entry *, char *))
{
	int i, count=0;
	void *dir;
	char *s;
	share_mode_entry e;

	dir = opendir(lp_lockdir());
	if (!dir) {
		return(0);
	}

	while ((s=readdirname(dir))) {
		char *buf;
		char *base;
		int fd;
		pstring lname;
		uint32 dev,inode;
		BOOL new_file;
		pstring fname;

		if (sscanf(s,"share.%u.%u",&dev,&inode)!=2) continue;
       
		pstrcpy(lname,lp_lockdir());
		trim_string(lname,NULL,"/");
		pstrcat(lname,"/");
		pstrcat(lname,s);
       
		fd = open(lname,read_only?O_RDONLY:O_RDWR,0);
		if (fd < 0) {
			continue;
		}

		/* Lock the share mode file while we read it. */
		if(!read_only &&
		   fcntl_lock(fd, F_SETLKW, 0, 1, F_WRLCK) == False) {
			close(fd);
			continue;
		}

		if(read_share_file( 0, fd, lname, &buf, &new_file)) {
			close(fd);
			continue;
		} 
		pstrcpy( fname, &buf[10]);
		close(fd);
      
		base = buf + SMF_HEADER_LENGTH + 
			SVAL(buf,SMF_FILENAME_LEN_OFFSET); 
		for( i = 0; i < IVAL(buf, SMF_NUM_ENTRIES_OFFSET); i++) {
			char *p = base + (i*SMF_ENTRY_LENGTH);
			e.pid = IVAL(p,SME_PID_OFFSET);
			e.share_mode = IVAL(p,SME_SHAREMODE_OFFSET);
			e.time.tv_sec = IVAL(p,SME_SEC_OFFSET);
			e.time.tv_usec = IVAL(p,SME_USEC_OFFSET);
			e.op_port = SVAL(p,SME_PORT_OFFSET);
			e.pid = SVAL(p,SME_PID_OFFSET);
			e.op_type = SVAL(p,SME_OPLOCK_TYPE_OFFSET);

			if (process_exists(e.pid)) {
				fn(&e, fname);
				count++;
			}
		} /* end for i */

		if(buf)
			free(buf);
		base = 0;
	} /* end while */
	closedir(dir);

	return count;
}


/*******************************************************************
dump the state of the system
********************************************************************/
static void slow_share_status(FILE *f)
{
	
}


static struct share_ops share_ops = {
	slow_stop_share_mode_mgmt,
	slow_lock_share_entry,
	slow_unlock_share_entry,
	slow_get_share_modes,
	slow_del_share_mode,
	slow_set_share_mode,
	slow_remove_share_oplock,
	slow_share_forall,
	slow_share_status,
};

/*******************************************************************
  initialize the slow share_mode management 
  ******************************************************************/
struct share_ops *locking_slow_init(int ronly)
{

	read_only = ronly;

	if (!directory_exist(lp_lockdir(),NULL)) {
		if (!read_only)
			mkdir(lp_lockdir(),0755);
		if (!directory_exist(lp_lockdir(),NULL))
			return NULL;
	}

	return &share_ops;
}
