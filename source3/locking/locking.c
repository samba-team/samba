/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Locking functions
   Copyright (C) Andrew Tridgell 1992-1997
   
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

*/

#include "includes.h"
extern int DEBUGLEVEL;
extern connection_struct Connections[];
extern files_struct Files[];

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

#ifdef FAST_SHARE_MODES
/*******************************************************************
  initialize the shared memory for share_mode management 
  ******************************************************************/
BOOL start_share_mode_mgmt(void)
{
   pstring shmem_file_name;
   
  pstrcpy(shmem_file_name,lp_lockdir());
  if (!directory_exist(shmem_file_name,NULL))
    mkdir(shmem_file_name,0755);
  trim_string(shmem_file_name,"","/");
  if (!*shmem_file_name) return(False);
  strcat(shmem_file_name, "/SHARE_MEM_FILE");
  return smb_shm_open(shmem_file_name, lp_shmem_size());
}


/*******************************************************************
  deinitialize the shared memory for share_mode management 
  ******************************************************************/
BOOL stop_share_mode_mgmt(void)
{
   return smb_shm_close();
}

/*******************************************************************
  lock a hash bucket entry in shared memory for share_mode management 
  ******************************************************************/
BOOL lock_share_entry(int cnum, uint32 dev, uint32 inode, share_lock_token *ptok)
{
  return smb_shm_lock_hash_entry(HASH_ENTRY(dev, inode));
}

/*******************************************************************
  unlock a hash bucket entry in shared memory for share_mode management 
  ******************************************************************/
BOOL unlock_share_entry(int cnum, uint32 dev, uint32 inode, share_lock_token token)
{
  return smb_shm_unlock_hash_entry(HASH_ENTRY(dev, inode));
}

/*******************************************************************
get all share mode entries in shared memory for a dev/inode pair.
********************************************************************/
int get_share_modes(int cnum, share_lock_token token, uint32 dev, uint32 inode, 
                    min_share_mode_entry **old_shares)
{
  smb_shm_offset_t *mode_array;
  unsigned int hash_entry = HASH_ENTRY(dev, inode); 
  share_mode_record *file_scanner_p;
  share_mode_record *file_prev_p;
  share_mode_entry *entry_scanner_p;
  share_mode_entry *entry_prev_p;
  int num_entries;
  int num_entries_copied;
  BOOL found = False;
  min_share_mode_entry *share_array = (min_share_mode_entry *)0;

  *old_shares = 0;

  if(hash_entry > lp_shmem_hash_size() )
  {
    DEBUG(0, 
      ("PANIC ERROR : get_share_modes (FAST_SHARE_MODES): hash_entry %d too large \
(max = %d)\n",
      hash_entry, lp_shmem_hash_size() ));
    return 0;
  }

  mode_array = (smb_shm_offset_t *)smb_shm_offset2addr(smb_shm_get_userdef_off());
  
  if(mode_array[hash_entry] == NULL_OFFSET)
  {
    DEBUG(5,("get_share_modes (FAST_SHARE_MODES): hash bucket %d empty\n", hash_entry));
    return 0;
  }

  file_scanner_p = (share_mode_record *)smb_shm_offset2addr(mode_array[hash_entry]);
  file_prev_p = file_scanner_p;
  while(file_scanner_p)
  {
    if( (file_scanner_p->st_dev == dev) && (file_scanner_p->st_ino == inode) )
    {
      found = True;
      break;
    }
    else
    {
      file_prev_p = file_scanner_p ;
      file_scanner_p = (share_mode_record *)smb_shm_offset2addr(
                                    file_scanner_p->next_offset);
    }
  }
  
  if(!found)
  {
    DEBUG(5,("get_share_modes (FAST_SHARE_MODES): no entry for \
file dev = %d, ino = %d in hash_bucket %d\n", dev, inode, hash_entry));
    return (0);
  }
  
  if(file_scanner_p->locking_version != LOCKING_VERSION)
  {
    DEBUG(0,("ERROR:get_share_modes (FAST_SHARE_MODES): Deleting old share mode \
record due to old locking version %d for file dev = %d, inode = %d in hash \
bucket %d\n", file_scanner_p->locking_version, dev, inode, hash_entry));
    if(file_prev_p == file_scanner_p)
      mode_array[hash_entry] = file_scanner_p->next_offset;
    else
      file_prev_p->next_offset = file_scanner_p->next_offset;
    smb_shm_free(smb_shm_addr2offset(file_scanner_p));
    return (0);
  }

  /* Allocate the old_shares array */
  num_entries = file_scanner_p->num_share_mode_entries;
  if(num_entries)
  {
    *old_shares = share_array = (min_share_mode_entry *)
                 malloc(num_entries * sizeof(min_share_mode_entry));
    if(*old_shares == 0)
    {
      DEBUG(0,("get_share_modes (FAST_SHARE_MODES): malloc fail !\n"));
      return 0;
    }
  }

  num_entries_copied = 0;
  
  entry_scanner_p = (share_mode_entry*)smb_shm_offset2addr(
                                           file_scanner_p->share_mode_entries);
  entry_prev_p = entry_scanner_p;
  while(entry_scanner_p)
  {
    int pid = entry_scanner_p->pid;

    if (pid && !process_exists(pid))
    {
      /* Delete this share mode entry */
      share_mode_entry *delete_entry_p = entry_scanner_p;
      int share_mode = entry_scanner_p->share_mode;

      if(entry_prev_p == entry_scanner_p)
      {
        /* We are at start of list */
        file_scanner_p->share_mode_entries = entry_scanner_p->next_share_mode_entry;
        entry_scanner_p = (share_mode_entry*)smb_shm_offset2addr(
                                           file_scanner_p->share_mode_entries);
        entry_prev_p = entry_scanner_p;
      }
      else
      {
        entry_prev_p->next_share_mode_entry = entry_scanner_p->next_share_mode_entry;
        entry_scanner_p = (share_mode_entry*)
                           smb_shm_offset2addr(entry_scanner_p->next_share_mode_entry);
      }
      /* Decrement the number of share mode entries on this share mode record */
      file_scanner_p->num_share_mode_entries -= 1;

      /* PARANOIA TEST */
      if(file_scanner_p->num_share_mode_entries < 0)
      {
        DEBUG(0,("PANIC ERROR:get_share_mode (FAST_SHARE_MODES): num_share_mode_entries < 0 (%d) \
for dev = %d, ino = %d, hashbucket %d\n", file_scanner_p->num_share_mode_entries,
             dev, inode, hash_entry));
        return 0;
      }

      DEBUG(0,("get_share_modes (FAST_SHARE_MODES): process %d no longer exists and \
it left a share mode entry with mode 0x%X for file dev = %d, ino = %d in hash \
bucket %d (number of entries now = %d)\n", 
            pid, share_mode, dev, inode, hash_entry,
            file_scanner_p->num_share_mode_entries));

      smb_shm_free(smb_shm_addr2offset(delete_entry_p));
    } 
    else
    {
       /* This is a valid share mode entry and the process that
           created it still exists. Copy it into the output array.
       */
       share_array[num_entries_copied].pid = entry_scanner_p->pid;
       share_array[num_entries_copied].share_mode = entry_scanner_p->share_mode;
       share_array[num_entries_copied].op_port = entry_scanner_p->op_port;
       share_array[num_entries_copied].op_type = entry_scanner_p->op_type;
       memcpy(&share_array[num_entries_copied].time, &entry_scanner_p->time,
              sizeof(struct timeval));
       num_entries_copied++;
       DEBUG(5,("get_share_modes (FAST_SHARE_MODES): Read share mode \
record mode 0x%X pid=%d\n", entry_scanner_p->share_mode, entry_scanner_p->pid));
       entry_prev_p = entry_scanner_p;
       entry_scanner_p = (share_mode_entry *)
                           smb_shm_offset2addr(entry_scanner_p->next_share_mode_entry);
    }
  }
  
  /* If no valid share mode entries were found then this record shouldn't exist ! */
  if(num_entries_copied == 0)
  {
    DEBUG(0,("get_share_modes (FAST_SHARE_MODES): file with dev %d, inode %d in \
hash bucket %d has a share mode record but no entries - deleting\n", 
                 dev, inode, hash_entry));
    if(*old_shares)
      free((char *)*old_shares);
    *old_shares = 0;

    if(file_prev_p == file_scanner_p)
      mode_array[hash_entry] = file_scanner_p->next_offset;
    else
      file_prev_p->next_offset = file_scanner_p->next_offset;
    smb_shm_free(smb_shm_addr2offset(file_scanner_p));
  }

  DEBUG(5,("get_share_modes (FAST_SHARE_MODES): file with dev %d, inode %d in \
hash bucket %d returning %d entries\n", dev, inode, hash_entry, num_entries_copied));

  return(num_entries_copied);
}  

/*******************************************************************
del the share mode of a file.
********************************************************************/
void del_share_mode(share_lock_token token, int fnum)
{
  uint32 dev, inode;
  smb_shm_offset_t *mode_array;
  unsigned int hash_entry;
  share_mode_record *file_scanner_p;
  share_mode_record *file_prev_p;
  share_mode_entry *entry_scanner_p;
  share_mode_entry *entry_prev_p;
  BOOL found = False;
  int pid = getpid();

  dev = Files[fnum].fd_ptr->dev;
  inode = Files[fnum].fd_ptr->inode;

  hash_entry = HASH_ENTRY(dev, inode);

  if(hash_entry > lp_shmem_hash_size() )
  {
    DEBUG(0,
      ("PANIC ERROR:del_share_mode (FAST_SHARE_MODES): hash_entry %d too large \
(max = %d)\n",
      hash_entry, lp_shmem_hash_size() ));
    return;
  }

  mode_array = (smb_shm_offset_t *)smb_shm_offset2addr(smb_shm_get_userdef_off());
 
  if(mode_array[hash_entry] == NULL_OFFSET)
  {  
    DEBUG(0,("PANIC ERROR:del_share_mode (FAST_SHARE_MODES): hash bucket %d empty\n", 
                  hash_entry));
    return;
  }  
  
  file_scanner_p = (share_mode_record *)smb_shm_offset2addr(mode_array[hash_entry]);
  file_prev_p = file_scanner_p;

  while(file_scanner_p)
  {
    if( (file_scanner_p->st_dev == dev) && (file_scanner_p->st_ino == inode) )
    {
      found = True;
      break;
    }
    else
    {
      file_prev_p = file_scanner_p ;
      file_scanner_p = (share_mode_record *)
                        smb_shm_offset2addr(file_scanner_p->next_offset);
    }
  }
    
  if(!found)
  {
     DEBUG(0,("ERROR:del_share_mode (FAST_SHARE_MODES): no entry found for dev %d, \
inode %d in hash bucket %d\n", dev, inode, hash_entry));
     return;
  }
  
  if(file_scanner_p->locking_version != LOCKING_VERSION)
  {
    DEBUG(0,("ERROR: del_share_modes (FAST_SHARE_MODES): Deleting old share mode \
record due to old locking version %d for file dev %d, inode %d hash bucket %d\n",
       file_scanner_p->locking_version, dev, inode, hash_entry ));
    if(file_prev_p == file_scanner_p)
      mode_array[hash_entry] = file_scanner_p->next_offset;
    else
      file_prev_p->next_offset = file_scanner_p->next_offset;
    smb_shm_free(smb_shm_addr2offset(file_scanner_p));
    return;
  }

  found = False;
  entry_scanner_p = (share_mode_entry*)smb_shm_offset2addr(
                                         file_scanner_p->share_mode_entries);
  entry_prev_p = entry_scanner_p;
  while(entry_scanner_p)
  {
    if( (pid == entry_scanner_p->pid) && 
          (memcmp(&entry_scanner_p->time, 
                 &Files[fnum].open_time,sizeof(struct timeval)) == 0) )
    {
      found = True;
      break;
    }
    else
    {
      entry_prev_p = entry_scanner_p;
      entry_scanner_p = (share_mode_entry *)
                          smb_shm_offset2addr(entry_scanner_p->next_share_mode_entry);
    }
  } 

  if (found)
  {
    /* Decrement the number of entries in the record. */
    file_scanner_p->num_share_mode_entries -= 1;

    DEBUG(2,("del_share_modes (FAST_SHARE_MODES): \
Deleting share mode entry dev = %d, inode = %d in hash bucket %d (num entries now = %d)\n",
              dev, inode, hash_entry, file_scanner_p->num_share_mode_entries));
    if(entry_prev_p == entry_scanner_p)
      /* We are at start of list */
      file_scanner_p->share_mode_entries = entry_scanner_p->next_share_mode_entry;
    else
      entry_prev_p->next_share_mode_entry = entry_scanner_p->next_share_mode_entry;
    smb_shm_free(smb_shm_addr2offset(entry_scanner_p));

    /* PARANOIA TEST */
    if(file_scanner_p->num_share_mode_entries < 0)
    {
      DEBUG(0,("PANIC ERROR:del_share_mode (FAST_SHARE_MODES): num_share_mode_entries < 0 (%d) \
for dev = %d, ino = %d, hashbucket %d\n", file_scanner_p->num_share_mode_entries,
           dev, inode, hash_entry));
      return;
    }

    /* If we deleted the last share mode entry then remove the share mode record. */
    if(file_scanner_p->num_share_mode_entries == 0)
    {
      DEBUG(2,("del_share_modes (FAST_SHARE_MODES): num entries = 0, deleting share_mode \
record dev = %d, inode = %d in hash bucket %d\n", dev, inode, hash_entry));
      if(file_prev_p == file_scanner_p)
        mode_array[hash_entry] = file_scanner_p->next_offset;
      else
        file_prev_p->next_offset = file_scanner_p->next_offset;
      smb_shm_free(smb_shm_addr2offset(file_scanner_p));
    }
  }
  else
  {
    DEBUG(0,("ERROR: del_share_modes (FAST_SHARE_MODES): No share mode record found \
dev = %d, inode = %d in hash bucket %d\n", dev, inode, hash_entry));
  }
}

/*******************************************************************
set the share mode of a file. Return False on fail, True on success.
********************************************************************/
BOOL set_share_mode(share_lock_token token, int fnum, uint16 port, uint16 op_type)
{
  files_struct *fs_p = &Files[fnum];
  int32 dev, inode;
  smb_shm_offset_t *mode_array;
  unsigned int hash_entry;
  share_mode_record *file_scanner_p;
  share_mode_record *file_prev_p;
  share_mode_entry *new_entry_p;
  smb_shm_offset_t new_entry_offset;
  BOOL found = False;

  dev = fs_p->fd_ptr->dev;
  inode = fs_p->fd_ptr->inode;

  hash_entry = HASH_ENTRY(dev, inode);
  if(hash_entry > lp_shmem_hash_size() )
  {
    DEBUG(0,
      ("PANIC ERROR:set_share_mode (FAST_SHARE_MODES): hash_entry %d too large \
(max = %d)\n",
      hash_entry, lp_shmem_hash_size() ));
    return False;
  }

  mode_array = (smb_shm_offset_t *)smb_shm_offset2addr(smb_shm_get_userdef_off());

  file_scanner_p = (share_mode_record *)smb_shm_offset2addr(mode_array[hash_entry]);
  file_prev_p = file_scanner_p;
  
  while(file_scanner_p)
  {
    if( (file_scanner_p->st_dev == dev) && (file_scanner_p->st_ino == inode) )
    {
      found = True;
      break;
    }
    else
    {
      file_prev_p = file_scanner_p ;
      file_scanner_p = (share_mode_record *)
                         smb_shm_offset2addr(file_scanner_p->next_offset);
    }
  }
  
  if(!found)
  {
    /* We must create a share_mode_record */
    share_mode_record *new_mode_p = NULL;
    smb_shm_offset_t new_offset = smb_shm_alloc( sizeof(share_mode_record) +
                                        strlen(fs_p->name) + 1);
    if(new_offset == NULL_OFFSET)
    {
      DEBUG(0,("ERROR:set_share_mode (FAST_SHARE_MODES): smb_shm_alloc fail !\n"));
      return False;
    }
    new_mode_p = smb_shm_offset2addr(new_offset);
    new_mode_p->locking_version = LOCKING_VERSION;
    new_mode_p->st_dev = dev;
    new_mode_p->st_ino = inode;
    new_mode_p->num_share_mode_entries = 0;
    new_mode_p->share_mode_entries = NULL_OFFSET;
    strcpy(new_mode_p->file_name, fs_p->name);

    /* Chain onto the start of the hash chain (in the hope we will be used first). */
    new_mode_p->next_offset = mode_array[hash_entry];
    mode_array[hash_entry] = new_offset;

    file_scanner_p = new_mode_p;

    DEBUG(3,("set_share_mode (FAST_SHARE_MODES): Created share record for %s (dev %d \
inode %d in hash bucket %d\n", fs_p->name, dev, inode, hash_entry));
  }
 
  /* Now create the share mode entry */ 
  new_entry_offset = smb_shm_alloc( sizeof(share_mode_entry));
  if(new_entry_offset == NULL_OFFSET)
  {
    smb_shm_offset_t delete_offset = mode_array[hash_entry];
    DEBUG(0,("ERROR:set_share_mode (FAST_SHARE_MODES): smb_shm_alloc fail 1!\n"));
    /* Unlink the damaged record */
    mode_array[hash_entry] = file_scanner_p->next_offset;
    /* And delete it */
    smb_shm_free( delete_offset );
    return False;
  }

  new_entry_p = smb_shm_offset2addr(new_entry_offset);

  new_entry_p->pid = getpid();
  new_entry_p->share_mode = fs_p->share_mode;
  new_entry_p->op_port = port;
  new_entry_p->op_type = op_type;
  memcpy( (char *)&new_entry_p->time, (char *)&fs_p->open_time, sizeof(struct timeval));

  /* Chain onto the share_mode_record */
  new_entry_p->next_share_mode_entry = file_scanner_p->share_mode_entries;
  file_scanner_p->share_mode_entries = new_entry_offset;

  /* PARANOIA TEST */
  if(file_scanner_p->num_share_mode_entries < 0)
  {
    DEBUG(0,("PANIC ERROR:set_share_mode (FAST_SHARE_MODES): num_share_mode_entries < 0 (%d) \
for dev = %d, ino = %d, hashbucket %d\n", file_scanner_p->num_share_mode_entries,
         dev, inode, hash_entry));
    return False;
  }

  /* Increment the share_mode_entries counter */
  file_scanner_p->num_share_mode_entries += 1;

  DEBUG(3,("set_share_mode (FAST_SHARE_MODES): Created share entry for %s with mode \
0x%X pid=%d (num_entries now = %d)\n",fs_p->name, fs_p->share_mode, new_entry_p->pid,
                             file_scanner_p->num_share_mode_entries));

  return(True);
}

/*******************************************************************
Remove an oplock port and mode entry from a share mode.
********************************************************************/
BOOL remove_share_oplock(int fnum, share_lock_token token)
{
  uint32 dev, inode;
  smb_shm_offset_t *mode_array;
  unsigned int hash_entry;
  share_mode_record *file_scanner_p;
  share_mode_record *file_prev_p;
  share_mode_entry *entry_scanner_p;
  share_mode_entry *entry_prev_p;
  BOOL found = False;
  int pid = getpid();

  dev = Files[fnum].fd_ptr->dev;
  inode = Files[fnum].fd_ptr->inode;

  hash_entry = HASH_ENTRY(dev, inode);

  if(hash_entry > lp_shmem_hash_size() )
  {
    DEBUG(0,
      ("PANIC ERROR:remove_share_oplock (FAST_SHARE_MODES): hash_entry %d too large \
(max = %d)\n",
      hash_entry, lp_shmem_hash_size() ));
    return False;
  }

  mode_array = (smb_shm_offset_t *)smb_shm_offset2addr(smb_shm_get_userdef_off());

  if(mode_array[hash_entry] == NULL_OFFSET)
  {
    DEBUG(0,("PANIC ERROR:remove_share_oplock (FAST_SHARE_MODES): hash bucket %d empty\n",
                  hash_entry));
    return False;
  } 
    
  file_scanner_p = (share_mode_record *)smb_shm_offset2addr(mode_array[hash_entry]);
  file_prev_p = file_scanner_p;
    
  while(file_scanner_p)
  { 
    if( (file_scanner_p->st_dev == dev) && (file_scanner_p->st_ino == inode) )
    {
      found = True;
      break;
    }
    else
    {
      file_prev_p = file_scanner_p ;
      file_scanner_p = (share_mode_record *)
                        smb_shm_offset2addr(file_scanner_p->next_offset);
    }
  } 
   
  if(!found)
  { 
     DEBUG(0,("ERROR:remove_share_oplock (FAST_SHARE_MODES): no entry found for dev %d, \
inode %d in hash bucket %d\n", dev, inode, hash_entry));
     return False;
  } 

  if(file_scanner_p->locking_version != LOCKING_VERSION)
  {
    DEBUG(0,("ERROR: remove_share_oplock (FAST_SHARE_MODES): Deleting old share mode \
record due to old locking version %d for file dev %d, inode %d hash bucket %d\n",
       file_scanner_p->locking_version, dev, inode, hash_entry ));
    if(file_prev_p == file_scanner_p)
      mode_array[hash_entry] = file_scanner_p->next_offset;
    else
      file_prev_p->next_offset = file_scanner_p->next_offset;
    smb_shm_free(smb_shm_addr2offset(file_scanner_p));
    return False;
  }

  found = False;
  entry_scanner_p = (share_mode_entry*)smb_shm_offset2addr(
                                         file_scanner_p->share_mode_entries);
  entry_prev_p = entry_scanner_p;
  while(entry_scanner_p)
  {
    if( (pid == entry_scanner_p->pid) && 
        (entry_scanner_p->share_mode == Files[fnum].share_mode) &&
        (memcmp(&entry_scanner_p->time, 
                &Files[fnum].open_time,sizeof(struct timeval)) == 0) )
    {
      /* Delete the oplock info. */
      entry_scanner_p->op_port = 0;
      entry_scanner_p->op_type = 0;
      found = True;
      break;
    }
    else
    {
      entry_prev_p = entry_scanner_p;
      entry_scanner_p = (share_mode_entry *)
                          smb_shm_offset2addr(entry_scanner_p->next_share_mode_entry);
    }
  } 

  if(!found)
  {
    DEBUG(0,("ERROR: remove_share_oplock (FAST_SHARE_MODES): No oplock granted share \
mode record found dev = %d, inode = %d in hash bucket %d\n", dev, inode, hash_entry));
    return False;
  }

  return True;
}

#else /* FAST_SHARE_MODES */

/* SHARE MODE LOCKS USING SLOW DESCRIPTION FILES */

/*******************************************************************
  name a share file
  ******************************************************************/
static BOOL share_name(int cnum, uint32 dev, uint32 inode, char *name)
{
  strcpy(name,lp_lockdir());
  standard_sub(cnum,name);
  trim_string(name,"","/");
  if (!*name) return(False);
  name += strlen(name);
  
  sprintf(name,"/share.%u.%u",dev,inode);
  return(True);
}

/*******************************************************************
Force a share file to be deleted.
********************************************************************/

static int delete_share_file( int cnum, char *fname )
{
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
BOOL lock_share_entry(int cnum, uint32 dev, uint32 inode, share_lock_token *ptok)
{
  pstring fname;
  int fd;
  int ret = True;

  *ptok = (share_lock_token)-1;

  if(!share_name(cnum, dev, inode, fname))
    return False;

  /* we need to do this as root */
  become_root(False);

  {
    int old_umask;
    BOOL gotlock = False;
    old_umask = umask(0);

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

#ifdef SECURE_SHARE_MODES
      fd = (share_lock_token)open(fname,O_RDWR|O_CREAT,0600);
#else /* SECURE_SHARE_MODES */
      fd = (share_lock_token)open(fname,O_RDWR|O_CREAT,0666);
#endif /* SECURE_SHARE_MODES */

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

    umask(old_umask);
  }

  *ptok = (share_lock_token)fd;

  /* return to our previous privilage level */
  unbecome_root(False);

  return ret;
}

/*******************************************************************
  unlock a share mode file.
  ******************************************************************/
BOOL unlock_share_entry(int cnum, uint32 dev, uint32 inode, share_lock_token token)
{
  int fd = (int)token;
  int ret = True;
  struct stat sb;
  pstring fname;

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
int get_share_modes(int cnum, share_lock_token token, uint32 dev, uint32 inode, 
                    min_share_mode_entry **old_shares)
{
  int fd = (int)token;
  pstring fname;
  int i;
  int num_entries;
  int num_entries_copied;
  int newsize;
  min_share_mode_entry *share_array;
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
    *old_shares = share_array = (min_share_mode_entry *)
                 malloc(num_entries * sizeof(min_share_mode_entry));
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
    if(ftruncate(fd, newsize)!= 0)
    {
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

  if(buf)
    free(buf);

  DEBUG(5,("get_share_modes: Read share file %s returning %d entries\n",fname,
            num_entries_copied));

  return num_entries_copied;
}

/*******************************************************************
del a share mode from a share mode file.
********************************************************************/
void del_share_mode(share_lock_token token, int fnum)
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
  if(ftruncate(fd, newsize) != 0)
  {
    DEBUG(0,("ERROR: del_share_mode: failed to ftruncate share \
mode file %s to size %d (%s)\n", fname, newsize, strerror(errno)));
    if(buf)
      free(buf);
    return;
  }
}
  
/*******************************************************************
set the share mode of a file
********************************************************************/
BOOL set_share_mode(share_lock_token token,int fnum, uint16 port, uint16 op_type)
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
    strcpy(buf + SMF_HEADER_LENGTH, fs_p->name);
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
  if(ftruncate(fd, header_size + (SMF_ENTRY_LENGTH*num_entries))!= 0)
  {
    DEBUG(0,("ERROR: set_share_mode: failed to ftruncate share \
mode file %s to size %d (%s)\n", fname, header_size + (SMF_ENTRY_LENGTH*num_entries), 
                strerror(errno)));
    if(buf)
      free(buf);
    return False;
  }

  if(buf)
    free(buf);

  DEBUG(3,("set_share_mode: Created share file %s with \
mode 0x%X pid=%d\n",fname,fs_p->share_mode,pid));

  return True;
}

/*******************************************************************
Remove an oplock port and mode entry from a share mode.
********************************************************************/
BOOL remove_share_oplock(int fnum, share_lock_token token)
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
#endif /* FAST_SHARE_MODES */
