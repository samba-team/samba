/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB NT transaction handling
   Copyright (C) Jeremy Allison 1994-1998

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
extern int Protocol;
extern int chain_fnum;
extern connection_struct Connections[];
extern files_struct Files[];
extern int Client;  
extern int oplock_sock;
extern int smb_read_error;
extern int global_oplock_break;
extern BOOL case_sensitive;
extern BOOL case_preserve;
extern BOOL short_case_preserve;

static char *known_nt_pipes[] = {
  "\\LANMAN",
  "\\srvsvc",
  "\\samr",
  "\\wkssvc",
  "\\NETLOGON",
  "\\ntlsa",
  "\\ntsvcs",
  "\\lsass",
  "\\lsarpc",
  NULL
};

/****************************************************************************
 Send the required number of replies back.
 We assume all fields other than the data fields are
 set correctly for the type of call.
 HACK ! Always assumes smb_setup field is zero.
****************************************************************************/

static int send_nt_replies(char *outbuf, int bufsize, char *params,
                           int paramsize, char *pdata, int datasize)
{
  extern int max_send;
  int data_to_send = datasize;
  int params_to_send = paramsize;
  int useable_space;
  char *pp = params;
  char *pd = pdata;
  int params_sent_thistime, data_sent_thistime, total_sent_thistime;
  int alignment_offset = 3;
  int data_alignment_offset = 0;

  /*
   * Initially set the wcnt area to be 18 - this is true for all
   * transNT replies.
   */

  set_message(outbuf,18,0,True);

  /* 
   * If there genuinely are no parameters or data to send just send
   * the empty packet.
   */

  if(params_to_send == 0 && data_to_send == 0) {
    send_smb(Client,outbuf);
    return 0;
  }

  /*
   * When sending params and data ensure that both are nicely aligned.
   * Only do this alignment when there is also data to send - else
   * can cause NT redirector problems.
   */

  if (((params_to_send % 4) != 0) && (data_to_send != 0))
    data_alignment_offset = 4 - (params_to_send % 4);

  /* 
   * Space is bufsize minus Netbios over TCP header minus SMB header.
   * The alignment_offset is to align the param bytes on a four byte
   * boundary (2 bytes for data len, one byte pad). 
   * NT needs this to work correctly.
   */

  useable_space = bufsize - ((smb_buf(outbuf)+
                    alignment_offset+data_alignment_offset) -
                    outbuf);

  /*
   * useable_space can never be more than max_send minus the
   * alignment offset.
   */

  useable_space = MIN(useable_space,
                      max_send - (alignment_offset+data_alignment_offset));


  while (params_to_send || data_to_send) {

    /*
     * Calculate whether we will totally or partially fill this packet.
     */

    total_sent_thistime = params_to_send + data_to_send +
                            alignment_offset + data_alignment_offset;

    /* 
     * We can never send more than useable_space.
     */

    total_sent_thistime = MIN(total_sent_thistime, useable_space);

    set_message(outbuf, 18, total_sent_thistime, True);

    /*
     * Set total params and data to be sent.
     */

    SIVAL(outbuf,smb_ntr_TotalParameterCount,paramsize);
    SIVAL(outbuf,smb_ntr_TotalDataCount,datasize);

    /* 
     * Calculate how many parameters and data we can fit into
     * this packet. Parameters get precedence.
     */

    params_sent_thistime = MIN(params_to_send,useable_space);
    data_sent_thistime = useable_space - params_sent_thistime;
    data_sent_thistime = MIN(data_sent_thistime,data_to_send);

    SIVAL(outbuf,smb_ntr_ParameterCount,params_sent_thistime);

    if(params_sent_thistime == 0) {
      SIVAL(outbuf,smb_ntr_ParameterOffset,0);
      SIVAL(outbuf,smb_ntr_ParameterDisplacement,0);
    } else {
      /*
       * smb_ntr_ParameterOffset is the offset from the start of the SMB header to the
       * parameter bytes, however the first 4 bytes of outbuf are
       * the Netbios over TCP header. Thus use smb_base() to subtract
       * them from the calculation.
       */

      SIVAL(outbuf,smb_ntr_ParameterOffset,
            ((smb_buf(outbuf)+alignment_offset) - smb_base(outbuf)));
      /* 
       * Absolute displacement of param bytes sent in this packet.
       */

      SIVAL(outbuf,smb_ntr_ParameterDisplacement,pp - params);
    }

    /*
     * Deal with the data portion.
     */

    SIVAL(outbuf,smb_ntr_DataCount, data_sent_thistime);

    if(data_sent_thistime == 0) {
      SIVAL(outbuf,smb_ntr_DataOffset,0);
      SIVAL(outbuf,smb_ntr_DataDisplacement, 0);
    } else {
      /*
       * The offset of the data bytes is the offset of the
       * parameter bytes plus the number of parameters being sent this time.
       */

      SIVAL(outbuf,smb_ntr_DataOffset,((smb_buf(outbuf)+alignment_offset) -
            smb_base(outbuf)) + params_sent_thistime + data_alignment_offset);
      SIVAL(outbuf,smb_ntr_DataDisplacement, pd - pdata);
    }

    /* 
     * Copy the param bytes into the packet.
     */

    if(params_sent_thistime)
      memcpy((smb_buf(outbuf)+alignment_offset),pp,params_sent_thistime);

    /*
     * Copy in the data bytes
     */

    if(data_sent_thistime)
      memcpy(smb_buf(outbuf)+alignment_offset+params_sent_thistime+
             data_alignment_offset,pd,data_sent_thistime);
    
    DEBUG(9,("nt_rep: params_sent_thistime = %d, data_sent_thistime = %d, useable_space = %d\n",
          params_sent_thistime, data_sent_thistime, useable_space));
    DEBUG(9,("nt_rep: params_to_send = %d, data_to_send = %d, paramsize = %d, datasize = %d\n",
          params_to_send, data_to_send, paramsize, datasize));
    
    /* Send the packet */
    send_smb(Client,outbuf);
    
    pp += params_sent_thistime;
    pd += data_sent_thistime;
    
    params_to_send -= params_sent_thistime;
    data_to_send -= data_sent_thistime;

    /*
     * Sanity check
     */

    if(params_to_send < 0 || data_to_send < 0) {
      DEBUG(0,("send_nt_replies failed sanity check pts = %d, dts = %d\n!!!",
            params_to_send, data_to_send));
      return -1;
    }
  } 

  return 0;
}

/****************************************************************************
 Save case statics.
****************************************************************************/

static BOOL saved_case_sensitive;
static BOOL saved_case_preserve;
static BOOL saved_short_case_preserve;

/****************************************************************************
 Save case semantics.
****************************************************************************/

static void set_posix_case_semantics(uint32 file_attributes)
{
  if(!(file_attributes & FILE_FLAG_POSIX_SEMANTICS))
    return;

  saved_case_sensitive = case_sensitive;
  saved_case_preserve = case_preserve;
  saved_short_case_preserve = short_case_preserve;

  /* Set to POSIX. */
  case_sensitive = True;
  case_preserve = True;
  short_case_preserve = True;
}

/****************************************************************************
 Restore case semantics.
****************************************************************************/

static void restore_case_semantics(uint32 file_attributes)
{
  if(!(file_attributes & FILE_FLAG_POSIX_SEMANTICS))
    return;

  case_sensitive = saved_case_sensitive;
  case_preserve = saved_case_preserve;
  short_case_preserve = saved_short_case_preserve;
}

/****************************************************************************
 Utility function to map create disposition.
****************************************************************************/

static int map_create_disposition( uint32 create_disposition)
{
  switch( create_disposition ) {
  case FILE_CREATE:
    /* create if not exist, fail if exist */
    return 0x10;
  case FILE_SUPERSEDE:
  case FILE_OVERWRITE_IF:
    /* create if not exist, trunc if exist */
    return 0x12;
  case FILE_OPEN:
    /* fail if not exist, open if exists */
    return 0x1;
  case FILE_OPEN_IF:
    /* create if not exist, open if exists */
    return 0x11;
  case FILE_OVERWRITE:
    /* fail if not exist, truncate if exists */
    return 0x2;
  default:
    DEBUG(0,("map_create_disposition: Incorrect value for create_disposition = %d\n",
             create_disposition ));
    return -1;
  }
}

/****************************************************************************
 Utility function to map share modes.
****************************************************************************/

static int map_share_mode( uint32 desired_access, uint32 share_access, uint32 file_attributes)
{
  int smb_open_mode = -1;

  switch( desired_access & (FILE_READ_DATA|FILE_WRITE_DATA) ) {
  case FILE_READ_DATA:
    smb_open_mode = 0;
    break;
  case FILE_WRITE_DATA:
    smb_open_mode = 1;
    break;
  case FILE_READ_DATA|FILE_WRITE_DATA:
    smb_open_mode = 2;
    break;
  }

  if (smb_open_mode == -1) {
    if(desired_access & DELETE_ACCESS)
      smb_open_mode = 2;
    else if( desired_access & FILE_EXECUTE)
      smb_open_mode = 0;
    else {
      DEBUG(0,("map_share_mode: Incorrect value for desired_access = %x\n",
             desired_access));
      return -1;
    }
  }

  /* Add in the requested share mode - ignore FILE_SHARE_DELETE for now. */
  switch( share_access & (FILE_SHARE_READ|FILE_SHARE_WRITE)) {
  case FILE_SHARE_READ:
    smb_open_mode |= (DENY_WRITE<<4);
    break;
  case FILE_SHARE_WRITE:
    smb_open_mode |= (DENY_READ<<4);
    break;
  case (FILE_SHARE_READ|FILE_SHARE_WRITE):
    smb_open_mode |= (DENY_NONE<<4);
    break;
  case FILE_SHARE_NONE:
    smb_open_mode |= (DENY_ALL<<4);
    break;
  }

  /*
   * Handle a O_SYNC request.
   */
  if(file_attributes & FILE_FLAG_WRITE_THROUGH)
    smb_open_mode |= (1<<14);

  return smb_open_mode;
}

/****************************************************************************
 Reply to an NT create and X call on a pipe.
****************************************************************************/

static int nt_open_pipe(char *fname, char *inbuf, char *outbuf, int *ppnum)
{
  int cnum = SVAL(inbuf,smb_tid);
  int pnum = -1;
  uint16 vuid = SVAL(inbuf, smb_uid);
  int i;

  DEBUG(4,("nt_open_pipe: Opening pipe %s.\n", fname));
    
  /* See if it is one we want to handle. */
  for( i = 0; known_nt_pipes[i]; i++ )
    if( strequal(fname,known_nt_pipes[i]))
      break;
    
  if ( known_nt_pipes[i] == NULL )
    return(ERROR(ERRSRV,ERRaccess));
    
  /* Strip \\ off the name. */
  fname++;
    
  DEBUG(3,("nt_open_pipe: Known pipe %s opening.\n", fname));

  pnum = open_rpc_pipe_hnd(fname, cnum, vuid);
  if (pnum < 0)
    return(ERROR(ERRSRV,ERRnofids));

  *ppnum = pnum + 0x800; /* Mark file handle up into high range. */
  return 0;
}

/****************************************************************************
 Reply to an NT create and X call.
****************************************************************************/

int reply_ntcreate_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{  
  pstring fname;
  int cnum = SVAL(inbuf,smb_tid);
  int fnum = -1;
  uint32 flags = IVAL(inbuf,smb_ntcreate_Flags);
  uint32 desired_access = IVAL(inbuf,smb_ntcreate_DesiredAccess);
  uint32 file_attributes = IVAL(inbuf,smb_ntcreate_FileAttributes);
  uint32 share_access = IVAL(inbuf,smb_ntcreate_ShareAccess);
  uint32 create_disposition = IVAL(inbuf,smb_ntcreate_CreateDisposition);
  uint32 fname_len = MIN(((uint32)SVAL(inbuf,smb_ntcreate_NameLength)),
                         ((uint32)sizeof(fname)-1));
  int smb_ofun;
  int smb_open_mode;
  int smb_attr = (file_attributes & SAMBA_ATTRIBUTES_MASK);
  /* Breakout the oplock request bits so we can set the
     reply bits separately. */
  int oplock_request = 0;
  int unixmode;
  int fmode=0,mtime=0,rmode=0;
  off_t file_len = 0;
  struct stat sbuf;
  int smb_action = 0;
  BOOL bad_path = False;
  files_struct *fsp;
  char *p = NULL;
  
  /* 
   * We need to construct the open_and_X ofun value from the
   * NT values, as that's what our code is structured to accept.
   */    

  if((smb_ofun = map_create_disposition( create_disposition )) == -1)
    return(ERROR(ERRDOS,ERRbadaccess));

  /*
   * Now contruct the smb_open_mode value from the desired access
   * and the share access.
   */

  if((smb_open_mode = map_share_mode( desired_access, share_access, file_attributes)) == -1)
    return(ERROR(ERRDOS,ERRbadaccess));

  /*
   * Get the file name.
   */
  StrnCpy(fname,smb_buf(inbuf),fname_len);
  fname[fname_len] = '\0';

  /* If it's an IPC, use the pipe handler. */
  if (IS_IPC(cnum)) {
    int ret = nt_open_pipe(fname, inbuf, outbuf, &fnum);
    if(ret != 0)
      return ret;
    smb_action = FILE_WAS_OPENED;
  } else {

    /*
     * Ordinary file or directory.
     */

    /*
     * Check if POSIX semantics are wanted.
     */

    set_posix_case_semantics(file_attributes);

    unix_convert(fname,cnum,0,&bad_path);
    
    fnum = find_free_file();
    if (fnum < 0) {
      restore_case_semantics(file_attributes);
      return(ERROR(ERRSRV,ERRnofids));
    }

    fsp = &Files[fnum];
    
    if (!check_name(fname,cnum)) { 
      if((errno == ENOENT) && bad_path) {
        unix_ERR_class = ERRDOS;
        unix_ERR_code = ERRbadpath;
      }
      fsp->reserved = False;

      restore_case_semantics(file_attributes);

      return(UNIXERROR(ERRDOS,ERRnoaccess));
    } 
  
    unixmode = unix_mode(cnum,smb_attr | aARCH);
    
    oplock_request = (flags & REQUEST_OPLOCK) ? EXCLUSIVE_OPLOCK : 0;
    oplock_request |= (flags & REQUEST_BATCH_OPLOCK) ? BATCH_OPLOCK : 0;

    /* 
     * If it's a request for a directory open, deal with it separately.
     */

    if(flags & OPEN_DIRECTORY) {
      oplock_request = 0;

      open_directory(fnum, cnum, fname, smb_ofun, unixmode, &smb_action);

      restore_case_semantics(file_attributes);

      if(!fsp->open) {
        fsp->reserved = False;
        return(UNIXERROR(ERRDOS,ERRnoaccess));
      }
    } else {

      /*
       * Ordinary file case.
       */

      /*
       * NB. We have a potential bug here. If we cause an oplock
       * break to ourselves, then we could end up processing filename
       * related SMB requests whilst we await the oplock break
       * response. As we may have changed the filename case
       * semantics to be POSIX-like, this could mean a filename
       * request could fail when it should succeed. This is a
       * rare condition, but eventually we must arrange to restore
       * the correct case semantics before issuing an oplock break
       * request to our client. JRA.
       */

      open_file_shared(fnum,cnum,fname,smb_open_mode,smb_ofun,unixmode,
                       oplock_request,&rmode,&smb_action);

      if (!fsp->open) { 
        /*
         * We cheat here. The only case we care about is a directory
         * rename, where the NT client will attempt to open the source
         * directory for DELETE access. Note that when the NT client
         * does this it does *not* set the directory bit in the
         * request packet. This is translated into a read/write open
         * request. POSIX states that any open for write request on a directory
         * will generate an EISDIR error, so we can catch this here and open
         * a pseudo handle that is flagged as a directory. JRA.
         */

        if(errno == EISDIR) {
          oplock_request = 0;

          open_directory(fnum, cnum, fname, smb_ofun, unixmode, &smb_action);

          if(!fsp->open) {
            fsp->reserved = False;
            restore_case_semantics(file_attributes);
            return(UNIXERROR(ERRDOS,ERRnoaccess));
          }
        } else {
          if((errno == ENOENT) && bad_path) {
            unix_ERR_class = ERRDOS;
            unix_ERR_code = ERRbadpath;
          }

          fsp->reserved = False;

          restore_case_semantics(file_attributes);

          return(UNIXERROR(ERRDOS,ERRnoaccess));
        }
      } 
    }
  
    if(fsp->is_directory) {
      if(sys_stat(fsp->name, &sbuf) != 0) {
        close_directory(fnum);
        restore_case_semantics(file_attributes);
        return(ERROR(ERRDOS,ERRnoaccess));
      }
    } else {
      if (fstat(fsp->f_u.fd_ptr->fd,&sbuf) != 0) {
        close_file(fnum,False);
        restore_case_semantics(file_attributes);
        return(ERROR(ERRDOS,ERRnoaccess));
      } 
    }
  
    restore_case_semantics(file_attributes);

    file_len = sbuf.st_size;
    fmode = dos_mode(cnum,fname,&sbuf);
    if(fmode == 0)
      fmode = FILE_ATTRIBUTE_NORMAL;
    mtime = sbuf.st_mtime;
    if (!fsp->is_directory && (fmode & aDIR)) {
      close_file(fnum,False);
      return(ERROR(ERRDOS,ERRnoaccess));
    } 
  
    /* 
     * If the caller set the extended oplock request bit
     * and we granted one (by whatever means) - set the
     * correct bit for extended oplock reply.
     */
    
    if (oplock_request && lp_fake_oplocks(SNUM(cnum)))
      smb_action |= EXTENDED_OPLOCK_GRANTED;
  
    if(oplock_request && fsp->granted_oplock)
      smb_action |= EXTENDED_OPLOCK_GRANTED;
  }
 
  set_message(outbuf,34,0,True);

  p = outbuf + smb_vwv2;

  /*
   * Currently as we don't support level II oplocks we just report
   * exclusive & batch here.
   */

  SCVAL(p,0, (smb_action & EXTENDED_OPLOCK_GRANTED ? 1 : 0));
  p++;
  SSVAL(p,0,fnum);
  p += 2;
  SIVAL(p,0,smb_action);
  p += 4;

  if (IS_IPC(cnum)) {
    /*
     * Deal with pipe return.
     */  
    p += 32;
    SIVAL(p,0,FILE_ATTRIBUTE_NORMAL); /* File Attributes. */
    p += 20;
    /* File type. */
    SSVAL(p,0,FILE_TYPE_MESSAGE_MODE_PIPE);
    /* Device state. */
    SSVAL(p,2, 0x5FF); /* ? */
  } else {
    /*
     * Deal with file return.
     */  
    /* Create time. */  
    put_long_date(p,get_create_time(&sbuf,lp_fake_dir_create_times(SNUM(cnum))));
    p += 8;
    put_long_date(p,sbuf.st_atime); /* access time */
    p += 8;
    put_long_date(p,sbuf.st_mtime); /* write time */
    p += 8;
    put_long_date(p,sbuf.st_mtime); /* change time */
    p += 8;
    SIVAL(p,0,fmode); /* File Attributes. */
    p += 12;
#if OFF_T_IS_64_BITS
      SIVAL(p,0, file_len & 0xFFFFFFFF);
      SIVAL(p,4, file_len >> 32);
#else /* OFF_T_IS_64_BITS */
      SIVAL(p,0,file_len);
#endif /* OFF_T_IS_64_BITS */
    p += 12;
    SCVAL(p,0,fsp->is_directory ? 1 : 0);
  }

  chain_fnum = fnum;

  return chain_reply(inbuf,outbuf,length,bufsize);
}

/****************************************************************************
 Reply to a NT_TRANSACT_CREATE call (needs to process SD's).
****************************************************************************/

static int call_nt_transact_create(char *inbuf, char *outbuf, int length, 
                                   int bufsize, int cnum,
                                   char **ppsetup, char **ppparams, char **ppdata)
{
  pstring fname;
  int fnum = -1;
  char *params = *ppparams;
  uint32 flags = IVAL(params,0);
  uint32 desired_access = IVAL(params,8);
  uint32 file_attributes = IVAL(params,20);
  uint32 share_access = IVAL(params,24);
  uint32 create_disposition = IVAL(params,28);
  uint32 fname_len = MIN(((uint32)IVAL(params,44)),
                         ((uint32)sizeof(fname)-1));
  int smb_ofun;
  int smb_open_mode;
  int smb_attr = (file_attributes & SAMBA_ATTRIBUTES_MASK);
  /* Breakout the oplock request bits so we can set the
     reply bits separately. */
  int oplock_request = 0;
  int unixmode;
  int fmode=0,mtime=0,rmode=0;
  off_t file_len = 0;
  struct stat sbuf;
  int smb_action = 0;
  BOOL bad_path = False;
  files_struct *fsp;
  char *p = NULL;

  /* 
   * We need to construct the open_and_X ofun value from the
   * NT values, as that's what our code is structured to accept.
   */    

  if((smb_ofun = map_create_disposition( create_disposition )) == -1)
    return(ERROR(ERRDOS,ERRbadaccess));

  /*
   * Now contruct the smb_open_mode value from the desired access
   * and the share access.
   */

  if((smb_open_mode = map_share_mode( desired_access, share_access, file_attributes)) == -1)
    return(ERROR(ERRDOS,ERRbadaccess));

  /*
   * Get the file name.
   */

  StrnCpy(fname,params+53,fname_len);
  fname[fname_len] = '\0';

  /* If it's an IPC, use the pipe handler. */
  if (IS_IPC(cnum)) {
    int ret = nt_open_pipe(fname, inbuf, outbuf, &fnum);
    if(ret != 0)
      return ret;
    smb_action = FILE_WAS_OPENED;
  } else {
    /*
     * Check if POSIX semantics are wanted.
     */

    set_posix_case_semantics(file_attributes);

    unix_convert(fname,cnum,0,&bad_path);
    
    fnum = find_free_file();
    if (fnum < 0) {
      restore_case_semantics(file_attributes);
      return(ERROR(ERRSRV,ERRnofids));
    }

    if (!check_name(fname,cnum)) { 
      if((errno == ENOENT) && bad_path) {
        unix_ERR_class = ERRDOS;
        unix_ERR_code = ERRbadpath;
      }
      Files[fnum].reserved = False;

      restore_case_semantics(file_attributes);

      return(UNIXERROR(ERRDOS,ERRnoaccess));
    } 
  
    unixmode = unix_mode(cnum,smb_attr | aARCH);
    
    oplock_request = (flags & REQUEST_OPLOCK) ? EXCLUSIVE_OPLOCK : 0;
    oplock_request |= (flags & REQUEST_BATCH_OPLOCK) ? BATCH_OPLOCK : 0;

    /*
     * If it's a request for a directory open, deal with it separately.
     */

    if(flags & OPEN_DIRECTORY) {

      oplock_request = 0;

      /*
       * We will get a create directory here if the Win32
       * app specified a security descriptor in the 
       * CreateDirectory() call.
       */

      open_directory(fnum, cnum, fname, smb_ofun, unixmode, &smb_action);

      if(!fsp->open) {
        fsp->reserved = False;
        return(UNIXERROR(ERRDOS,ERRnoaccess));
      }
    } else {

      /*
       * Ordinary file case.
       */

      open_file_shared(fnum,cnum,fname,smb_open_mode,smb_ofun,unixmode,
                       oplock_request,&rmode,&smb_action);

      fsp = &Files[fnum];
    
      if (!fsp->open) { 
        if((errno == ENOENT) && bad_path) {
          unix_ERR_class = ERRDOS;
          unix_ERR_code = ERRbadpath;
        }
        Files[fnum].reserved = False;

        restore_case_semantics(file_attributes);

        return(UNIXERROR(ERRDOS,ERRnoaccess));
      } 
  
      if (fstat(fsp->f_u.fd_ptr->fd,&sbuf) != 0) {
        close_file(fnum,False);

        restore_case_semantics(file_attributes);

        return(ERROR(ERRDOS,ERRnoaccess));
      } 
  
      file_len = sbuf.st_size;
      fmode = dos_mode(cnum,fname,&sbuf);
      if(fmode == 0)
        fmode = FILE_ATTRIBUTE_NORMAL;
      mtime = sbuf.st_mtime;

      if (fmode & aDIR) {
        close_file(fnum,False);
        restore_case_semantics(file_attributes);
        return(ERROR(ERRDOS,ERRnoaccess));
      } 

      /* 
       * If the caller set the extended oplock request bit
       * and we granted one (by whatever means) - set the
       * correct bit for extended oplock reply.
       */
    
      if (oplock_request && lp_fake_oplocks(SNUM(cnum)))
        smb_action |= EXTENDED_OPLOCK_GRANTED;
  
      if(oplock_request && fsp->granted_oplock)
        smb_action |= EXTENDED_OPLOCK_GRANTED;
    }
  }

  restore_case_semantics(file_attributes);

  /* Realloc the size of parameters and data we will return */
  params = *ppparams = Realloc(*ppparams, 69);
  if(params == NULL)
    return(ERROR(ERRDOS,ERRnomem));

  p = params;
  SCVAL(p,0, (smb_action & EXTENDED_OPLOCK_GRANTED ? 1 : 0));
  p += 2;
  SSVAL(p,0,fnum);
  p += 2;
  SIVAL(p,0,smb_action);
  p += 8;

  if (IS_IPC(cnum)) {
    /*
     * Deal with pipe return.
     */  
    p += 32;
    SIVAL(p,0,FILE_ATTRIBUTE_NORMAL); /* File Attributes. */
    p += 20;
    /* File type. */
    SSVAL(p,0,FILE_TYPE_MESSAGE_MODE_PIPE);
    /* Device state. */
    SSVAL(p,2, 0x5FF); /* ? */
  } else {
    /*
     * Deal with file return.
     */
    /* Create time. */
    put_long_date(p,get_create_time(&sbuf,lp_fake_dir_create_times(SNUM(cnum))));
    p += 8;
    put_long_date(p,sbuf.st_atime); /* access time */
    p += 8;
    put_long_date(p,sbuf.st_mtime); /* write time */
    p += 8;
    put_long_date(p,sbuf.st_mtime); /* change time */
    p += 8;
    SIVAL(p,0,fmode); /* File Attributes. */
    p += 12;
#if OFF_T_IS_64_BITS
      SIVAL(p,0, file_len & 0xFFFFFFFF);
      SIVAL(p,4, (file_len >> 32));
#else /* OFF_T_IS_64_BITS */
      SIVAL(p,0,file_len);
#endif /* OFF_T_IS_64_BITS */
  }

  /* Send the required number of replies */
  send_nt_replies(outbuf, bufsize, params, 69, *ppdata, 0);

  return -1;
}

/****************************************************************************
 Reply to a NT CANCEL request - just ignore it.
****************************************************************************/

int reply_ntcancel(char *inbuf,char *outbuf,int length,int bufsize)
{
  DEBUG(4,("Ignoring ntcancel of length %d\n",length));
  return(-1);
}

/****************************************************************************
 Reply to an unsolicited SMBNTtranss - just ignore it!
****************************************************************************/

int reply_nttranss(char *inbuf,char *outbuf,int length,int bufsize)
{
  DEBUG(4,("Ignoring nttranss of length %d\n",length));
  return(-1);
}

/****************************************************************************
 Reply to an NT transact rename command.
****************************************************************************/

static int call_nt_transact_rename(char *inbuf, char *outbuf, int length, 
                                   int bufsize, int cnum,
                                   char **ppsetup, char **ppparams, char **ppdata)
{
  char *params = *ppparams;
  pstring new_name;
  int fnum = SVAL(params, 0);
  BOOL replace_if_exists = (SVAL(params,2) & RENAME_REPLACE_IF_EXISTS) ? True : False;
  uint32 fname_len = MIN((((uint32)IVAL(inbuf,smb_nt_TotalParameterCount)-4)),
                         ((uint32)sizeof(new_name)-1));
  int outsize = 0;

  CHECK_FNUM(fnum, cnum);
  StrnCpy(new_name,params+4,fname_len);
  new_name[fname_len] = '\0';

  outsize = rename_internals(inbuf, outbuf, Files[fnum].name,
                             new_name, replace_if_exists);
  if(outsize == 0) {
    /*
     * Rename was successful.
     */
    send_nt_replies(outbuf, bufsize, NULL, 0, NULL, 0);
    outsize = -1;
  }

  return(outsize);
}
   
/****************************************************************************
 Reply to a notify change - we should never get this (for now) as we
 don't allow a directory to be opened.
****************************************************************************/

static int call_nt_transact_notify_change(char *inbuf, char *outbuf, int length,
                                          int bufsize, int cnum,
                                          char **ppsetup, char **ppparams, char **ppdata)
{
  DEBUG(0,("call_nt_transact_notify_change: Should not be called !\n"));
  return(ERROR(ERRSRV,ERRnosupport));
}
   
/****************************************************************************
 Reply to query a security descriptor - currently this is not implemented (it
 is planned to be though).
****************************************************************************/

static int call_nt_transact_query_security_desc(char *inbuf, char *outbuf, int length, 
                                                int bufsize, int cnum,
                                                char **ppsetup, char **ppparams, char **ppdata)
{
  DEBUG(0,("call_nt_transact_query_security_desc: Currently not implemented.\n"));
  return(ERROR(ERRSRV,ERRnosupport));
}
   
/****************************************************************************
 Reply to set a security descriptor - currently this is not implemented (it
 is planned to be though).
****************************************************************************/

static int call_nt_transact_set_security_desc(char *inbuf, char *outbuf, int length,
                                              int bufsize, int cnum,
                                              char **ppsetup, char **ppparams, char **ppdata)
{
  DEBUG(0,("call_nt_transact_set_security_desc: Currently not implemented.\n"));
  return(ERROR(ERRSRV,ERRnosupport));
}
   
/****************************************************************************
 Reply to IOCTL - not implemented - no plans.
****************************************************************************/

static int call_nt_transact_ioctl(char *inbuf, char *outbuf, int length,
                                  int bufsize, int cnum,
                                  char **ppsetup, char **ppparams, char **ppdata)
{
  DEBUG(0,("call_nt_transact_ioctl: Currently not implemented.\n"));
  return(ERROR(ERRSRV,ERRnosupport));
}
   
/****************************************************************************
 Reply to a SMBNTtrans.
****************************************************************************/

int reply_nttrans(char *inbuf,char *outbuf,int length,int bufsize)
{
  int outsize = 0;
  int cnum = SVAL(inbuf,smb_tid);
#if 0 /* Not used. */
  uint16 max_setup_count = CVAL(inbuf, smb_nt_MaxSetupCount);
  uint32 max_parameter_count = IVAL(inbuf, smb_nt_MaxParameterCount);
  uint32 max_data_count = IVAL(inbuf,smb_nt_MaxDataCount);
#endif /* Not used. */
  uint32 total_parameter_count = IVAL(inbuf, smb_nt_TotalParameterCount);
  uint32 total_data_count = IVAL(inbuf, smb_nt_TotalDataCount);
  uint32 parameter_count = IVAL(inbuf,smb_nt_ParameterCount);
  uint32 parameter_offset = IVAL(inbuf,smb_nt_ParameterOffset);
  uint32 data_count = IVAL(inbuf,smb_nt_DataCount);
  uint32 data_offset = IVAL(inbuf,smb_nt_DataOffset);
  uint16 setup_count = CVAL(inbuf,smb_nt_SetupCount);
  uint16 function_code = SVAL( inbuf, smb_nt_Function);
  char *params = NULL, *data = NULL, *setup = NULL;
  uint32 num_params_sofar, num_data_sofar;

  if(global_oplock_break && (function_code == NT_TRANSACT_CREATE)) {
    /*
     * Queue this open message as we are the process of an oplock break.
     */

    DEBUG( 2, ( "reply_nttrans: queueing message NT_TRANSACT_CREATE " ) );
    DEBUGADD( 2, ( "due to being in oplock break state.\n" ) );

    push_oplock_pending_smb_message( inbuf, length);
    return -1;
  }

  outsize = set_message(outbuf,0,0,True);

  /* 
   * All nttrans messages we handle have smb_wct == 19 + setup_count.
   * Ensure this is so as a sanity check.
   */

  if(CVAL(inbuf, smb_wct) != 19 + setup_count) {
    DEBUG(2,("Invalid smb_wct %d in nttrans call (should be %d)\n",
          CVAL(inbuf, smb_wct), 19 + setup_count));
    return(ERROR(ERRSRV,ERRerror));
  }
    
  /* Allocate the space for the setup, the maximum needed parameters and data */

  if(setup_count > 0)
    setup = (char *)malloc(setup_count);
  if (total_parameter_count > 0)
    params = (char *)malloc(total_parameter_count);
  if (total_data_count > 0)
    data = (char *)malloc(total_data_count);
 
  if ((total_parameter_count && !params)  || (total_data_count && !data) ||
      (setup_count && !setup)) {
    DEBUG(0,("reply_nttrans : Out of memory\n"));
    return(ERROR(ERRDOS,ERRnomem));
  }

  /* Copy the param and data bytes sent with this request into
     the params buffer */
  num_params_sofar = parameter_count;
  num_data_sofar = data_count;

  if (parameter_count > total_parameter_count || data_count > total_data_count)
    exit_server("reply_nttrans: invalid sizes in packet.\n");

  if(setup)
    memcpy( setup, &inbuf[smb_nt_SetupStart], setup_count);
  if(params)
    memcpy( params, smb_base(inbuf) + parameter_offset, parameter_count);
  if(data)
    memcpy( data, smb_base(inbuf) + data_offset, data_count);

  if(num_data_sofar < total_data_count || num_params_sofar < total_parameter_count) {
    /* We need to send an interim response then receive the rest
       of the parameter/data bytes */
    outsize = set_message(outbuf,0,0,True);
    send_smb(Client,outbuf);

    while( num_data_sofar < total_data_count || num_params_sofar < total_parameter_count) {
      BOOL ret;

      ret = receive_next_smb(Client,oplock_sock,inbuf,bufsize,
                             SMB_SECONDARY_WAIT);

      if((ret && (CVAL(inbuf, smb_com) != SMBnttranss)) || !ret) {
        outsize = set_message(outbuf,0,0,True);
        if(ret)
          DEBUG(0,("reply_nttrans: Invalid secondary nttrans packet\n"));
        else
          DEBUG(0,("reply_nttrans: %s in getting secondary nttrans response.\n",
                (smb_read_error == READ_ERROR) ? "error" : "timeout" ));
        if(params)
          free(params);
        if(data)
          free(data);
        if(setup)
          free(setup);
        return(ERROR(ERRSRV,ERRerror));
      }
      
      /* Revise total_params and total_data in case they have changed downwards */
      total_parameter_count = IVAL(inbuf, smb_nts_TotalParameterCount);
      total_data_count = IVAL(inbuf, smb_nts_TotalDataCount);
      num_params_sofar += (parameter_count = IVAL(inbuf,smb_nts_ParameterCount));
      num_data_sofar += ( data_count = IVAL(inbuf, smb_nts_DataCount));
      if (num_params_sofar > total_parameter_count || num_data_sofar > total_data_count)
        exit_server("reply_nttrans2: data overflow in secondary nttrans packet\n");

      memcpy( &params[ IVAL(inbuf, smb_nts_ParameterDisplacement)], 
              smb_base(inbuf) + IVAL(inbuf, smb_nts_ParameterOffset), parameter_count);
      memcpy( &data[IVAL(inbuf, smb_nts_DataDisplacement)],
              smb_base(inbuf)+ IVAL(inbuf, smb_nts_DataOffset), data_count);
    }
  }

  if (Protocol >= PROTOCOL_NT1) {
    uint16 flg2 = SVAL(outbuf,smb_flg2);
    SSVAL(outbuf,smb_flg2,flg2 | 0x40); /* IS_LONG_NAME */
  }

  /* Now we must call the relevant NT_TRANS function */
  switch(function_code) {
    case NT_TRANSACT_CREATE:
      outsize = call_nt_transact_create(inbuf, outbuf, length, bufsize, cnum, 
                                        &setup, &params, &data);
      break;
    case NT_TRANSACT_IOCTL:
      outsize = call_nt_transact_ioctl(inbuf, outbuf, length, bufsize, cnum,
                                       &setup, &params, &data);
      break;
    case NT_TRANSACT_SET_SECURITY_DESC:
      outsize = call_nt_transact_set_security_desc(inbuf, outbuf, length, bufsize, cnum,
                                                   &setup, &params, &data);
      break;
    case NT_TRANSACT_NOTIFY_CHANGE:
      outsize = call_nt_transact_notify_change(inbuf, outbuf, length, bufsize, cnum,
                                               &setup, &params, &data);
      break;
    case NT_TRANSACT_RENAME:
      outsize = call_nt_transact_rename(inbuf, outbuf, length, bufsize, cnum,
                                        &setup, &params, &data);
      break;
    case NT_TRANSACT_QUERY_SECURITY_DESC:
      outsize = call_nt_transact_query_security_desc(inbuf, outbuf, length, bufsize, cnum,
                                                     &setup, &params, &data);
      break;
    default:
      /* Error in request */
      DEBUG( 0, ( "reply_nttrans: Unknown request %d in nttrans call\n",
                  function_code ) );
      if(setup)
        free(setup);
      if(params)
	free(params);
      if(data)
	free(data);
      return (ERROR(ERRSRV,ERRerror));
  }

  /* As we do not know how many data packets will need to be
     returned here the various call_nt_transact_xxxx calls
     must send their own. Thus a call_nt_transact_xxxx routine only
     returns a value other than -1 when it wants to send
     an error packet. 
  */

  if(setup)
    free(setup);
  if(params)
    free(params);
  if(data)
    free(data);
  return outsize; /* If a correct response was needed the call_nt_transact_xxxx 
		     calls have already sent it. If outsize != -1 then it is
		     returning an error packet. */
}
