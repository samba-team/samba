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
extern connection_struct Connections[];
extern files_struct Files[];
extern int Client;  
extern int oplock_sock;
extern int smb_read_error;
extern int global_oplock_break;

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
  reply to an NT create and X call.
****************************************************************************/

THIS IS JUST CRIBBED FROM REPLY.C AT PRESENT AND IS A WORK
IN PROGRESS. JRA.

int reply_ntcreate_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{  
  pstring fname;
  int cnum = SVAL(inbuf,smb_tid);
  int fnum = -1;
  int smb_mode = SVAL(inbuf,smb_vwv3);
  int smb_attr = SVAL(inbuf,smb_vwv5);
  /* Breakout the oplock request bits so we can set the
     reply bits separately. */
  BOOL ex_oplock_request = EXTENDED_OPLOCK_REQUEST(inbuf);
  BOOL core_oplock_request = CORE_OPLOCK_REQUEST(inbuf);
  BOOL oplock_request = ex_oplock_request | core_oplock_request;
#if 0
  int open_flags = SVAL(inbuf,smb_vwv2);
  int smb_sattr = SVAL(inbuf,smb_vwv4);
  uint32 smb_time = make_unix_date3(inbuf+smb_vwv6);
#endif 
  int smb_ofun = SVAL(inbuf,smb_vwv8);
  int unixmode;
  int size=0,fmode=0,mtime=0,rmode=0;
  struct stat sbuf;
  int smb_action = 0;
  BOOL bad_path = False;
  files_struct *fsp;
    
  /* If it's an IPC, pass off the pipe handler. */
  if (IS_IPC(cnum))
    return reply_open_pipe_and_X(inbuf,outbuf,length,bufsize);
    
  /* XXXX we need to handle passed times, sattr and flags */
    
  pstrcpy(fname,smb_buf(inbuf));
  unix_convert(fname,cnum,0,&bad_path);
    
  fnum = find_free_file();
  if (fnum < 0)
    return(ERROR(ERRSRV,ERRnofids));
  if (!check_name(fname,cnum))
  { 
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }
    Files[fnum].reserved = False;
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  } 
  
  unixmode = unix_mode(cnum,smb_attr | aARCH);
    
  open_file_shared(fnum,cnum,fname,smb_mode,smb_ofun,unixmode,
           oplock_request, &rmode,&smb_action);

  fsp = &Files[fnum];
    
  if (!fsp->open)
  { 
    if((errno == ENOENT) && bad_path)
    {
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRbadpath;
    }
    Files[fnum].reserved = False;
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  } 
  
  if (fstat(fsp->fd_ptr->fd,&sbuf) != 0) {
    close_file(fnum,False);
    return(ERROR(ERRDOS,ERRnoaccess));
  } 
  
  size = sbuf.st_size;
  fmode = dos_mode(cnum,fname,&sbuf);
  mtime = sbuf.st_mtime;
  if (fmode & aDIR) {
    close_file(fnum,False);
    return(ERROR(ERRDOS,ERRnoaccess));
  } 
  
  /* If the caller set the extended oplock request bit
     and we granted one (by whatever means) - set the
     correct bit for extended oplock reply.
   */
    
  if (ex_oplock_request && lp_fake_oplocks(SNUM(cnum))) {
    smb_action |= EXTENDED_OPLOCK_GRANTED;
  } 
  
  if(ex_oplock_request && fsp->granted_oplock) {
    smb_action |= EXTENDED_OPLOCK_GRANTED;
  } 
  
  /* If the caller set the core oplock request bit
     and we granted one (by whatever means) - set the
     correct bit for core oplock reply.
   */
    
  if (core_oplock_request && lp_fake_oplocks(SNUM(cnum))) {
    CVAL(outbuf,smb_flg) |= CORE_OPLOCK_GRANTED;
  } 
  
  if(core_oplock_request && fsp->granted_oplock) {
    CVAL(outbuf,smb_flg) |= CORE_OPLOCK_GRANTED;
  } 
  
  set_message(outbuf,15,0,True);
  SSVAL(outbuf,smb_vwv2,fnum);
  SSVAL(outbuf,smb_vwv3,fmode);
  if(lp_dos_filetime_resolution(SNUM(cnum)) )
    put_dos_date3(outbuf,smb_vwv4,mtime & ~1);
  else
    put_dos_date3(outbuf,smb_vwv4,mtime);
  SIVAL(outbuf,smb_vwv6,size);
  SSVAL(outbuf,smb_vwv8,rmode);
  SSVAL(outbuf,smb_vwv11,smb_action);
    
  chain_fnum = fnum;
    
  return chain_reply(inbuf,outbuf,length,bufsize);
}   

/****************************************************************************
  reply to an unsolicited SMBNTtranss - just ignore it!
****************************************************************************/

int reply_nttranss(char *inbuf,char *outbuf,int length,int bufsize)
{
  DEBUG(4,("Ignoring nttranss of length %d\n",length));
  return(-1);
}

/****************************************************************************
  reply to a SMBNTtrans
****************************************************************************/

int reply_nttrans(char *inbuf,char *outbuf,int length,int bufsize)
{
  int outsize = 0;
  int cnum = SVAL(inbuf,smb_tid);
#if 0
  uint16 max_setup_count = CVAL(inbuf, smb_nt_MaxSetupCount);
  uint32 max_parameter_count = IVAL(inbuf, smb_nt_MaxParameterCount);
  uint32 max_data_count = IVAL(inbuf,smb_nt_MaxDataCount);
#endif
  uint32 total_parameter_count = IVAL(inbuf, smb_nt_TotalParameterCount);
  uint32 total_data_count = IVAL(inbuf, smb_nt_TotalDataCount);
  uint32 parameter_count = IVAL(inbuf,smb_nt_ParameterCount);
  uint32 parameter_offset = IVAL(inbuf,smb_nt_ParameterOffset);
  uint32 data_count = IVAL(inbuf,smb_nt_DataCount);
  uint32 data_offset = IVAL(inbuf,smb_nt_DataOffset);
  uint16 setup_count = SVAL(inbuf,smb_nt_SetupCount);
  uint16 function_code = SVAL( inbuf, smb_nt_Function);
  char *params = NULL, *data = NULL, *setup = NULL;
  uint32 num_params_sofar, num_data_sofar;

  if(global_oplock_break && (function_code == NT_TRANSACT_CREATE)) {
    /*
     * Queue this open message as we are the process of an oplock break.
     */

    DEBUG(2,("%s: reply_nttrans: queueing message NT_TRANSACT_CREATE \
due to being in oplock break state.\n", timestring() ));

    push_smb_message( inbuf, length);
    return -1;
  }

  outsize = set_message(outbuf,0,0,True);

  /* 
   * All nttrans messages we handle have smb_wcnt == 19 + setup_count.
   * Ensure this is so as a sanity check.
   */

  if(CVAL(inbuf, smb_wcnt) != 19 + setup_count) {
    DEBUG(2,("Invalid smb_wcnt in trans2 call\n"));
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
      total_parameter_count = SIVAL(inbuf, smb_nts_TotalParameterCount);
      total_data_count = SIVAL(inbuf, smb_nts_TotalDataCount);
      num_params_sofar += (parameter_count = SIVAL(inbuf,smb_nts_ParameterCount));
      num_data_sofar += ( data_count = SIVAL(inbuf, smb_nts_DataCount));
      if (num_params_sofar > total_parameter_count || num_data_sofar > total_data_count)
        exit_server("reply_nttrans2: data overflow in secondary nttrans packet\n");

      memcpy( &params[ SIVAL(inbuf, smb_nts_ParameterDisplacement)], 
              smb_base(inbuf) + SVAL(inbuf, smb_nts_ParameterOffset), parameter_count);
      memcpy( &data[SVAL(inbuf, smb_nts_DataDisplacement)],
              smb_base(inbuf)+ SVAL(inbuf, smb_nts_DataOffset), data_count);
    }
  }

  if (Protocol >= PROTOCOL_NT1) {
    uint16 flg2 = SVAL(outbuf,smb_flg2);
    SSVAL(outbuf,smb_flg2,flg2 | 0x40); /* IS_LONG_NAME */
  }

  /* Now we must call the relevant NT_TRANS function */
  switch(function_code) {
    case NT_TRANSACT_CREATE:
      outsize = call_nt_transact_create(inbuf, outbuf, bufsize, cnum, 
                                        &setup, &params, &data);
      break;
    case NT_TRANSACT_IOCTL:
      outsize = call_nt_transact_ioctl(inbuf, outbuf, bufsize, cnum,
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
                                                     &setup, &params, &data, total_data);
      break;
    default:
      /* Error in request */
      DEBUG(0,("reply_nttrans: %s Unknown request %d in nttrans call\n",timestring(),
                 tran_call));
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
