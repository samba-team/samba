/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Pipe SMB reply routines
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   Copyright (C) Paul Ashton  1997-1998.
   
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
/*
   This file handles reply_ calls on named pipes that the server
   makes to handle specific protocols
*/


#include "includes.h"
#include "trans2.h"

#define	PIPE		"\\PIPE\\"
#define	PIPELEN		strlen(PIPE)

#define REALLOC(ptr,size) Realloc(ptr,MAX((size),4*1024))

/* look in server.c for some explanation of these variables */
extern int Protocol;
extern int DEBUGLEVEL;
extern char magic_char;
extern BOOL case_sensitive;
extern pstring sesssetup_user;
extern int Client;

#define VALID_PNUM(pnum)   (((pnum) >= 0) && ((pnum) < MAX_OPEN_PIPES))
#define OPEN_PNUM(pnum)    (VALID_PNUM(pnum) && Pipes[pnum].open)
#define PNUM_OK(pnum,c) (OPEN_PNUM(pnum) && (c)==Pipes[pnum].cnum)

/* this macro should always be used to extract an pnum (smb_fid) from
   a packet to ensure chaining works correctly */
#define GETPNUM(buf,where) (chain_pnum!= -1?chain_pnum:SVAL(buf,where))

extern struct pipe_id_info pipe_names[];

/****************************************************************************
  reply to an open and X on a named pipe

  This code is basically stolen from reply_open_and_X with some
  wrinkles to handle pipes.
****************************************************************************/
int reply_open_pipe_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring fname;
  uint16 cnum = SVAL(inbuf, smb_tid);
  uint16 vuid = SVAL(inbuf, smb_uid);
  int pnum = -1;
  int smb_ofun = SVAL(inbuf,smb_vwv8);
  int size=0,fmode=0,mtime=0,rmode=0;
  int i;

  /* XXXX we need to handle passed times, sattr and flags */
  pstrcpy(fname,smb_buf(inbuf));

  /* If the name doesn't start \PIPE\ then this is directed */
  /* at a mailslot or something we really, really don't understand, */
  /* not just something we really don't understand. */
  if ( strncmp(fname,PIPE,PIPELEN) != 0 )
    return(ERROR(ERRSRV,ERRaccess));

  DEBUG(4,("Opening pipe %s.\n", fname));

  /* See if it is one we want to handle. */
  for( i = 0; pipe_names[i].client_pipe ; i++ )
    if( strcmp(fname,pipe_names[i].client_pipe) == 0 )
      break;

  if ( pipe_names[i].client_pipe == NULL )
    return(ERROR(ERRSRV,ERRaccess));

  /* Strip \PIPE\ off the name. */
  pstrcpy(fname,smb_buf(inbuf) + PIPELEN);

  /* Known pipes arrive with DIR attribs. Remove it so a regular file */
  /* can be opened and add it in after the open. */
  DEBUG(3,("Known pipe %s opening.\n",fname));
  smb_ofun |= 0x10;		/* Add Create it not exists flag */

  pnum = open_rpc_pipe_hnd(fname, cnum, vuid);
  if (pnum < 0) return(ERROR(ERRSRV,ERRnofids));

  /* Prepare the reply */
  set_message(outbuf,15,0,True);

  /* Mark the opened file as an existing named pipe in message mode. */
  SSVAL(outbuf,smb_vwv9,2);
  SSVAL(outbuf,smb_vwv10,0xc700);

  if (rmode == 2)
  {
    DEBUG(4,("Resetting open result to open from create.\n"));
    rmode = 1;
  }

  SSVAL(outbuf,smb_vwv2, pnum + 0x800); /* mark file handle up into high range */
  SSVAL(outbuf,smb_vwv3,fmode);
  put_dos_date3(outbuf,smb_vwv4,mtime);
  SIVAL(outbuf,smb_vwv6,size);
  SSVAL(outbuf,smb_vwv8,rmode);
  SSVAL(outbuf,smb_vwv11,0);

  return chain_reply(inbuf,outbuf,length,bufsize);
}


/****************************************************************************
  reply to a read and X

  This code is basically stolen from reply_read_and_X with some
  wrinkles to handle pipes.
****************************************************************************/
int reply_pipe_read_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  int pnum = get_rpc_pipe_num(inbuf,smb_vwv2);
  uint32 smb_offs = IVAL(inbuf,smb_vwv3);
  int smb_maxcnt = SVAL(inbuf,smb_vwv5);
  int smb_mincnt = SVAL(inbuf,smb_vwv6);
  int cnum;
  int nread = -1;
  char *data;
  BOOL ok = False;

  cnum = SVAL(inbuf,smb_tid);

/*
  CHECK_FNUM(fnum,cnum);
  CHECK_READ(fnum);
  CHECK_ERROR(fnum);
*/

  set_message(outbuf,12,0,True);
  data = smb_buf(outbuf);

  nread = read_pipe(pnum, data, smb_offs, smb_maxcnt);

  ok = True;
  
  if (nread < 0)
    return(UNIXERROR(ERRDOS,ERRnoaccess));
  
  SSVAL(outbuf,smb_vwv5,nread);
  SSVAL(outbuf,smb_vwv6,smb_offset(data,outbuf));
  SSVAL(smb_buf(outbuf),-2,nread);
  
  DEBUG(3,("%s readX pnum=%04x cnum=%d min=%d max=%d nread=%d\n",
	timestring(),pnum,cnum,
	smb_mincnt,smb_maxcnt,nread));

  set_chain_pnum(pnum);

  return chain_reply(inbuf,outbuf,length,bufsize);
}
/****************************************************************************
  reply to a close
****************************************************************************/
int reply_pipe_close(char *inbuf,char *outbuf)
{
  int pnum = get_rpc_pipe_num(inbuf,smb_vwv0);
  int cnum = SVAL(inbuf,smb_tid);
  int outsize = set_message(outbuf,0,0,True);

  DEBUG(5,("reply_pipe_close: pnum:%x cnum:%x\n", pnum, cnum));

  if (!close_rpc_pipe_hnd(pnum, cnum)) return(ERROR(ERRDOS,ERRbadfid));

  return(outsize);
}

