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
extern fstring myworkgroup;

#define VALID_PNUM(pnum)   (((pnum) >= 0) && ((pnum) < MAX_OPEN_PIPES))
#define OPEN_PNUM(pnum)    (VALID_PNUM(pnum) && Pipes[pnum].open)
#define PNUM_OK(pnum,c) (OPEN_PNUM(pnum) && (c)==Pipes[pnum].cnum)

/* this macro should always be used to extract an pnum (smb_fid) from
   a packet to ensure chaining works correctly */
#define GETPNUM(buf,where) (chain_pnum!= -1?chain_pnum:SVAL(buf,where))

char * known_pipes [] =
{
  "lsarpc",
#if NTDOMAIN
  "NETLOGON",
  "srvsvc",
  "wkssvc",
  "samr",
#endif
  NULL
};

/****************************************************************************
  reply to an open and X on a named pipe

  This code is basically stolen from reply_open_and_X with some
  wrinkles to handle pipes.
****************************************************************************/
int reply_open_pipe_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring fname;
  int cnum = SVAL(inbuf,smb_tid);
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

  /* Strip \PIPE\ off the name. */
  pstrcpy(fname,smb_buf(inbuf) + PIPELEN);

  /* See if it is one we want to handle. */
  for( i = 0; known_pipes[i] ; i++ )
    if( strcmp(fname,known_pipes[i]) == 0 )
      break;

  if ( known_pipes[i] == NULL )
    return(ERROR(ERRSRV,ERRaccess));

  /* Known pipes arrive with DIR attribs. Remove it so a regular file */
  /* can be opened and add it in after the open. */
  DEBUG(3,("Known pipe %s opening.\n",fname));
  smb_ofun |= 0x10;		/* Add Create it not exists flag */

  pnum = open_rpc_pipe_hnd(fname, cnum);
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


/****************************************************************************
 api_LsarpcSNPHS

 SetNamedPipeHandleState on \PIPE\lsarpc. 
****************************************************************************/
BOOL api_LsarpcSNPHS(int pnum, int cnum, char *param)
{
  uint16 id;

  if (!param) return False;

  id = param[0] + (param[1] << 8);
  DEBUG(4,("lsarpc SetNamedPipeHandleState to code %x\n",id));

  return set_rpc_pipe_hnd_state(pnum, cnum, id);
}


/****************************************************************************
 api_LsarpcTNP

 TransactNamedPipe on \PIPE\lsarpc.
****************************************************************************/
static void LsarpcTNP1(char *data,char **rdata, int *rdata_len)
{
  uint32 dword1, dword2;
  char pname[] = "\\PIPE\\lsass";

  /* All kinds of mysterious numbers here */
  *rdata_len = 68;
  *rdata = REALLOC(*rdata,*rdata_len);

  dword1 = IVAL(data,0xC);
  dword2 = IVAL(data,0x10);

  SIVAL(*rdata,0,0xc0005);
  SIVAL(*rdata,4,0x10);
  SIVAL(*rdata,8,0x44);
  SIVAL(*rdata,0xC,dword1);
  
  SIVAL(*rdata,0x10,dword2);
  SIVAL(*rdata,0x14,0x15);
  SSVAL(*rdata,0x18,sizeof(pname));
  pstrcpy(*rdata + 0x1a,pname);
  SIVAL(*rdata,0x28,1);
  memcpy(*rdata + 0x30, data + 0x34, 0x14);
}

static void LsarpcTNP2(char *data,char **rdata, int *rdata_len)
{
  uint32 dword1;

  /* All kinds of mysterious numbers here */
  *rdata_len = 48;
  *rdata = REALLOC(*rdata,*rdata_len);

  dword1 = IVAL(data,0xC);

  SIVAL(*rdata,0,0x03020005);
  SIVAL(*rdata,4,0x10);
  SIVAL(*rdata,8,0x30);
  SIVAL(*rdata,0xC,dword1);
  SIVAL(*rdata,0x10,0x18);
  SIVAL(*rdata,0x1c,0x44332211);
  SIVAL(*rdata,0x20,0x88776655);
  SIVAL(*rdata,0x24,0xCCBBAA99);
  SIVAL(*rdata,0x28,0x11FFEEDD);
}

static void LsarpcTNP3(char *data,char **rdata, int *rdata_len)
{
  uint32 dword1;
  uint16 word1;
  char * workgroup = myworkgroup;
  int wglen = strlen(workgroup);
  int i;

  /* All kinds of mysterious numbers here */
  *rdata_len = 90 + 2 * wglen;
  *rdata = REALLOC(*rdata,*rdata_len);

  dword1 = IVAL(data,0xC);
  word1 = SVAL(data,0x2C);

  SIVAL(*rdata,0,0x03020005);
  SIVAL(*rdata,4,0x10);
  SIVAL(*rdata,8,0x60);
  SIVAL(*rdata,0xC,dword1);
  SIVAL(*rdata,0x10,0x48);
  SSVAL(*rdata,0x18,0x5988);	/* This changes */
  SSVAL(*rdata,0x1A,0x15);
  SSVAL(*rdata,0x1C,word1);
  SSVAL(*rdata,0x20,6);
  SSVAL(*rdata,0x22,8);
  SSVAL(*rdata,0x24,0x8E8);	/* So does this */
  SSVAL(*rdata,0x26,0x15);
  SSVAL(*rdata,0x28,0x4D48);	/* And this */
  SSVAL(*rdata,0x2A,0x15);
  SIVAL(*rdata,0x2C,4);
  SIVAL(*rdata,0x34,wglen);
  for ( i = 0 ; i < wglen ; i++ )
    (*rdata)[0x38 + i * 2] = workgroup[i];
   
  /* Now fill in the rest */
  i = 0x38 + wglen * 2;
  SSVAL(*rdata,i,0x648);
  SIVAL(*rdata,i+2,4);
  SIVAL(*rdata,i+6,0x401);
  SSVAL(*rdata,i+0xC,0x500);
  SIVAL(*rdata,i+0xE,0x15);
  SIVAL(*rdata,i+0x12,0x2372FE1);
  SIVAL(*rdata,i+0x16,0x7E831BEF);
  SIVAL(*rdata,i+0x1A,0x4B454B2);
}

static void LsarpcTNP4(char *data,char **rdata, int *rdata_len)
{
  uint32 dword1;

  /* All kinds of mysterious numbers here */
  *rdata_len = 48;
  *rdata = REALLOC(*rdata,*rdata_len);

  dword1 = IVAL(data,0xC);

  SIVAL(*rdata,0,0x03020005);
  SIVAL(*rdata,4,0x10);
  SIVAL(*rdata,8,0x30);
  SIVAL(*rdata,0xC,dword1);
  SIVAL(*rdata,0x10,0x18);
}


BOOL api_LsarpcTNP(int cnum,int uid, char *param,char *data,
		     int mdrcnt,int mprcnt,
		     char **rdata,char **rparam,
		     int *rdata_len,int *rparam_len)
{
  uint32 id,id2;

  id = IVAL(data,0);

  DEBUG(4,("lsarpc TransactNamedPipe id %lx\n",id));
  switch (id)
  {
    case 0xb0005:
      LsarpcTNP1(data,rdata,rdata_len);
      break;

    case 0x03000005:
      id2 = IVAL(data,8);
      DEBUG(4,("\t- Suboperation %lx\n",id2));
      switch (id2 & 0xF)
      {
        case 8:
          LsarpcTNP2(data,rdata,rdata_len);
          break;

        case 0xC:
          LsarpcTNP4(data,rdata,rdata_len);
          break;

        case 0xE:
          LsarpcTNP3(data,rdata,rdata_len);
          break;
      }
      break;
  }
  return(True);
}

