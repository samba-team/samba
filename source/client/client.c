/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client
   Copyright (C) Andrew Tridgell 1994-1998
   
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

#define NO_SYSLOG

#include "includes.h"

#ifndef REGISTER
#define REGISTER 0
#endif

extern BOOL in_client;
pstring cur_dir = "\\";
pstring cd_path = "";
extern pstring service;
extern pstring desthost;
extern pstring global_myname;
extern pstring myhostname;
extern pstring password;
extern pstring username;
extern pstring workgroup;
char *cmdstr="";
extern BOOL got_pass;
extern BOOL no_pass;
extern BOOL connect_as_printer;
extern BOOL connect_as_ipc;
extern struct in_addr ipzero;

extern BOOL doencrypt;

extern pstring user_socket_options;

static int process_tok(fstring tok);
static void cmd_help(char *dum_in, char *dum_out);

/* 30 second timeout on most commands */
#define CLIENT_TIMEOUT (30*1000)
#define SHORT_TIMEOUT (5*1000)

/* value for unused fid field in trans2 secondary request */
#define FID_UNUSED (0xFFFF)

extern int name_type;

extern int max_protocol;


time_t newer_than = 0;
int archive_level = 0;

extern pstring debugf;
extern int DEBUGLEVEL;

BOOL translation = False;

extern uint16 cnum;
extern uint16 mid;
extern uint16 pid;
extern uint16 vuid;

extern BOOL have_ip;
extern int max_xmit;

static int interpret_long_filename(int level,char *p,file_info *finfo);
static void dir_action(char *inbuf,char *outbuf,int attribute,file_info *finfo,BOOL recurse_dir,void (*fn)(file_info *),BOOL longdir, BOOL dirstoo);
static int interpret_short_filename(char *p,file_info *finfo);
static BOOL do_this_one(file_info *finfo);

/* clitar bits insert */
extern int blocksize;
extern BOOL tar_inc;
extern BOOL tar_reset;
/* clitar bits end */
 

mode_t myumask = 0755;

extern pstring scope;

BOOL prompt = True;

int printmode = 1;

BOOL recurse = False;
BOOL lowercase = False;

struct in_addr dest_ip;

#define SEPARATORS " \t\n\r"

BOOL abort_mget = True;

extern int Protocol;

extern BOOL readbraw_supported ;
extern BOOL writebraw_supported;

pstring fileselection = "";

extern file_info def_finfo;

/* timing globals */
int get_total_size = 0;
int get_total_time_ms = 0;
int put_total_size = 0;
int put_total_time_ms = 0;

/* totals globals */
int dir_total = 0;

extern int Client;

#define USENMB

#define CNV_LANG(s) dos_to_unix(s,False)
#define CNV_INPUT(s) unix_to_dos(s,True)

/****************************************************************************
send an SMBclose on an SMB file handle
****************************************************************************/
static void cli_smb_close(char *inbuf, char *outbuf, int clnt_fd, int c_num, int f_num)
{
  bzero(outbuf,smb_size);
  set_message(outbuf,3,0,True);

  CVAL (outbuf,smb_com) = SMBclose;
  SSVAL(outbuf,smb_tid,c_num);
  cli_setup_pkt(outbuf);
  SSVAL (outbuf,smb_vwv0, f_num);
  SIVALS(outbuf,smb_vwv1, -1);
  
  send_smb(clnt_fd, outbuf);
  client_receive_smb(clnt_fd,inbuf,CLIENT_TIMEOUT);
}


/****************************************************************************
write to a local file with CR/LF->LF translation if appropriate. return the 
number taken from the buffer. This may not equal the number written.
****************************************************************************/
static int writefile(int f, char *b, int n)
{
  int i;

  if (!translation)
    return(write(f,b,n));
  
  i = 0;
  while (i < n)
    {
      if (*b == '\r' && (i<(n-1)) && *(b+1) == '\n')
	{
	  b++;i++;
	}
      if (write(f, b, 1) != 1)
	{
	  break;
	}
      b++;
      i++;
    }
  
  return(i);
}

/****************************************************************************
  read from a file with LF->CR/LF translation if appropriate. return the 
  number read. read approx n bytes.
****************************************************************************/
static int readfile(char *b, int size, int n, FILE *f)
{
  int i;
  int c;

  if (!translation || (size != 1))
    return(fread(b,size,n,f));
  
  i = 0;
  while (i < n)
    {
      if ((c = getc(f)) == EOF)
	{
	  break;
	}
      
      if (c == '\n') /* change all LFs to CR/LF */
	{
	  b[i++] = '\r';
	  n++;
	}
      
      if(i < n)
        b[i++] = c;
    }
  
  return(i);
}
 

/****************************************************************************
read from a file with print translation. return the number read. read approx n
bytes.
****************************************************************************/
static int printread(FILE *f,char *b,int n)
{
  int i;

  i = readfile(b,1, n-1,f);
#if FORMFEED
  if (feof(f) && i>0)
    b[i++] = '\014';
#endif

  return(i);
}

/****************************************************************************
check for existance of a dir
****************************************************************************/
static BOOL chkpath(char *path,BOOL report)
{
  fstring path2;
  pstring inbuf,outbuf;
  char *p;

  fstrcpy(path2,path);
  trim_string(path2,NULL,"\\");
  if (!*path2) *path2 = '\\';

  bzero(outbuf,smb_size);
  set_message(outbuf,0,4 + strlen(path2),True);
  SCVAL(outbuf,smb_com,SMBchkpth);
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  p = smb_buf(outbuf);
  *p++ = 4;
  fstrcpy(p,path2);

#if 0
  {
	  /* this little bit of code can be used to extract NT error codes.
	     Just feed a bunch of "cd foo" commands to smbclient then watch
	     in netmon (tridge) */
	  static int code=0;
	  SIVAL(outbuf, smb_rcls, code | 0xC0000000);
	  SSVAL(outbuf, smb_flg2, SVAL(outbuf, smb_flg2) | (1<<14));
	  code++;
  }
#endif

  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  if (report && CVAL(inbuf,smb_rcls) != 0)
    DEBUG(2,("chkpath: %s\n",smb_errstr(inbuf)));

  return(CVAL(inbuf,smb_rcls) == 0);
}


/****************************************************************************
send a message
****************************************************************************/
static void send_message(char *inbuf,char *outbuf)
{
  int total_len = 0;

  char *p;
  int grp_id;

  /* send a SMBsendstrt command */
  bzero(outbuf,smb_size);
  set_message(outbuf,0,0,True);
  CVAL(outbuf,smb_com) = SMBsendstrt;
  SSVAL(outbuf,smb_tid,cnum);

  p = smb_buf(outbuf);
  *p++ = 4;
  pstrcpy(p,username);
  p = skip_string(p,1);
  *p++ = 4;
  pstrcpy(p,desthost);
  p = skip_string(p,1);

  set_message(outbuf,0,PTR_DIFF(p,smb_buf(outbuf)),False);

  send_smb(Client,outbuf);
  

  if (!client_receive_smb(Client,inbuf,SHORT_TIMEOUT) || CVAL(inbuf,smb_rcls) != 0)
    {
      printf("SMBsendstrt failed. (%s)\n",smb_errstr(inbuf));
      return;
    }

  grp_id = SVAL(inbuf,smb_vwv0);

  printf("Connected. Type your message, ending it with a Control-D\n");

  while (!feof(stdin) && total_len < 1600)
    {
      int maxlen = MIN(1600 - total_len,127);
      pstring msg;
      int l=0;
      int c;

      bzero(msg,smb_size);

      for (l=0;l<maxlen && (c=fgetc(stdin))!=EOF;l++)
	{
	  if (c == '\n')
	    msg[l++] = '\r';
	  msg[l] = c;   
	}

      CVAL(outbuf,smb_com) = SMBsendtxt;

      set_message(outbuf,1,l+3,True);

      SSVAL(outbuf,smb_vwv0,grp_id);

      p = smb_buf(outbuf);
      *p = 1;
      SSVAL(p,1,l);
      memcpy(p+3,msg,l);

      send_smb(Client,outbuf);
      

      if (!client_receive_smb(Client,inbuf,SHORT_TIMEOUT) || CVAL(inbuf,smb_rcls) != 0)
	{
	  printf("SMBsendtxt failed (%s)\n",smb_errstr(inbuf));
	  return;
	}      

      total_len += l;
    }

  if (total_len >= 1600)
    printf("the message was truncated to 1600 bytes ");
  else
    printf("sent %d bytes ",total_len);

  printf("(status was %d-%d)\n",CVAL(inbuf,smb_rcls),SVAL(inbuf,smb_err));

  CVAL(outbuf,smb_com) = SMBsendend;
  set_message(outbuf,1,0,False);
  SSVAL(outbuf,smb_vwv0,grp_id);

  send_smb(Client,outbuf);
  

  if (!client_receive_smb(Client,inbuf,SHORT_TIMEOUT) || CVAL(inbuf,smb_rcls) != 0)
    {
      printf("SMBsendend failed (%s)\n",smb_errstr(inbuf));
      return;
    }      
}



/****************************************************************************
check the space on a device
****************************************************************************/
static void do_dskattr(void)
{
  pstring inbuf,outbuf;

  bzero(outbuf,smb_size);
  set_message(outbuf,0,0,True);
  CVAL(outbuf,smb_com) = SMBdskattr;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  if (CVAL(inbuf,smb_rcls) != 0) 
    DEBUG(0,("Error in dskattr: %s\n",smb_errstr(inbuf)));      

  DEBUG(0,("\n\t\t%d blocks of size %d. %d blocks available\n",
	SVAL(inbuf,smb_vwv0),
	SVAL(inbuf,smb_vwv1)*SVAL(inbuf,smb_vwv2),
	SVAL(inbuf,smb_vwv3)));
}

/****************************************************************************
show cd/pwd
****************************************************************************/
static void cmd_pwd(char *dum_in, char *dum_out)
{
  DEBUG(0,("Current directory is %s",CNV_LANG(service)));
  DEBUG(0,("%s\n",CNV_LANG(cur_dir)));
}


/****************************************************************************
change directory - inner section
****************************************************************************/
static void do_cd(char *newdir)
{
  char *p = newdir;
  pstring saved_dir;
  pstring dname;
      
  dos_format(newdir);

  /* Save the current directory in case the
     new directory is invalid */
  pstrcpy(saved_dir, cur_dir);
  if (*p == '\\')
    pstrcpy(cur_dir,p);
  else
    pstrcat(cur_dir,p);
  if (*(cur_dir+strlen(cur_dir)-1) != '\\') {
    pstrcat(cur_dir, "\\");
  }
  dos_clean_name(cur_dir);
  pstrcpy(dname,cur_dir);
  pstrcat(cur_dir,"\\");
  dos_clean_name(cur_dir);

  if (!strequal(cur_dir,"\\"))
    if (!chkpath(dname,True))
      pstrcpy(cur_dir,saved_dir);

  pstrcpy(cd_path,cur_dir);
}

/****************************************************************************
change directory
****************************************************************************/
static void cmd_cd(char *inbuf,char *outbuf)
{
  fstring buf;

  if (next_token(NULL,buf,NULL,sizeof(buf)))
    do_cd(buf);
  else
    DEBUG(0,("Current directory is %s\n",CNV_LANG(cur_dir)));
}


/****************************************************************************
  display info about a file
  ****************************************************************************/
static void display_finfo(file_info *finfo)
{
  if (do_this_one(finfo)) {
    time_t t = finfo->mtime; /* the time is assumed to be passed as GMT */
    DEBUG(0,("  %-30s%7.7s%.0f  %s",
       CNV_LANG(finfo->name),
	   attrib_string(finfo->mode),
	   (double)finfo->size,
	   asctime(LocalTime(&t))));
    dir_total += finfo->size;
  }
}


/****************************************************************************
  calculate size of a file
  ****************************************************************************/
static void do_du(file_info *finfo)
{
  if (do_this_one(finfo)) {
    dir_total += finfo->size;
  }
}


/****************************************************************************
  do a directory listing, calling fn on each file found. Use the TRANSACT2
  call for long filenames
  ****************************************************************************/
static int do_long_dir(char *inbuf,char *outbuf,char *Mask,int attribute,void (*fn)(file_info *),BOOL recurse_dir, BOOL dirstoo)
{
  int max_matches = 512;
  int info_level = Protocol<PROTOCOL_NT1?1:260; /* NT uses 260, OS/2 uses 2. Both accept 1. */
  char *p;
  pstring mask;
  file_info finfo;
  int i;
  char *dirlist = NULL;
  int dirlist_len = 0;
  int total_received = 0;
  BOOL First = True;
  char *resp_data=NULL;
  char *resp_param=NULL;
  int resp_data_len = 0;
  int resp_param_len=0;

  int ff_resume_key = 0;
  int ff_searchcount=0;
  int ff_eos=0;
  int ff_lastname=0;
  int ff_dir_handle=0;
  int loop_count = 0;

  uint16 setup;
  pstring param;

  pstrcpy(mask,Mask);

  while (ff_eos == 0)
    {
      loop_count++;
      if (loop_count > 200)
	{
	  DEBUG(0,("Error: Looping in FIND_NEXT??\n"));
	  break;
	}

      if (First)
	{
	  setup = TRANSACT2_FINDFIRST;
	  SSVAL(param,0,attribute); /* attribute */
	  SSVAL(param,2,max_matches); /* max count */
	  SSVAL(param,4,8+4+2);	/* resume required + close on end + continue */
	  SSVAL(param,6,info_level); 
	  SIVAL(param,8,0);
	  pstrcpy(param+12,mask);
	}
      else
	{
	  setup = TRANSACT2_FINDNEXT;
	  SSVAL(param,0,ff_dir_handle);
	  SSVAL(param,2,max_matches); /* max count */
	  SSVAL(param,4,info_level); 
	  SIVAL(param,6,ff_resume_key); /* ff_resume_key */
	  SSVAL(param,10,8+4+2);	/* resume required + close on end + continue */
	  pstrcpy(param+12,mask);

	  DEBUG(5,("hand=0x%X resume=%d ff_lastname=%d mask=%s\n",
		   ff_dir_handle,ff_resume_key,ff_lastname,mask));
	}
      /* ??? original code added 1 pad byte after param */

      cli_send_trans_request(outbuf,SMBtrans2,NULL,0,FID_UNUSED,0,
			 NULL,param,&setup,
			 0,12+strlen(mask)+1,1,
			 BUFFER_SIZE,10,0);

      if (!cli_receive_trans_response(inbuf,SMBtrans2,
			      &resp_data_len,&resp_param_len,
			          &resp_data,&resp_param))
	{
	  DEBUG(3,("FIND%s gave %s\n",First?"FIRST":"NEXT",smb_errstr(inbuf)));
	  break;
	}

      /* parse out some important return info */
      p = resp_param;
      if (First)
	{
	  ff_dir_handle = SVAL(p,0);
	  ff_searchcount = SVAL(p,2);
	  ff_eos = SVAL(p,4);
	  ff_lastname = SVAL(p,8);
	}
      else
	{
	  ff_searchcount = SVAL(p,0);
	  ff_eos = SVAL(p,2);
	  ff_lastname = SVAL(p,6);
	}

      if (ff_searchcount == 0) 
	break;

      /* point to the data bytes */
      p = resp_data;

      /* we might need the lastname for continuations */
      if (ff_lastname > 0)
	{
	  switch(info_level)
	    {
	    case 260:
	      ff_resume_key =0;
	      StrnCpy(mask,p+ff_lastname,resp_data_len-ff_lastname);
	      /* pstrcpy(mask,p+ff_lastname+94); */
	      break;
	    case 1:
	      pstrcpy(mask,p + ff_lastname + 1);
	      ff_resume_key = 0;
	      break;
	    }
	}
      else
	pstrcpy(mask,"");
  
      /* and add them to the dirlist pool */
      dirlist = Realloc(dirlist,dirlist_len + resp_data_len);

      if (!dirlist)
	{
	  DEBUG(0,("Failed to expand dirlist\n"));
	  break;
	}

      /* put in a length for the last entry, to ensure we can chain entries 
	 into the next packet */
      {
	char *p2;
	for (p2=p,i=0;i<(ff_searchcount-1);i++)
	  p2 += interpret_long_filename(info_level,p2,NULL);
	SSVAL(p2,0,resp_data_len - PTR_DIFF(p2,p));
      }

      /* grab the data for later use */
      memcpy(dirlist+dirlist_len,p,resp_data_len);
      dirlist_len += resp_data_len;

      total_received += ff_searchcount;

      if (resp_data) free(resp_data); resp_data = NULL;
      if (resp_param) free(resp_param); resp_param = NULL;

      DEBUG(3,("received %d entries (eos=%d resume=%d)\n",
	       ff_searchcount,ff_eos,ff_resume_key));

      First = False;
    }

  if (!fn)
    for (p=dirlist,i=0;i<total_received;i++)
      {
	p += interpret_long_filename(info_level,p,&finfo);
	display_finfo(&finfo);
      }

  for (p=dirlist,i=0;i<total_received;i++)
    {
      p += interpret_long_filename(info_level,p,&finfo);
      dir_action(inbuf,outbuf,attribute,&finfo,recurse_dir,fn,True, dirstoo);
    }

  /* free up the dirlist buffer */
  if (dirlist) free(dirlist);
  return(total_received);
}


/****************************************************************************
  do a directory listing, calling fn on each file found
  ****************************************************************************/
static int do_short_dir(char *inbuf,char *outbuf,char *Mask,int attribute,void (*fn)(file_info *),BOOL recurse_dir, BOOL dirstoo)
{
  char *p;
  int received = 0;
  BOOL first = True;
  char status[21];
  int num_asked = (max_xmit - 100)/DIR_STRUCT_SIZE;
  int num_received = 0;
  int i;
  char *dirlist = NULL;
  pstring mask;
  file_info finfo;

  finfo = def_finfo;

  bzero(status,21);

  pstrcpy(mask,Mask);
  
  while (1)
    {
      bzero(outbuf,smb_size);
      if (first)	
	set_message(outbuf,2,5 + strlen(mask),True);
      else
	set_message(outbuf,2,5 + 21,True);

#if FFIRST
      if (Protocol >= PROTOCOL_LANMAN1)
	CVAL(outbuf,smb_com) = SMBffirst;
      else
#endif
	CVAL(outbuf,smb_com) = SMBsearch;

      SSVAL(outbuf,smb_tid,cnum);
      cli_setup_pkt(outbuf);

      SSVAL(outbuf,smb_vwv0,num_asked);
      SSVAL(outbuf,smb_vwv1,attribute);
  
      p = smb_buf(outbuf);
      *p++ = 4;
      
      if (first)
	pstrcpy(p,mask);
      else
	pstrcpy(p,"");
      p += strlen(p) + 1;
      
      *p++ = 5;
      if (first)
	SSVAL(p,0,0);
      else
	{
	  SSVAL(p,0,21);
	  p += 2;
	  memcpy(p,status,21);
	}

      send_smb(Client,outbuf);
      client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

      received = SVAL(inbuf,smb_vwv0);

      DEBUG(5,("dir received %d\n",received));

      DEBUG(6,("errstr=%s\n",smb_errstr(inbuf)));

      if (received <= 0) break;

      first = False;

      dirlist = Realloc(dirlist,(num_received + received)*DIR_STRUCT_SIZE);

      if (!dirlist) 
	return 0;

      p = smb_buf(inbuf) + 3;

      memcpy(dirlist+num_received*DIR_STRUCT_SIZE,
	     p,received*DIR_STRUCT_SIZE);

      memcpy(status,p + ((received-1)*DIR_STRUCT_SIZE),21);

      num_received += received;

      if (CVAL(inbuf,smb_rcls) != 0) break;
    }

#if FFIRST
  if (!first && Protocol >= PROTOCOL_LANMAN1)
    {
      bzero(outbuf,smb_size);
      CVAL(outbuf,smb_com) = SMBfclose;

      SSVAL(outbuf,smb_tid,cnum);
      cli_setup_pkt(outbuf);

      p = smb_buf(outbuf);
      *p++ = 4;
      
      pstrcpy(p,"");
      p += strlen(p) + 1;
      
      *p++ = 5;
      SSVAL(p,0,21);
      p += 2;
      memcpy(p,status,21);

      send_smb(Client,outbuf);
      client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

      if (CVAL(inbuf,smb_rcls) != 0) 
	DEBUG(0,("Error closing search: %s\n",smb_errstr(inbuf)));      
    }
#endif

  if (!fn)
    for (p=dirlist,i=0;i<num_received;i++)
      {
	p += interpret_short_filename(p,&finfo);
	display_finfo(&finfo);
      }

  for (p=dirlist,i=0;i<num_received;i++)
    {
      p += interpret_short_filename(p,&finfo);
      dir_action(inbuf,outbuf,attribute,&finfo,recurse_dir,fn,False,dirstoo);
    }

  if (dirlist) free(dirlist);
  return(num_received);
}



/****************************************************************************
  do a directory listing, calling fn on each file found
  ****************************************************************************/
void do_dir(char *inbuf,char *outbuf,char *mask,int attribute,void (*fn)(file_info *),BOOL recurse_dir, BOOL dirstoo)
{
  dos_format(mask);
  DEBUG(5,("do_dir(%s,%x,%s)\n",mask,attribute,BOOLSTR(recurse_dir)));
  if (Protocol >= PROTOCOL_LANMAN2)
    {
      if (do_long_dir(inbuf,outbuf,mask,attribute,fn,recurse_dir,dirstoo) > 0)
	return;
    }

  expand_mask(mask,False);
  do_short_dir(inbuf,outbuf,mask,attribute,fn,recurse_dir,dirstoo);
  return;
}

/*******************************************************************
  decide if a file should be operated on
  ********************************************************************/
static BOOL do_this_one(file_info *finfo)
{
  if (finfo->mode & aDIR) return(True);

  if (newer_than && finfo->mtime < newer_than)
    return(False);

  if ((archive_level==1 || archive_level==2) && !(finfo->mode & aARCH))
    return(False);

  return(True);
}


/*****************************************************************************
 Convert a character pointer in a cli_call_api() response to a form we can use.
 This function contains code to prevent core dumps if the server returns 
 invalid data.
*****************************************************************************/
static char *fix_char_ptr(unsigned int datap, unsigned int converter, char *rdata, int rdrcnt)
{
  if( datap == 0 )		/* turn NULL pointers */
  {				/* into zero length strings */
    return "";
  }
  else
  {
    unsigned int offset = datap - converter;

    if( offset >= rdrcnt )
    {
      DEBUG(1,("bad char ptr: datap=%u, converter=%u, rdata=%lu, rdrcnt=%d>", datap, converter, (unsigned long)rdata, rdrcnt));
      return "<ERROR>";
    }
    else
    {
      return &rdata[offset];
    }
  }
}

/****************************************************************************
interpret a short filename structure
The length of the structure is returned
****************************************************************************/
static int interpret_short_filename(char *p,file_info *finfo)
{
  finfo->mode = CVAL(p,21);

  /* this date is converted to GMT by make_unix_date */
  finfo->ctime = make_unix_date(p+22);
  finfo->mtime = finfo->atime = finfo->ctime;
  finfo->size = IVAL(p,26);
  pstrcpy(finfo->name,p+30);
  
  return(DIR_STRUCT_SIZE);
}

/****************************************************************************
interpret a long filename structure - this is mostly guesses at the moment
The length of the structure is returned
The structure of a long filename depends on the info level. 260 is used
by NT and 2 is used by OS/2
****************************************************************************/
static int interpret_long_filename(int level,char *p,file_info *finfo)
{
  if (finfo)
    memcpy(finfo,&def_finfo,sizeof(*finfo));

  switch (level)
    {
    case 1: /* OS/2 understands this */
      if (finfo)
	{
	  /* these dates are converted to GMT by make_unix_date */
	  finfo->ctime = make_unix_date2(p+4);
	  finfo->atime = make_unix_date2(p+8);
	  finfo->mtime = make_unix_date2(p+12);
	  finfo->size = IVAL(p,16);
	  finfo->mode = CVAL(p,24);
	  pstrcpy(finfo->name,p+27);
	}
      return(28 + CVAL(p,26));

    case 2: /* this is what OS/2 uses mostly */
      if (finfo)
	{
	  /* these dates are converted to GMT by make_unix_date */
	  finfo->ctime = make_unix_date2(p+4);
	  finfo->atime = make_unix_date2(p+8);
	  finfo->mtime = make_unix_date2(p+12);
	  finfo->size = IVAL(p,16);
	  finfo->mode = CVAL(p,24);
	  pstrcpy(finfo->name,p+31);
	}
      return(32 + CVAL(p,30));

      /* levels 3 and 4 are untested */
    case 3:
      if (finfo)
	{
	  /* these dates are probably like the other ones */
	  finfo->ctime = make_unix_date2(p+8);
	  finfo->atime = make_unix_date2(p+12);
	  finfo->mtime = make_unix_date2(p+16);
	  finfo->size = IVAL(p,20);
	  finfo->mode = CVAL(p,28);
	  pstrcpy(finfo->name,p+33);
	}
      return(SVAL(p,4)+4);

    case 4:
      if (finfo)
	{
	  /* these dates are probably like the other ones */
	  finfo->ctime = make_unix_date2(p+8);
	  finfo->atime = make_unix_date2(p+12);
	  finfo->mtime = make_unix_date2(p+16);
	  finfo->size = IVAL(p,20);
	  finfo->mode = CVAL(p,28);
	  pstrcpy(finfo->name,p+37);
	}
      return(SVAL(p,4)+4);

    case 260: /* NT uses this, but also accepts 2 */
      if (finfo)
	{
	  int ret = SVAL(p,0);
	  int namelen;
	  p += 4; /* next entry offset */
	  p += 4; /* fileindex */

	  /* these dates appear to arrive in a weird way. It seems to
	     be localtime plus the serverzone given in the initial
	     connect. This is GMT when DST is not in effect and one
	     hour from GMT otherwise. Can this really be right??

	     I suppose this could be called kludge-GMT. Is is the GMT
	     you get by using the current DST setting on a different
	     localtime. It will be cheap to calculate, I suppose, as
	     no DST tables will be needed */

	  finfo->ctime = interpret_long_date(p); p += 8;
	  finfo->atime = interpret_long_date(p); p += 8;
	  finfo->mtime = interpret_long_date(p); p += 8; p += 8;
	  finfo->size = IVAL(p,0); p += 8;
	  p += 8; /* alloc size */
	  finfo->mode = CVAL(p,0); p += 4;
	  namelen = IVAL(p,0); p += 4;
	  p += 4; /* EA size */
	  p += 2; /* short name len? */
	  p += 24; /* short name? */	  
	  StrnCpy(finfo->name,p,namelen);
	  return(ret);
	}
      return(SVAL(p,0));
    }

  DEBUG(1,("Unknown long filename format %d\n",level));
  return(SVAL(p,0));
}




/****************************************************************************
  act on the files in a dir listing

  RJS, 4-Apr-1998, dirstoo added to allow caller to indicate that directories
                   should be processed as well.
  ****************************************************************************/
static void dir_action(char *inbuf,char *outbuf,int attribute,file_info *finfo,BOOL recurse_dir,void (*fn)(file_info *),BOOL longdir, BOOL dirstoo)
{

  if (!((finfo->mode & aDIR) == 0 && *fileselection && 
	!mask_match(finfo->name,fileselection,False,False)) &&
      !(recurse_dir && (strequal(finfo->name,".") || 
			strequal(finfo->name,".."))))
    {
      if (recurse_dir && (finfo->mode & aDIR))
	{
	  pstring mask2;
	  pstring sav_dir;

          if (fn && dirstoo && do_this_one(finfo)) { /* Do dirs, RJS */
	    fn(finfo);
	  }

	  pstrcpy(sav_dir,cur_dir);
	  pstrcat(cur_dir,finfo->name);
	  pstrcat(cur_dir,"\\");
	  pstrcpy(mask2,cur_dir);

	  if (!fn)
	    DEBUG(0,("\n%s\n",CNV_LANG(cur_dir)));

	  pstrcat(mask2,"*");

	  if (longdir)
	    do_long_dir(inbuf,outbuf,mask2,attribute,fn,True, dirstoo);      
	  else
	    do_dir(inbuf,outbuf,mask2,attribute,fn,True, dirstoo);

	  pstrcpy(cur_dir,sav_dir);
	}
      else
	{
	  if (fn && do_this_one(finfo))
	    fn(finfo);
	}
    }
}


/****************************************************************************
  get a directory listing
  ****************************************************************************/
static void cmd_dir(char *inbuf,char *outbuf)
{
  int attribute = aDIR | aSYSTEM | aHIDDEN;
  pstring mask;
  fstring buf;
  char *p=buf;

  dir_total = 0;
  pstrcpy(mask,cur_dir);
  if(mask[strlen(mask)-1]!='\\')
    pstrcat(mask,"\\");

  if (next_token(NULL,buf,NULL,sizeof(buf))) {
    dos_format(p);
    if (*p == '\\')
      pstrcpy(mask,p);
    else
      pstrcat(mask,p);
  }
  else {
    pstrcat(mask,"*");
  }

  do_dir(inbuf,outbuf,mask,attribute,NULL,recurse,False);

  do_dskattr();

  DEBUG(3, ("Total bytes listed: %d\n", dir_total));
}


/****************************************************************************
  get a directory listing
  ****************************************************************************/
static void cmd_du(char *inbuf,char *outbuf)
{
  int attribute = aDIR | aSYSTEM | aHIDDEN;
  pstring mask;
  fstring buf;
  char *p=buf;

  dir_total = 0;
  pstrcpy(mask,cur_dir);
  if(mask[strlen(mask)-1]!='\\')
    pstrcat(mask,"\\");

  if (next_token(NULL,buf,NULL,sizeof(buf)))
  {
    dos_format(p);
    if (*p == '\\')
      pstrcpy(mask,p);
    else
      pstrcat(mask,p);
  }
  else {
    pstrcat(mask,"*");
  }

  do_dir(inbuf,outbuf,mask,attribute,do_du,recurse,False);

  do_dskattr();

  DEBUG(0, ("Total number of bytes: %d\n", dir_total));
}

/****************************************************************************
  get a file from rname to lname
  ****************************************************************************/
static void do_get(char *rname,char *lname,file_info *finfo1)
{  
  int handle=0,fnum;
  uint32 nread=0;
  char *p;
  BOOL newhandle = False;
  char *inbuf,*outbuf;
  file_info finfo;
  BOOL close_done = False;
  BOOL ignore_close_error = False;
  char *dataptr=NULL;
  int datalen=0;

  struct timeval tp_start;
  GetTimeOfDay(&tp_start);

  if (finfo1) 
    finfo = *finfo1;
  else
    finfo = def_finfo;

  if (lowercase)
    strlower(lname);


  inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

  if (!inbuf || !outbuf)
  {
    DEBUG(0,("out of memory\n"));
    return;
  }

  bzero(outbuf,smb_size);
  set_message(outbuf,15,1 + strlen(rname),True);

  CVAL(outbuf,smb_com) = SMBopenX;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,0xFF);
  SSVAL(outbuf,smb_vwv2,1); /* return additional info */
  SSVAL(outbuf,smb_vwv3,(DENY_NONE<<4));
  SSVAL(outbuf,smb_vwv4,aSYSTEM | aHIDDEN);
  SSVAL(outbuf,smb_vwv5,aSYSTEM | aHIDDEN);
  SSVAL(outbuf,smb_vwv8,1);
  SSVAL(outbuf,smb_vwv11,0xffff);
  SSVAL(outbuf,smb_vwv12,0xffff);
  
  p = smb_buf(outbuf);
  pstrcpy(p,rname);
  p = skip_string(p,1);

  /* do a chained openX with a readX? */
#if 1
  if (finfo.size > 0)
    {
      DEBUG(3,("Chaining readX wth openX\n"));
      SSVAL(outbuf,smb_vwv0,SMBreadX);
      SSVAL(outbuf,smb_vwv1,smb_offset(p,outbuf));
      bzero(p,200);
      p -= smb_wct;
      SCVAL(p,smb_wct,10);
      SSVAL(p,smb_vwv0,0xFF);
      SSVAL(p,smb_vwv5,MIN(max_xmit-500,finfo.size));
      SSVAL(p,smb_vwv9,MIN(BUFFER_SIZE,finfo.size));
      smb_setlen(outbuf,smb_len(outbuf)+11*2+1);  
    }
#endif

  if(!strcmp(lname,"-"))
    handle = fileno(stdout);
  else 
    {
      handle = creat(lname,0644);
      newhandle = True;
    }
  if (handle < 0)
    {
      DEBUG(0,("Error opening local file %s\n",lname));
      free(inbuf);free(outbuf);
      return;
    }

  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  if (CVAL(inbuf,smb_rcls) != 0)
    {
      if (CVAL(inbuf,smb_rcls) == ERRSRV &&
	  SVAL(inbuf,smb_err) == ERRnoresource &&
	  cli_reopen_connection(inbuf,outbuf))
	{
	  do_get(rname,lname,finfo1);
	  return;
	}
      DEBUG(0,("%s opening remote file %s\n",smb_errstr(inbuf),CNV_LANG(rname)));
      if(newhandle)
	{
 	  close(handle);
	  unlink(lname);
	}
      free(inbuf);free(outbuf);
      return;
    }

  pstrcpy(finfo.name,rname);

  if (!finfo1)
    {
      finfo.mode = SVAL(inbuf,smb_vwv3);
      /* these times arrive as LOCAL time, using the DST offset 
	 corresponding to that time, we convert them to GMT */
      finfo.mtime = make_unix_date3(inbuf+smb_vwv4);
      finfo.atime = finfo.ctime = finfo.mtime;
      finfo.size = IVAL(inbuf,smb_vwv6);
    }

  DEBUG(3,("file %s attrib 0x%X\n",CNV_LANG(finfo.name),finfo.mode));

  fnum = SVAL(inbuf,smb_vwv2);

  /* we might have got some data from a chained readX */
  if (SVAL(inbuf,smb_vwv0) == SMBreadX)
    {
      p = (smb_base(inbuf)+SVAL(inbuf,smb_vwv1)) - smb_wct;
      datalen = SVAL(p,smb_vwv5);
      dataptr = smb_base(inbuf) + SVAL(p,smb_vwv6);
    }
  else
    {
      dataptr = NULL;
      datalen = 0;
    }


  DEBUG(2,("getting file %s of size %.0f bytes as %s ",
	   CNV_LANG(finfo.name),
	   (double)finfo.size,
	   lname));

  while (nread < finfo.size && !close_done)
    {
      int method = -1;
      static BOOL can_chain_close = True;

      p=NULL;
      
      DEBUG(3,("nread=%d max_xmit=%d fsize=%.0f\n",nread,max_xmit,(double)finfo.size));

      /* 3 possible read types. readbraw if a large block is required.
	 readX + close if not much left and read if neither is supported */

      /* we might have already read some data from a chained readX */
      if (dataptr && datalen>0)
	method=3;

      /* if we can finish now then readX+close */
      if (method<0 && can_chain_close && (Protocol >= PROTOCOL_LANMAN1) && 
	  ((finfo.size - nread) < 
	   (max_xmit - (2*smb_size + 13*SIZEOFWORD + 300))))
	method = 0;

      /* if we support readraw then use that */
      if (method<0 && readbraw_supported)
	method = 1;

      /* if we can then use readX */
      if (method<0 && (Protocol >= PROTOCOL_LANMAN1))
	method = 2;

      switch (method)
	{
	  /* use readX */
	case 0:
	case 2:
	  if (method == 0)
	    close_done = True;
	    
	  /* use readX + close */
	  bzero(outbuf,smb_size);
	  set_message(outbuf,10,0,True);
	  CVAL(outbuf,smb_com) = SMBreadX;
	  SSVAL(outbuf,smb_tid,cnum);
	  cli_setup_pkt(outbuf);
	  
	  if (close_done)
	    {
	      CVAL(outbuf,smb_vwv0) = SMBclose;
	      SSVAL(outbuf,smb_vwv1,smb_offset(smb_buf(outbuf),outbuf));
	    }
	  else
	    CVAL(outbuf,smb_vwv0) = 0xFF;	      
	  
	  SSVAL(outbuf,smb_vwv2,fnum);
	  SIVAL(outbuf,smb_vwv3,nread);
	  SSVAL(outbuf,smb_vwv5,MIN(max_xmit-200,finfo.size - nread));
	  SSVAL(outbuf,smb_vwv6,0);
	  SIVAL(outbuf,smb_vwv7,0);
	  SSVAL(outbuf,smb_vwv9,MIN(BUFFER_SIZE,finfo.size-nread));
	  
	  if (close_done)
	    {
	      p = smb_buf(outbuf);
	      bzero(p,9);
	      
	      CVAL(p,0) = 3;
	      SSVAL(p,1,fnum);
	      SIVALS(p,3,-1);
	      
	      /* now set the total packet length */
	      smb_setlen(outbuf,smb_len(outbuf)+9);
	    }
	  
	  send_smb(Client,outbuf);
	  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
	  
	  if (CVAL(inbuf,smb_rcls) != 0)
	    {
	      DEBUG(0,("Error %s reading remote file\n",smb_errstr(inbuf)));
	      break;
	    }
	  
	  if (close_done &&
	      SVAL(inbuf,smb_vwv0) != SMBclose)
	    {
	      /* NOTE: WfWg sometimes just ignores the chained
		 command! This seems to break the spec? */
	      DEBUG(3,("Rejected chained close?\n"));
	      close_done = False;
	      can_chain_close = False;
	      ignore_close_error = True;
	    }
	  
	  datalen = SVAL(inbuf,smb_vwv5);
	  dataptr = smb_base(inbuf) + SVAL(inbuf,smb_vwv6);
	  break;

	  /* use readbraw */
	case 1:
	  {
	    static int readbraw_size = BUFFER_SIZE;
	  
	    extern int Client;
	    bzero(outbuf,smb_size);
	    set_message(outbuf,8,0,True);
	    CVAL(outbuf,smb_com) = SMBreadbraw;
	    SSVAL(outbuf,smb_tid,cnum);
	    cli_setup_pkt(outbuf);
	    SSVAL(outbuf,smb_vwv0,fnum);
	    SIVAL(outbuf,smb_vwv1,nread);
	    SSVAL(outbuf,smb_vwv3,MIN(finfo.size-nread,readbraw_size));
	    SSVAL(outbuf,smb_vwv4,0);
	    SIVALS(outbuf,smb_vwv5,-1);
	    send_smb(Client,outbuf);

	    /* Now read the raw data into the buffer and write it */	  
	    if(read_smb_length(Client,inbuf,0) == -1) {
	      DEBUG(0,("Failed to read length in readbraw\n"));	    
	      exit(1);
	    }
	    
	    /* Even though this is not an smb message, smb_len
	       returns the generic length of an smb message */
	    datalen = smb_len(inbuf);

	    if (datalen == 0)
	      {
		/* we got a readbraw error */
		DEBUG(4,("readbraw error - reducing size\n"));
		readbraw_size = (readbraw_size * 9) / 10;
		
		if (readbraw_size < max_xmit)
		  {
		    DEBUG(0,("disabling readbraw\n"));
		    readbraw_supported = False;
		  }
		
		dataptr=NULL;
		continue;
	      }

	    if(read_data(Client,inbuf,datalen) != datalen) {
	      DEBUG(0,("Failed to read data in readbraw\n"));
	      exit(1);
	    }
	    dataptr = inbuf;
	  }
	  break;

	case 3:
	  /* we've already read some data with a chained readX */
	  break;

	default:
	  /* use plain read */
	  bzero(outbuf,smb_size);
	  set_message(outbuf,5,0,True);
	  CVAL(outbuf,smb_com) = SMBread;
	  SSVAL(outbuf,smb_tid,cnum);
	  cli_setup_pkt(outbuf);

	  SSVAL(outbuf,smb_vwv0,fnum);
	  SSVAL(outbuf,smb_vwv1,MIN(max_xmit-200,finfo.size - nread));
	  SIVAL(outbuf,smb_vwv2,nread);
	  SSVAL(outbuf,smb_vwv4,finfo.size - nread);

	  send_smb(Client,outbuf);
	  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

	  if (CVAL(inbuf,smb_rcls) != 0)
	    {
	      DEBUG(0,("Error %s reading remote file\n",smb_errstr(inbuf)));
	      break;
	    }

	  datalen = SVAL(inbuf,smb_vwv0);
	  dataptr = smb_buf(inbuf) + 3;
	  break;
	}
 
      if (writefile(handle,dataptr,datalen) != datalen)
	{
	  DEBUG(0,("Error writing local file\n"));
	  break;
	}
      
      nread += datalen;
      if (datalen == 0) 
	{
	  DEBUG(0,("Error reading file %s. Got %d bytes\n",CNV_LANG(rname),nread));
	  break;
	}

      dataptr=NULL;
      datalen=0;
    }



  if (!close_done)
    {
      cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
      
      if (!ignore_close_error && CVAL(inbuf,smb_rcls) != 0)
	{
	  DEBUG(0,("Error %s closing remote file\n",smb_errstr(inbuf)));
	  if(newhandle)
	    close(handle);
	  free(inbuf);free(outbuf);
	  return;
	}
    }

  if(newhandle)
    close(handle);

  if (archive_level >= 2 && (finfo.mode & aARCH)) {
    bzero(outbuf,smb_size);
    set_message(outbuf,8,strlen(rname)+4,True);
    CVAL(outbuf,smb_com) = SMBsetatr;
    SSVAL(outbuf,smb_tid,cnum);
    cli_setup_pkt(outbuf);
    SSVAL(outbuf,smb_vwv0,finfo.mode & ~(aARCH));
    SIVALS(outbuf,smb_vwv1,0);
    p = smb_buf(outbuf);
    *p++ = 4;
    pstrcpy(p,rname);
    p += strlen(p)+1;
    *p++ = 4;
    *p = 0;
    send_smb(Client,outbuf);
    client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  }

  {
    struct timeval tp_end;
    int this_time;

    GetTimeOfDay(&tp_end);
    this_time = 
      (tp_end.tv_sec - tp_start.tv_sec)*1000 +
	(tp_end.tv_usec - tp_start.tv_usec)/1000;
    get_total_time_ms += this_time;
    get_total_size += finfo.size;

    DEBUG(1,("(%g kb/s) (average %g kb/s)\n",
	     finfo.size / (1.024*this_time + 1.0e-4),
	     get_total_size / (1.024*get_total_time_ms)));
  }

  free(inbuf);free(outbuf);
}


/****************************************************************************
  get a file
  ****************************************************************************/
static void cmd_get(char *dum_in, char *dum_out)
{
  pstring lname;
  pstring rname;
  char *p;

  pstrcpy(rname,cur_dir);
  pstrcat(rname,"\\");

  p = rname + strlen(rname);

  if (!next_token(NULL,p,NULL,sizeof(rname)-strlen(rname))) {
    DEBUG(0,("get <filename>\n"));
    return;
  }
  pstrcpy(lname,p);
  dos_clean_name(rname);
    
  next_token(NULL,lname,NULL,sizeof(lname));

  do_get(rname,lname,NULL);
}


/****************************************************************************
  do a mget operation on one file
  ****************************************************************************/
static void do_mget(file_info *finfo)
{
  pstring rname;
  pstring quest;

  if (strequal(finfo->name,".") || strequal(finfo->name,".."))
    return;

  if (abort_mget)
    {
      DEBUG(0,("mget aborted\n"));
      return;
    }

  if (finfo->mode & aDIR)
    slprintf(quest,sizeof(pstring)-1,
	     "Get directory %s? ",CNV_LANG(finfo->name));
  else
    slprintf(quest,sizeof(pstring)-1,
	     "Get file %s? ",CNV_LANG(finfo->name));

  if (prompt && !yesno(quest)) return;

  if (finfo->mode & aDIR)
    {
      pstring saved_curdir;
      pstring mget_mask;
      char *inbuf,*outbuf;

      inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
      outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

      if (!inbuf || !outbuf)
	{
	  DEBUG(0,("out of memory\n"));
	  return;
	}

      pstrcpy(saved_curdir,cur_dir);

      pstrcat(cur_dir,finfo->name);
      pstrcat(cur_dir,"\\");

      unix_format(finfo->name);
      {
	if (lowercase)
	  strlower(finfo->name);

	if (!directory_exist(finfo->name,NULL) && 
	    dos_mkdir(finfo->name,0777) != 0) 
	  {
	    DEBUG(0,("failed to create directory %s\n",CNV_LANG(finfo->name)));
	    pstrcpy(cur_dir,saved_curdir);
	    free(inbuf);free(outbuf);
	    return;
	  }

	if (dos_chdir(finfo->name) != 0)
	  {
	    DEBUG(0,("failed to chdir to directory %s\n",CNV_LANG(finfo->name)));
	    pstrcpy(cur_dir,saved_curdir);
	    free(inbuf);free(outbuf);
	    return;
	  }
      }       

      pstrcpy(mget_mask,cur_dir);
      pstrcat(mget_mask,"*");
      
      do_dir((char *)inbuf,(char *)outbuf,
	     mget_mask,aSYSTEM | aHIDDEN | aDIR,do_mget,False, False);
      chdir("..");
      pstrcpy(cur_dir,saved_curdir);
      free(inbuf);free(outbuf);
    }
  else
    {
      pstrcpy(rname,cur_dir);
      pstrcat(rname,finfo->name);
      do_get(rname,finfo->name,finfo);
    }
}

/****************************************************************************
view the file using the pager
****************************************************************************/
static void cmd_more(char *dum_in, char *dum_out)
{
  fstring rname,lname,tmpname,pager_cmd;
  char *pager;

  fstrcpy(rname,cur_dir);
  fstrcat(rname,"\\");
  slprintf(tmpname,
	   sizeof(fstring)-1,
	   "%s/smbmore.%d",tmpdir(),(int)getpid());
  fstrcpy(lname,tmpname);

  if (!next_token(NULL,rname+strlen(rname),NULL,sizeof(rname)-strlen(rname))) {
    DEBUG(0,("more <filename>\n"));
    return;
  }
  dos_clean_name(rname);

  do_get(rname,lname,NULL);

  pager=getenv("PAGER");

  slprintf(pager_cmd,sizeof(pager_cmd)-1,
	   "%s %s",(pager? pager:PAGER), tmpname);
  system(pager_cmd);
  unlink(tmpname);
}



/****************************************************************************
do a mget command
****************************************************************************/
static void cmd_mget(char *inbuf,char *outbuf)
{
  int attribute = aSYSTEM | aHIDDEN;
  pstring mget_mask;
  fstring buf;
  char *p=buf;

  *mget_mask = 0;

  if (recurse)
    attribute |= aDIR;

  abort_mget = False;

  while (next_token(NULL,p,NULL,sizeof(buf)))
    {
      pstrcpy(mget_mask,cur_dir);
      if(mget_mask[strlen(mget_mask)-1]!='\\')
	pstrcat(mget_mask,"\\");

      if (*p == '\\')
	pstrcpy(mget_mask,p);
      else
	pstrcat(mget_mask,p);
      do_dir((char *)inbuf,(char *)outbuf,mget_mask,attribute,do_mget,False,False);
    }

  if (! *mget_mask)
    {
      pstrcpy(mget_mask,cur_dir);
      if(mget_mask[strlen(mget_mask)-1]!='\\')
	pstrcat(mget_mask,"\\");
      pstrcat(mget_mask,"*");
      do_dir((char *)inbuf,(char *)outbuf,mget_mask,attribute,do_mget,False,False);
    }
}

/****************************************************************************
make a directory of name "name"
****************************************************************************/
static BOOL do_mkdir(char *name)
{
  char *p;
  char *inbuf,*outbuf;

  inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

  if (!inbuf || !outbuf)
    {
      DEBUG(0,("out of memory\n"));
      return False;
    }

  bzero(outbuf,smb_size);
  set_message(outbuf,0,2 + strlen(name),True);
  
  CVAL(outbuf,smb_com) = SMBmkdir;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  
  p = smb_buf(outbuf);
  *p++ = 4;      
  pstrcpy(p,name);
  
  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("%s making remote directory %s\n",
	       smb_errstr(inbuf),CNV_LANG(name)));

      free(inbuf);free(outbuf);
      return(False);
    }

  free(inbuf);free(outbuf);
  return(True);
}


/****************************************************************************
  make a directory
  ****************************************************************************/
static void cmd_mkdir(char *inbuf,char *outbuf)
{
  pstring mask;
  fstring buf;
  char *p=buf;
  
  pstrcpy(mask,cur_dir);

  if (!next_token(NULL,p,NULL,sizeof(buf)))
    {
      if (!recurse)
	DEBUG(0,("mkdir <dirname>\n"));
      return;
    }
  pstrcat(mask,p);

  if (recurse)
    {
      pstring ddir;
      pstring ddir2;
      *ddir2 = 0;

      pstrcpy(ddir,mask);
      trim_string(ddir,".",NULL);
      p = strtok(ddir,"/\\");
      while (p)
	{
	  pstrcat(ddir2,p);
	  if (!chkpath(ddir2,False))
	    {		  
	      do_mkdir(ddir2);
	    }
	  pstrcat(ddir2,"\\");
	  p = strtok(NULL,"/\\");
	}	 
    }
  else
    do_mkdir(mask);
}


/*******************************************************************
  write to a file using writebraw
  ********************************************************************/
static int smb_writeraw(char *outbuf,int fnum,int pos,char *buf,int n)
{
  extern int Client;
  pstring inbuf;

  bzero(outbuf,smb_size);
  bzero(inbuf,smb_size);  
  set_message(outbuf,Protocol>PROTOCOL_COREPLUS?12:10,0,True);

  CVAL(outbuf,smb_com) = SMBwritebraw;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,fnum);
  SSVAL(outbuf,smb_vwv1,n);
  SIVAL(outbuf,smb_vwv3,pos);
  SSVAL(outbuf,smb_vwv7,1);

  send_smb(Client,outbuf);
  
  if (!client_receive_smb(Client,inbuf,CLIENT_TIMEOUT) || CVAL(inbuf,smb_rcls) != 0)
    return(0);

  _smb_setlen(buf-4,n);		/* HACK! XXXX */

  if (write_socket(Client,buf-4,n+4) != n+4)
    return(0);

  if (!client_receive_smb(Client,inbuf,CLIENT_TIMEOUT) || CVAL(inbuf,smb_rcls) != 0) {
    DEBUG(0,("Error writing remote file (2)\n"));
    return(0);
  }
  return(SVAL(inbuf,smb_vwv0));
}
      


/*******************************************************************
  write to a file
  ********************************************************************/
static int smb_writefile(char *outbuf,int fnum,int pos,char *buf,int n)
{
  pstring inbuf;

  if (writebraw_supported && n > (max_xmit-200)) 
    return(smb_writeraw(outbuf,fnum,pos,buf,n));

  bzero(outbuf,smb_size);
  bzero(inbuf,smb_size);
  set_message(outbuf,5,n + 3,True);

  CVAL(outbuf,smb_com) = SMBwrite;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,fnum);
  SSVAL(outbuf,smb_vwv1,n);
  SIVAL(outbuf,smb_vwv2,pos);
  SSVAL(outbuf,smb_vwv4,0);
  CVAL(smb_buf(outbuf),0) = 1;
  SSVAL(smb_buf(outbuf),1,n);

  memcpy(smb_buf(outbuf)+3,buf,n);

  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  if (CVAL(inbuf,smb_rcls) != 0) {
    DEBUG(0,("%s writing remote file\n",smb_errstr(inbuf)));
    return(0);
  }
  return(SVAL(inbuf,smb_vwv0));
}
      


/****************************************************************************
  put a single file
  ****************************************************************************/
static void do_put(char *rname,char *lname,file_info *finfo)
{
  int fnum;
  FILE *f;
  int nread=0;
  char *p;
  char *inbuf,*outbuf; 
  time_t close_time = finfo->mtime;
  char *buf=NULL;
  static int maxwrite=0;

  struct timeval tp_start;
  GetTimeOfDay(&tp_start);

  inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

  if (!inbuf || !outbuf)
    {
      DEBUG(0,("out of memory\n"));
      return;
    }

  bzero(outbuf,smb_size);
  set_message(outbuf,3,2 + strlen(rname),True);

  if (finfo->mtime == 0 || finfo->mtime == -1)
    finfo->mtime = finfo->atime = finfo->ctime = time(NULL);

  CVAL(outbuf,smb_com) = SMBcreate;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,finfo->mode);
  put_dos_date3(outbuf,smb_vwv1,finfo->mtime);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  pstrcpy(p,rname);
  
  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("%s opening remote file %s\n",smb_errstr(inbuf),CNV_LANG(rname)));

      free(inbuf);free(outbuf);if (buf) free(buf);
      return;
    }

  /* allow files to be piped into smbclient
     jdblair 24.jun.98 */
  if (!strcmp(lname, "-")) {
    f = stdin;
    /* size of file is not known */
    finfo->size = 0;
  } else {
    f = fopen(lname,"r");
  }

  if (!f)
    {
      DEBUG(0,("Error opening local file %s\n",lname));
      free(inbuf);free(outbuf);
      return;
    }

  
  fnum = SVAL(inbuf,smb_vwv0);
  if (finfo->size < 0)
    finfo->size = file_size(lname);
  
  DEBUG(1,("putting file %s of size %.0f bytes as %s ",lname,(double)finfo->size,CNV_LANG(rname)));
  
  if (!maxwrite)
    maxwrite = writebraw_supported?MAX(max_xmit,BUFFER_SIZE):(max_xmit-200);

  /* This is a rewrite of the read/write loop that doesn't require the input
     file to be of a known length.  This allows the stream pointer 'f' to
     refer to stdin.

     Rather than reallocing the read buffer every loop to keep it the min
     necessary length this look uses a fixed length buffer and just tests
     for eof on the file stream at the top of each loop.
     jdblair, 24.jun.98 */

  buf = (char *)malloc(maxwrite+4);
  while (! feof(f) )
    {
      int n = maxwrite;
      int ret;

      if ((n = readfile(buf+4,1,n,f)) < 1)
	{
	  DEBUG(0,("Error reading local file\n"));
	  break;
	}	  

      ret = smb_writefile(outbuf,fnum,nread,buf+4,n);

      if (n != ret) {
	      if (!maxwrite) {
		      DEBUG(0,("Error writing file\n"));
		      break;
	      } else {
		      fseek(f,nread,SEEK_SET);
		      maxwrite /= 2;
		      continue;
	      }
      }

      nread += n;
    }

  bzero(outbuf,smb_size);
  set_message(outbuf,3,0,True);
  CVAL(outbuf,smb_com) = SMBclose;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,fnum);  
  put_dos_date3(outbuf,smb_vwv1,close_time);

  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("%s closing remote file %s\n",smb_errstr(inbuf),CNV_LANG(rname)));
      fclose(f);
      free(inbuf);free(outbuf);
      if (buf) free(buf);
      return;
    }

  
  fclose(f);
  free(inbuf);free(outbuf);
  if (buf) free(buf);

  {
    struct timeval tp_end;
    int this_time;

    GetTimeOfDay(&tp_end);
    this_time = 
      (tp_end.tv_sec - tp_start.tv_sec)*1000 +
	(tp_end.tv_usec - tp_start.tv_usec)/1000;
    put_total_time_ms += this_time;
    put_total_size += finfo->size;

    DEBUG(1,("(%g kb/s) (average %g kb/s)\n",
	     finfo->size / (1.024*this_time + 1.0e-4),
	     put_total_size / (1.024*put_total_time_ms)));
  }
}

 

/****************************************************************************
  put a file
  ****************************************************************************/
static void cmd_put(char *dum_in, char *dum_out)
{
  pstring lname;
  pstring rname;
  fstring buf;
  char *p=buf;
  file_info finfo;
  finfo = def_finfo;
  
  pstrcpy(rname,cur_dir);
  pstrcat(rname,"\\");
  
  
  if (!next_token(NULL,p,NULL,sizeof(buf)))
    {
      DEBUG(0,("put <filename>\n"));
      return;
    }
  pstrcpy(lname,p);
  
  if (next_token(NULL,p,NULL,sizeof(buf)))
    pstrcat(rname,p);      
  else
    pstrcat(rname,lname);

  dos_clean_name(rname);

  {
    SMB_STRUCT_STAT st;
    /* allow '-' to represent stdin
       jdblair, 24.jun.98 */
    if (!file_exist(lname,&st) &&
      (strcmp(lname,"-"))) {
      DEBUG(0,("%s does not exist\n",lname));
      return;
    }
    finfo.mtime = st.st_mtime;
  }

  do_put(rname,lname,&finfo);
}

/****************************************************************************
  seek in a directory/file list until you get something that doesn't start with
  the specified name
  ****************************************************************************/
static BOOL seek_list(FILE *f,char *name)
{
  pstring s;
  while (!feof(f))
    {
      if (fscanf(f,"%s",s) != 1) return(False);
      trim_string(s,"./",NULL);
      if (strncmp(s,name,strlen(name)) != 0)
	{
	  pstrcpy(name,s);
	  return(True);
	}
    }
      
  return(False);
}


/****************************************************************************
  set the file selection mask
  ****************************************************************************/
static void cmd_select(char *dum_in, char *dum_out)
{
  pstrcpy(fileselection,"");
  next_token(NULL,fileselection,NULL,sizeof(fileselection));
}


/****************************************************************************
  mput some files
  ****************************************************************************/
static void cmd_mput(char *dum_in, char *dum_out)
{
  pstring lname;
  pstring rname;
  file_info finfo;
  fstring buf;
  char *p=buf;

  finfo = def_finfo;

  
  while (next_token(NULL,p,NULL,sizeof(buf)))
    {
      SMB_STRUCT_STAT st;
      pstring cmd;
      pstring tmpname;
      FILE *f;
      
      slprintf(tmpname,sizeof(pstring)-1,
	       "%s/ls.smb.%d",tmpdir(),(int)getpid());
      if (recurse)
	slprintf(cmd,sizeof(pstring)-1,
		"find . -name \"%s\" -print > %s",p,tmpname);
      else
	slprintf(cmd,sizeof(pstring)-1,
		 "/bin/ls %s > %s",p,tmpname);
      system(cmd);

      f = fopen(tmpname,"r");
      if (!f) continue;

      while (!feof(f))
	{
	  pstring quest;

	  if (fscanf(f,"%s",lname) != 1) break;
	  trim_string(lname,"./",NULL);

	again1:

	  /* check if it's a directory */
	  if (directory_exist(lname,&st))
	    {
	      if (!recurse) continue;
	      slprintf(quest,sizeof(pstring)-1,
		       "Put directory %s? ",lname);
	      if (prompt && !yesno(quest)) 
		{
		  pstrcat(lname,"/");
		  if (!seek_list(f,lname))
		    break;
		  goto again1;		    
		}
	      
	      pstrcpy(rname,cur_dir);
	      pstrcat(rname,lname);
	      if (!chkpath(rname,False) && !do_mkdir(rname)) {
		pstrcat(lname,"/");
		if (!seek_list(f,lname))
		  break;
		goto again1;		    		  
	      }

	      continue;
	    }
	  else
	    {
	      slprintf(quest,sizeof(quest)-1,
		       "Put file %s? ",lname);
	      if (prompt && !yesno(quest)) continue;

	      pstrcpy(rname,cur_dir);
	      pstrcat(rname,lname);
	    }
	  dos_format(rname);

	  /* null size so do_put knows to ignore it */
	  finfo.size = -1;

	  /* set the date on the file */
	  finfo.mtime = st.st_mtime;

	  do_put(rname,lname,&finfo);
	}
      fclose(f);
      unlink(tmpname);
    }
}

/****************************************************************************
  cancel a print job
  ****************************************************************************/
static void do_cancel(int job)
{
  char *rparam = NULL;
  char *rdata = NULL;
  char *p;
  int rdrcnt,rprcnt;
  pstring param;

  bzero(param,sizeof(param));

  p = param;
  SSVAL(p,0,81);		/* DosPrintJobDel() */
  p += 2;
  pstrcpy(p,"W");
  p = skip_string(p,1);
  pstrcpy(p,"");
  p = skip_string(p,1);
  SSVAL(p,0,job);     
  p += 2;

  if (cli_call_api(PIPE_LANMAN, 0,PTR_DIFF(p,param),0, 0,
           6, 1000,
	       &rprcnt,&rdrcnt,
	       param,NULL, NULL,
	       &rparam,&rdata))
    {
      int res = SVAL(rparam,0);

      if (!res)
	printf("Job %d cancelled\n",job);
      else
	printf("Error %d calcelling job %d\n",res,job);
      return;
    }
  else
  printf("Server refused cancel request\n");

  if (rparam) free(rparam);
  if (rdata) free(rdata);

  return;
}


/****************************************************************************
  cancel a print job
  ****************************************************************************/
static void cmd_cancel(char *inbuf,char *outbuf )
{
  fstring buf;
  int job; 

  if (!connect_as_printer)
    {
      DEBUG(0,("WARNING: You didn't use the -P option to smbclient.\n"));
      DEBUG(0,("Trying to cancel print jobs without -P may fail\n"));
    }

  if (!next_token(NULL,buf,NULL,sizeof(buf))) {
    printf("cancel <jobid> ...\n");
    return;
  }
  do {
    job = atoi(buf);
    do_cancel(job);
  } while (next_token(NULL,buf,NULL,sizeof(buf)));
}




/****************************************************************************
  print a file
  ****************************************************************************/
static void cmd_print(char *inbuf,char *outbuf )
{
  int fnum;
  FILE *f = NULL;
  uint32 nread=0;
  pstring lname;
  pstring rname;
  char *p;

  if (!connect_as_printer)
    {
      DEBUG(0,("WARNING: You didn't use the -P option to smbclient.\n"));
      DEBUG(0,("Trying to print without -P may fail\n"));
    }

  if (!next_token(NULL,lname,NULL, sizeof(lname)))
    {
      DEBUG(0,("print <filename>\n"));
      return;
    }

  pstrcpy(rname,lname);
  p = strrchr(rname,'/');
  if (p)
    {
      pstring tname;
      pstrcpy(tname,p+1);
      pstrcpy(rname,tname);
    }

  if ((int)strlen(rname) > 14)
    rname[14] = 0;

  if (strequal(lname,"-"))
    {
      f = stdin;
      pstrcpy(rname,"stdin");
    }
  
  dos_clean_name(rname);

  bzero(outbuf,smb_size);
  set_message(outbuf,2,2 + strlen(rname),True);
  
  CVAL(outbuf,smb_com) = SMBsplopen;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,0);
  SSVAL(outbuf,smb_vwv1,printmode);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  pstrcpy(p,rname);
  
  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("%s opening printer for %s\n",smb_errstr(inbuf),CNV_LANG(rname)));
      return;
    }
  
  if (!f)
    f = fopen(lname,"r");
  if (!f)
    {
      DEBUG(0,("Error opening local file %s\n",lname));
      return;
    }

  
  fnum = SVAL(inbuf,smb_vwv0);
  
  DEBUG(1,("printing file %s as %s\n",lname,CNV_LANG(rname)));
  
  while (!feof(f))
    {
      int n;
  
      bzero(outbuf,smb_size);
      set_message(outbuf,1,3,True);

      /* for some strange reason the OS/2 print server can't handle large
	 packets when printing. weird */
      n = MIN(1024,max_xmit-(smb_len(outbuf)+4));

      if (translation)
	n = printread(f,smb_buf(outbuf)+3,(int)(0.95*n));
      else
	n = readfile(smb_buf(outbuf)+3,1,n,f);
      if (n <= 0) 
	{
	  DEBUG(0,("read gave %d\n",n));
	  break;
	}

      smb_setlen(outbuf,smb_len(outbuf) + n);

      CVAL(outbuf,smb_com) = SMBsplwr;
      SSVAL(outbuf,smb_tid,cnum);
      cli_setup_pkt(outbuf);

      SSVAL(outbuf,smb_vwv0,fnum);
      SSVAL(outbuf,smb_vwv1,n+3);
      CVAL(smb_buf(outbuf),0) = 1;
      SSVAL(smb_buf(outbuf),1,n);

      send_smb(Client,outbuf);
      client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);

      if (CVAL(inbuf,smb_rcls) != 0)
	{
	  DEBUG(0,("%s printing remote file\n",smb_errstr(inbuf)));
	  break;
	}

      nread += n;
    }

  DEBUG(2,("%d bytes printed\n",nread));

  bzero(outbuf,smb_size);
  set_message(outbuf,1,0,True);
  CVAL(outbuf,smb_com) = SMBsplclose;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,fnum);

  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("%s closing print file\n",smb_errstr(inbuf)));
      if (f != stdin)
	fclose(f);
      return;
    }

  if (f != stdin)
    fclose(f);
}

/****************************************************************************
 show a print queue - this is deprecated as it uses the old smb that
 has limited support - the correct call is the cmd_p_queue_4() after this.
****************************************************************************/
static void cmd_queue(char *inbuf,char *outbuf )
{
  int count;
  char *p;

  bzero(outbuf,smb_size);
  set_message(outbuf,2,0,True);
  
  CVAL(outbuf,smb_com) = SMBsplretq;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,32); /* a max of 20 entries is to be shown */
  SSVAL(outbuf,smb_vwv1,0); /* the index into the queue */
  
  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("%s obtaining print queue\n",smb_errstr(inbuf)));
      return;
    }

  count = SVAL(inbuf,smb_vwv0);
  p = smb_buf(inbuf) + 3;
  if (count <= 0)
    {
      DEBUG(0,("No entries in the print queue\n"));
      return;
    }  

  {
    char status[20];

    DEBUG(0,("Job      Name              Size         Status\n"));

    while (count--)
      {
	switch (CVAL(p,4))
	  {
	  case 0x01: safe_strcpy(status,"held or stopped", sizeof(status)-1); break;
	  case 0x02: safe_strcpy(status,"printing",sizeof(status)-1); break;
	  case 0x03: safe_strcpy(status,"awaiting print", sizeof(status)-1); break;
	  case 0x04: safe_strcpy(status,"in intercept",sizeof(status)-1); break;
	  case 0x05: safe_strcpy(status,"file had error",sizeof(status)-1); break;
	  case 0x06: safe_strcpy(status,"printer error",sizeof(status)-1); break;
	  default: safe_strcpy(status,"unknown",sizeof(status)-1); break;
	  }

	DEBUG(0,("%-6d   %-16.16s  %-9d    %s\n",
		 SVAL(p,5),p+12,IVAL(p,7),status));
	p += 28;
      }
  }
  
}


/****************************************************************************
show information about a print queue
****************************************************************************/
static void cmd_p_queue_4(char *inbuf,char *outbuf )
{
  char *rparam = NULL;
  char *rdata = NULL;
  char *p;
  int rdrcnt, rprcnt;
  pstring param;
  int result_code=0;

  if (!connect_as_printer)
    {
      DEBUG(0,("WARNING: You didn't use the -P option to smbclient.\n"));
      DEBUG(0,("Trying to print without -P may fail\n"));
    }
  
  bzero(param,sizeof(param));

  p = param;
  SSVAL(p,0,76);                        /* API function number 76 (DosPrintJobEnum) */
  p += 2;
  pstrcpy(p,"zWrLeh");                   /* parameter description? */
  p = skip_string(p,1);
  pstrcpy(p,"WWzWWDDzz");                /* returned data format */
  p = skip_string(p,1);
  pstrcpy(p,strrchr(service,'\\')+1);    /* name of queue */
  p = skip_string(p,1);
  SSVAL(p,0,2);                 /* API function level 2, PRJINFO_2 data structure */
  SSVAL(p,2,1000);                      /* size of bytes of returned data buffer */
  p += 4;
  pstrcpy(p,"");                         /* subformat */
  p = skip_string(p,1);

  DEBUG(1,("Calling DosPrintJobEnum()...\n"));
  if( cli_call_api(PIPE_LANMAN, 0,PTR_DIFF(p,param), 0, 0,
               10, 4096,
               &rprcnt, &rdrcnt,
               param, NULL, NULL,
               &rparam, &rdata) )
    {
      int converter;
      result_code = SVAL(rparam,0);
      converter = SVAL(rparam,2);             /* conversion factor */

      DEBUG(2,("returned %d bytes of parameters, %d bytes of data, %d records\n", rprcnt, rdrcnt, SVAL(rparam,4) ));

      if (result_code == 0)                   /* if no error, */
        {
          int i;
          uint16 JobId;
          uint16 Priority;
          uint32 Size;
          char *UserName;
          char *JobName;
          char *JobTimeStr;
          time_t JobTime;
          fstring PrinterName;
             
          fstrcpy(PrinterName,strrchr(service,'\\')+1);       /* name of queue */
          strlower(PrinterName);                             /* in lower case */

          p = rdata;                          /* received data */
          for( i = 0; i < SVAL(rparam,4); ++i)
            {
              JobId = SVAL(p,0);
              Priority = SVAL(p,2);
              UserName = fix_char_ptr(SVAL(p,4), converter, rdata, rdrcnt);
              strlower(UserName);
              Priority = SVAL(p,2);
              JobTime = make_unix_date3( p + 12);
              JobTimeStr = asctime(LocalTime( &JobTime));
              Size = IVAL(p,16);
              JobName = fix_char_ptr(SVAL(p,24), converter, rdata, rdrcnt);
            

              printf("%s-%u    %s    priority %u   %s    %s   %u bytes\n", 
		PrinterName, JobId, UserName,
                Priority, JobTimeStr, JobName, Size);
   
#if 0 /* DEBUG code */
              printf("Job Id: \"%u\"\n", SVAL(p,0));
              printf("Priority: \"%u\"\n", SVAL(p,2));
            
              printf("User Name: \"%s\"\n", fix_char_ptr(SVAL(p,4), converter, rdata, rdrcnt) );
              printf("Position: \"%u\"\n", SVAL(p,8));
              printf("Status: \"%u\"\n", SVAL(p,10));
            
              JobTime = make_unix_date3( p + 12);
              printf("Submitted: \"%s\"\n", asctime(LocalTime(&JobTime)));
              printf("date: \"%u\"\n", SVAL(p,12));

              printf("Size: \"%u\"\n", SVAL(p,16));
              printf("Comment: \"%s\"\n", fix_char_ptr(SVAL(p,20), converter, rdata, rdrcnt) );
              printf("Document: \"%s\"\n", fix_char_ptr(SVAL(p,24), converter, rdata, rdrcnt) );
#endif /* DEBUG CODE */ 
              p += 28;
            }
        }
    }
  else                  /* cli_call_api() failed */
    {
      printf("Failed, error = %d\n", result_code);
    }

  /* If any parameters or data were returned, free the storage. */
  if(rparam) free(rparam);
  if(rdata) free(rdata);

  return;
}

/****************************************************************************
show information about a print queue
****************************************************************************/
static void cmd_qinfo(char *inbuf,char *outbuf )
{
  char *rparam = NULL;
  char *rdata = NULL;
  char *p;
  int rdrcnt, rprcnt;
  pstring param;
  int result_code=0;
  
  bzero(param,sizeof(param));

  p = param;
  SSVAL(p,0,70); 			/* API function number 70 (DosPrintQGetInfo) */
  p += 2;
  pstrcpy(p,"zWrLh");			/* parameter description? */
  p = skip_string(p,1);
  pstrcpy(p,"zWWWWzzzzWWzzl");		/* returned data format */
  p = skip_string(p,1);
  pstrcpy(p,strrchr(service,'\\')+1);	/* name of queue */
  p = skip_string(p,1);
  SSVAL(p,0,3);				/* API function level 3, just queue info, no job info */
  SSVAL(p,2,1000);			/* size of bytes of returned data buffer */
  p += 4;
  pstrcpy(p,"");				/* subformat */
  p = skip_string(p,1);

  DEBUG(1,("Calling DosPrintQueueGetInfo()...\n"));
  if( cli_call_api(PIPE_LANMAN, 0,PTR_DIFF(p,param), 0, 0,
           10, 4096,
	       &rprcnt, &rdrcnt,
	       param, NULL, NULL,
	       &rparam, &rdata) )
	{
	int converter;
	result_code = SVAL(rparam,0);
	converter = SVAL(rparam,2);		/* conversion factor */

	DEBUG(2,("returned %d bytes of parameters, %d bytes of data, %d records\n", rprcnt, rdrcnt, SVAL(rparam,4) ));

	if (result_code == 0)			/* if no error, */
	    {
	    p = rdata;				/* received data */

	    printf("Name: \"%s\"\n", fix_char_ptr(SVAL(p,0), converter, rdata, rdrcnt) );
	    printf("Priority: %u\n", SVAL(p,4) );
	    printf("Start time: %u\n", SVAL(p,6) );
	    printf("Until time: %u\n", SVAL(p,8) );
	    printf("Seperator file: \"%s\"\n", fix_char_ptr(SVAL(p,12), converter, rdata, rdrcnt) );
	    printf("Print processor: \"%s\"\n", fix_char_ptr(SVAL(p,16), converter, rdata, rdrcnt) );
	    printf("Parameters: \"%s\"\n", fix_char_ptr(SVAL(p,20), converter, rdata, rdrcnt) );
	    printf("Comment: \"%s\"\n", fix_char_ptr(SVAL(p,24), converter, rdata, rdrcnt) );
	    printf("Status: %u\n", SVAL(p,28) );
	    printf("Jobs: %u\n", SVAL(p,30) );
	    printf("Printers: \"%s\"\n", fix_char_ptr(SVAL(p,32), converter, rdata, rdrcnt) );
	    printf("Drivername: \"%s\"\n", fix_char_ptr(SVAL(p,36), converter, rdata, rdrcnt) );

	    /* Dump the driver data */
	    {
	    int count, x, y, c;
	    char *ddptr;

	    ddptr = rdata + SVAL(p,40) - converter;
	    if( SVAL(p,40) == 0 ) {count = 0;} else {count = IVAL(ddptr,0);}
	    printf("Driverdata: size=%d, version=%u\n", count, IVAL(ddptr,4) );

	    for(x=8; x < count; x+=16)
		{
		for(y=0; y < 16; y++)
		    {
		    if( (x+y) < count )
		    	printf("%2.2X ", CVAL(ddptr,(x+y)) );
		    else
		    	fputs("   ", stdout);
		    }
		for(y=0; y < 16 && (x+y) < count; y++)
		    {
		    c = CVAL(ddptr,(x+y));
		    if(isprint(c))
		    	fputc(c, stdout);
		    else
		    	fputc('.', stdout);
		    }
		fputc('\n', stdout);
		}
	    }
	    
	    }
	}
  else			/* cli_call_api() failed */
  	{
  	printf("Failed, error = %d\n", result_code);
  	}

  /* If any parameters or data were returned, free the storage. */
  if(rparam) free(rparam);
  if(rdata) free(rdata);

  return;
}

/****************************************************************************
delete some files
****************************************************************************/
static void do_del(file_info *finfo)
{
  char *p;
  char *inbuf,*outbuf;
  pstring mask;

  pstrcpy(mask,cur_dir);
  pstrcat(mask,finfo->name);

  if (finfo->mode & aDIR) 
    return;

  inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  
  if (!inbuf || !outbuf)
    {
      DEBUG(0,("out of memory\n"));
      return;
    }

  bzero(outbuf,smb_size);
  set_message(outbuf,1,2 + strlen(mask),True);
  
  CVAL(outbuf,smb_com) = SMBunlink;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,0);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  pstrcpy(p,mask);
  
  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    DEBUG(0,("%s deleting remote file %s\n",smb_errstr(inbuf),CNV_LANG(mask)));

  free(inbuf);free(outbuf);
  
}

/****************************************************************************
delete some files
****************************************************************************/
static void cmd_del(char *inbuf,char *outbuf )
{
  pstring mask;
  fstring buf;
  int attribute = aSYSTEM | aHIDDEN;

  if (recurse)
    attribute |= aDIR;
  
  pstrcpy(mask,cur_dir);
    
  if (!next_token(NULL,buf,NULL,sizeof(buf)))
    {
      DEBUG(0,("del <filename>\n"));
      return;
    }
  pstrcat(mask,buf);

  do_dir((char *)inbuf,(char *)outbuf,mask,attribute,do_del,False,False);
}


/****************************************************************************
remove a directory
****************************************************************************/
static void cmd_rmdir(char *inbuf,char *outbuf )
{
  pstring mask;
  fstring buf;
  char *p;
  
  pstrcpy(mask,cur_dir);
  
  if (!next_token(NULL,buf,NULL,sizeof(buf)))
    {
      DEBUG(0,("rmdir <dirname>\n"));
      return;
    }
  pstrcat(mask,buf);

  bzero(outbuf,smb_size);
  set_message(outbuf,0,2 + strlen(mask),True);
  
  CVAL(outbuf,smb_com) = SMBrmdir;
  SSVAL(outbuf,smb_tid,cnum);
  cli_setup_pkt(outbuf);

  
  p = smb_buf(outbuf);
  *p++ = 4;      
  pstrcpy(p,mask);
  
  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("%s removing remote directory file %s\n",smb_errstr(inbuf),CNV_LANG(mask)));
      return;
    }
  
}

/****************************************************************************
rename some files
****************************************************************************/
static void cmd_rename(char *inbuf,char *outbuf )
{
  pstring src,dest;
  fstring buf,buf2;
  char *p;
  
  pstrcpy(src,cur_dir);
  pstrcpy(dest,cur_dir);
  
  if (!next_token(NULL,buf,NULL,sizeof(buf)) || 
      !next_token(NULL,buf2,NULL, sizeof(buf2)))
    {
      DEBUG(0,("rename <src> <dest>\n"));
      return;
    }
  pstrcat(src,buf);
  pstrcat(dest,buf2);

  bzero(outbuf,smb_size);
  set_message(outbuf,1,4 + strlen(src) + strlen(dest),True);
  
  CVAL(outbuf,smb_com) = SMBmv;
  SSVAL(outbuf,smb_tid,cnum);
  SSVAL(outbuf,smb_vwv0,aHIDDEN | aDIR | aSYSTEM);
  cli_setup_pkt(outbuf);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  pstrcpy(p,src);
  p = skip_string(p,1);
  *p++ = 4;      
  pstrcpy(p,dest);
  
  send_smb(Client,outbuf);
  client_receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("%s renaming files\n",smb_errstr(inbuf)));
      return;
    }
  
}


/****************************************************************************
toggle the prompt flag
****************************************************************************/
static void cmd_prompt(char *dum_in, char *dum_out)
{
  prompt = !prompt;
  DEBUG(2,("prompting is now %s\n",prompt?"on":"off"));
}


/****************************************************************************
set the newer than time
****************************************************************************/
static void cmd_newer(char *dum_in, char *dum_out)
{
  fstring buf;
  BOOL ok;
  SMB_STRUCT_STAT sbuf;

  ok = next_token(NULL,buf,NULL,sizeof(buf));
  if (ok && (dos_stat(buf,&sbuf) == 0))
    {
      newer_than = sbuf.st_mtime;
      DEBUG(1,("Getting files newer than %s",
	       asctime(LocalTime(&newer_than))));
    }
  else
    newer_than = 0;

  if (ok && newer_than == 0)
    DEBUG(0,("Error setting newer-than time\n"));
}

/****************************************************************************
set the archive level
****************************************************************************/
static void cmd_archive(char *dum_in, char *dum_out)
{
  fstring buf;

  if (next_token(NULL,buf,NULL,sizeof(buf))) {
    archive_level = atoi(buf);
  } else
    DEBUG(0,("Archive level is %d\n",archive_level));
}

/****************************************************************************
toggle the lowercaseflag
****************************************************************************/
static void cmd_lowercase(char *dum_in, char *dum_out)
{
  lowercase = !lowercase;
  DEBUG(2,("filename lowercasing is now %s\n",lowercase?"on":"off"));
}




/****************************************************************************
toggle the recurse flag
****************************************************************************/
static void cmd_recurse(char *dum_in, char *dum_out)
{
  recurse = !recurse;
  DEBUG(2,("directory recursion is now %s\n",recurse?"on":"off"));
}

/****************************************************************************
toggle the translate flag
****************************************************************************/
static void cmd_translate(char *dum_in, char *dum_out)
{
  translation = !translation;
  DEBUG(2,("CR/LF<->LF and print text translation now %s\n",
	translation?"on":"off"));
}


/****************************************************************************
do a printmode command
****************************************************************************/
static void cmd_printmode(char *dum_in, char *dum_out)
{
  fstring buf;
  fstring mode;

  if (next_token(NULL,buf,NULL,sizeof(buf)))
    {
      if (strequal(buf,"text"))
	printmode = 0;      
      else
	{
	  if (strequal(buf,"graphics"))
	    printmode = 1;
	  else
	    printmode = atoi(buf);
	}
    }

  switch(printmode)
    {
    case 0: 
      fstrcpy(mode,"text");
      break;
    case 1: 
      fstrcpy(mode,"graphics");
      break;
    default: 
      slprintf(mode,sizeof(mode)-1,"%d",printmode);
      break;
    }

  DEBUG(2,("the printmode is now %s\n",mode));
}

/****************************************************************************
do the lcd command
****************************************************************************/
static void cmd_lcd(char *dum_in, char *dum_out)
{
  fstring buf;
  pstring d;

  if (next_token(NULL,buf,NULL,sizeof(buf)))
    dos_chdir(buf);
  DEBUG(2,("the local directory is now %s\n",GetWd(d)));
}


/****************************************************************************
try and browse available connections on a host
****************************************************************************/
static BOOL browse_host(BOOL sort)
{
  char *rparam = NULL;
  char *rdata = NULL;
  char *p;
  int rdrcnt,rprcnt;
  pstring param;
  int count = -1;

  /* now send a SMBtrans command with api RNetShareEnum */
  p = param;
  SSVAL(p,0,0); /* api number */
  p += 2;
  pstrcpy(p,"WrLeh");
  p = skip_string(p,1);
  pstrcpy(p,"B13BWz");
  p = skip_string(p,1);
  SSVAL(p,0,1);
  SSVAL(p,2,BUFFER_SIZE);
  p += 4;

  if (cli_call_api(PIPE_LANMAN, 0,PTR_DIFF(p,param),0, 0,
             1024, BUFFER_SIZE,
             &rprcnt,&rdrcnt,
             param,NULL, NULL,
             &rparam,&rdata))
  {
    int res = SVAL(rparam,0);
    int converter=SVAL(rparam,2);
    int i;
    BOOL long_share_name=False;
      
    if (res == 0 || res == ERRmoredata)
    {
      count=SVAL(rparam,4);
      p = rdata;

      if (count > 0)
      {
        printf("\n\tSharename      Type      Comment\n");
        printf("\t---------      ----      -------\n");
      }

      if (sort)
        qsort(p,count,20,QSORT_CAST StrCaseCmp);

      for (i=0;i<count;i++)
      {
        char *sname = p;
        int type = SVAL(p,14);
        int comment_offset = IVAL(p,16) & 0xFFFF;
        fstring typestr;
        *typestr=0;

        switch (type)
        {
          case STYPE_DISKTREE:
            fstrcpy(typestr,"Disk"); break;
          case STYPE_PRINTQ:
            fstrcpy(typestr,"Printer"); break;	      
          case STYPE_DEVICE:
            fstrcpy(typestr,"Device"); break;
          case STYPE_IPC:
            fstrcpy(typestr,"IPC"); break;      
        }

        printf("\t%-15.15s%-10.10s%s\n",
               sname, typestr,
               comment_offset?rdata+comment_offset-converter:"");
	  
        if (strlen(sname)>8) long_share_name=True;
	  
        p += 20;
      }

      if (long_share_name) {
        printf("\nNOTE: There were share names longer than 8 chars.\n\
On older clients these may not be accessible or may give browsing errors\n");
      }

      if(res == ERRmoredata)
        printf("\nNOTE: More data was available, the list was truncated.\n");
    }
  }
  
  if (rparam) free(rparam);
  if (rdata) free(rdata);

  return(count>0);
}


/****************************************************************************
get some server info
****************************************************************************/
static void server_info(void)
{
  char *rparam = NULL;
  char *rdata = NULL;
  char *p;
  int rdrcnt,rprcnt;
  pstring param;

  bzero(param,sizeof(param));

  p = param;
  SSVAL(p,0,63); 		/* NetServerGetInfo()? */
  p += 2;
  pstrcpy(p,"WrLh");
  p = skip_string(p,1);
  pstrcpy(p,"zzzBBzz");
  p = skip_string(p,1);
  SSVAL(p,0,10); /* level 10 */
  SSVAL(p,2,1000);
  p += 6;

  if (cli_call_api(PIPE_LANMAN, 0,PTR_DIFF(p,param),0, 0,
           6, 1000,
	       &rprcnt,&rdrcnt,
	       param,NULL, NULL,
	       &rparam,&rdata))
    {
      int res = SVAL(rparam,0);
      int converter=SVAL(rparam,2);

      if (res == 0)
	{
      p = rdata;

      printf("\nServer=[%s] User=[%s] Workgroup=[%s] Domain=[%s]\n",
	     rdata+SVAL(p,0)-converter,
	     rdata+SVAL(p,4)-converter,
	     rdata+SVAL(p,8)-converter,
	     rdata+SVAL(p,14)-converter);
    }
    }

  if (rparam) free(rparam);
  if (rdata) free(rdata);

  return;
}


/****************************************************************************
try and browse available connections on a host
****************************************************************************/
static BOOL list_servers(char *wk_grp)
{
  char *rparam = NULL;
  char *rdata = NULL;
  int rdrcnt,rprcnt;
  char *p,*svtype_p;
  pstring param;
  int uLevel = 1;
  int count = 0;
  BOOL ok = False;
  BOOL generic_request = False;


  if (strequal(wk_grp,"WORKGROUP")) {
    /* we won't specify a workgroup */
    generic_request = True;
  } 

  /* now send a SMBtrans command with api ServerEnum? */
  p = param;
  SSVAL(p,0,0x68); /* api number */
  p += 2;

  pstrcpy(p,generic_request?"WrLehDO":"WrLehDz");
  p = skip_string(p,1);

  pstrcpy(p,"B16BBDz");

  p = skip_string(p,1);
  SSVAL(p,0,uLevel);
  SSVAL(p,2,BUFFER_SIZE - SAFETY_MARGIN); /* buf length */
  p += 4;

  svtype_p = p;
  p += 4;

  if (!generic_request) {
    pstrcpy(p, wk_grp);
    p = skip_string(p,1);
  }

  /* first ask for a list of servers in this workgroup */
  SIVAL(svtype_p,0,SV_TYPE_ALL);

  if (cli_call_api(PIPE_LANMAN, 0,PTR_DIFF(p+4,param),0, 0,
           8, BUFFER_SIZE - SAFETY_MARGIN,
           &rprcnt,&rdrcnt,
           param,NULL, NULL,
           &rparam,&rdata))
  {
    int res = SVAL(rparam,0);
    int converter=SVAL(rparam,2);
    int i;

    if (res == 0 || res == ERRmoredata) {	
      char *p2 = rdata;
      count=SVAL(rparam,4);

      if (count > 0) {
        printf("\n\nThis machine has a browse list:\n");
        printf("\n\tServer               Comment\n");
        printf("\t---------            -------\n");
      }
	
      for (i=0;i<count;i++) {
        char *sname = p2;
        int comment_offset = IVAL(p2,22) & 0xFFFF;
        printf("\t%-16.16s     %s\n", sname,
               comment_offset?rdata+comment_offset-converter:"");

        ok=True;
        p2 += 26;
      }

      if(res == ERRmoredata)
        printf("\nNOTE: More data was available, the list was truncated.\n");
    }
  }

  if (rparam) {free(rparam); rparam = NULL;}
  if (rdata) {free(rdata); rdata = NULL;}

  /* now ask for a list of workgroups */
  SIVAL(svtype_p,0,SV_TYPE_DOMAIN_ENUM);

  if (cli_call_api(PIPE_LANMAN, 0,PTR_DIFF(p+4,param),0, 0,
           8, BUFFER_SIZE - SAFETY_MARGIN,
           &rprcnt,&rdrcnt,
           param,NULL, NULL,
           &rparam,&rdata))
  {
    int res = SVAL(rparam,0);
    int converter=SVAL(rparam,2);
    int i;

    if (res == 0 || res == ERRmoredata) {
      char *p2 = rdata;
      count=SVAL(rparam,4);

      if (count > 0) {
        printf("\n\nThis machine has a workgroup list:\n");
        printf("\n\tWorkgroup            Master\n");
        printf("\t---------            -------\n");
      }
	
      for (i=0;i<count;i++) {
        char *sname = p2;
        int comment_offset = IVAL(p2,22) & 0xFFFF;
        printf("\t%-16.16s     %s\n", sname,
               comment_offset?rdata+comment_offset-converter:"");
	  
        ok=True;
        p2 += 26;
      }

      if(res == ERRmoredata)
        printf("\nNOTE: More data was available, the list was truncated.\n");
    }
  }

  if (rparam) free(rparam);
  if (rdata) free(rdata);

  return(ok);
}


/* Some constants for completing filename arguments */

#define COMPL_NONE        0          /* No completions */
#define COMPL_REMOTE      1          /* Complete remote filename */
#define COMPL_LOCAL       2          /* Complete local filename */

/* This defines the commands supported by this client */
struct
{
  char *name;
  void (*fn)(char *, char *);
  char *description;
  char compl_args[2];      /* Completion argument info */
} commands[] = 
{
  {"ls",cmd_dir,"<mask> list the contents of the current directory",{COMPL_REMOTE,COMPL_NONE}},
  {"dir",cmd_dir,"<mask> list the contents of the current directory",{COMPL_REMOTE,COMPL_NONE}},
  {"du",cmd_du,"<mask> computes the total size of the current directory",{COMPL_REMOTE,COMPL_NONE}},
  {"lcd",cmd_lcd,"[directory] change/report the local current working directory",{COMPL_LOCAL,COMPL_NONE}},
  {"cd",cmd_cd,"[directory] change/report the remote directory",{COMPL_REMOTE,COMPL_NONE}},
  {"pwd",cmd_pwd,"show current remote directory (same as 'cd' with no args)",{COMPL_NONE,COMPL_NONE}},
  {"get",cmd_get,"<remote name> [local name] get a file",{COMPL_REMOTE,COMPL_LOCAL}},
  {"mget",cmd_mget,"<mask> get all the matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"put",cmd_put,"<local name> [remote name] put a file",{COMPL_LOCAL,COMPL_REMOTE}},
  {"mput",cmd_mput,"<mask> put all matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"rename",cmd_rename,"<src> <dest> rename some files",{COMPL_REMOTE,COMPL_REMOTE}},
  {"more",cmd_more,"<remote name> view a remote file with your pager",{COMPL_REMOTE,COMPL_NONE}},  
  {"mask",cmd_select,"<mask> mask all filenames against this",{COMPL_REMOTE,COMPL_NONE}},
  {"del",cmd_del,"<mask> delete all matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"rm",cmd_del,"<mask> delete all matching files",{COMPL_REMOTE,COMPL_NONE}},
  {"mkdir",cmd_mkdir,"<directory> make a directory",{COMPL_NONE,COMPL_NONE}},
  {"md",cmd_mkdir,"<directory> make a directory",{COMPL_NONE,COMPL_NONE}},
  {"rmdir",cmd_rmdir,"<directory> remove a directory",{COMPL_NONE,COMPL_NONE}},
  {"rd",cmd_rmdir,"<directory> remove a directory",{COMPL_NONE,COMPL_NONE}},
  {"pq",cmd_p_queue_4,"enumerate the print queue",{COMPL_NONE,COMPL_NONE}},
  {"prompt",cmd_prompt,"toggle prompting for filenames for mget and mput",{COMPL_NONE,COMPL_NONE}},  
  {"recurse",cmd_recurse,"toggle directory recursion for mget and mput",{COMPL_NONE,COMPL_NONE}},  
  {"translate",cmd_translate,"toggle text translation for printing",{COMPL_NONE,COMPL_NONE}},  
  {"lowercase",cmd_lowercase,"toggle lowercasing of filenames for get",{COMPL_NONE,COMPL_NONE}},  
  {"print",cmd_print,"<file name> print a file",{COMPL_NONE,COMPL_NONE}},
  {"printmode",cmd_printmode,"<graphics or text> set the print mode",{COMPL_NONE,COMPL_NONE}},
  {"queue",cmd_queue,"show the print queue",{COMPL_NONE,COMPL_NONE}},
  {"qinfo",cmd_qinfo,"show print queue information",{COMPL_NONE,COMPL_NONE}},
  {"cancel",cmd_cancel,"<jobid> cancel a print queue entry",{COMPL_NONE,COMPL_NONE}},
  {"quit",cli_send_logout,"logoff the server",{COMPL_NONE,COMPL_NONE}},
  {"q",cli_send_logout,"logoff the server",{COMPL_NONE,COMPL_NONE}},
  {"exit",cli_send_logout,"logoff the server",{COMPL_NONE,COMPL_NONE}},
  {"newer",cmd_newer,"<file> only mget files newer than the specified local file",{COMPL_LOCAL,COMPL_NONE}},
  {"archive",cmd_archive,"<level>\n0=ignore archive bit\n1=only get archive files\n2=only get archive files and reset archive bit\n3=get all files and reset archive bit",{COMPL_NONE,COMPL_NONE}},
  {"tar",cmd_tar,"tar <c|x>[IXFqbgNan] current directory to/from <file name>",{COMPL_NONE,COMPL_NONE}},
  {"blocksize",cmd_block,"blocksize <number> (default 20)",{COMPL_NONE,COMPL_NONE}},
  {"tarmode",cmd_tarmode,
     "<full|inc|reset|noreset> tar's behaviour towards archive bits",{COMPL_NONE,COMPL_NONE}},
  {"setmode",cmd_setmode,"filename <setmode string> change modes of file",{COMPL_REMOTE,COMPL_NONE}},
  {"help",cmd_help,"[command] give help on a command",{COMPL_NONE,COMPL_NONE}},
  {"?",cmd_help,"[command] give help on a command",{COMPL_NONE,COMPL_NONE}},
  {"!",NULL,"run a shell command on the local system",{COMPL_NONE,COMPL_NONE}},
  {"",NULL,NULL,{COMPL_NONE,COMPL_NONE}}
};


/*******************************************************************
  lookup a command string in the list of commands, including 
  abbreviations
  ******************************************************************/
static int process_tok(fstring tok)
{
  int i = 0, matches = 0;
  int cmd=0;
  int tok_len = strlen(tok);
  
  while (commands[i].fn != NULL)
    {
      if (strequal(commands[i].name,tok))
	{
	  matches = 1;
	  cmd = i;
	  break;
	}
      else if (strnequal(commands[i].name, tok, tok_len))
	{
	  matches++;
	  cmd = i;
	}
      i++;
    }
  
  if (matches == 0)
    return(-1);
  else if (matches == 1)
    return(cmd);
  else
    return(-2);
}

/****************************************************************************
help
****************************************************************************/
static void cmd_help(char *dum_in, char *dum_out)
{
  int i=0,j;
  fstring buf;

  if (next_token(NULL,buf,NULL,sizeof(buf)))
    {
      if ((i = process_tok(buf)) >= 0)
	DEBUG(0,("HELP %s:\n\t%s\n\n",commands[i].name,commands[i].description));		    
    }
  else
    while (commands[i].description)
      {
	for (j=0; commands[i].description && (j<5); j++) {
	  DEBUG(0,("%-15s",commands[i].name));
	  i++;
	}
	DEBUG(0,("\n"));
      }
}

#ifndef HAVE_LIBREADLINE

/****************************************************************************
wait for keyboard activity, swallowing network packets
****************************************************************************/
static void wait_keyboard(char *buffer)
{
  fd_set fds;
  struct timeval timeout;
  
  while (1) 
    {
      extern int Client;
      FD_ZERO(&fds);
      FD_SET(Client,&fds);
      FD_SET(fileno(stdin),&fds);

      timeout.tv_sec = 20;
      timeout.tv_usec = 0;
      sys_select(MAX(Client,fileno(stdin))+1,&fds,&timeout);
      
      if (FD_ISSET(fileno(stdin),&fds))
  	return;

      /* We deliberately use receive_smb instead of
         client_receive_smb as we want to receive
         session keepalives and then drop them here.
       */
      if (FD_ISSET(Client,&fds))
  	receive_smb(Client,buffer,0);
      
      chkpath("\\",False);
    }  
}

#else /* if HAVE_LIBREADLINE */

/****************************************************************************
  completion routines for GNU Readline
****************************************************************************/

/* To avoid filename completion being activated when no valid
   completions are found, we assign this stub completion function
   to the rl_completion_entry_function variable. */

char *complete_cmd_null(char *text, int state)
{
  return NULL;
}

/* Argh.  This is starting to get ugly.  We need to be able to pass data
   back from the do_dir() iterator function. */

static int compl_state;
static char *compl_text;
static pstring result;

/* Iterator function for do_dir() */

void complete_process_file(file_info *f)
{
  /* Do we have a partial match? */

  if ((compl_state >= 0) && (strncmp(compl_text, f->name, 
				     strlen(compl_text)) == 0)) {

    /* Return filename if we have made enough matches */

    if (compl_state == 0) {
      pstrcpy(result, f->name);
      compl_state = -1;

      return;
    }
    compl_state--;
  }
}

/* Complete a remote file */

char *complete_remote_file(char *text, int state)
{
  char *InBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  char *OutBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  int attribute = aDIR | aSYSTEM | aHIDDEN;
  pstring mask;

  if ((InBuffer == NULL) || (OutBuffer == NULL)) 
    return(NULL);

  /* Create dir mask */

  pstrcpy(mask, cur_dir);
  pstrcat(mask, "*");

  /* Initialise static vars for filename match */

  compl_text = text;
  compl_state = state;
  result[0] = '\0';

  /* Iterate over all files in directory */

  do_dir(InBuffer, OutBuffer, mask, attribute, complete_process_file, False, 
	 True);

  /* Clean up */

  free(InBuffer);
  free(OutBuffer);

  /* Return matched filename */

  if (result[0] != '\0') {
    return strdup(result);      /* Readline will dispose of strings */
  } else {
    return NULL;
  }
}

/* Complete a smbclient command */

char *complete_cmd(char *text, int state)
{
  static int cmd_index;
  char *name;

  /* Initialise */
  
  if (state == 0) {
    cmd_index = 0;
  }

  /* Return the next name which partially matches the list of commands */

  while (strlen(name = commands[cmd_index++].name) > 0) {
    if (strncmp(name, text, strlen(text)) == 0) {
      return strdup(name);
    }
  }

  return NULL;
}

/* Main completion function for smbclient.  Work out which word we are
   trying to complete and call the appropriate function. */

char **completion_fn(char *text, int start, int end)
{
  int i, num_words, cmd_index;
  char lastch = ' ';

  /* If we are at the start of a word, we are completing a smbclient
     command. */

  if (start == 0) {
    return completion_matches(text, complete_cmd);
  }

  /* Count # of words in command */

  num_words = 0;
  for (i = 0; i <= end; i++) {
    if ((rl_line_buffer[i] != ' ') && (lastch == ' '))
      num_words++;
    lastch = rl_line_buffer[i];
  }

  if (rl_line_buffer[end] == ' ')
    num_words++;

  /* Work out which command we are completing for */

  for (cmd_index = 0; strcmp(commands[cmd_index].name, "") != 0; 
       cmd_index++) {

    /* Check each command in array */

    if (strncmp(rl_line_buffer, commands[cmd_index].name,
		strlen(commands[cmd_index].name)) == 0) {

      /* Call appropriate completion function */

      if ((num_words == 2) || (num_words == 3)) {
	switch (commands[cmd_index].compl_args[num_words - 2]) {

	case COMPL_REMOTE:
	  return completion_matches(text, complete_remote_file);
	  break;

	case COMPL_LOCAL:
	  return completion_matches(text, filename_completion_function);
	  break;

	default:
	    /* An invalid completion type */
	    break;
	}
      }

      /* We're either completing an argument > 3 or found an invalid
	 completion type.  Either way do nothing about it. */

      break;
    }
  }
 
  return NULL;
}

#endif /* HAVE_LIBREADLINE */

/****************************************************************************
  process commands from the client
****************************************************************************/
static BOOL process(char *base_directory)
{
  pstring line;
  char *cmd;

  char *InBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  char *OutBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

  if ((InBuffer == NULL) || (OutBuffer == NULL)) 
    return(False);
  
  bzero(OutBuffer,smb_size);

  if (!cli_send_login(InBuffer,OutBuffer,True,True,NULL))
    return(False);

  if (*base_directory) do_cd(base_directory);

  cmd = cmdstr;
  if (cmd[0] != '\0') while (cmd[0] != '\0')
    {
      char *p;
      fstring tok;
      int i;

      if ((p = strchr(cmd, ';')) == 0)
	{
	  strncpy(line, cmd, 999);
	  line[1000] = '\0';
	  cmd += strlen(cmd);
	}
      else
	{
	  if (p - cmd > 999) p = cmd + 999;
	  strncpy(line, cmd, p - cmd);
	  line[p - cmd] = '\0';
	  cmd = p + 1;
	}

      /* input language code to internal one */
      CNV_INPUT (line);
      
      /* and get the first part of the command */
      {
	char *ptr = line;
	if (!next_token(&ptr,tok,NULL,sizeof(tok))) continue;
      }

      if ((i = process_tok(tok)) >= 0)
	commands[i].fn(InBuffer,OutBuffer);
      else if (i == -2)
	DEBUG(0,("%s: command abbreviation ambiguous\n",CNV_LANG(tok)));
      else
	DEBUG(0,("%s: command not found\n",CNV_LANG(tok)));
    }
  else while (!feof(stdin))
    {
      fstring tok;
      int i;

      bzero(OutBuffer,smb_size);

#ifdef HAVE_LIBREADLINE

      {
	pstring promptline;
	
	/* Read input using GNU Readline */

	slprintf(promptline, 
		 sizeof(promptline) - 1, "smb: %s> ", CNV_LANG(cur_dir));
	if (!readline(promptline))
	  break;

	/* Copy read line to samba buffer */
	
	pstrcpy(line, rl_line_buffer);
	pstrcat(line, "\n");

	/* Add line to history */

	if (strlen(line) > 0)
	  add_history(line);
      }

#else

      /* display a prompt */
      DEBUG(0,("smb: %s> ", CNV_LANG(cur_dir)));
      dbgflush( );

      wait_keyboard(InBuffer);
  
      /* and get a response */
      if (!fgets(line,1000,stdin))
	break;

#endif

      /* input language code to internal one */
      CNV_INPUT (line);

      /* special case - first char is ! */
      if (*line == '!')
	{
	  system(line + 1);
	  continue;
	}
      
      /* and get the first part of the command */
      {
	char *ptr = line;
	if (!next_token(&ptr,tok,NULL,sizeof(tok))) continue;
      }

      if ((i = process_tok(tok)) >= 0)
	commands[i].fn(InBuffer,OutBuffer);
      else if (i == -2)
	DEBUG(0,("%s: command abbreviation ambiguous\n",CNV_LANG(tok)));
      else
	DEBUG(0,("%s: command not found\n",CNV_LANG(tok)));
    }
  
  cli_send_logout(InBuffer,OutBuffer);
  return(True);
}

/****************************************************************************
usage on the program
****************************************************************************/
static void usage(char *pname)
{
  DEBUG(0,("Usage: %s service <password> ", pname));

  DEBUG(0,("\nVersion %s\n",VERSION));
  DEBUG(0,("\t-s smb.conf           pathname to smb.conf file\n"));
  DEBUG(0,("\t-B IP addr            broadcast IP address to use\n"));
  DEBUG(0,("\t-O socket_options     socket options to use\n"));
  DEBUG(0,("\t-R name resolve order use these name resolution services only\n"));
  DEBUG(0,("\t-M host               send a winpopup message to the host\n"));
  DEBUG(0,("\t-i scope              use this NetBIOS scope\n"));
  DEBUG(0,("\t-N                    don't ask for a password\n"));
  DEBUG(0,("\t-n netbios name.      Use this name as my netbios name\n"));
  DEBUG(0,("\t-d debuglevel         set the debuglevel\n"));
  DEBUG(0,("\t-P                    connect to service as a printer\n"));
  DEBUG(0,("\t-p port               connect to the specified port\n"));
  DEBUG(0,("\t-l log basename.      Basename for log/debug files\n"));
  DEBUG(0,("\t-h                    Print this help message.\n"));
  DEBUG(0,("\t-I dest IP            use this IP to connect to\n"));
  DEBUG(0,("\t-E                    write messages to stderr instead of stdout\n"));
  DEBUG(0,("\t-U username           set the network username\n"));
  DEBUG(0,("\t-L host               get a list of shares available on a host\n"));
  DEBUG(0,("\t-t terminal code      terminal i/o code {sjis|euc|jis7|jis8|junet|hex}\n"));
  DEBUG(0,("\t-m max protocol       set the max protocol level\n"));
  DEBUG(0,("\t-W workgroup          set the workgroup name\n"));
  DEBUG(0,("\t-T<c|x>IXFqgbNan      command line tar\n"));
  DEBUG(0,("\t-D directory          start from directory\n"));
  DEBUG(0,("\t-c command string     execute semicolon separated commands\n"));
  DEBUG(0,("\n"));
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
  fstring base_directory;
  char *pname = argv[0];
  int port = SMB_PORT;
  int opt;
  extern FILE *dbf;
  extern char *optarg;
  extern int optind;
  pstring query_host;
  BOOL message = False;
  BOOL explicit_user = False;
  extern char tar_type;
  static pstring servicesf = CONFIGFILE;
  pstring term_code;
  pstring new_name_resolve_order;
  char *p;

#ifdef KANJI
  pstrcpy(term_code, KANJI);
#else /* KANJI */
  *term_code = 0;
#endif /* KANJI */

  *query_host = 0;
  *base_directory = 0;

  *new_name_resolve_order = 0;

  DEBUGLEVEL = 2;

  setup_logging(pname,True);

  TimeInit();
  charset_initialise();

  if(!get_myname(myhostname,NULL))
  {
    DEBUG(0,("Failed to get my hostname.\n"));
  }

  in_client = True;   /* Make sure that we tell lp_load we are */

  if (!lp_load(servicesf,True,False,False)) {
    fprintf(stderr, "Can't load %s - run testparm to debug it\n", servicesf);
  }

  codepage_initialise(lp_client_code_page());

  interpret_coding_system(term_code);

#ifdef WITH_SSL
  sslutil_init(0);
#endif

  pstrcpy(workgroup,lp_workgroup());

  load_interfaces();
  pid = (uint16)getpid();
  vuid = (uint16)getuid();
  mid = pid + 100;
  myumask = umask(0);
  umask(myumask);

  if (getenv("USER"))
  {
    pstrcpy(username,getenv("USER"));

    /* modification to support userid%passwd syntax in the USER var
       25.Aug.97, jdblair@uab.edu */

    if ((p=strchr(username,'%')))
    {
      *p = 0;
      pstrcpy(password,p+1);
      got_pass = True;
      memset(strchr(getenv("USER"),'%')+1,'X',strlen(password));
    }
    strupper(username);
  }

 /* modification to support PASSWD environmental var
  25.Aug.97, jdblair@uab.edu */

  if (getenv("PASSWD")) {
    pstrcpy(password,getenv("PASSWD"));
    got_pass = True;
  }

  if (getenv("PASSWD_FD") || getenv("PASSWD_FILE")) {
    int fd = -1;
    BOOL close_it = False;
    pstring spec;
    char pass[128];

    if ((p = getenv("PASSWD_FD")) != NULL) {
      pstrcpy(spec, "descriptor ");
      pstrcat(spec, p);
      sscanf(p, "%d", &fd);
      close_it = False;
    } else if ((p = getenv("PASSWD_FILE")) != NULL) {
      fd = open(p, O_RDONLY);
      pstrcpy(spec, p);
      if (fd < 0) {
	fprintf(stderr, "Error opening PASSWD_FILE %s: %s\n",
		spec, strerror(errno));
	exit(1);
      }
      close_it = True;
    }
    for(p = pass, *p = '\0'; /* ensure that pass is null-terminated */
	p && p - pass < sizeof(pass);) {
      switch (read(fd, p, 1)) {
      case 1:
	if (*p != '\n' && *p != '\0') {
	  *++p = '\0'; /* advance p, and null-terminate pass */
	  break;
	}
      case 0:
	if (p - pass) {
	  *p = '\0'; /* null-terminate it, just in case... */
	  p = NULL; /* then force the loop condition to become false */
	  break;
	} else {
	  fprintf(stderr, "Error reading password from file %s: %s\n",
		  spec, "empty password\n");
	  exit(1);
	}

      default:
	fprintf(stderr, "Error reading password from file %s: %s\n",
		spec, strerror(errno));
	exit(1);
      }
    }
    pstrcpy(password, pass);
    got_pass = True;
    if (close_it)
      close(fd);
  }

  if (*username == 0 && getenv("LOGNAME"))
    {
      pstrcpy(username,getenv("LOGNAME"));
      strupper(username);
    }

  if (*username == 0)
    {
      pstrcpy(username,"GUEST");
    }

  if (argc < 2)
    {
      usage(pname);
      exit(1);
    }
  
  if (*argv[1] != '-')
    {

      pstrcpy(service,argv[1]);  
      /* Convert any '/' characters in the service name to '\' characters */
      string_replace( service, '/','\\');
      argc--;
      argv++;

      if (count_chars(service,'\\') < 3)
	{
	  usage(pname);
	  printf("\n%s: Not enough '\\' characters in service\n",service);
	  exit(1);
	}

/*
      if (count_chars(service,'\\') > 3)
	{
	  usage(pname);
	  printf("\n%s: Too many '\\' characters in service\n",service);
	  exit(1);
	}
	*/

      if (argc > 1 && (*argv[1] != '-'))
	{
	  got_pass = True;
	  pstrcpy(password,argv[1]);  
	  memset(argv[1],'X',strlen(argv[1]));
	  argc--;
	  argv++;
	}
    }

  while ((opt = 
	  getopt(argc, argv,"s:B:O:R:M:i:Nn:d:Pp:l:hI:EU:L:t:m:W:T:D:c:")) != EOF)
	switch (opt)
	{
	case 's':
		pstrcpy(servicesf, optarg);
		break;
	case 'B':
		iface_set_default(NULL,optarg,NULL);
		break;
	case 'O':
		pstrcpy(user_socket_options,optarg);
		break;	
	case 'R':
		pstrcpy(new_name_resolve_order, optarg);
		break;
	case 'M':
		name_type = 0x03; /* messages are sent to NetBIOS name type 0x3 */
		pstrcpy(desthost,optarg);
		strupper(desthost);
		message = True;
		break;
#if 0 /* This option doesn't seem to do anything - JRA. */
	case 'S':
		pstrcpy(desthost,optarg);
		strupper(desthost);
		nt_domain_logon = True;
		break;
#endif /* 0 */
	case 'i':
		pstrcpy(scope,optarg);
		break;
	case 'N':
		got_pass = True;
		no_pass = True;
		break;
	case 'n':
		pstrcpy(global_myname,optarg);
		break;
	case 'd':
		if (*optarg == 'A')
			DEBUGLEVEL = 10000;
		else
			DEBUGLEVEL = atoi(optarg);
		break;
	case 'P':
		connect_as_printer = True;
		break;
	case 'p':
		port = atoi(optarg);
		break;
	case 'l':
		slprintf(debugf,sizeof(debugf)-1, "%s.client",optarg);
		break;
	case 'h':
		usage(pname);
		exit(0);
		break;
	case 'I':
		{
			dest_ip = *interpret_addr2(optarg);
			if (zero_ip(dest_ip))
				exit(1);
			have_ip = True;
		}
		break;
	case 'E':
		dbf = stderr;
		break;
	case 'U':
		{
			char *lp;
			explicit_user = True;
			pstrcpy(username,optarg);
			if ((lp=strchr(username,'%')))
			{
				*lp = 0;
				pstrcpy(password,lp+1);
				got_pass = True;
				memset(strchr(optarg,'%')+1,'X',strlen(password));
			}
		}
		break;
	case 'L':
		got_pass = True;
		pstrcpy(query_host,optarg);
		if(!explicit_user)
			*username = '\0';
		break;
	case 't':
		pstrcpy(term_code, optarg);
		break;
	case 'm':
		max_protocol = interpret_protocol(optarg,max_protocol);
		break;
	case 'W':
		pstrcpy(workgroup,optarg);
		break;
	case 'T':
		if (!tar_parseargs(argc, argv, optarg, optind)) {
			usage(pname);
			exit(1);
		}
		break;
	case 'D':
		pstrcpy(base_directory,optarg);
		break;
	case 'c':
		cmdstr = optarg;
		got_pass = True;
		break;
	default:
		usage(pname);
		exit(1);
	}

  get_myname((*global_myname)?NULL:global_myname,NULL);  
  strupper(global_myname);

  if(*new_name_resolve_order)
    lp_set_name_resolve_order(new_name_resolve_order);

  if (!tar_type && !*query_host && !*service && !message)
    {
      usage(pname);
      exit(1);
    }

#ifdef HAVE_LIBREADLINE

  /* Initialise GNU Readline */
  
  rl_readline_name = "smbclient";
  rl_attempted_completion_function = completion_fn;
  rl_completion_entry_function = (Function *)complete_cmd_null;

  /* Initialise history list */

  using_history();

#endif /* HAVE_LIBREADLINE */

  DEBUG( 3, ( "Client started (version %s).\n", VERSION ) );

  if (tar_type) {
    recurse=True;

    if (cli_open_sockets(port)) {
        char *InBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
	char *OutBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
	int ret;

	if ((InBuffer == NULL) || (OutBuffer == NULL)) 
	  return(1);

	bzero(OutBuffer,smb_size);
	if (!cli_send_login(InBuffer,OutBuffer,True,True,NULL))
	  return(False);

	if (*base_directory) do_cd(base_directory);

	ret=process_tar(InBuffer, OutBuffer);

	cli_send_logout(InBuffer, OutBuffer);
	close_sockets();
	return(ret);
    } else
      return(1);
  }

  if ((p=strchr(query_host,'#'))) {
	  *p = 0;
	  p++;
	  sscanf(p, "%x", &name_type);
  }
  
#if 0 /* This seemed to be used with the unknown -S option. JRA */
  if (*query_host && !nt_domain_logon)
#else
  if (*query_host)
#endif
    {
      int ret = 0;
      slprintf(service,sizeof(service)-1,
	       "\\\\%s\\IPC$",query_host);
      strupper(service);
      connect_as_ipc = True;
      if (cli_open_sockets(port))
	{
#if 0
	  *username = 0;
#endif
	  if (!cli_send_login(NULL,NULL,True,True,NULL))
	    return(1);

	  server_info();
	  if (!browse_host(True)) {
	    sleep(1);
	    browse_host(True);
	  }
	  if (!list_servers(workgroup)) {
	    sleep(1);
	    list_servers(workgroup);
	  }

	  cli_send_logout(NULL,NULL);
	  close_sockets();
	}

      return(ret);
    }

  if (message)
    {
      int ret = 0;
      if (cli_open_sockets(port))
	{
	  pstring inbuf,outbuf;
	  bzero(outbuf,smb_size);
	  if (!cli_send_session_request(inbuf,outbuf))
	    return(1);

	  send_message(inbuf,outbuf);

	  close_sockets();
	}

      return(ret);
    }

  if (cli_open_sockets(port))
    {
      if (!process(base_directory))
	{
	  close_sockets();
	  return(1);
	}
      close_sockets();
    }
  else
    return(1);

  return(0);
}
