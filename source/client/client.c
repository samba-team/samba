/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client
   Copyright (C) Andrew Tridgell 1994-1995
   
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

#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

#ifndef REGISTER
#define REGISTER 0
#endif

pstring cur_dir = "\\";
pstring cd_path = "";
pstring service="";
pstring desthost="";
extern pstring myname;
pstring password = "";
pstring username="";
pstring workgroup=WORKGROUP;
char *cmdstr="";
BOOL got_pass = False;
BOOL connect_as_printer = False;
BOOL connect_as_ipc = False;
extern struct in_addr ipzero;

char cryptkey[8];
BOOL doencrypt=False;

extern pstring user_socket_options;

/* 30 second timeout on most commands */
#define CLIENT_TIMEOUT (30*1000)
#define SHORT_TIMEOUT (5*1000)

/* value for unused fid field in trans2 secondary request */
#define FID_UNUSED (0xFFFF)

int name_type = 0x20;

int max_protocol = PROTOCOL_NT1;


time_t newer_than = 0;
int archive_level = 0;

extern pstring debugf;
extern int DEBUGLEVEL;

BOOL translation = False;


static BOOL send_trans_request(char *outbuf,int trans,
			       char *name,int fid,int flags,
			       char *data,char *param,uint16 *setup,
			       int ldata,int lparam,int lsetup,
			       int mdata,int mparam,int msetup);
static BOOL receive_trans_response(char *inbuf,int trans,
                                   int *data_len,int *param_len,
				   char **data,char **param);
static int interpret_long_filename(int level,char *p,file_info *finfo);
static void dir_action(char *inbuf,char *outbuf,int attribute,file_info *finfo,BOOL recurse_dir,void (*fn)(),BOOL longdir);
static int interpret_short_filename(char *p,file_info *finfo);
static BOOL call_api(int prcnt,int drcnt,
		     int mprcnt,int mdrcnt,
		     int *rprcnt,int *rdrcnt,
		     char *param,char *data,
		     char **rparam,char **rdata);


/* clitar bits insert */
extern int blocksize;
extern BOOL tar_inc;
extern BOOL tar_reset;
/* clitar bits end */
 

int cnum = 0;
int pid = 0;
int gid = 0;
int uid = 0;
int mid = 0;
int myumask = 0755;

int max_xmit = BUFFER_SIZE;

extern pstring scope;

BOOL prompt = True;

int printmode = 1;

BOOL recurse = False;
BOOL lowercase = False;

BOOL have_ip = False;

struct in_addr dest_ip;

#define SEPARATORS " \t\n\r"

BOOL abort_mget = True;

extern int Protocol;

BOOL readbraw_supported = False;
BOOL writebraw_supported = False;

pstring fileselection = "";

extern file_info def_finfo;

/* timing globals */
int get_total_size = 0;
int get_total_time_ms = 0;
int put_total_size = 0;
int put_total_time_ms = 0;


extern int Client;

#define USENMB

#ifdef KANJI
extern int coding_system;
#define CNV_LANG(s) (coding_system == DOSV_CODE?s:dos_to_unix(s, False))
#define CNV_INPUT(s) (coding_system == DOSV_CODE?s:unix_to_dos(s, True))
static BOOL
setup_term_code (char *code)
{
    int new;
    new = interpret_coding_system (code, UNKNOWN_CODE);
    if (new != UNKNOWN_CODE) {
	coding_system = new;
	return True;
    }
    return False;
}
#else
#define CNV_LANG(s) dos2unix_format(s,False)
#define CNV_INPUT(s) unix2dos_format(s,True)
#endif

/****************************************************************************
setup basics in a outgoing packet
****************************************************************************/
void setup_pkt(char *outbuf)
{
  SSVAL(outbuf,smb_pid,pid);
  SSVAL(outbuf,smb_uid,uid);
  SSVAL(outbuf,smb_mid,mid);
  if (Protocol > PROTOCOL_CORE)
    {
      SCVAL(outbuf,smb_flg,0x8);
      SSVAL(outbuf,smb_flg2,0x1);
    }
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

  strcpy(path2,path);
  trim_string(path2,NULL,"\\");
  if (!*path2) *path2 = '\\';

  bzero(outbuf,smb_size);
  set_message(outbuf,0,4 + strlen(path2),True);
  SCVAL(outbuf,smb_com,SMBchkpth);
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  p = smb_buf(outbuf);
  *p++ = 4;
  strcpy(p,path2);

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);

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
  strcpy(p,username);
  p = skip_string(p,1);
  *p++ = 4;
  strcpy(p,desthost);
  p = skip_string(p,1);

  set_message(outbuf,0,PTR_DIFF(p,smb_buf(outbuf)),False);

  send_smb(Client,outbuf);
  

  if (!receive_smb(Client,inbuf,SHORT_TIMEOUT) || CVAL(inbuf,smb_rcls) != 0)
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
      

      if (!receive_smb(Client,inbuf,SHORT_TIMEOUT) || CVAL(inbuf,smb_rcls) != 0)
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
  

  if (!receive_smb(Client,inbuf,SHORT_TIMEOUT) || CVAL(inbuf,smb_rcls) != 0)
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
  setup_pkt(outbuf);

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);

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
static void cmd_pwd(void)
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
      
  /* Save the current directory in case the
     new directory is invalid */
  strcpy(saved_dir, cur_dir);
  if (*p == '\\')
    strcpy(cur_dir,p);
  else
    strcat(cur_dir,p);
  if (*(cur_dir+strlen(cur_dir)-1) != '\\') {
    strcat(cur_dir, "\\");
  }
  dos_clean_name(cur_dir);
  strcpy(dname,cur_dir);
  strcat(cur_dir,"\\");
  dos_clean_name(cur_dir);

  if (!strequal(cur_dir,"\\"))
    if (!chkpath(dname,True))
      strcpy(cur_dir,saved_dir);

  strcpy(cd_path,cur_dir);
}

/****************************************************************************
change directory
****************************************************************************/
static void cmd_cd(char *inbuf,char *outbuf)
{
  fstring buf;

  if (next_token(NULL,buf,NULL))
    do_cd(buf);
  else
    DEBUG(0,("Current directory is %s\n",CNV_LANG(cur_dir)));
}


/****************************************************************************
  display info about a file
  ****************************************************************************/
static void display_finfo(file_info *finfo)
{
  time_t t = finfo->mtime; /* the time is assumed to be passed as GMT */
  DEBUG(0,("  %-30s%7.7s%10d  %s",
	   CNV_LANG(finfo->name),
	   attrib_string(finfo->mode),
	   finfo->size,
	   asctime(LocalTime(&t))));
}


/****************************************************************************
  do a directory listing, calling fn on each file found. Use the TRANSACT2
  call for long filenames
  ****************************************************************************/
static int do_long_dir(char *inbuf,char *outbuf,char *Mask,int attribute,void (*fn)(),BOOL recurse_dir)
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

  strcpy(mask,Mask);

  while (ff_eos == 0)
    {
      loop_count++;
      if (loop_count > 200)
	{
	  DEBUG(0,("ERROR: Looping in FIND_NEXT??\n"));
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
	  strcpy(param+12,mask);
	}
      else
	{
	  setup = TRANSACT2_FINDNEXT;
	  SSVAL(param,0,ff_dir_handle);
	  SSVAL(param,2,max_matches); /* max count */
	  SSVAL(param,4,info_level); 
	  SIVAL(param,6,ff_resume_key); /* ff_resume_key */
	  SSVAL(param,10,8+4+2);	/* resume required + close on end + continue */
	  strcpy(param+12,mask);

	  DEBUG(5,("hand=0x%X resume=%d ff_lastname=%d mask=%s\n",
		   ff_dir_handle,ff_resume_key,ff_lastname,mask));
	}
      /* ??? original code added 1 pad byte after param */

      send_trans_request(outbuf,SMBtrans2,NULL,FID_UNUSED,0,
			 NULL,param,&setup,
			 0,12+strlen(mask)+1,1,
			 BUFFER_SIZE,10,0);

      if (!receive_trans_response(inbuf,SMBtrans2,
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
	      /* strcpy(mask,p+ff_lastname+94); */
	      break;
	    case 1:
	      strcpy(mask,p + ff_lastname + 1);
	      ff_resume_key = 0;
	      break;
	    }
	}
      else
	strcpy(mask,"");
  
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
      dir_action(inbuf,outbuf,attribute,&finfo,recurse_dir,fn,True);
    }

  /* free up the dirlist buffer */
  if (dirlist) free(dirlist);
  return(total_received);
}


/****************************************************************************
  do a directory listing, calling fn on each file found
  ****************************************************************************/
static int do_short_dir(char *inbuf,char *outbuf,char *Mask,int attribute,void (*fn)(),BOOL recurse_dir)
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

  strcpy(mask,Mask);
  
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
      setup_pkt(outbuf);

      SSVAL(outbuf,smb_vwv0,num_asked);
      SSVAL(outbuf,smb_vwv1,attribute);
  
      p = smb_buf(outbuf);
      *p++ = 4;
      
      if (first)
	strcpy(p,mask);
      else
	strcpy(p,"");
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
      receive_smb(Client,inbuf,CLIENT_TIMEOUT);

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
      setup_pkt(outbuf);

      p = smb_buf(outbuf);
      *p++ = 4;
      
      strcpy(p,"");
      p += strlen(p) + 1;
      
      *p++ = 5;
      SSVAL(p,0,21);
      p += 2;
      memcpy(p,status,21);

      send_smb(Client,outbuf);
      receive_smb(Client,inbuf,CLIENT_TIMEOUT);

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
      dir_action(inbuf,outbuf,attribute,&finfo,recurse_dir,fn,False);
    }

  if (dirlist) free(dirlist);
  return(num_received);
}



/****************************************************************************
  do a directory listing, calling fn on each file found
  ****************************************************************************/
void do_dir(char *inbuf,char *outbuf,char *Mask,int attribute,void (*fn)(),BOOL recurse_dir)
{
  DEBUG(5,("do_dir(%s,%x,%s)\n",Mask,attribute,BOOLSTR(recurse_dir)));
  if (Protocol >= PROTOCOL_LANMAN2)
    {
      if (do_long_dir(inbuf,outbuf,Mask,attribute,fn,recurse_dir) > 0)
	return;
    }

  expand_mask(Mask,False);
  do_short_dir(inbuf,outbuf,Mask,attribute,fn,recurse_dir);
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
 Convert a character pointer in a call_api() response to a form we can use.
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

  if( offset < 0 || offset >= rdrcnt )
    {
      DEBUG(1,("bad char ptr: datap=%u, converter=%u, rdata=%u, rdrcnt=%d>", datap, converter, (unsigned)rdata, rdrcnt));
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
  strcpy(finfo->name,p+30);
  
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
	  strcpy(finfo->name,p+27);
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
	  strcpy(finfo->name,p+31);
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
	  strcpy(finfo->name,p+33);
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
	  strcpy(finfo->name,p+37);
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
  ****************************************************************************/
static void dir_action(char *inbuf,char *outbuf,int attribute,file_info *finfo,BOOL recurse_dir,void (*fn)(),BOOL longdir)
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
	  strcpy(sav_dir,cur_dir);
	  strcat(cur_dir,finfo->name);
	  strcat(cur_dir,"\\");
	  strcpy(mask2,cur_dir);

	  if (!fn)
	    DEBUG(0,("\n%s\n",CNV_LANG(cur_dir)));

	  strcat(mask2,"*");

	  if (longdir)
	    do_long_dir(inbuf,outbuf,mask2,attribute,fn,True);      
	  else
	    do_dir(inbuf,outbuf,mask2,attribute,fn,True);

	  strcpy(cur_dir,sav_dir);
	}
      else
	{
	  if (fn && do_this_one(finfo))
	    fn(finfo);
	}
    }
}


/****************************************************************************
  receive a SMB trans or trans2 response allocating the necessary memory
  ****************************************************************************/
static BOOL receive_trans_response(char *inbuf,int trans,
                                   int *data_len,int *param_len,
				   char **data,char **param)
{
  int total_data=0;
  int total_param=0;
  int this_data,this_param;

  *data_len = *param_len = 0;

  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  show_msg(inbuf);

  /* sanity check */
  if (CVAL(inbuf,smb_com) != trans)
    {
      DEBUG(0,("Expected %s response, got command 0x%02x\n",
	       trans==SMBtrans?"SMBtrans":"SMBtrans2", CVAL(inbuf,smb_com)));
      return(False);
    }
  if (CVAL(inbuf,smb_rcls) != 0)
    return(False);

  /* parse out the lengths */
  total_data = SVAL(inbuf,smb_tdrcnt);
  total_param = SVAL(inbuf,smb_tprcnt);

  /* allocate it */
  *data = Realloc(*data,total_data);
  *param = Realloc(*param,total_param);

  while (1)
    {
      this_data = SVAL(inbuf,smb_drcnt);
      this_param = SVAL(inbuf,smb_prcnt);
      if (this_data)
	memcpy(*data + SVAL(inbuf,smb_drdisp),
	       smb_base(inbuf) + SVAL(inbuf,smb_droff),
	       this_data);
      if (this_param)
	memcpy(*param + SVAL(inbuf,smb_prdisp),
	       smb_base(inbuf) + SVAL(inbuf,smb_proff),
	       this_param);
      *data_len += this_data;
      *param_len += this_param;

      /* parse out the total lengths again - they can shrink! */
      total_data = SVAL(inbuf,smb_tdrcnt);
      total_param = SVAL(inbuf,smb_tprcnt);

      if (total_data <= *data_len && total_param <= *param_len)
	break;

      receive_smb(Client,inbuf,CLIENT_TIMEOUT);
      show_msg(inbuf);

      /* sanity check */
      if (CVAL(inbuf,smb_com) != trans)
	{
	  DEBUG(0,("Expected %s response, got command 0x%02x\n",
		   trans==SMBtrans?"SMBtrans":"SMBtrans2", CVAL(inbuf,smb_com)));
	  return(False);
	}
      if (CVAL(inbuf,smb_rcls) != 0)
	  return(False);
    }
  
  return(True);
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

  strcpy(mask,cur_dir);
  if(mask[strlen(mask)-1]!='\\')
    strcat(mask,"\\");

  if (next_token(NULL,buf,NULL))
    {
      if (*p == '\\')
	strcpy(mask,p);
      else
	strcat(mask,p);
    }
  else {
    strcat(mask,"*");
  }

  do_dir(inbuf,outbuf,mask,attribute,NULL,recurse);

  do_dskattr();
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
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,0xFF);
  SSVAL(outbuf,smb_vwv2,1);
  SSVAL(outbuf,smb_vwv3,(DENY_NONE<<4));
  SSVAL(outbuf,smb_vwv4,aSYSTEM | aHIDDEN);
  SSVAL(outbuf,smb_vwv5,aSYSTEM | aHIDDEN);
  SSVAL(outbuf,smb_vwv8,1);
  
  p = smb_buf(outbuf);
  strcpy(p,rname);
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
      SSVAL(p,smb_wct,10);
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
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  if (CVAL(inbuf,smb_rcls) != 0)
    {
      if (CVAL(inbuf,smb_rcls) == ERRSRV &&
	  SVAL(inbuf,smb_err) == ERRnoresource &&
	  reopen_connection(inbuf,outbuf))
	{
	  do_get(rname,lname,finfo1);
	  return;
	}
      DEBUG(0,("%s opening remote file %s\n",smb_errstr(inbuf),CNV_LANG(rname)));
      if(newhandle)
	close(handle);
      free(inbuf);free(outbuf);
      return;
    }

  strcpy(finfo.name,rname);

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


  DEBUG(2,("getting file %s of size %d bytes as %s ",
	   CNV_LANG(finfo.name),
	   finfo.size,
	   lname));

  while (nread < finfo.size && !close_done)
    {
      int method = -1;
      static BOOL can_chain_close = True;

      p=NULL;
      
      DEBUG(3,("nread=%d max_xmit=%d fsize=%d\n",nread,max_xmit,finfo.size));

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
	  setup_pkt(outbuf);
	  
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
	  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
	  
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
	    setup_pkt(outbuf);
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
	  setup_pkt(outbuf);

	  SSVAL(outbuf,smb_vwv0,fnum);
	  SSVAL(outbuf,smb_vwv1,MIN(max_xmit-200,finfo.size - nread));
	  SIVAL(outbuf,smb_vwv2,nread);
	  SSVAL(outbuf,smb_vwv4,finfo.size - nread);

	  send_smb(Client,outbuf);
	  receive_smb(Client,inbuf,CLIENT_TIMEOUT);

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
      bzero(outbuf,smb_size);
      set_message(outbuf,3,0,True);
      CVAL(outbuf,smb_com) = SMBclose;
      SSVAL(outbuf,smb_tid,cnum);
      setup_pkt(outbuf);
      
      SSVAL(outbuf,smb_vwv0,fnum);
      SIVALS(outbuf,smb_vwv1,-1);
      
      send_smb(Client,outbuf);
      receive_smb(Client,inbuf,CLIENT_TIMEOUT);
      
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
    setup_pkt(outbuf);
    SSVAL(outbuf,smb_vwv0,finfo.mode & ~(aARCH));
    SIVALS(outbuf,smb_vwv1,0);
    p = smb_buf(outbuf);
    *p++ = 4;
    strcpy(p,rname);
    p += strlen(p)+1;
    *p++ = 4;
    *p = 0;
    send_smb(Client,outbuf);
    receive_smb(Client,inbuf,CLIENT_TIMEOUT);
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

    DEBUG(2,("(%g kb/s) (average %g kb/s)\n",
	     finfo.size / (1.024*this_time + 1.0e-4),
	     get_total_size / (1.024*get_total_time_ms)));
  }

  free(inbuf);free(outbuf);
}


/****************************************************************************
  get a file
  ****************************************************************************/
static void cmd_get(void)
{
  pstring lname;
  pstring rname;
  char *p;

  strcpy(rname,cur_dir);
  strcat(rname,"\\");

  p = rname + strlen(rname);

  if (!next_token(NULL,p,NULL)) {
    DEBUG(0,("get <filename>\n"));
    return;
  }
  strcpy(lname,p);
  dos_clean_name(rname);
    
  next_token(NULL,lname,NULL);

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
    sprintf(quest,"Get directory %s? ",CNV_LANG(finfo->name));
  else
    sprintf(quest,"Get file %s? ",CNV_LANG(finfo->name));

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

      strcpy(saved_curdir,cur_dir);

      strcat(cur_dir,finfo->name);
      strcat(cur_dir,"\\");

      unix_format(finfo->name);
      {
	if (lowercase)
	  strlower(finfo->name);

	if (!directory_exist(finfo->name,NULL) && 
	    sys_mkdir(finfo->name,0777) != 0) 
	  {
	    DEBUG(0,("failed to create directory %s\n",CNV_LANG(finfo->name)));
	    strcpy(cur_dir,saved_curdir);
	    free(inbuf);free(outbuf);
	    return;
	  }

	if (sys_chdir(finfo->name) != 0)
	  {
	    DEBUG(0,("failed to chdir to directory %s\n",CNV_LANG(finfo->name)));
	    strcpy(cur_dir,saved_curdir);
	    free(inbuf);free(outbuf);
	    return;
	  }
      }       

      strcpy(mget_mask,cur_dir);
      strcat(mget_mask,"*");
      
      do_dir((char *)inbuf,(char *)outbuf,
	     mget_mask,aSYSTEM | aHIDDEN | aDIR,do_mget,False);
      chdir("..");
      strcpy(cur_dir,saved_curdir);
      free(inbuf);free(outbuf);
    }
  else
    {
      strcpy(rname,cur_dir);
      strcat(rname,finfo->name);
      do_get(rname,finfo->name,finfo);
    }
}

/****************************************************************************
view the file using the pager
****************************************************************************/
static void cmd_more(void)
{
  fstring rname,lname,tmpname,pager_cmd;
  char *pager;

  strcpy(rname,cur_dir);
  strcat(rname,"\\");
  sprintf(tmpname,"/tmp/smbmore.%d",getpid());
  strcpy(lname,tmpname);

  if (!next_token(NULL,rname+strlen(rname),NULL)) {
    DEBUG(0,("more <filename>\n"));
    return;
  }
  dos_clean_name(rname);

  do_get(rname,lname,NULL);

  pager=getenv("PAGER");
  sprintf(pager_cmd,"%s %s",(pager? pager:PAGER), tmpname);
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

  while (next_token(NULL,p,NULL))
    {
      strcpy(mget_mask,cur_dir);
      if(mget_mask[strlen(mget_mask)-1]!='\\')
	strcat(mget_mask,"\\");

      if (*p == '\\')
	strcpy(mget_mask,p);
      else
	strcat(mget_mask,p);
      do_dir((char *)inbuf,(char *)outbuf,mget_mask,attribute,do_mget,False);
    }

  if (! *mget_mask)
    {
      strcpy(mget_mask,cur_dir);
      if(mget_mask[strlen(mget_mask)-1]!='\\')
	strcat(mget_mask,"\\");
      strcat(mget_mask,"*");
      do_dir((char *)inbuf,(char *)outbuf,mget_mask,attribute,do_mget,False);
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
  setup_pkt(outbuf);

  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,name);
  
  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
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
  
  strcpy(mask,cur_dir);

  if (!next_token(NULL,p,NULL))
    {
      if (!recurse)
	DEBUG(0,("mkdir <dirname>\n"));
      return;
    }
  strcat(mask,p);

  if (recurse)
    {
      pstring ddir;
      pstring ddir2;
      *ddir2 = 0;

      strcpy(ddir,mask);
      trim_string(ddir,".",NULL);
      p = strtok(ddir,"/\\");
      while (p)
	{
	  strcat(ddir2,p);
	  if (!chkpath(ddir2,False))
	    {		  
	      do_mkdir(ddir2);
	    }
	  strcat(ddir2,"\\");
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
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,fnum);
  SSVAL(outbuf,smb_vwv1,n);
  SIVAL(outbuf,smb_vwv3,pos);
  SSVAL(outbuf,smb_vwv7,1);

  send_smb(Client,outbuf);
  
  if (!receive_smb(Client,inbuf,CLIENT_TIMEOUT) || CVAL(inbuf,smb_rcls) != 0)
    return(0);

  _smb_setlen(buf-4,n);		/* HACK! XXXX */

  if (write_socket(Client,buf-4,n+4) != n+4)
    return(0);

  if (!receive_smb(Client,inbuf,CLIENT_TIMEOUT) || CVAL(inbuf,smb_rcls) != 0) {
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
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,fnum);
  SSVAL(outbuf,smb_vwv1,n);
  SIVAL(outbuf,smb_vwv2,pos);
  SSVAL(outbuf,smb_vwv4,0);
  CVAL(smb_buf(outbuf),0) = 1;
  SSVAL(smb_buf(outbuf),1,n);

  memcpy(smb_buf(outbuf)+3,buf,n);

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);

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
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,finfo->mode);
  put_dos_date3(outbuf,smb_vwv1,finfo->mtime);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,rname);
  
  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("%s opening remote file %s\n",smb_errstr(inbuf),CNV_LANG(rname)));

      free(inbuf);free(outbuf);if (buf) free(buf);
      return;
    }

  f = fopen(lname,"r");

  if (!f)
    {
      DEBUG(0,("Error opening local file %s\n",lname));
      free(inbuf);free(outbuf);
      return;
    }

  
  fnum = SVAL(inbuf,smb_vwv0);
  if (finfo->size < 0)
    finfo->size = file_size(lname);
  
  DEBUG(1,("putting file %s of size %d bytes as %s ",lname,finfo->size,CNV_LANG(rname)));
  
  if (!maxwrite)
    maxwrite = writebraw_supported?MAX(max_xmit,BUFFER_SIZE):(max_xmit-200);

  while (nread < finfo->size)
    {
      int n = maxwrite;
      int ret;

      n = MIN(n,finfo->size - nread);

      buf = (char *)Realloc(buf,n+4);
  
      fseek(f,nread,SEEK_SET);
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
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,fnum);  
  put_dos_date3(outbuf,smb_vwv1,close_time);

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
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

    DEBUG(2,("(%g kb/s) (average %g kb/s)\n",
	     finfo->size / (1.024*this_time + 1.0e-4),
	     put_total_size / (1.024*put_total_time_ms)));
  }
} 

 

/****************************************************************************
  put a file
  ****************************************************************************/
static void cmd_put(void)
{
  pstring lname;
  pstring rname;
  fstring buf;
  char *p=buf;
  file_info finfo;
  finfo = def_finfo;
  
  strcpy(rname,cur_dir);
  strcat(rname,"\\");
  
  
  if (!next_token(NULL,p,NULL))
    {
      DEBUG(0,("put <filename>\n"));
      return;
    }
  strcpy(lname,p);
  
  if (next_token(NULL,p,NULL))
    strcat(rname,p);      
  else
    strcat(rname,lname);

  dos_clean_name(rname);

  {
    struct stat st;
    if (!file_exist(lname,&st)) {
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
	  strcpy(name,s);
	  return(True);
	}
    }
      
  return(False);
}


/****************************************************************************
  set the file selection mask
  ****************************************************************************/
static void cmd_select(void)
{
  strcpy(fileselection,"");
  next_token(NULL,fileselection,NULL);
}


/****************************************************************************
  mput some files
  ****************************************************************************/
static void cmd_mput(void)
{
  pstring lname;
  pstring rname;
  file_info finfo;
  fstring buf;
  char *p=buf;

  finfo = def_finfo;

  
  while (next_token(NULL,p,NULL))
    {
      struct stat st;
      pstring cmd;
      pstring tmpname;
      FILE *f;
      
      sprintf(tmpname,"/tmp/ls.smb.%d",(int)getpid());
      if (recurse)
	sprintf(cmd,"find . -name \"%s\" -print > %s",p,tmpname);
      else
	sprintf(cmd,"/bin/ls %s > %s",p,tmpname);
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
	      sprintf(quest,"Put directory %s? ",lname);
	      if (prompt && !yesno(quest)) 
		{
		  strcat(lname,"/");
		  if (!seek_list(f,lname))
		    break;
		  goto again1;		    
		}
	      
	      strcpy(rname,cur_dir);
	      strcat(rname,lname);
	      if (!chkpath(rname,False) && !do_mkdir(rname)) {
		strcat(lname,"/");
		if (!seek_list(f,lname))
		  break;
		goto again1;		    		  
	      }

	      continue;
	    }
	  else
	    {
	      sprintf(quest,"Put file %s? ",lname);
	      if (prompt && !yesno(quest)) continue;

	      strcpy(rname,cur_dir);
	      strcat(rname,lname);
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
  strcpy(p,"W");
  p = skip_string(p,1);
  strcpy(p,"");
  p = skip_string(p,1);
  SSVAL(p,0,job);     
  p += 2;

  if (call_api(PTR_DIFF(p,param),0,
	       6,1000,
	       &rprcnt,&rdrcnt,
	       param,NULL,
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

  if (!next_token(NULL,buf,NULL)) {
    printf("cancel <jobid> ...\n");
    return;
  }
  do {
    job = atoi(buf);
    do_cancel(job);
  } while (next_token(NULL,buf,NULL));
}


/****************************************************************************
  get info on a file
  ****************************************************************************/
static void cmd_stat(char *inbuf,char *outbuf)
{
  fstring buf;
  pstring param;
  char *resp_data=NULL;
  char *resp_param=NULL;
  int resp_data_len = 0;
  int resp_param_len=0;
  char *p;
  uint16 setup = TRANSACT2_QPATHINFO;

  if (!next_token(NULL,buf,NULL)) {
    printf("stat <file>\n");
    return;
  }

  bzero(param,6);
  SSVAL(param,0,4); /* level */
  p = param+6;
  strcpy(p,cur_dir);
  strcat(p,buf);

  send_trans_request(outbuf,SMBtrans2,NULL,FID_UNUSED,0,
		     NULL,param,&setup,
		     0,6 + strlen(p)+1,1,
		     BUFFER_SIZE,2,0);

  receive_trans_response(inbuf,SMBtrans2,
			  &resp_data_len,&resp_param_len,
			  &resp_data,&resp_param);

  if (resp_data) free(resp_data); resp_data = NULL;
  if (resp_param) free(resp_param); resp_param = NULL;
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

  if (!next_token(NULL,lname,NULL))
    {
      DEBUG(0,("print <filename>\n"));
      return;
    }

  strcpy(rname,lname);
  p = strrchr(rname,'/');
  if (p)
    {
      pstring tname;
      strcpy(tname,p+1);
      strcpy(rname,tname);
    }

  if ((int)strlen(rname) > 14)
    rname[14] = 0;

  if (strequal(lname,"-"))
    {
      f = stdin;
      strcpy(rname,"stdin");
    }
  
  dos_clean_name(rname);

  bzero(outbuf,smb_size);
  set_message(outbuf,2,2 + strlen(rname),True);
  
  CVAL(outbuf,smb_com) = SMBsplopen;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,0);
  SSVAL(outbuf,smb_vwv1,printmode);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,rname);
  
  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
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
      setup_pkt(outbuf);

      SSVAL(outbuf,smb_vwv0,fnum);
      SSVAL(outbuf,smb_vwv1,n+3);
      CVAL(smb_buf(outbuf),0) = 1;
      SSVAL(smb_buf(outbuf),1,n);

      send_smb(Client,outbuf);
      receive_smb(Client,inbuf,CLIENT_TIMEOUT);

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
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,fnum);

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
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
show a print queue
****************************************************************************/
static void cmd_queue(char *inbuf,char *outbuf )
{
  int count;
  char *p;

  bzero(outbuf,smb_size);
  set_message(outbuf,2,0,True);
  
  CVAL(outbuf,smb_com) = SMBsplretq;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,32); /* a max of 20 entries is to be shown */
  SSVAL(outbuf,smb_vwv1,0); /* the index into the queue */
  
  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
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
	  case 0x01: sprintf(status,"held or stopped"); break;
	  case 0x02: sprintf(status,"printing"); break;
	  case 0x03: sprintf(status,"awaiting print"); break;
	  case 0x04: sprintf(status,"in intercept"); break;
	  case 0x05: sprintf(status,"file had error"); break;
	  case 0x06: sprintf(status,"printer error"); break;
	  default: sprintf(status,"unknown"); break;
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
  strcpy(p,"zWrLh");			/* parameter description? */
  p = skip_string(p,1);
  strcpy(p,"zWWWWzzzzWWzzl");		/* returned data format */
  p = skip_string(p,1);
  strcpy(p,strrchr(service,'\\')+1);	/* name of queue */
  p = skip_string(p,1);
  SSVAL(p,0,3);				/* API function level 3, just queue info, no job info */
  SSVAL(p,2,1000);			/* size of bytes of returned data buffer */
  p += 4;
  strcpy(p,"");				/* subformat */
  p = skip_string(p,1);

  DEBUG(1,("Calling DosPrintQueueGetInfo()...\n"));
  if( call_api(PTR_DIFF(p,param), 0,
	       10, 4096,
	       &rprcnt, &rdrcnt,
	       param, NULL,
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
  else			/* call_api() failed */
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

  strcpy(mask,cur_dir);
  strcat(mask,finfo->name);

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
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,0);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,mask);
  
  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
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
  
  strcpy(mask,cur_dir);
    
  if (!next_token(NULL,buf,NULL))
    {
      DEBUG(0,("del <filename>\n"));
      return;
    }
  strcat(mask,buf);

  do_dir((char *)inbuf,(char *)outbuf,mask,attribute,do_del,False);
}


/****************************************************************************
remove a directory
****************************************************************************/
static void cmd_rmdir(char *inbuf,char *outbuf )
{
  pstring mask;
  fstring buf;
  char *p;
  
  strcpy(mask,cur_dir);
  
  if (!next_token(NULL,buf,NULL))
    {
      DEBUG(0,("rmdir <dirname>\n"));
      return;
    }
  strcat(mask,buf);

  bzero(outbuf,smb_size);
  set_message(outbuf,0,2 + strlen(mask),True);
  
  CVAL(outbuf,smb_com) = SMBrmdir;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,mask);
  
  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
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
  
  strcpy(src,cur_dir);
  strcpy(dest,cur_dir);
  
  if (!next_token(NULL,buf,NULL) || !next_token(NULL,buf2,NULL))
    {
      DEBUG(0,("rename <src> <dest>\n"));
      return;
    }
  strcat(src,buf);
  strcat(dest,buf2);

  bzero(outbuf,smb_size);
  set_message(outbuf,1,4 + strlen(src) + strlen(dest),True);
  
  CVAL(outbuf,smb_com) = SMBmv;
  SSVAL(outbuf,smb_tid,cnum);
  SSVAL(outbuf,smb_vwv0,aHIDDEN | aDIR | aSYSTEM);
  setup_pkt(outbuf);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,src);
  p = skip_string(p,1);
  *p++ = 4;      
  strcpy(p,dest);
  
  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("%s renaming files\n",smb_errstr(inbuf)));
      return;
    }
  
}


/****************************************************************************
toggle the prompt flag
****************************************************************************/
static void cmd_prompt(void)
{
  prompt = !prompt;
  DEBUG(2,("prompting is now %s\n",prompt?"on":"off"));
}


/****************************************************************************
set the newer than time
****************************************************************************/
static void cmd_newer(void)
{
  fstring buf;
  BOOL ok;
  struct stat sbuf;

  ok = next_token(NULL,buf,NULL);
  if (ok && (sys_stat(buf,&sbuf) == 0))
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
static void cmd_archive(void)
{
  fstring buf;

  if (next_token(NULL,buf,NULL)) {
    archive_level = atoi(buf);
  } else
    DEBUG(0,("Archive level is %d\n",archive_level));
}

/****************************************************************************
toggle the lowercaseflag
****************************************************************************/
static void cmd_lowercase(void)
{
  lowercase = !lowercase;
  DEBUG(2,("filename lowercasing is now %s\n",lowercase?"on":"off"));
}




/****************************************************************************
toggle the recurse flag
****************************************************************************/
static void cmd_recurse(void)
{
  recurse = !recurse;
  DEBUG(2,("directory recursion is now %s\n",recurse?"on":"off"));
}

/****************************************************************************
toggle the translate flag
****************************************************************************/
static void cmd_translate(void)
{
  translation = !translation;
  DEBUG(2,("CR/LF<->LF and print text translation now %s\n",
	translation?"on":"off"));
}


/****************************************************************************
do a printmode command
****************************************************************************/
static void cmd_printmode(void)
{
  fstring buf;
  fstring mode;

  if (next_token(NULL,buf,NULL))
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
      strcpy(mode,"text");
      break;
    case 1: 
      strcpy(mode,"graphics");
      break;
    default: 
      sprintf(mode,"%d",printmode);
      break;
    }

  DEBUG(2,("the printmode is now %s\n",mode));
}

/****************************************************************************
do the lcd command
****************************************************************************/
static void cmd_lcd(void)
{
  fstring buf;
  pstring d;

  if (next_token(NULL,buf,NULL))
    sys_chdir(buf);
  DEBUG(2,("the local directory is now %s\n",GetWd(d)));
}


/****************************************************************************
send a session request
****************************************************************************/
static BOOL send_session_request(char *inbuf,char *outbuf)
{
  fstring dest;
  char *p;
  int len = 4;
  /* send a session request (RFC 8002) */

  strcpy(dest,desthost);
  p = strchr(dest,'.');
  if (p) *p = 0;

  /* put in the destination name */
  p = outbuf+len;
  name_mangle(dest,p,name_type);
  len += name_len(p);

  /* and my name */
  p = outbuf+len;
  name_mangle(myname,p,0);
  len += name_len(p);

  /* setup the packet length */
  _smb_setlen(outbuf,len);
  CVAL(outbuf,0) = 0x81;

  send_smb(Client,outbuf);
  DEBUG(5,("Sent session request\n"));

  receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  if (CVAL(inbuf,0) == 0x84) /* C. Hoch  9/14/95 Start */
    {
      /* For information, here is the response structure.
       * We do the byte-twiddling to for portability.
       struct RetargetResponse{
       unsigned char type;
       unsigned char flags;
       int16 length;
       int32 ip_addr;
       int16 port;
       };
       */
      extern int Client;
      int port = (CVAL(inbuf,8)<<8)+CVAL(inbuf,9);
      /* SESSION RETARGET */
      putip((char *)&dest_ip,inbuf+4);

      close_sockets();
      Client = open_socket_out(SOCK_STREAM, &dest_ip, port, LONG_CONNECT_TIMEOUT);
      if (Client == -1)
        return False;

      DEBUG(3,("Retargeted\n"));

      set_socket_options(Client,user_socket_options);

      /* Try again */
      return send_session_request(inbuf,outbuf);
    } /* C. Hoch 9/14/95 End */


  if (CVAL(inbuf,0) != 0x82)
    {
      int ecode = CVAL(inbuf,4);
      DEBUG(0,("Session request failed (%d,%d) with myname=%s destname=%s\n",
	       CVAL(inbuf,0),ecode,myname,desthost));
      switch (ecode)
	{
	case 0x80: 
	  DEBUG(0,("Not listening on called name\n")); 
	  DEBUG(0,("Try to connect to another name (instead of %s)\n",desthost));
	  DEBUG(0,("You may find the -I option useful for this\n"));
	  break;
	case 0x81: 
	  DEBUG(0,("Not listening for calling name\n")); 
	  DEBUG(0,("Try to connect as another name (instead of %s)\n",myname));
	  DEBUG(0,("You may find the -n option useful for this\n"));
	  break;
	case 0x82: 
	  DEBUG(0,("Called name not present\n")); 
	  DEBUG(0,("Try to connect to another name (instead of %s)\n",desthost));
	  DEBUG(0,("You may find the -I option useful for this\n"));
	  break;
	case 0x83: 
	  DEBUG(0,("Called name present, but insufficient resources\n")); 
	  DEBUG(0,("Perhaps you should try again later?\n")); 
	  break;
	default:
	  DEBUG(0,("Unspecified error 0x%X\n",ecode)); 
	  DEBUG(0,("Your server software is being unfriendly\n"));
	  break;	  
	}
      return(False);
    }
  return(True);
}

static struct {
  int prot;
  char *name;
} prots[] = {
  {PROTOCOL_CORE,"PC NETWORK PROGRAM 1.0"},
  {PROTOCOL_COREPLUS,"MICROSOFT NETWORKS 1.03"},
  {PROTOCOL_LANMAN1,"MICROSOFT NETWORKS 3.0"},
  {PROTOCOL_LANMAN1,"LANMAN1.0"},
  {PROTOCOL_LANMAN2,"LM1.2X002"},
  {PROTOCOL_LANMAN2,"Samba"},
  {PROTOCOL_NT1,"NT LM 0.12"},
  {PROTOCOL_NT1,"NT LANMAN 1.0"},
  {-1,NULL}
};


/****************************************************************************
send a login command
****************************************************************************/
static BOOL send_login(char *inbuf,char *outbuf,BOOL start_session,BOOL use_setup)
{
  BOOL was_null = (!inbuf && !outbuf);
  int sesskey=0;
  time_t servertime = 0;
  extern int serverzone;
  int sec_mode=0;
  int crypt_len;
  int max_vcs=0;
  char *pass = NULL;  
  pstring dev;
  char *p;
  int numprots;
  int tries=0;

  if (was_null)
    {
      inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
      outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
    }

#if AJT
  if (strstr(service,"IPC$")) connect_as_ipc = True;
#endif

  strcpy(dev,"A:");
  if (connect_as_printer)
    strcpy(dev,"LPT1:");
  if (connect_as_ipc)
    strcpy(dev,"IPC");


  if (start_session && !send_session_request(inbuf,outbuf))
    {
      if (was_null)
	{
	  free(inbuf);
	  free(outbuf);
	}      
      return(False);
    }

  bzero(outbuf,smb_size);

  /* setup the protocol strings */
  {
    int plength;

    for (plength=0,numprots=0;
	 prots[numprots].name && prots[numprots].prot<=max_protocol;
	 numprots++)
      plength += strlen(prots[numprots].name)+2;
    
    set_message(outbuf,0,plength,True);

    p = smb_buf(outbuf);
    for (numprots=0;
	 prots[numprots].name && prots[numprots].prot<=max_protocol;
	 numprots++)
      {
	*p++ = 2;
	strcpy(p,prots[numprots].name);
	p += strlen(p) + 1;
      }
  }

  CVAL(outbuf,smb_com) = SMBnegprot;
  setup_pkt(outbuf);

  CVAL(smb_buf(outbuf),0) = 2;

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  show_msg(inbuf);

  if (CVAL(inbuf,smb_rcls) != 0 || ((int)SVAL(inbuf,smb_vwv0) >= numprots))
    {
      DEBUG(0,("SMBnegprot failed. myname=%s destname=%s - %s \n",
	    myname,desthost,smb_errstr(inbuf)));
      if (was_null)
	{
	  free(inbuf);
	  free(outbuf);
	}
      return(False);
    }

  Protocol = prots[SVAL(inbuf,smb_vwv0)].prot;


  if (Protocol < PROTOCOL_NT1) {    
    sec_mode = SVAL(inbuf,smb_vwv1);
    max_xmit = SVAL(inbuf,smb_vwv2);
    sesskey = IVAL(inbuf,smb_vwv6);
    serverzone = SVALS(inbuf,smb_vwv10)*60;
    /* this time is converted to GMT by make_unix_date */
    servertime = make_unix_date(inbuf+smb_vwv8);
    if (Protocol >= PROTOCOL_COREPLUS) {
      readbraw_supported = ((SVAL(inbuf,smb_vwv5) & 0x1) != 0);
      writebraw_supported = ((SVAL(inbuf,smb_vwv5) & 0x2) != 0);
    }
    crypt_len = smb_buflen(inbuf);
    memcpy(cryptkey,smb_buf(inbuf),8);
    DEBUG(3,("max mux %d\n",SVAL(inbuf,smb_vwv3)));
    max_vcs = SVAL(inbuf,smb_vwv4); 
    DEBUG(3,("max vcs %d\n",max_vcs)); 
    DEBUG(3,("max blk %d\n",SVAL(inbuf,smb_vwv5)));
  } else {
    /* NT protocol */
    sec_mode = CVAL(inbuf,smb_vwv1);
    max_xmit = IVAL(inbuf,smb_vwv3+1);
    sesskey = IVAL(inbuf,smb_vwv7+1);
    serverzone = SVALS(inbuf,smb_vwv15+1)*60;
    /* this time arrives in real GMT */
    servertime = interpret_long_date(inbuf+smb_vwv11+1);
    crypt_len = CVAL(inbuf,smb_vwv16+1);
    memcpy(cryptkey,smb_buf(inbuf),8);
    if (IVAL(inbuf,smb_vwv9+1) & 1)
      readbraw_supported = writebraw_supported = True;      
    DEBUG(3,("max mux %d\n",SVAL(inbuf,smb_vwv1+1)));
    max_vcs = SVAL(inbuf,smb_vwv2+1); 
    DEBUG(3,("max vcs %d\n",max_vcs));
    DEBUG(3,("max raw %d\n",IVAL(inbuf,smb_vwv5+1)));
    DEBUG(3,("capabilities 0x%x\n",IVAL(inbuf,smb_vwv9+1)));
  }

  DEBUG(3,("Sec mode %d\n",SVAL(inbuf,smb_vwv1)));
  DEBUG(3,("max xmt %d\n",max_xmit));
  DEBUG(3,("Got %d byte crypt key\n",crypt_len));
  DEBUG(3,("Chose protocol [%s]\n",prots[SVAL(inbuf,smb_vwv0)].name));

  doencrypt = ((sec_mode & 2) != 0);

  if (servertime) {
    static BOOL done_time = False;
    if (!done_time) {
      DEBUG(1,("Server time is %sTimezone is UTC%+02.1f\n",
	       asctime(LocalTime(&servertime)),
	       -(double)(serverzone/3600.0)));
      done_time = True;
    }
  }

 get_pass:

  if (got_pass)
    pass = password;
  else
    pass = (char *)getpass("Password: ");

  /* use a blank username for the 2nd try with a blank password */
  if (tries++ && !*pass)
    *username = 0;

  if (Protocol >= PROTOCOL_LANMAN1 && use_setup)
    {
      fstring pword;
      int passlen = strlen(pass)+1;
      strcpy(pword,pass);      

#ifdef SMB_PASSWD
      if (doencrypt && *pass) {
	DEBUG(3,("Using encrypted passwords\n"));
	passlen = 24;
	SMBencrypt(pass,cryptkey,pword);
      }
#else
      doencrypt = False;
#endif

      /* if in share level security then don't send a password now */
      if (!(sec_mode & 1)) {strcpy(pword, "");passlen=1;} 

      /* send a session setup command */
      bzero(outbuf,smb_size);

      if (Protocol < PROTOCOL_NT1) {
	set_message(outbuf,10,1 + strlen(username) + passlen,True);
	CVAL(outbuf,smb_com) = SMBsesssetupX;
	setup_pkt(outbuf);

	CVAL(outbuf,smb_vwv0) = 0xFF;
	SSVAL(outbuf,smb_vwv2,max_xmit);
	SSVAL(outbuf,smb_vwv3,2);
	SSVAL(outbuf,smb_vwv4,max_vcs-1);
	SIVAL(outbuf,smb_vwv5,sesskey);
	SSVAL(outbuf,smb_vwv7,passlen);
	p = smb_buf(outbuf);
	memcpy(p,pword,passlen);
	p += passlen;
	strcpy(p,username);
      } else {
	if (!doencrypt) passlen--;
	/* for Win95 */
	set_message(outbuf,13,0,True);
	CVAL(outbuf,smb_com) = SMBsesssetupX;
	setup_pkt(outbuf);

	CVAL(outbuf,smb_vwv0) = 0xFF;
	SSVAL(outbuf,smb_vwv2,BUFFER_SIZE);
	SSVAL(outbuf,smb_vwv3,2);
	SSVAL(outbuf,smb_vwv4,getpid());
	SIVAL(outbuf,smb_vwv5,sesskey);
	SSVAL(outbuf,smb_vwv7,passlen);
	SSVAL(outbuf,smb_vwv8,0);
	p = smb_buf(outbuf);
	memcpy(p,pword,passlen); p += SVAL(outbuf,smb_vwv7);
	strcpy(p,username);p = skip_string(p,1);
	strcpy(p,workgroup);p = skip_string(p,1);
	strcpy(p,"Unix");p = skip_string(p,1);
	strcpy(p,"Samba");p = skip_string(p,1);
	set_message(outbuf,13,PTR_DIFF(p,smb_buf(outbuf)),False);
      }

      send_smb(Client,outbuf);
      receive_smb(Client,inbuf,CLIENT_TIMEOUT);

      show_msg(inbuf);

      if (CVAL(inbuf,smb_rcls) != 0)
	{
	  if (! *pass &&
	      ((CVAL(inbuf,smb_rcls) == ERRDOS && 
		SVAL(inbuf,smb_err) == ERRnoaccess) ||
	       (CVAL(inbuf,smb_rcls) == ERRSRV && 
		SVAL(inbuf,smb_err) == ERRbadpw)))
	    {
	      got_pass = False;
	      DEBUG(3,("resending login\n"));
	      goto get_pass;
	    }
	      
	  DEBUG(0,("Session setup failed for username=%s myname=%s destname=%s   %s\n",
		username,myname,desthost,smb_errstr(inbuf)));
	  DEBUG(0,("You might find the -U, -W or -n options useful\n"));
	  DEBUG(0,("Sometimes you have to use `-n USERNAME' (particularly with OS/2)\n"));
	  DEBUG(0,("Some servers also insist on uppercase-only passwords\n"));
	  if (was_null)
	    {
	      free(inbuf);
	      free(outbuf);
	    }
	  return(False);
	}

      if (Protocol >= PROTOCOL_NT1) {
	char *domain,*os,*lanman;
	p = smb_buf(inbuf);
	os = p;
	lanman = skip_string(os,1);
	domain = skip_string(lanman,1);
	if (*domain || *os || *lanman)
	  DEBUG(1,("Domain=[%s] OS=[%s] Server=[%s]\n",domain,os,lanman));
      }

      /* use the returned uid from now on */
      if (SVAL(inbuf,smb_uid) != uid)
	DEBUG(3,("Server gave us a UID of %d. We gave %d\n",
	      SVAL(inbuf,smb_uid),uid));
      uid = SVAL(inbuf,smb_uid);
    }

  /* now we've got a connection - send a tcon message */
  bzero(outbuf,smb_size);

  if (strncmp(service,"\\\\",2) != 0)
    {
      DEBUG(0,("\nWarning: Your service name doesn't start with \\\\. This is probably incorrect.\n"));
      DEBUG(0,("Perhaps try replacing each \\ with \\\\ on the command line?\n\n"));
    }


 again2:

  {
    int passlen = strlen(pass)+1;
    fstring pword;
    strcpy(pword,pass);

#ifdef SMB_PASSWD
    if (doencrypt && *pass) {
      passlen=24;
      SMBencrypt(pass,cryptkey,pword);      
    }
#endif

    /* if in user level security then don't send a password now */
    if ((sec_mode & 1)) {
      strcpy(pword, ""); passlen=1; 
    }

    if (Protocol <= PROTOCOL_CORE) {
      set_message(outbuf,0,6 + strlen(service) + passlen + strlen(dev),True);
      CVAL(outbuf,smb_com) = SMBtcon;
      setup_pkt(outbuf);

      p = smb_buf(outbuf);
      *p++ = 0x04;
      strcpy(p, service);
      p = skip_string(p,1);
      *p++ = 0x04;
      memcpy(p,pword,passlen);
      p += passlen;
      *p++ = 0x04;
      strcpy(p, dev);
    }
    else {
      set_message(outbuf,4,2 + strlen(service) + passlen + strlen(dev),True);
      CVAL(outbuf,smb_com) = SMBtconX;
      setup_pkt(outbuf);
  
      SSVAL(outbuf,smb_vwv0,0xFF);
      SSVAL(outbuf,smb_vwv3,passlen);
  
      p = smb_buf(outbuf);
      memcpy(p,pword,passlen);
      p += passlen;
      strcpy(p,service);
      p = skip_string(p,1);
      strcpy(p,dev);
    }
  }

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,CLIENT_TIMEOUT);

  /* trying again with a blank password */
  if (CVAL(inbuf,smb_rcls) != 0 && 
      (int)strlen(pass) > 0 && 
      !doencrypt &&
      Protocol >= PROTOCOL_LANMAN1)
    {
      DEBUG(2,("first SMBtconX failed, trying again. %s\n",smb_errstr(inbuf)));
      strcpy(pass,"");
      goto again2;
    }  

  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("SMBtconX failed. %s\n",smb_errstr(inbuf)));
      DEBUG(0,("Perhaps you are using the wrong sharename, username or password?\n"));
      DEBUG(0,("Some servers insist that these be in uppercase\n"));
      if (was_null)
	{
	  free(inbuf);
	  free(outbuf);
	}
      return(False);
    }
  

  if (Protocol <= PROTOCOL_CORE) {
    max_xmit = SVAL(inbuf,smb_vwv0);

    cnum = SVAL(inbuf,smb_vwv1);
  }
  else {
    max_xmit = MIN(max_xmit,BUFFER_SIZE-4);
    if (max_xmit <= 0)
      max_xmit = BUFFER_SIZE - 4;

    cnum = SVAL(inbuf,smb_tid);
  }

  DEBUG(3,("Connected with cnum=%d max_xmit=%d\n",cnum,max_xmit));

  if (was_null)
    {
      free(inbuf);
      free(outbuf);
    }
  return True;
}


/****************************************************************************
send a logout command
****************************************************************************/
static void send_logout(void )
{
  pstring inbuf,outbuf;

  bzero(outbuf,smb_size);
  set_message(outbuf,0,0,True);
  CVAL(outbuf,smb_com) = SMBtdis;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,SHORT_TIMEOUT);

  if (CVAL(inbuf,smb_rcls) != 0)
    {
      DEBUG(0,("SMBtdis failed %s\n",smb_errstr(inbuf)));
    }

  
#ifdef STATS
  stats_report();
#endif
  exit(0);
}



/****************************************************************************
call a remote api
****************************************************************************/
static BOOL call_api(int prcnt,int drcnt,
		     int mprcnt,int mdrcnt,
		     int *rprcnt,int *rdrcnt,
		     char *param,char *data,
		     char **rparam,char **rdata)
{
  static char *inbuf=NULL;
  static char *outbuf=NULL;

  if (!inbuf) inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  if (!outbuf) outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

  send_trans_request(outbuf,SMBtrans,"\\PIPE\\LANMAN",0,0,
		     data,param,NULL,
		     drcnt,prcnt,0,
		     mdrcnt,mprcnt,0);

  return (receive_trans_response(inbuf,SMBtrans,
                                 rdrcnt,rprcnt,
                                 rdata,rparam));
}

/****************************************************************************
  send a SMB trans or trans2 request
  ****************************************************************************/
static BOOL send_trans_request(char *outbuf,int trans,
			       char *name,int fid,int flags,
			       char *data,char *param,uint16 *setup,
			       int ldata,int lparam,int lsetup,
			       int mdata,int mparam,int msetup)
{
  int i;
  int this_ldata,this_lparam;
  int tot_data=0,tot_param=0;
  char *outdata,*outparam;
  pstring inbuf;
  char *p;

  this_lparam = MIN(lparam,max_xmit - (500+lsetup*SIZEOFWORD)); /* hack */
  this_ldata = MIN(ldata,max_xmit - (500+lsetup*SIZEOFWORD+this_lparam));

  bzero(outbuf,smb_size);
  set_message(outbuf,14+lsetup,0,True);
  CVAL(outbuf,smb_com) = trans;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  outparam = smb_buf(outbuf)+(trans==SMBtrans ? strlen(name)+1 : 3);
  outdata = outparam+this_lparam;

  /* primary request */
  SSVAL(outbuf,smb_tpscnt,lparam);	/* tpscnt */
  SSVAL(outbuf,smb_tdscnt,ldata);	/* tdscnt */
  SSVAL(outbuf,smb_mprcnt,mparam);	/* mprcnt */
  SSVAL(outbuf,smb_mdrcnt,mdata);	/* mdrcnt */
  SCVAL(outbuf,smb_msrcnt,msetup);	/* msrcnt */
  SSVAL(outbuf,smb_flags,flags);	/* flags */
  SIVAL(outbuf,smb_timeout,0);		/* timeout */
  SSVAL(outbuf,smb_pscnt,this_lparam);	/* pscnt */
  SSVAL(outbuf,smb_psoff,smb_offset(outparam,outbuf)); /* psoff */
  SSVAL(outbuf,smb_dscnt,this_ldata);	/* dscnt */
  SSVAL(outbuf,smb_dsoff,smb_offset(outdata,outbuf)); /* dsoff */
  SCVAL(outbuf,smb_suwcnt,lsetup);	/* suwcnt */
  for (i=0;i<lsetup;i++)		/* setup[] */
    SSVAL(outbuf,smb_setup+i*SIZEOFWORD,setup[i]);
  p = smb_buf(outbuf);
  if (trans==SMBtrans)
    strcpy(p,name);			/* name[] */
  else
    {
      *p++ = 0;				/* put in a null smb_name */
      *p++ = 'D'; *p++ = ' ';		/* this was added because OS/2 does it */
    }
  if (this_lparam)			/* param[] */
    memcpy(outparam,param,this_lparam);
  if (this_ldata)			/* data[] */
    memcpy(outdata,data,this_ldata);
  set_message(outbuf,14+lsetup,		/* wcnt, bcc */
	      PTR_DIFF(outdata+this_ldata,smb_buf(outbuf)),False);

  show_msg(outbuf);
  send_smb(Client,outbuf);

  if (this_ldata < ldata || this_lparam < lparam)
    {
      /* receive interim response */
      if (!receive_smb(Client,inbuf,SHORT_TIMEOUT) || CVAL(inbuf,smb_rcls) != 0)
	{
	  DEBUG(0,("%s request failed (%s)\n",
	           trans==SMBtrans?"SMBtrans":"SMBtrans2", smb_errstr(inbuf)));
	  return(False);
	}      

      tot_data = this_ldata;
      tot_param = this_lparam;

      while (tot_data < ldata || tot_param < lparam)
    {
	  this_lparam = MIN(lparam-tot_param,max_xmit - 500); /* hack */
	  this_ldata = MIN(ldata-tot_data,max_xmit - (500+this_lparam));

	  set_message(outbuf,trans==SMBtrans?8:9,0,True);
	  CVAL(outbuf,smb_com) = trans==SMBtrans ? SMBtranss : SMBtranss2;

	  outparam = smb_buf(outbuf);
	  outdata = outparam+this_lparam;

	  /* secondary request */
	  SSVAL(outbuf,smb_tpscnt,lparam);	/* tpscnt */
	  SSVAL(outbuf,smb_tdscnt,ldata);	/* tdscnt */
	  SSVAL(outbuf,smb_spscnt,this_lparam);	/* pscnt */
	  SSVAL(outbuf,smb_spsoff,smb_offset(outparam,outbuf)); /* psoff */
	  SSVAL(outbuf,smb_spsdisp,tot_param);	/* psdisp */
	  SSVAL(outbuf,smb_sdscnt,this_ldata);	/* dscnt */
	  SSVAL(outbuf,smb_sdsoff,smb_offset(outdata,outbuf)); /* dsoff */
	  SSVAL(outbuf,smb_sdsdisp,tot_data);	/* dsdisp */
	  if (trans==SMBtrans2)
	    SSVAL(outbuf,smb_sfid,fid);		/* fid */
	  if (this_lparam)			/* param[] */
	    memcpy(outparam,param,this_lparam);
	  if (this_ldata)			/* data[] */
	    memcpy(outdata,data,this_ldata);
	  set_message(outbuf,trans==SMBtrans?8:9, /* wcnt, bcc */
		      PTR_DIFF(outdata+this_ldata,smb_buf(outbuf)),False);

	  show_msg(outbuf);
	  send_smb(Client,outbuf);

	  tot_data += this_ldata;
	  tot_param += this_lparam;
	}
    }

    return(True);
}

/****************************************************************************
try and browse available connections on a host
****************************************************************************/
static BOOL browse_host(BOOL sort)
{
#ifdef NOSTRCASECMP
#define strcasecmp StrCaseCmp
#endif
  extern int strcasecmp();

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
  strcpy(p,"WrLeh");
  p = skip_string(p,1);
  strcpy(p,"B13BWz");
  p = skip_string(p,1);
  SSVAL(p,0,1);
  SSVAL(p,2,BUFFER_SIZE);
  p += 4;

  if (call_api(PTR_DIFF(p,param),0,
	       1024,BUFFER_SIZE,
               &rprcnt,&rdrcnt,
	       param,NULL,
	       &rparam,&rdata))
    {
      int res = SVAL(rparam,0);
      int converter=SVAL(rparam,2);
      int i;
      BOOL long_share_name=False;
      
      if (res == 0)
	{
	  count=SVAL(rparam,4);
	  p = rdata;

	  if (count > 0)
	    {
	      printf("\n\tSharename      Type      Comment\n");
	      printf("\t---------      ----      -------\n");
	    }

	  if (sort)
	    qsort(p,count,20,QSORT_CAST strcasecmp);

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
		  strcpy(typestr,"Disk"); break;
		case STYPE_PRINTQ:
		  strcpy(typestr,"Printer"); break;	      
		case STYPE_DEVICE:
		  strcpy(typestr,"Device"); break;
		case STYPE_IPC:
		  strcpy(typestr,"IPC"); break;      
		}

	      printf("\t%-15.15s%-10.10s%s\n",
		     sname,
		     typestr,
		     comment_offset?rdata+comment_offset-converter:"");
	  
	      if (strlen(sname)>8) long_share_name=True;
	  
	      p += 20;
	    }

	  if (long_share_name) {
	    printf("\nNOTE: There were share names longer than 8 chars.\nOn older clients these may not be accessible or may give browsing errors\n");
	  }
	}
    }
  
  if (rparam) free(rparam);
  if (rdata) free(rdata);

  return(count>0);
}


/****************************************************************************
get some server info
****************************************************************************/
static void server_info()
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
  strcpy(p,"WrLh");
  p = skip_string(p,1);
  strcpy(p,"zzzBBzz");
  p = skip_string(p,1);
  SSVAL(p,0,10); /* level 10 */
  SSVAL(p,2,1000);
  p += 6;

  if (call_api(PTR_DIFF(p,param),0,
	       6,1000,
	       &rprcnt,&rdrcnt,
	       param,NULL,
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

  strcpy(p,generic_request?"WrLehDO":"WrLehDz");
  p = skip_string(p,1);

  strcpy(p,"B16BBDz");

  p = skip_string(p,1);
  SSVAL(p,0,uLevel);
  SSVAL(p,2,0x2000); /* buf length */
  p += 4;

  svtype_p = p;
  p += 4;

  if (!generic_request) {
    strcpy(p, wk_grp);
    p = skip_string(p,1);
  }

  /* first ask for a list of servers in this workgroup */
  SIVAL(svtype_p,0,SV_TYPE_ALL);

  if (call_api(PTR_DIFF(p+4,param),0,
	       8,10000,
	       &rprcnt,&rdrcnt,
	       param,NULL,
	       &rparam,&rdata))
    {
      int res = SVAL(rparam,0);
      int converter=SVAL(rparam,2);
      int i;

      if (res == 0) {	
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
	  printf("\t%-16.16s     %s\n",
		 sname,
		 comment_offset?rdata+comment_offset-converter:"");

	  ok=True;
	  p2 += 26;
	}
      }
    }

  if (rparam) {free(rparam); rparam = NULL;}
  if (rdata) {free(rdata); rdata = NULL;}

  /* now ask for a list of workgroups */
  SIVAL(svtype_p,0,SV_TYPE_DOMAIN_ENUM);

  if (call_api(PTR_DIFF(p+4,param),0,
	       8,10000,
	       &rprcnt,&rdrcnt,
	       param,NULL,
	       &rparam,&rdata))
    {
      int res = SVAL(rparam,0);
      int converter=SVAL(rparam,2);
      int i;

      if (res == 0) {
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
	  printf("\t%-16.16s     %s\n",
		 sname,
		 comment_offset?rdata+comment_offset-converter:"");
	  
	  ok=True;
	  p2 += 26;
	}
      }
    }

  if (rparam) free(rparam);
  if (rdata) free(rdata);

  return(ok);
}


/* This defines the commands supported by this client */
struct
{
  char *name;
  void (*fn)();
  char *description;
} commands[] = 
{
  {"ls",cmd_dir,"<mask> list the contents of the current directory"},
  {"dir",cmd_dir,"<mask> list the contents of the current directory"},
  {"lcd",cmd_lcd,"[directory] change/report the local current working directory"},
  {"cd",cmd_cd,"[directory] change/report the remote directory"},
  {"pwd",cmd_pwd,"show current remote directory (same as 'cd' with no args)"},
  {"get",cmd_get,"<remote name> [local name] get a file"},
  {"mget",cmd_mget,"<mask> get all the matching files"},
  {"put",cmd_put,"<local name> [remote name] put a file"},
  {"mput",cmd_mput,"<mask> put all matching files"},
  {"rename",cmd_rename,"<src> <dest> rename some files"},
  {"more",cmd_more,"<remote name> view a remote file with your pager"},  
  {"mask",cmd_select,"<mask> mask all filenames against this"},
  {"del",cmd_del,"<mask> delete all matching files"},
  {"rm",cmd_del,"<mask> delete all matching files"},
  {"mkdir",cmd_mkdir,"<directory> make a directory"},
  {"md",cmd_mkdir,"<directory> make a directory"},
  {"rmdir",cmd_rmdir,"<directory> remove a directory"},
  {"rd",cmd_rmdir,"<directory> remove a directory"},
  {"prompt",cmd_prompt,"toggle prompting for filenames for mget and mput"},  
  {"recurse",cmd_recurse,"toggle directory recursion for mget and mput"},  
  {"translate",cmd_translate,"toggle text translation for printing"},  
  {"lowercase",cmd_lowercase,"toggle lowercasing of filenames for get"},  
  {"print",cmd_print,"<file name> print a file"},
  {"printmode",cmd_printmode,"<graphics or text> set the print mode"},
  {"queue",cmd_queue,"show the print queue"},
  {"qinfo",cmd_qinfo,"show print queue information"},
  {"cancel",cmd_cancel,"<jobid> cancel a print queue entry"},
  {"stat",cmd_stat,"<file> get info on a file (experimental!)"},
  {"quit",send_logout,"logoff the server"},
  {"q",send_logout,"logoff the server"},
  {"exit",send_logout,"logoff the server"},
  {"newer",cmd_newer,"<file> only mget files newer than the specified local file"},
  {"archive",cmd_archive,"<level>\n0=ignore archive bit\n1=only get archive files\n2=only get archive files and reset archive bit\n3=get all files and reset archive bit"},
  {"tar",cmd_tar,"tar <c|x>[IXbgNa] current directory to/from <file name>" },
  {"blocksize",cmd_block,"blocksize <number> (default 20)" },
  {"tarmode",cmd_tarmode,
     "<full|inc|reset|noreset> tar's behaviour towards archive bits" },
  {"setmode",cmd_setmode,"filename <setmode string> change modes of file"},
  {"help",cmd_help,"[command] give help on a command"},
  {"?",cmd_help,"[command] give help on a command"},
  {"!",NULL,"run a shell command on the local system"},
  {"",NULL,NULL}
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
      else if (strnequal(commands[i].name, tok, tok_len+1))
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
void cmd_help(void)
{
  int i=0,j;
  fstring buf;

  if (next_token(NULL,buf,NULL))
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

/****************************************************************************
open the client sockets
****************************************************************************/
static BOOL open_sockets(int port )
{
  static int last_port;
  char *host;
  pstring service2;
  extern int Client;
#ifdef USENMB
  BOOL failed = True;
#endif

  if (port == 0) port=last_port;
  last_port=port;

  strupper(service);

  if (*desthost)
    {
      host = desthost;
    }
  else
    {
      strcpy(service2,service);
      host = strtok(service2,"\\/");
      if (!host) {
	DEBUG(0,("Badly formed host name\n"));
	return(False);
      }
      strcpy(desthost,host);
    }

  if (*myname == 0) {
      get_myname(myname,NULL);
  }
  strupper(myname);

  DEBUG(3,("Opening sockets\n"));

  if (!have_ip)
    {
      struct hostent *hp;

      if ((hp = Get_Hostbyname(host))) {
	putip((char *)&dest_ip,(char *)hp->h_addr);
	failed = False;
      } else {
#ifdef USENMB
	/* Try and resolve the name with the netbios server */
	int           	bcast;

	if ((bcast = open_socket_in(SOCK_DGRAM, 0, 3,
				    interpret_addr(lp_socket_address()))) != -1) {
	  set_socket_options(bcast, "SO_BROADCAST");

	  if (name_query(bcast, host, 0x20, True, True, *iface_bcast(dest_ip),
			 &dest_ip,0)) {
	    failed = False;
	  }
	  close (bcast);
	}
#endif
	if (failed) {
	  DEBUG(0,("Get_Hostbyname: Unknown host %s.\n",host));
	  return False;
	}
      }
    }

  Client = open_socket_out(SOCK_STREAM, &dest_ip, port, LONG_CONNECT_TIMEOUT);
  if (Client == -1)
    return False;

  DEBUG(3,("Connected\n"));
  
  set_socket_options(Client,user_socket_options);  
  
  return True;
}

/****************************************************************************
wait for keyboard activity, swallowing network packets
****************************************************************************/
#ifdef CLIX
static char wait_keyboard(char *buffer)
#else
static void wait_keyboard(char *buffer)
#endif
{
  fd_set fds;
  int selrtn;
  struct timeval timeout;
  
#ifdef CLIX
  int delay = 0;
#endif
  
  while (1) 
    {
      extern int Client;
      FD_ZERO(&fds);
      FD_SET(Client,&fds);
#ifndef CLIX
      FD_SET(fileno(stdin),&fds);
#endif

      timeout.tv_sec = 20;
      timeout.tv_usec = 0;
#ifdef CLIX
      timeout.tv_sec = 0;
#endif
      selrtn = sys_select(&fds,&timeout);
      
#ifndef CLIX
      if (FD_ISSET(fileno(stdin),&fds))
  	return;
#else
      {
	char ch;
	int f_flags;
	int readret;
	
	f_flags = fcntl(fileno(stdin), F_GETFL, 0);
	fcntl( fileno(stdin), F_SETFL, f_flags | O_NONBLOCK);
	readret = read_data( fileno(stdin), &ch, 1);
	fcntl(fileno(stdin), F_SETFL, f_flags);
	if (readret == -1)
	  {
	    if (errno != EAGAIN)
	      {
		/* should crash here */
		DEBUG(1,("readchar stdin failed\n"));
	      }
	  }
	else if (readret != 0)
	  {
	    return ch;
	  }
      }
#endif
      if (FD_ISSET(Client,&fds))
  	receive_smb(Client,buffer,0);
      
#ifdef CLIX
      delay++;
      if (delay > 100000)
	{
	  delay = 0;
	  chkpath("\\",False);
	}
#else
      chkpath("\\",False);
#endif
    }  
}


/****************************************************************************
close and open the connection again
****************************************************************************/
BOOL reopen_connection(char *inbuf,char *outbuf)
{
  static int open_count=0;

  open_count++;

  if (open_count>5) return(False);

  DEBUG(1,("Trying to re-open connection\n"));

  set_message(outbuf,0,0,True);
  SCVAL(outbuf,smb_com,SMBtdis);
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  send_smb(Client,outbuf);
  receive_smb(Client,inbuf,SHORT_TIMEOUT);

  close_sockets();
  if (!open_sockets(0)) return(False);

  return(send_login(inbuf,outbuf,True,True));
}

/****************************************************************************
  process commands from the client
****************************************************************************/
static BOOL process(char *base_directory)
{
  extern FILE *dbf;
  pstring line;
  char *cmd;

  char *InBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  char *OutBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

  if ((InBuffer == NULL) || (OutBuffer == NULL)) 
    return(False);
  
  bzero(OutBuffer,smb_size);

  if (!send_login(InBuffer,OutBuffer,True,True))
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
	if (!next_token(&ptr,tok,NULL)) continue;
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

      /* display a prompt */
      DEBUG(1,("smb: %s> ", CNV_LANG(cur_dir)));
      fflush(dbf);

#ifdef CLIX
      line[0] = wait_keyboard(InBuffer);
      /* this might not be such a good idea... */
      if ( line[0] == EOF)
	break;
#else
      wait_keyboard(InBuffer);
#endif
  
      /* and get a response */
#ifdef CLIX
      fgets( &line[1],999, stdin);
#else
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
	if (!next_token(&ptr,tok,NULL)) continue;
      }

      if ((i = process_tok(tok)) >= 0)
	commands[i].fn(InBuffer,OutBuffer);
      else if (i == -2)
	DEBUG(0,("%s: command abbreviation ambiguous\n",CNV_LANG(tok)));
      else
	DEBUG(0,("%s: command not found\n",CNV_LANG(tok)));
    }
  
  send_logout();
  return(True);
}


/****************************************************************************
usage on the program
****************************************************************************/
static void usage(char *pname)
{
  DEBUG(0,("Usage: %s service <password> [-p port] [-d debuglevel] [-l log] ",
	   pname));

#ifdef KANJI
  DEBUG(0,("[-t termcode] "));
#endif /* KANJI */

  DEBUG(0,("\nVersion %s\n",VERSION));
  DEBUG(0,("\t-p port               listen on the specified port\n"));
  DEBUG(0,("\t-d debuglevel         set the debuglevel\n"));
  DEBUG(0,("\t-l log basename.      Basename for log/debug files\n"));
  DEBUG(0,("\t-n netbios name.      Use this name as my netbios name\n"));
  DEBUG(0,("\t-N                    don't ask for a password\n"));
  DEBUG(0,("\t-P                    connect to service as a printer\n"));
  DEBUG(0,("\t-M host               send a winpopup message to the host\n"));
  DEBUG(0,("\t-m max protocol       set the max protocol level\n"));
  DEBUG(0,("\t-L host               get a list of shares available on a host\n"));
  DEBUG(0,("\t-I dest IP            use this IP to connect to\n"));
  DEBUG(0,("\t-E                    write messages to stderr instead of stdout\n"));
  DEBUG(0,("\t-U username           set the network username\n"));
  DEBUG(0,("\t-W workgroup          set the workgroup name\n"));
  DEBUG(0,("\t-c command string     execute semicolon separated commands\n"));
#ifdef KANJI
  DEBUG(0,("\t-t terminal code      terminal i/o code {sjis|euc|jis7|jis8|junet|hex}\n"));
#endif /* KANJI */
  DEBUG(0,("\t-T<c|x>IXgbNa          command line tar\n"));
  DEBUG(0,("\t-D directory          start from directory\n"));
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
  extern char tar_type;
  static pstring servicesf = CONFIGFILE;

  *query_host = 0;
  *base_directory = 0;

  DEBUGLEVEL = 2;

  setup_logging(pname,True);

  TimeInit();
  charset_initialise();

  pid = getpid();
  uid = getuid();
  gid = getgid();
  mid = pid + 100;
  myumask = umask(0);
  umask(myumask);

  if (getenv("USER"))
    {
      strcpy(username,getenv("USER"));
      strupper(username);
    }

  if (*username == 0 && getenv("LOGNAME"))
    {
      strcpy(username,getenv("LOGNAME"));
      strupper(username);
    }

  if (argc < 2)
    {
      usage(pname);
      exit(1);
    }
  
  if (*argv[1] != '-')
    {

      strcpy(service,argv[1]);  
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
	  strcpy(password,argv[1]);  
	  memset(argv[1],'X',strlen(argv[1]));
	  argc--;
	  argv++;
	}
    }

#ifdef KANJI
  setup_term_code (KANJI);
#endif
  while ((opt = 
	  getopt(argc, argv,"s:B:O:M:i:Nn:d:Pp:l:hI:EB:U:L:t:m:W:T:D:c:")) != EOF)
    switch (opt)
      {
      case 'm':
	max_protocol = interpret_protocol(optarg,max_protocol);
	break;
      case 'O':
	strcpy(user_socket_options,optarg);
	break;	
      case 'M':
	name_type = 3;
	strcpy(desthost,optarg);
	strupper(desthost);
	message = True;
	break;
      case 'B':
	iface_set_default(NULL,optarg,NULL);
	break;
      case 'D':
	strcpy(base_directory,optarg);
	break;
      case 'T':
	if (!tar_parseargs(argc, argv, optarg, optind)) {
	  usage(pname);
	  exit(1);
	}
	break;
      case 'i':
	strcpy(scope,optarg);
	break;
      case 'L':
	got_pass = True;
	strcpy(query_host,optarg);
	break;
      case 'U':
	{
	  char *p;
	strcpy(username,optarg);
	if ((p=strchr(username,'%')))
	  {
	    *p = 0;
	    strcpy(password,p+1);
	    got_pass = True;
	    memset(strchr(optarg,'%')+1,'X',strlen(password));
	  }
	}
	    
	break;
      case 'W':
	strcpy(workgroup,optarg);
	break;
      case 'E':
	dbf = stderr;
	break;
      case 'I':
	{
	  dest_ip = *interpret_addr2(optarg);
	  if (zero_ip(dest_ip)) exit(1);
	  have_ip = True;
	}
	break;
      case 'n':
	strcpy(myname,optarg);
	break;
      case 'N':
	got_pass = True;
	break;
      case 'P':
	connect_as_printer = True;
	break;
      case 'd':
	if (*optarg == 'A')
	  DEBUGLEVEL = 10000;
	else
	  DEBUGLEVEL = atoi(optarg);
	break;
      case 'l':
	sprintf(debugf,"%s.client",optarg);
	break;
      case 'p':
	port = atoi(optarg);
	break;
      case 'c':
	cmdstr = optarg;
	got_pass = True;
	break;
      case 'h':
	usage(pname);
	exit(0);
	break;
      case 's':
	strcpy(servicesf, optarg);
	break;
      case 't':
#ifdef KANJI
	if (!setup_term_code (optarg)) {
	    DEBUG(0, ("%s: unknown terminal code name\n", optarg));
	    usage (pname);
	    exit (1);
	}
#endif
	break;
      default:
	usage(pname);
	exit(1);
      }

  if (!tar_type && !*query_host && !*service && !message)
    {
      usage(pname);
      exit(1);
    }


  DEBUG(3,("%s client started (version %s)\n",timestring(),VERSION));

  if (!lp_load(servicesf,True)) {
    fprintf(stderr, "Can't load %s - run testparm to debug it\n", servicesf);
    return (-1);
  }

  load_interfaces();
  get_myname(*myname?NULL:myname,NULL);  
  strupper(myname);

  if (tar_type) {
    recurse=True;

    if (open_sockets(port)) {
        char *InBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
	char *OutBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
	int ret;

	if ((InBuffer == NULL) || (OutBuffer == NULL)) 
	  return(1);

	bzero(OutBuffer,smb_size);
	if (!send_login(InBuffer,OutBuffer,True,True))
	  return(False);

	if (*base_directory) do_cd(base_directory);

	ret=process_tar(InBuffer, OutBuffer);

	send_logout();
	close_sockets();
	return(ret);
    } else
      return(1);
  }
  
  if (*query_host)
    {
      int ret = 0;
      sprintf(service,"\\\\%s\\IPC$",query_host);
      strupper(service);
      connect_as_ipc = True;
      if (open_sockets(port))
	{
#if 0
	  *username = 0;
#endif
	  if (!send_login(NULL,NULL,True,True))
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

	  send_logout();
	  close_sockets();
	}

      return(ret);
    }

  if (message)
    {
      int ret = 0;
      if (open_sockets(port))
	{
	  pstring inbuf,outbuf;
	  bzero(outbuf,smb_size);
	  if (!send_session_request(inbuf,outbuf))
	    return(1);

	  send_message(inbuf,outbuf);

	  close_sockets();
	}

      return(ret);
    }

  if (open_sockets(port))
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


/* error code stuff - put together by Merik Karman
   merik@blackadder.dsh.oz.au */

typedef struct
{
  char *name;
  int code;
  char *message;
} err_code_struct;

/* Dos Error Messages */
err_code_struct dos_msgs[] = {
  {"ERRbadfunc",1,"Invalid function."},
  {"ERRbadfile",2,"File not found."},
  {"ERRbadpath",3,"Directory invalid."},
  {"ERRnofids",4,"No file descriptors available"},
  {"ERRnoaccess",5,"Access denied."},
  {"ERRbadfid",6,"Invalid file handle."},
  {"ERRbadmcb",7,"Memory control blocks destroyed."},
  {"ERRnomem",8,"Insufficient server memory to perform the requested function."},
  {"ERRbadmem",9,"Invalid memory block address."},
  {"ERRbadenv",10,"Invalid environment."},
  {"ERRbadformat",11,"Invalid format."},
  {"ERRbadaccess",12,"Invalid open mode."},
  {"ERRbaddata",13,"Invalid data."},
  {"ERR",14,"reserved."},
  {"ERRbaddrive",15,"Invalid drive specified."},
  {"ERRremcd",16,"A Delete Directory request attempted  to  remove  the  server's  current directory."},
  {"ERRdiffdevice",17,"Not same device."},
  {"ERRnofiles",18,"A File Search command can find no more files matching the specified criteria."},
  {"ERRbadshare",32,"The sharing mode specified for an Open conflicts with existing  FIDs  on the file."},
  {"ERRlock",33,"A Lock request conflicted with an existing lock or specified an  invalid mode,  or an Unlock requested attempted to remove a lock held by another process."},
  {"ERRfilexists",80,"The file named in a Create Directory, Make  New  File  or  Link  request already exists."},
  {"ERRbadpipe",230,"Pipe invalid."},
  {"ERRpipebusy",231,"All instances of the requested pipe are busy."},
  {"ERRpipeclosing",232,"Pipe close in progress."},
  {"ERRnotconnected",233,"No process on other end of pipe."},
  {"ERRmoredata",234,"There is more data to be returned."},
  {"ERRinvgroup",2455,"Invalid workgroup (try the -W option)"},
  {NULL,-1,NULL}};

/* Server Error Messages */
err_code_struct server_msgs[] = {
  {"ERRerror",1,"Non-specific error code."},
  {"ERRbadpw",2,"Bad password - name/password pair in a Tree Connect or Session Setup are invalid."},
  {"ERRbadtype",3,"reserved."},
  {"ERRaccess",4,"The requester does not have  the  necessary  access  rights  within  the specified  context for the requested function. The context is defined by the TID or the UID."},
  {"ERRinvnid",5,"The tree ID (TID) specified in a command was invalid."},
  {"ERRinvnetname",6,"Invalid network name in tree connect."},
  {"ERRinvdevice",7,"Invalid device - printer request made to non-printer connection or  non-printer request made to printer connection."},
  {"ERRqfull",49,"Print queue full (files) -- returned by open print file."},
  {"ERRqtoobig",50,"Print queue full -- no space."},
  {"ERRqeof",51,"EOF on print queue dump."},
  {"ERRinvpfid",52,"Invalid print file FID."},
  {"ERRsmbcmd",64,"The server did not recognize the command received."},
  {"ERRsrverror",65,"The server encountered an internal error, e.g., system file unavailable."},
  {"ERRfilespecs",67,"The file handle (FID) and pathname parameters contained an invalid  combination of values."},
  {"ERRreserved",68,"reserved."},
  {"ERRbadpermits",69,"The access permissions specified for a file or directory are not a valid combination.  The server cannot set the requested attribute."},
  {"ERRreserved",70,"reserved."},
  {"ERRsetattrmode",71,"The attribute mode in the Set File Attribute request is invalid."},
  {"ERRpaused",81,"Server is paused."},
  {"ERRmsgoff",82,"Not receiving messages."},
  {"ERRnoroom",83,"No room to buffer message."},
  {"ERRrmuns",87,"Too many remote user names."},
  {"ERRtimeout",88,"Operation timed out."},
  {"ERRnoresource",89,"No resources currently available for request."},
  {"ERRtoomanyuids",90,"Too many UIDs active on this session."},
  {"ERRbaduid",91,"The UID is not known as a valid ID on this session."},
  {"ERRusempx",250,"Temp unable to support Raw, use MPX mode."},
  {"ERRusestd",251,"Temp unable to support Raw, use standard read/write."},
  {"ERRcontmpx",252,"Continue in MPX mode."},
  {"ERRreserved",253,"reserved."},
  {"ERRreserved",254,"reserved."},
  {"ERRnosupport",0xFFFF,"Function not supported."},
  {NULL,-1,NULL}};

/* Hard Error Messages */
err_code_struct hard_msgs[] = {
  {"ERRnowrite",19,"Attempt to write on write-protected diskette."},
  {"ERRbadunit",20,"Unknown unit."},
  {"ERRnotready",21,"Drive not ready."},
  {"ERRbadcmd",22,"Unknown command."},
  {"ERRdata",23,"Data error (CRC)."},
  {"ERRbadreq",24,"Bad request structure length."},
  {"ERRseek",25 ,"Seek error."},
  {"ERRbadmedia",26,"Unknown media type."},
  {"ERRbadsector",27,"Sector not found."},
  {"ERRnopaper",28,"Printer out of paper."},
  {"ERRwrite",29,"Write fault."},
  {"ERRread",30,"Read fault."},
  {"ERRgeneral",31,"General failure."},
  {"ERRbadshare",32,"A open conflicts with an existing open."},
  {"ERRlock",33,"A Lock request conflicted with an existing lock or specified an invalid mode, or an Unlock requested attempted to remove a lock held by another process."},
  {"ERRwrongdisk",34,"The wrong disk was found in a drive."},
  {"ERRFCBUnavail",35,"No FCBs are available to process request."},
  {"ERRsharebufexc",36,"A sharing buffer has been exceeded."},
  {NULL,-1,NULL}};


struct
{
  int code;
  char *class;
  err_code_struct *err_msgs;
} err_classes[] = { 
  {0,"SUCCESS",NULL},
  {0x01,"ERRDOS",dos_msgs},
  {0x02,"ERRSRV",server_msgs},
  {0x03,"ERRHRD",hard_msgs},
  {0x04,"ERRXOS",NULL},
  {0xE1,"ERRRMX1",NULL},
  {0xE2,"ERRRMX2",NULL},
  {0xE3,"ERRRMX3",NULL},
  {0xFF,"ERRCMD",NULL},
  {-1,NULL,NULL}};


/****************************************************************************
return a SMB error string from a SMB buffer
****************************************************************************/
char *smb_errstr(char *inbuf)
{
  static pstring ret;
  int class = CVAL(inbuf,smb_rcls);
  int num = SVAL(inbuf,smb_err);
  int i,j;

  for (i=0;err_classes[i].class;i++)
    if (err_classes[i].code == class)
      {
	if (err_classes[i].err_msgs)
	  {
	    err_code_struct *err = err_classes[i].err_msgs;
	    for (j=0;err[j].name;j++)
	      if (num == err[j].code)
		{
		  if (DEBUGLEVEL > 0)
		    sprintf(ret,"%s - %s (%s)",err_classes[i].class,
			    err[j].name,err[j].message);
		  else
		    sprintf(ret,"%s - %s",err_classes[i].class,err[j].name);
		  return ret;
		}
	  }

	sprintf(ret,"%s - %d",err_classes[i].class,num);
	return ret;
      }
  
  sprintf(ret,"ERROR: Unknown error (%d,%d)",class,num);
  return(ret);
}
