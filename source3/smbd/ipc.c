/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Inter-process communication and named pipe handling
   Copyright (C) Andrew Tridgell 1992-1995
   
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
   This file handles the named pipe and mailslot calls
   in the SMBtrans protocol
   */

#include "includes.h"

#ifdef CHECK_TYPES
#undef CHECK_TYPES
#endif
#define CHECK_TYPES 0

extern int DEBUGLEVEL;
extern int maxxmit;
extern files_struct Files[];
extern connection_struct Connections[];

extern fstring local_machine;

#define NERR_Success 0
#define NERR_badpass 86
#define NERR_notsupported 50

#define NERR_BASE (2100)
#define NERR_BufTooSmall (NERR_BASE+23)
#define NERR_JobNotFound (NERR_BASE+51)
#define NERR_DestNotFound (NERR_BASE+52)
#define ERROR_INVALID_LEVEL 124
#define ERROR_MORE_DATA 234

#define REALLOC(ptr,size) Realloc(ptr,MAX((size),4*1024))

#define ACCESS_READ 0x01
#define ACCESS_WRITE 0x02
#define ACCESS_CREATE 0x04

#define SHPWLEN 8		/* share password length */
#define NNLEN 12		/* 8.3 net name length */
#define SNLEN 15		/* service name length */
#define QNLEN 12		/* queue name maximum length */

#define MAJOR_VERSION 4
#define MINOR_VERSION 1

extern int Client;

static BOOL api_Unsupported(int cnum,int uid, char *param,char *data,
			    int mdrcnt,int mprcnt,
			    char **rdata,char **rparam,
			    int *rdata_len,int *rparam_len);
static BOOL api_TooSmall(int cnum,int uid, char *param,char *data,
			 int mdrcnt,int mprcnt,
			 char **rdata,char **rparam,
			 int *rdata_len,int *rparam_len);


static int CopyExpanded(int cnum, int snum, char** dst, char* src, int* n)
{
  pstring buf;
  int l;

  if (!src || !dst || !n || !(*dst)) return(0);

  StrnCpy(buf,src,sizeof(buf)/2);
  string_sub(buf,"%S",lp_servicename(snum));
  standard_sub(cnum,buf);
  StrnCpy(*dst,buf,*n);
  l = strlen(*dst) + 1;
  (*dst) += l;
  (*n) -= l;
  return l;
}

static int CopyAndAdvance(char** dst, char* src, int* n)
{
  int l;
  if (!src || !dst || !n || !(*dst)) return(0);
  StrnCpy(*dst,src,*n);
  l = strlen(*dst) + 1;
  (*dst) += l;
  (*n) -= l;
  return l;
}

static int StrlenExpanded(int cnum, int snum, char* s)
{
  pstring buf;
  if (!s) return(0);
  StrnCpy(buf,s,sizeof(buf)/2);
  string_sub(buf,"%S",lp_servicename(snum));
  standard_sub(cnum,buf);
  return strlen(buf) + 1;
}

static char* Expand(int cnum, int snum, char* s)
{
  static pstring buf;
  if (!s) return(NULL);
  StrnCpy(buf,s,sizeof(buf)/2);
  string_sub(buf,"%S",lp_servicename(snum));
  standard_sub(cnum,buf);
  return &buf[0];
}

/*******************************************************************
  check a API string for validity when we only need to check the prefix
  ******************************************************************/
static BOOL prefix_ok(char *str,char *prefix)
{
  return(strncmp(str,prefix,strlen(prefix)) == 0);
}


/****************************************************************************
  send a trans reply
  ****************************************************************************/
static void send_trans_reply(char *outbuf,char *data,char *param,uint16 *setup,
			     int ldata,int lparam,int lsetup)
{
  int i;
  int this_ldata,this_lparam;
  int tot_data=0,tot_param=0;
  int align;

  this_lparam = MIN(lparam,maxxmit - (500+lsetup*SIZEOFWORD)); /* hack */
  this_ldata = MIN(ldata,maxxmit - (500+lsetup*SIZEOFWORD+this_lparam));

  align = (this_lparam%4);

  set_message(outbuf,10+lsetup,align+this_ldata+this_lparam,True);
  if (this_lparam)
    memcpy(smb_buf(outbuf),param,this_lparam);
  if (this_ldata)
    memcpy(smb_buf(outbuf)+this_lparam+align,data,this_ldata);

  SSVAL(outbuf,smb_vwv0,lparam);
  SSVAL(outbuf,smb_vwv1,ldata);
  SSVAL(outbuf,smb_vwv3,this_lparam);
  SSVAL(outbuf,smb_vwv4,smb_offset(smb_buf(outbuf),outbuf));
  SSVAL(outbuf,smb_vwv5,0);
  SSVAL(outbuf,smb_vwv6,this_ldata);
  SSVAL(outbuf,smb_vwv7,smb_offset(smb_buf(outbuf)+this_lparam+align,outbuf));
  SSVAL(outbuf,smb_vwv8,0);
  SSVAL(outbuf,smb_vwv9,lsetup);
  for (i=0;i<lsetup;i++)
    SSVAL(outbuf,smb_vwv10+i*SIZEOFWORD,setup[i]);

  show_msg(outbuf);
  send_smb(Client,outbuf);

  tot_data = this_ldata;
  tot_param = this_lparam;

  while (tot_data < ldata || tot_param < lparam)
    {
      this_lparam = MIN(lparam-tot_param,maxxmit - 500); /* hack */
      this_ldata = MIN(ldata-tot_data,maxxmit - (500+this_lparam));

      align = (this_lparam%4);

      set_message(outbuf,10,this_ldata+this_lparam+align,False);
      if (this_lparam)
	memcpy(smb_buf(outbuf),param+tot_param,this_lparam);
      if (this_ldata)
	memcpy(smb_buf(outbuf)+this_lparam+align,data+tot_data,this_ldata);

      SSVAL(outbuf,smb_vwv3,this_lparam);
      SSVAL(outbuf,smb_vwv4,smb_offset(smb_buf(outbuf),outbuf));
      SSVAL(outbuf,smb_vwv5,tot_param);
      SSVAL(outbuf,smb_vwv6,this_ldata);
      SSVAL(outbuf,smb_vwv7,smb_offset(smb_buf(outbuf)+this_lparam+align,outbuf));
      SSVAL(outbuf,smb_vwv8,tot_data);
      SSVAL(outbuf,smb_vwv9,0);

      show_msg(outbuf);
      send_smb(Client,outbuf);

      tot_data += this_ldata;
      tot_param += this_lparam;
    }
}

struct pack_desc {
  char* format;	    /* formatstring for structure */
  char* subformat;  /* subformat for structure */
  char* base;	    /* baseaddress of buffer */
  int buflen;	   /* remaining size for fixed part; on init: length of base */
  int subcount;	    /* count of substructures */
  char* structbuf;  /* pointer into buffer for remaining fixed part */
  int stringlen;    /* remaining size for variable part */		
  char* stringbuf;  /* pointer into buffer for remaining variable part */
  int neededlen;    /* total needed size */
  int usedlen;	    /* total used size (usedlen <= neededlen and usedlen <= buflen) */
  char* curpos;	    /* current position; pointer into format or subformat */
  int errcode;
};

static int get_counter(char** p)
{
  int i, n;
  if (!p || !(*p)) return(1);
  if (!isdigit(**p)) return 1;
  for (n = 0;;) {
    i = **p;
    if (isdigit(i))
      n = 10 * n + (i - '0');
    else
      return n;
    (*p)++;
  }
}

static int getlen(char* p)
{
  int n = 0;
  if (!p) return(0);
  while (*p) {
    switch( *p++ ) {
    case 'W':			/* word (2 byte) */
      n += 2;
      break;
    case 'N':			/* count of substructures (word) at end */
      n += 2;
      break;
    case 'D':			/* double word (4 byte) */
    case 'z':			/* offset to zero terminated string (4 byte) */
    case 'l':			/* offset to user data (4 byte) */
      n += 4;
      break;
    case 'b':			/* offset to data (with counter) (4 byte) */
      n += 4;
      get_counter(&p);
      break;
    case 'B':			/* byte (with optional counter) */
      n += get_counter(&p);
      break;
    }
  }
  return n;
}

static BOOL init_package(struct pack_desc* p, int count, int subcount)
{
  int n = p->buflen;
  int i;

  if (!p->format || !p->base) return(False);

  i = count * getlen(p->format);
  if (p->subformat) i += subcount * getlen(p->subformat);
  p->structbuf = p->base;
  p->neededlen = 0;
  p->usedlen = 0;
  p->subcount = 0;
  p->curpos = p->format;
  if (i > n) {
    i = n = 0;
    p->errcode = NERR_BufTooSmall;
  }

  p->errcode = NERR_Success;
  p->buflen = i;
  n -= i;
  p->stringbuf = p->base + i;
  p->stringlen = n;
  return(p->errcode == NERR_Success);
}

#ifdef __STDC__
static int package(struct pack_desc* p, ...)
{
#else
static int package(va_alist)
va_dcl
{
  struct pack_desc* p;
#endif
  va_list args;
  int needed=0, stringneeded;
  char* str=NULL;
  int is_string=0, stringused;
  int32 temp;

#ifdef __STDC__
  va_start(args,p);
#else
  va_start(args);
  p = va_arg(args,struct pack_desc *);
#endif

  if (!*p->curpos) {
    if (!p->subcount)
      p->curpos = p->format;
    else {
      p->curpos = p->subformat;
      p->subcount--;
    }
  }
#if CHECK_TYPES
  str = va_arg(args,char*);
  if (strncmp(str,p->curpos,strlen(str)) != 0) {
    DEBUG(2,("type error in package: %s instead of %*s\n",str,
 	     strlen(str),p->curpos));
    va_end(args);
#if AJT
    ajt_panic();
#endif  
    return 0;
  }
#endif
  stringneeded = -1;

  if (!p->curpos) return(0);

  switch( *p->curpos++ ) {
  case 'W':			/* word (2 byte) */
    needed = 2;
    temp = va_arg(args,int);
    if (p->buflen >= needed) SSVAL(p->structbuf,0,temp);
    break;
  case 'N':			/* count of substructures (word) at end */
    needed = 2;
    p->subcount = va_arg(args,int);
    if (p->buflen >= needed) SSVAL(p->structbuf,0,p->subcount);
    break;
  case 'D':			/* double word (4 byte) */
    needed = 4;
    temp = va_arg(args,int);
    if (p->buflen >= needed) SIVAL(p->structbuf,0,temp);
    break;
  case 'B':			/* byte (with optional counter) */
    needed = get_counter(&p->curpos);
    {
      char *s = va_arg(args,char*);
      if (p->buflen >= needed) StrnCpy(p->structbuf,s?s:"",needed);
    }
    break;
  case 'z':			/* offset to zero terminated string (4 byte) */
    str = va_arg(args,char*);
    stringneeded = (str ? strlen(str)+1 : 0);
    is_string = 1;
    break;
  case 'l':			/* offset to user data (4 byte) */
    str = va_arg(args,char*);
    stringneeded = va_arg(args,int);
    is_string = 0;
    break;
  case 'b':			/* offset to data (with counter) (4 byte) */
    str = va_arg(args,char*);
    stringneeded = get_counter(&p->curpos);
    is_string = 0;
    break;
  }
  va_end(args);
  if (stringneeded >= 0) {
    needed = 4;
    if (p->buflen >= needed) {
      stringused = stringneeded;
      if (stringused > p->stringlen) {
	stringused = (is_string ? p->stringlen : 0);
	if (p->errcode == NERR_Success) p->errcode = ERROR_MORE_DATA;
      }
      if (!stringused)
	SIVAL(p->structbuf,0,0);
      else {
	SIVAL(p->structbuf,0,PTR_DIFF(p->stringbuf,p->base));
	memcpy(p->stringbuf,str?str:"",stringused);
	if (is_string) p->stringbuf[stringused-1] = '\0';
	p->stringbuf += stringused;
	p->stringlen -= stringused;
	p->usedlen += stringused;
      }
    }
    p->neededlen += stringneeded;
  }
  p->neededlen += needed;
  if (p->buflen >= needed) {
    p->structbuf += needed;
    p->buflen -= needed;
    p->usedlen += needed;
  }
  else {
    if (p->errcode == NERR_Success) p->errcode = NERR_BufTooSmall;
  }
  return 1;
}

#if CHECK_TYPES
#define PACK(desc,t,v) package(desc,t,v,0,0,0,0)
#define PACKl(desc,t,v,l) package(desc,t,v,l,0,0,0,0)
#else
#define PACK(desc,t,v) package(desc,v)
#define PACKl(desc,t,v,l) package(desc,v,l)
#endif

static void PACKI(struct pack_desc* desc,char *t,int v)
{
  PACK(desc,t,v);
}

static void PACKS(struct pack_desc* desc,char *t,char *v)
{
  PACK(desc,t,v);
}


/****************************************************************************
  get a print queue
  ****************************************************************************/

static void PackDriverData(struct pack_desc* desc)
{
  char drivdata[4+4+32];
  SIVAL(drivdata,0,sizeof drivdata); /* cb */
  SIVAL(drivdata,4,1000);	/* lVersion */
  memset(drivdata+8,0,32);	/* szDeviceName */
  strcpy(drivdata+8,"NULL");
  PACKl(desc,"l",drivdata,sizeof drivdata); /* pDriverData */
}

static int check_printq_info(struct pack_desc* desc,
 			     int uLevel, const char* id1, const char* id2)
{
  desc->subformat = NULL;
  switch( uLevel ) {
  case 0:
    desc->format = "B13";
    break;
  case 1:
    desc->format = "B13BWWWzzzzzWW";
    break;
  case 2:
    desc->format = "B13BWWWzzzzzWN";
    desc->subformat = "WB21BB16B10zWWzDDz";
    break;
  case 3:
    desc->format = "zWWWWzzzzWWzzl";
    break;
  case 4:
    desc->format = "zWWWWzzzzWNzzl";
    desc->subformat = "WWzWWDDzz";
    break;
  case 5:
    desc->format = "z";
    break;
  default: return False;
  }
  if (strcmp(desc->format,id1) != 0) return False;
  if (desc->subformat && strcmp(desc->subformat,id2) != 0) return False;
  return True;
}

static void fill_printjob_info(int cnum, int snum, int uLevel,
			       struct pack_desc* desc,
			       print_queue_struct* queue, int n)
{
  time_t t = queue->time;

  /* the client expects localtime */
  t -= TimeDiff(t);

  PACKI(desc,"W",((snum%0xFF)<<8) | (queue->job%0xFF)); /* uJobId */
  if (uLevel == 1) {
    PACKS(desc,"B21",queue->user); /* szUserName */
    PACKS(desc,"B","");		/* pad */
    PACKS(desc,"B16","");	/* szNotifyName */
    PACKS(desc,"B10","PM_Q_RAW"); /* szDataType */
    PACKS(desc,"z","");		/* pszParms */
    PACKI(desc,"W",n+1);		/* uPosition */
    PACKI(desc,"W",queue->status); /* fsStatus */
    PACKS(desc,"z","");		/* pszStatus */
    PACKI(desc,"D",t); /* ulSubmitted */
    PACKI(desc,"D",queue->size); /* ulSize */
    PACKS(desc,"z",queue->file); /* pszComment */
  }
  if (uLevel == 2 || uLevel == 3) {
    PACKI(desc,"W",queue->priority);		/* uPriority */
    PACKS(desc,"z",queue->user); /* pszUserName */
    PACKI(desc,"W",n+1);		/* uPosition */
    PACKI(desc,"W",queue->status); /* fsStatus */
    PACKI(desc,"D",t); /* ulSubmitted */
    PACKI(desc,"D",queue->size); /* ulSize */
    PACKS(desc,"z","Samba");	/* pszComment */
    PACKS(desc,"z",queue->file); /* pszDocument */
    if (uLevel == 3) {
      PACKS(desc,"z","");	/* pszNotifyName */
      PACKS(desc,"z","PM_Q_RAW"); /* pszDataType */
      PACKS(desc,"z","");	/* pszParms */
      PACKS(desc,"z","");	/* pszStatus */
      PACKS(desc,"z",SERVICE(snum)); /* pszQueue */
      PACKS(desc,"z","lpd");	/* pszQProcName */
      PACKS(desc,"z","");	/* pszQProcParms */
      PACKS(desc,"z","NULL"); /* pszDriverName */
      PackDriverData(desc);	/* pDriverData */
      PACKS(desc,"z","");	/* pszPrinterName */
    }
  }
}

static void fill_printq_info(int cnum, int snum, int uLevel,
 			     struct pack_desc* desc,
 			     int count, print_queue_struct* queue,
 			     print_status_struct* status)
{
  if (uLevel < 3) {
    PACKS(desc,"B13",SERVICE(snum));
  } else {
    PACKS(desc,"z",Expand(cnum,snum,SERVICE(snum)));
  }
  if (uLevel == 1 || uLevel == 2) {
    PACKS(desc,"B","");		/* alignment */
    PACKI(desc,"W",5);		/* priority */
    PACKI(desc,"W",0);		/* start time */
    PACKI(desc,"W",0);		/* until time */
    PACKS(desc,"z","");		/* pSepFile */
    PACKS(desc,"z","lpd");	/* pPrProc */
    PACKS(desc,"z",SERVICE(snum)); /* pDestinations */
    PACKS(desc,"z","");		/* pParms */
    if (snum < 0) {
      PACKS(desc,"z","UNKNOWN PRINTER");
      PACKI(desc,"W",LPSTAT_ERROR);
    }
    else if (!status || !status->message[0]) {
      PACKS(desc,"z",Expand(cnum,snum,lp_comment(snum)));
      PACKI(desc,"W",LPSTAT_OK); /* status */
    } else {
      PACKS(desc,"z",status->message);
      PACKI(desc,"W",status->status); /* status */
    }
    PACKI(desc,(uLevel == 1 ? "W" : "N"),count);
  }
  if (uLevel == 3 || uLevel == 4) {
    PACKI(desc,"W",5);		/* uPriority */
    PACKI(desc,"W",0);		/* uStarttime */
    PACKI(desc,"W",0);		/* uUntiltime */
    PACKI(desc,"W",5);		/* pad1 */
    PACKS(desc,"z","");		/* pszSepFile */
    PACKS(desc,"z","WinPrint");	/* pszPrProc */
    PACKS(desc,"z","");		/* pszParms */
    if (!status || !status->message[0]) {
      PACKS(desc,"z",Expand(cnum,snum,lp_comment(snum))); /* pszComment */
      PACKI(desc,"W",LPSTAT_OK); /* fsStatus */
    } else {
      PACKS(desc,"z",status->message); /* pszComment */
      PACKI(desc,"W",status->status); /* fsStatus */
    }
    PACKI(desc,(uLevel == 3 ? "W" : "N"),count);	/* cJobs */
    PACKS(desc,"z",SERVICE(snum)); /* pszPrinters */
    PACKS(desc,"z",lp_printerdriver(snum));		/* pszDriverName */
    PackDriverData(desc);	/* pDriverData */
  }
  if (uLevel == 2 || uLevel == 4) {
    int i;
    for (i=0;i<count;i++)
      fill_printjob_info(cnum,snum,uLevel == 2 ? 1 : 2,desc,&queue[i],i);
  }
 
  DEBUG(3,("fill_printq_info on <%s> gave %d entries\n",SERVICE(snum),count));
}

static BOOL api_DosPrintQGetInfo(int cnum,int uid, char *param,char *data,
				 int mdrcnt,int mprcnt,
				 char **rdata,char **rparam,
				 int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  char *QueueName = p;
  int uLevel,cbBuf;
  int count=0;
  int snum;
  char* str3;
  struct pack_desc desc;
  print_queue_struct *queue=NULL;
  print_status_struct status;
  
  bzero(&status,sizeof(status));
  bzero(&desc,sizeof(desc));
 
  p = skip_string(p,1);
  uLevel = SVAL(p,0);
  cbBuf = SVAL(p,2);
  str3 = p + 4;
 
  /* remove any trailing username */
  if ((p = strchr(QueueName,'%'))) *p = 0;
 
  DEBUG(3,("PrintQueue uLevel=%d name=%s\n",uLevel,QueueName));
 
  /* check it's a supported varient */
  if (!prefix_ok(str1,"zWrLh")) return False;
  if (!check_printq_info(&desc,uLevel,str2,str3)) return False;
 
  snum = lp_servicenumber(QueueName);
  if (snum < 0 && pcap_printername_ok(QueueName,NULL)) {
    int pnum = lp_servicenumber(PRINTERS_NAME);
    if (pnum >= 0) {
      lp_add_printer(QueueName,pnum);
      snum = lp_servicenumber(QueueName);
    }
  }
  
  if (snum < 0 || !VALID_SNUM(snum)) return(False);

  count = get_printqueue(snum,cnum,&queue,&status);
  if (mdrcnt > 0) *rdata = REALLOC(*rdata,mdrcnt);
  desc.base = *rdata;
  desc.buflen = mdrcnt;
  if (init_package(&desc,1,count)) {
    desc.subcount = count;
    fill_printq_info(cnum,snum,uLevel,&desc,count,queue,&status);
  }

  *rdata_len = desc.usedlen;
  
  *rparam_len = 6;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVALS(*rparam,0,desc.errcode);
  SSVAL(*rparam,2,0);
  SSVAL(*rparam,4,desc.neededlen);
  
  DEBUG(4,("printqgetinfo: errorcode %d\n",desc.errcode));

  if (queue) free(queue);
  
  return(True);
}


/****************************************************************************
  view list of all print jobs on all queues
  ****************************************************************************/
static BOOL api_DosPrintQEnum(int cnum, int uid, char* param, char* data,
 			      int mdrcnt, int mprcnt,
 			      char **rdata, char** rparam,
 			      int *rdata_len, int *rparam_len)
{
  char *param_format = param+2;
  char *output_format1 = skip_string(param_format,1);
  char *p = skip_string(output_format1,1);
  int uLevel = SVAL(p,0);
  char *output_format2 = p + 4;
  int services = lp_numservices();
  int i, n;
  struct pack_desc desc;
  print_queue_struct **queue = NULL;
  print_status_struct *status = NULL;
  int* subcntarr = NULL;
  int queuecnt, subcnt=0, succnt=0;
 
  bzero(&desc,sizeof(desc));

  DEBUG(3,("DosPrintQEnum uLevel=%d\n",uLevel));
 
  if (!prefix_ok(param_format,"WrLeh")) return False;
  if (!check_printq_info(&desc,uLevel,output_format1,output_format2))
    return False;
  queuecnt = 0;
  for (i = 0; i < services; i++)
    if (lp_snum_ok(i) && lp_print_ok(i) && lp_browseable(i))
      queuecnt++;
  if (uLevel > 0) {
    queue = (print_queue_struct**)malloc(queuecnt*sizeof(print_queue_struct*));
    memset(queue,0,queuecnt*sizeof(print_queue_struct*));
    status = (print_status_struct*)malloc(queuecnt*sizeof(print_status_struct));
    memset(status,0,queuecnt*sizeof(print_status_struct));
    subcntarr = (int*)malloc(queuecnt*sizeof(int));
    subcnt = 0;
    n = 0;
    for (i = 0; i < services; i++)
      if (lp_snum_ok(i) && lp_print_ok(i) && lp_browseable(i)) {
 	subcntarr[n] = get_printqueue(i,cnum,&queue[n],&status[n]);
 	subcnt += subcntarr[n];
 	n++;
      }
  }
  if (mdrcnt > 0) *rdata = REALLOC(*rdata,mdrcnt);
  desc.base = *rdata;
  desc.buflen = mdrcnt;

  if (init_package(&desc,queuecnt,subcnt)) {
    n = 0;
    succnt = 0;
    for (i = 0; i < services; i++)
      if (lp_snum_ok(i) && lp_print_ok(i) && lp_browseable(i)) {
	fill_printq_info(cnum,i,uLevel,&desc,subcntarr[n],queue[n],&status[n]);
	n++;
	if (desc.errcode == NERR_Success) succnt = n;
      }
  }

  if (subcntarr) free(subcntarr);
 
  *rdata_len = desc.usedlen;
  *rparam_len = 8;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVALS(*rparam,0,desc.errcode);
  SSVAL(*rparam,2,0);
  SSVAL(*rparam,4,succnt);
  SSVAL(*rparam,6,queuecnt);
  
  for (i = 0; i < queuecnt; i++) {
    if (queue && queue[i]) free(queue[i]);
  }

  if (queue) free(queue);
  if (status) free(status);
  
  return True;
}

/****************************************************************************
  get info level for a server list query
  ****************************************************************************/
static BOOL check_server_info(int uLevel, char* id)
{
  switch( uLevel ) {
  case 0:
    if (strcmp(id,"B16") != 0) return False;
    break;
  case 1:
    if (strcmp(id,"B16BBDz") != 0) return False;
    break;
  default: 
    return False;
  }
  return True;
}

struct srv_info_struct
{
  fstring name;
  uint32 type;
  fstring comment;
  fstring domain;
  BOOL server_added;
};


/*******************************************************************
  get server info lists from the files saved by nmbd. Return the
  number of entries
  ******************************************************************/
static int get_server_info(uint32 servertype, 
			   struct srv_info_struct **servers,
			   char *domain)
{
  FILE *f;
  pstring fname;
  int count=0;
  int alloced=0;
  pstring line;

  strcpy(fname,lp_lockdir());
  trim_string(fname,NULL,"/");
  strcat(fname,"/");
  strcat(fname,SERVER_LIST);

  f = fopen(fname,"r");

  if (!f) {
    DEBUG(4,("Can't open %s - %s\n",fname,strerror(errno)));
    return(0);
  }

  /* request for everything is code for request all servers */
  if (servertype == SV_TYPE_ALL) servertype &= ~SV_TYPE_DOMAIN_ENUM;

  DEBUG(4,("Servertype search: %8x\n",servertype));

  while (!feof(f))
  {
    fstring stype;
    struct srv_info_struct *s;
    char *ptr = line;
    BOOL ok = True;
    *ptr = 0;

    fgets(line,sizeof(line)-1,f);
    if (!*line) continue;
    
    if (count == alloced) {
      alloced += 10;
      (*servers) = (struct srv_info_struct *)
	Realloc(*servers,sizeof(**servers)*alloced);
      if (!(*servers)) return(0);
      bzero((char *)((*servers)+count),sizeof(**servers)*(alloced-count));
    }
    s = &(*servers)[count];
    
    if (!next_token(&ptr,s->name   , NULL)) continue;
    if (!next_token(&ptr,stype     , NULL)) continue;
    if (!next_token(&ptr,s->comment, NULL)) continue;
    if (!next_token(&ptr,s->domain , NULL)) {
      /* this allows us to cope with an old nmbd */
      strcpy(s->domain,lp_workgroup()); 
    }
    
    if (sscanf(stype,"%X",&s->type) != 1) { 
      DEBUG(4,("r:host file ")); 
      ok = False; 
    }
    
    /* doesn't match up: don't want it */
    if (!(servertype & s->type)) { 
      DEBUG(4,("r:serv type ")); 
      ok = False; 
    }
    
    if ((servertype & SV_TYPE_DOMAIN_ENUM) != 
	(s->type & SV_TYPE_DOMAIN_ENUM))
      {
	DEBUG(4,("s: dom mismatch "));
	ok = False;
      }
    
    if (!strequal(domain, s->domain) && !(servertype & SV_TYPE_DOMAIN_ENUM))
      {
	ok = False;
      }
    
    if (ok)
      {
    	DEBUG(4,("**SV** %20s %8x %25s %15s\n",
		 s->name, s->type, s->comment, s->domain));
	
    	s->server_added = True;
    	count++;
      }
    else
      {
	DEBUG(4,("%20s %8x %25s %15s\n",
		 s->name, s->type, s->comment, s->domain));
      }
  }
  
  fclose(f);
  return(count);
}


/*******************************************************************
  fill in a server info structure
  ******************************************************************/
static int fill_srv_info(struct srv_info_struct *service, 
			 int uLevel, char **buf, int *buflen, 
			 char **stringbuf, int *stringspace, char *baseaddr)
{
  int struct_len;
  char* p;
  char* p2;
  int l2;
  int len;
 
  switch (uLevel) {
  case 0: struct_len = 16; break;
  case 1: struct_len = 26; break;
  default: return -1;
  }  
 
  if (!buf)
    {
      len = 0;
      switch (uLevel) 
	{
	case 1:
	  len = strlen(service->comment)+1;
	  break;
	}

      if (buflen) *buflen = struct_len;
      if (stringspace) *stringspace = len;
      return struct_len + len;
    }
  
  len = struct_len;
  p = *buf;
  if (*buflen < struct_len) return -1;
  if (stringbuf)
    {
      p2 = *stringbuf;
      l2 = *stringspace;
    }
  else
    {
      p2 = p + struct_len;
      l2 = *buflen - struct_len;
    }
  if (!baseaddr) baseaddr = p;
  
  switch (uLevel)
    {
    case 0:
      StrnCpy(p,service->name,15);
      break;

    case 1:
      StrnCpy(p,service->name,15);
      SIVAL(p,18,service->type);
      SIVAL(p,22,PTR_DIFF(p2,baseaddr));
      len += CopyAndAdvance(&p2,service->comment,&l2);
      break;
    }

  if (stringbuf)
    {
      *buf = p + struct_len;
      *buflen -= struct_len;
      *stringbuf = p2;
      *stringspace = l2;
    }
  else
    {
      *buf = p2;
      *buflen -= len;
    }
  return len;
}


static BOOL srv_comp(struct srv_info_struct *s1,struct srv_info_struct *s2)
{
  return(strcmp(s1->name,s2->name));
}

/****************************************************************************
  view list of servers available (or possibly domains). The info is
  extracted from lists saved by nmbd on the local host
  ****************************************************************************/
static BOOL api_RNetServerEnum(int cnum, int uid, char *param, char *data,
			       int mdrcnt, int mprcnt, char **rdata, 
			       char **rparam, int *rdata_len, int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  int uLevel = SVAL(p,0);
  int buf_len = SVAL(p,2);
  uint32 servertype = IVAL(p,4);
  char *p2;
  int data_len, fixed_len, string_len;
  int f_len, s_len;
  struct srv_info_struct *servers=NULL;
  int counted=0,total=0;
  int i,missed;
  fstring domain;
  BOOL domain_request;
  BOOL local_request = servertype & SV_TYPE_LOCAL_LIST_ONLY;

  if (servertype == SV_TYPE_ALL) servertype &= ~SV_TYPE_DOMAIN_ENUM;

  domain_request = ((servertype & SV_TYPE_DOMAIN_ENUM) != 0);

  p += 8;

  if (!prefix_ok(str1,"WrLehD")) return False;
  if (!check_server_info(uLevel,str2)) return False;
  
  DEBUG(4, ("server request level: %s %8x ", str2, servertype));
  DEBUG(4, ("domains_req:%s ", BOOLSTR(domain_request)));
  DEBUG(4, ("local_only:%s\n", BOOLSTR(local_request)));

  if (strcmp(str1, "WrLehDz") == 0) {
    StrnCpy(domain, p, sizeof(fstring)-1);
  } else {
    StrnCpy(domain, lp_workgroup(), sizeof(fstring)-1);    
  }

  if (lp_browse_list())
    total = get_server_info(servertype,&servers,domain);

  data_len = fixed_len = string_len = 0;
  missed = 0;

  qsort(servers,total,sizeof(servers[0]),QSORT_CAST srv_comp);

  {
    char *lastname=NULL;

    for (i=0;i<total;i++)
    {
      struct srv_info_struct *s = &servers[i];
      if (lastname && strequal(lastname,s->name)) continue;
      lastname = s->name;
      data_len += fill_srv_info(s,uLevel,0,&f_len,0,&s_len,0);
      DEBUG(4,("fill_srv_info %20s %8x %25s %15s\n",
	       s->name, s->type, s->comment, s->domain));
      
      if (data_len <= buf_len) {
	  counted++;
	  fixed_len += f_len;
	  string_len += s_len;
      } else {
	missed++;
      }
    }
  }

  *rdata_len = fixed_len + string_len;
  *rdata = REALLOC(*rdata,*rdata_len);
  bzero(*rdata,*rdata_len);
  
  p2 = (*rdata) + fixed_len;	/* auxilliary data (strings) will go here */
  p = *rdata;
  f_len = fixed_len;
  s_len = string_len;

  {
    char *lastname=NULL;
    int count2 = counted;
    for (i = 0; i < total && count2;i++)
      {
	struct srv_info_struct *s = &servers[i];
	if (lastname && strequal(lastname,s->name)) continue;
	lastname = s->name;
	fill_srv_info(s,uLevel,&p,&f_len,&p2,&s_len,*rdata);
	DEBUG(4,("fill_srv_info %20s %8x %25s %15s\n",
		 s->name, s->type, s->comment, s->domain));
	count2--;
      }
  }
  
  *rparam_len = 8;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVAL(*rparam,0,NERR_Success);
  SSVAL(*rparam,2,0);
  SSVAL(*rparam,4,counted);
  SSVAL(*rparam,6,counted+missed);

  if (servers) free(servers);

  DEBUG(3,("NetServerEnum domain = %s uLevel=%d counted=%d total=%d\n",
	   domain,uLevel,counted,counted+missed));

  return(True);
}


/****************************************************************************
  get info about a share
  ****************************************************************************/
static BOOL check_share_info(int uLevel, char* id)
{
  switch( uLevel ) {
  case 0:
    if (strcmp(id,"B13") != 0) return False;
    break;
  case 1:
    if (strcmp(id,"B13BWz") != 0) return False;
    break;
  case 2:
    if (strcmp(id,"B13BWzWWWzB9B") != 0) return False;
    break;
  case 91:
    if (strcmp(id,"B13BWzWWWzB9BB9BWzWWzWW") != 0) return False;
    break;
  default: return False;
  }
  return True;
}

static int fill_share_info(int cnum, int snum, int uLevel,
 			   char** buf, int* buflen,
 			   char** stringbuf, int* stringspace, char* baseaddr)
{
  int struct_len;
  char* p;
  char* p2;
  int l2;
  int len;
 
  switch( uLevel ) {
  case 0: struct_len = 13; break;
  case 1: struct_len = 20; break;
  case 2: struct_len = 40; break;
  case 91: struct_len = 68; break;
  default: return -1;
  }
  
 
  if (!buf)
    {
      len = 0;
      if (uLevel > 0) len += StrlenExpanded(cnum,snum,lp_comment(snum));
      if (uLevel > 1) len += strlen(lp_pathname(snum)) + 1;
      if (buflen) *buflen = struct_len;
      if (stringspace) *stringspace = len;
      return struct_len + len;
    }
  
  len = struct_len;
  p = *buf;
  if ((*buflen) < struct_len) return -1;
  if (stringbuf)
    {
      p2 = *stringbuf;
      l2 = *stringspace;
    }
  else
    {
      p2 = p + struct_len;
      l2 = (*buflen) - struct_len;
    }
  if (!baseaddr) baseaddr = p;
  
  StrnCpy(p,lp_servicename(snum),13);
  
  if (uLevel > 0)
    {
      int type;
      CVAL(p,13) = 0;
      type = STYPE_DISKTREE;
      if (lp_print_ok(snum)) type = STYPE_PRINTQ;
      if (strequal("IPC$",lp_servicename(snum))) type = STYPE_IPC;
      SSVAL(p,14,type);		/* device type */
      SIVAL(p,16,PTR_DIFF(p2,baseaddr));
      len += CopyExpanded(cnum,snum,&p2,lp_comment(snum),&l2);
    }
  
  if (uLevel > 1)
    {
      SSVAL(p,20,ACCESS_READ|ACCESS_WRITE|ACCESS_CREATE); /* permissions */
      SSVALS(p,22,-1);		/* max uses */
      SSVAL(p,24,1); /* current uses */
      SIVAL(p,26,PTR_DIFF(p2,baseaddr)); /* local pathname */
      len += CopyAndAdvance(&p2,lp_pathname(snum),&l2);
      memset(p+30,0,SHPWLEN+2); /* passwd (reserved), pad field */
    }
  
  if (uLevel > 2)
    {
      memset(p+40,0,SHPWLEN+2);
      SSVAL(p,50,0);
      SIVAL(p,52,0);
      SSVAL(p,56,0);
      SSVAL(p,58,0);
      SIVAL(p,60,0);
      SSVAL(p,64,0);
      SSVAL(p,66,0);
    }
       
  if (stringbuf)
    {
      (*buf) = p + struct_len;
      (*buflen) -= struct_len;
      (*stringbuf) = p2;
      (*stringspace) = l2;
    }
  else
    {
      (*buf) = p2;
      (*buflen) -= len;
    }
  return len;
}

static BOOL api_RNetShareGetInfo(int cnum,int uid, char *param,char *data,
				 int mdrcnt,int mprcnt,
				 char **rdata,char **rparam,
				 int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *netname = skip_string(str2,1);
  char *p = skip_string(netname,1);
  int uLevel = SVAL(p,0);
  int snum = find_service(netname);
  
  if (snum < 0) return False;
  
  /* check it's a supported varient */
  if (!prefix_ok(str1,"zWrLh")) return False;
  if (!check_share_info(uLevel,str2)) return False;
 
  *rdata = REALLOC(*rdata,mdrcnt);
  p = *rdata;
  *rdata_len = fill_share_info(cnum,snum,uLevel,&p,&mdrcnt,0,0,0);
  if (*rdata_len < 0) return False;
 
  *rparam_len = 6;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVAL(*rparam,0,NERR_Success);
  SSVAL(*rparam,2,0);		/* converter word */
  SSVAL(*rparam,4,*rdata_len);
 
  return(True);
}

/****************************************************************************
  view list of shares available
  ****************************************************************************/
static BOOL api_RNetShareEnum(int cnum,int uid, char *param,char *data,
  			      int mdrcnt,int mprcnt,
  			      char **rdata,char **rparam,
  			      int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  int uLevel = SVAL(p,0);
  int buf_len = SVAL(p,2);
  char *p2;
  int count=lp_numservices();
  int total=0,counted=0;
  int i;
  int data_len, fixed_len, string_len;
  int f_len, s_len;
 
  if (!prefix_ok(str1,"WrLeh")) return False;
  if (!check_share_info(uLevel,str2)) return False;
  
  data_len = fixed_len = string_len = 0;
  for (i=0;i<count;i++)
    if (lp_browseable(i) && lp_snum_ok(i))
      {
  	total++;
 	data_len += fill_share_info(cnum,i,uLevel,0,&f_len,0,&s_len,0);
 	if (data_len <= buf_len)
 	  {
 	    counted++;
 	    fixed_len += f_len;
 	    string_len += s_len;
 	  }
      }
  *rdata_len = fixed_len + string_len;
  *rdata = REALLOC(*rdata,*rdata_len);
  memset(*rdata,0,*rdata_len);
  
  p2 = (*rdata) + fixed_len;	/* auxillery data (strings) will go here */
  p = *rdata;
  f_len = fixed_len;
  s_len = string_len;
  for (i = 0; i < count;i++)
    if (lp_browseable(i) && lp_snum_ok(i))
      if (fill_share_info(cnum,i,uLevel,&p,&f_len,&p2,&s_len,*rdata) < 0)
 	break;
  
  *rparam_len = 8;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVAL(*rparam,0,NERR_Success);
  SSVAL(*rparam,2,0);
  SSVAL(*rparam,4,counted);
  SSVAL(*rparam,6,total);
  
  DEBUG(3,("RNetShareEnum gave %d entries of %d (%d %d %d %d)\n",
 	   counted,total,uLevel,
  	   buf_len,*rdata_len,mdrcnt));
  return(True);
}



/****************************************************************************
  get the time of day info
  ****************************************************************************/
static BOOL api_NetRemoteTOD(int cnum,int uid, char *param,char *data,
			     int mdrcnt,int mprcnt,
			     char **rdata,char **rparam,
			     int *rdata_len,int *rparam_len)
{
  char *p;
  *rparam_len = 4;
  *rparam = REALLOC(*rparam,*rparam_len);

  *rdata_len = 21;
  *rdata = REALLOC(*rdata,*rdata_len);

  SSVAL(*rparam,0,NERR_Success);
  SSVAL(*rparam,2,0);		/* converter word */

  p = *rdata;

  {
    struct tm *t;
    time_t unixdate = time(NULL);

    put_dos_date3(p,0,unixdate); /* this is the time that is looked at
				    by NT in a "net time" operation,
				    it seems to ignore the one below */

    /* the client expects to get localtime, not GMT, in this bit 
       (I think, this needs testing) */
    t = LocalTime(&unixdate);

    SIVAL(p,4,0);		/* msecs ? */
    CVAL(p,8) = t->tm_hour;
    CVAL(p,9) = t->tm_min;
    CVAL(p,10) = t->tm_sec;
    CVAL(p,11) = 0;		/* hundredths of seconds */
    SSVALS(p,12,TimeDiff(unixdate)/60); /* timezone in minutes from GMT */
    SSVAL(p,14,10000);		/* timer interval in 0.0001 of sec */
    CVAL(p,16) = t->tm_mday;
    CVAL(p,17) = t->tm_mon + 1;
    SSVAL(p,18,1900+t->tm_year);
    CVAL(p,20) = t->tm_wday;
  }


  return(True);
}

/****************************************************************************
  set the user password
  ****************************************************************************/
static BOOL api_SetUserPassword(int cnum,int uid, char *param,char *data,
				int mdrcnt,int mprcnt,
				char **rdata,char **rparam,
				int *rdata_len,int *rparam_len)
{
  char *p = skip_string(param+2,2);
  fstring user;
  fstring pass1,pass2;

  strcpy(user,p);

  p = skip_string(p,1);

  StrnCpy(pass1,p,16);
  StrnCpy(pass2,p+16,16);

  *rparam_len = 4;
  *rparam = REALLOC(*rparam,*rparam_len);

  *rdata_len = 0;

  SSVAL(*rparam,0,NERR_badpass);
  SSVAL(*rparam,2,0);		/* converter word */

  DEBUG(3,("Set password for <%s>\n",user));

  if (password_ok(user,pass1,strlen(pass1),NULL,False) &&
      chgpasswd(user,pass1,pass2))
  {
    SSVAL(*rparam,0,NERR_Success);
  }

  bzero(pass1,sizeof(fstring));
  bzero(pass2,sizeof(fstring));	 
	 
  return(True);
}

/****************************************************************************
  delete a print job
  Form: <W> <> 
  ****************************************************************************/
static BOOL api_RDosPrintJobDel(int cnum,int uid, char *param,char *data,
				int mdrcnt,int mprcnt,
				char **rdata,char **rparam,
				int *rdata_len,int *rparam_len)
{
  int function = SVAL(param,0);
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  int jobid = (SVAL(p,0)&0xFF); /* the snum and jobid are encoded
				   by the print queue api */
  int snum = (SVAL(p,0)>>8);  
  int i, count;


  /* check it's a supported varient */
  if (!(strcsequal(str1,"W") && strcsequal(str2,"")))
    return(False);

  *rparam_len = 4;
  *rparam = REALLOC(*rparam,*rparam_len);

  *rdata_len = 0;

  SSVAL(*rparam,0,NERR_Success);

  if (snum >= 0 && VALID_SNUM(snum))
    {
      print_queue_struct *queue=NULL;
      lpq_reset(snum);
      count = get_printqueue(snum,cnum,&queue,NULL);
  
      for (i=0;i<count;i++)
  	if ((queue[i].job%0xFF) == jobid)
  	  {
 	    switch (function) {
	    case 81:		/* delete */ 
	      DEBUG(3,("Deleting queue entry %d\n",queue[i].job));
	      del_printqueue(cnum,snum,queue[i].job);
	      break;
	    case 82:		/* pause */
	    case 83:		/* resume */
	      DEBUG(3,("%s queue entry %d\n",
		       (function==82?"pausing":"resuming"),queue[i].job));
	      status_printjob(cnum,snum,queue[i].job,
			      (function==82?LPQ_PAUSED:LPQ_QUEUED));
	      break;
 	    }
 	    break;
  	  }
  
      if (i==count)
	SSVAL(*rparam,0,NERR_JobNotFound);

      if (queue) free(queue);
    }

  SSVAL(*rparam,2,0);		/* converter word */

  return(True);
}

static BOOL api_WPrintQueuePurge(int cnum,int uid, char *param,char *data,
				 int mdrcnt,int mprcnt,
				 char **rdata,char **rparam,
				 int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *QueueName = skip_string(str2,1);
  int snum;

  /* check it's a supported varient */
  if (!(strcsequal(str1,"z") && strcsequal(str2,"")))
    return(False);

  *rparam_len = 4;
  *rparam = REALLOC(*rparam,*rparam_len);

  *rdata_len = 0;

  SSVAL(*rparam,0,NERR_Success);
  SSVAL(*rparam,2,0);		/* converter word */

  snum = lp_servicenumber(QueueName);
  if (snum < 0 && pcap_printername_ok(QueueName,NULL)) {
    int pnum = lp_servicenumber(PRINTERS_NAME);
    if (pnum >= 0) {
      lp_add_printer(QueueName,pnum);
      snum = lp_servicenumber(QueueName);
    }
  }

  if (snum >= 0 && VALID_SNUM(snum)) {
    print_queue_struct *queue=NULL;
    int i, count;
    lpq_reset(snum);
    
    count = get_printqueue(snum,cnum,&queue,NULL);
    for (i = 0; i < count; i++)
      del_printqueue(cnum,snum,queue[i].job);
    
    if (queue) free(queue);
  }

  DEBUG(3,("Print queue purge, queue=%s\n",QueueName));

  return(True);
}


/****************************************************************************
  set the property of a print job (undocumented?)
  ? function = 0xb -> set name of print job
  ? function = 0x6 -> move print job up/down
  Form: <WWsTP> <WWzWWDDzzzzzzzzzzlz> 
  or   <WWsTP> <WB21BB16B10zWWzDDz> 
****************************************************************************/
static int check_printjob_info(struct pack_desc* desc,
			       int uLevel, char* id)
{
  desc->subformat = NULL;
  switch( uLevel ) {
  case 0: desc->format = "W"; break;
  case 1: desc->format = "WB21BB16B10zWWzDDz"; break;
  case 2: desc->format = "WWzWWDDzz"; break;
  case 3: desc->format = "WWzWWDDzzzzzzzzzzlz"; break;
  default: return False;
  }
  if (strcmp(desc->format,id) != 0) return False;
  return True;
}

static BOOL api_PrintJobInfo(int cnum,int uid,char *param,char *data,
  			     int mdrcnt,int mprcnt,
  			     char **rdata,char **rparam,
  			     int *rdata_len,int *rparam_len)
{
  struct pack_desc desc;
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  int jobid = (SVAL(p,0)&0xFF); /* the snum and jobid are encoded
 				   by the print queue api */
  int snum = (SVAL(p,0)>>8);
  int uLevel = SVAL(p,2);
  int function = SVAL(p,4);	/* what is this ?? */
  int i;
  char *s = data;
   
  *rparam_len = 4;
  *rparam = REALLOC(*rparam,*rparam_len);
  
  *rdata_len = 0;
  
  /* check it's a supported varient */
  if ((strcmp(str1,"WWsTP")) || (!check_printjob_info(&desc,uLevel,str2)))
    return(False);
   
  switch (function) {
  case 0x6:	/* change job place in the queue, data gives the new place */
    if (snum >= 0 && VALID_SNUM(snum))
      {
	print_queue_struct *queue=NULL;
	int count;
  
	lpq_reset(snum);
	count = get_printqueue(snum,cnum,&queue,NULL);
	for (i=0;i<count;i++)	/* find job */
	  if ((queue[i].job%0xFF) == jobid) break;
 	    
	if (i==count) {
	  desc.errcode=NERR_JobNotFound;
	  if (queue) free(queue);
	}
	else {
	  desc.errcode=NERR_Success;
	  i++;
#if 0	
	  {
	    int place= SVAL(data,0);
	    /* we currently have no way of doing this. Can any unix do it? */
	    if (i < place)	/* move down */;
	    else if (i > place )	/* move up */;
	  }
#endif
	  desc.errcode=NERR_notsupported; /* not yet supported */
	  if (queue) free(queue);
	}
      }
    else desc.errcode=NERR_JobNotFound;
    break;
  case 0xb:   /* change print job name, data gives the name */
    /* jobid, snum should be zero */
    if (isalpha(*s))
      {
	pstring name;
	int l = 0;
	while (l<64 && *s)
	  {
	    if (issafe(*s)) name[l++] = *s;
	    s++;
	  }      
	name[l] = 0;
	
	DEBUG(3,("Setting print name to %s\n",name));
	
	for (i=0;i<MAX_OPEN_FILES;i++)
	  if (Files[i].open && Files[i].print_file)
	    {
	      pstring wd;
	      GetWd(wd);
	      unbecome_user();
	      
	      if (!become_user(Files[i].cnum,uid) || 
		  !become_service(Files[i].cnum,True))
		break;
	      
	      if (sys_rename(Files[i].name,name) == 0)
		string_set(&Files[i].name,name);
	      break;
	    }
      }
    desc.errcode=NERR_Success;
  
    break;
  default:			/* not implemented */
    return False;
  }
 
  SSVALS(*rparam,0,desc.errcode);
  SSVAL(*rparam,2,0);		/* converter word */
  
  return(True);
}


/****************************************************************************
  get info about the server
  ****************************************************************************/
static BOOL api_RNetServerGetInfo(int cnum,int uid, char *param,char *data,
				  int mdrcnt,int mprcnt,
				  char **rdata,char **rparam,
				  int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  int uLevel = SVAL(p,0);
  char *p2;
  int struct_len;

  DEBUG(4,("NetServerGetInfo level %d\n",uLevel));

  /* check it's a supported varient */
  if (!prefix_ok(str1,"WrLh")) return False;
  switch( uLevel ) {
  case 0:
    if (strcmp(str2,"B16") != 0) return False;
    struct_len = 16;
    break;
  case 1:
    if (strcmp(str2,"B16BBDz") != 0) return False;
    struct_len = 26;
    break;
  case 2:
    if (strcmp(str2,"B16BBDzDDDWWzWWWWWWWBB21zWWWWWWWWWWWWWWWWWWWWWWz")
	!= 0) return False;
    struct_len = 134;
    break;
  case 3:
    if (strcmp(str2,"B16BBDzDDDWWzWWWWWWWBB21zWWWWWWWWWWWWWWWWWWWWWWzDWz")
	!= 0) return False;
    struct_len = 144;
    break;
  case 20:
    if (strcmp(str2,"DN") != 0) return False;
    struct_len = 6;
    break;
  case 50:
    if (strcmp(str2,"B16BBDzWWzzz") != 0) return False;
    struct_len = 42;
    break;
  default: return False;
  }

  *rdata_len = mdrcnt;
  *rdata = REALLOC(*rdata,*rdata_len);

  p = *rdata;
  p2 = p + struct_len;
  if (uLevel != 20) {
    StrnCpy(p,local_machine,16);
    strupper(p);
  }
  p += 16;
  if (uLevel > 0)
    {
      struct srv_info_struct *servers=NULL;
      int i,count;
      pstring comment;
      uint32 servertype=DFLT_SERVER_TYPE;

      strcpy(comment,lp_serverstring());

      if ((count=get_server_info(SV_TYPE_ALL,&servers,lp_workgroup()))>0) {
	for (i=0;i<count;i++)
	  if (strequal(servers[i].name,local_machine)) {
	    servertype = servers[i].type;
	    strcpy(comment,servers[i].comment);	    
	  }
      }
      if (servers) free(servers);

      SCVAL(p,0,MAJOR_VERSION);
      SCVAL(p,1,MINOR_VERSION);
      SIVAL(p,2,servertype);

      if (mdrcnt == struct_len) {
	SIVAL(p,6,0);
      } else {
	SIVAL(p,6,PTR_DIFF(p2,*rdata));
	standard_sub(cnum,comment);
	StrnCpy(p2,comment,MAX(mdrcnt - struct_len,0));
	p2 = skip_string(p2,1);
      }
    }
  if (uLevel > 1)
    {
      return False;		/* not yet implemented */
    }

  *rdata_len = PTR_DIFF(p2,*rdata);

  *rparam_len = 6;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVAL(*rparam,0,NERR_Success);
  SSVAL(*rparam,2,0);		/* converter word */
  SSVAL(*rparam,4,*rdata_len);

  return(True);
}


/****************************************************************************
  get info about the server
  ****************************************************************************/
static BOOL api_NetWkstaGetInfo(int cnum,int uid, char *param,char *data,
				int mdrcnt,int mprcnt,
				char **rdata,char **rparam,
				int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  char *p2;
  extern pstring sesssetup_user;
  int level = SVAL(p,0);

  DEBUG(4,("NetWkstaGetInfo level %d\n",level));

  *rparam_len = 6;
  *rparam = REALLOC(*rparam,*rparam_len);

  /* check it's a supported varient */
  if (!(level==10 && strcsequal(str1,"WrLh") && strcsequal(str2,"zzzBBzz")))
    return(False);

  *rdata_len = mdrcnt + 1024;
  *rdata = REALLOC(*rdata,*rdata_len);

  SSVAL(*rparam,0,NERR_Success);
  SSVAL(*rparam,2,0);		/* converter word */

  p = *rdata;
  p2 = p + 22;

  SIVAL(p,0,PTR_DIFF(p2,*rdata));
  strcpy(p2,local_machine);
  p2 = skip_string(p2,1);
  p += 4;

  SIVAL(p,0,PTR_DIFF(p2,*rdata));
  strcpy(p2,sesssetup_user);
  p2 = skip_string(p2,1);
  p += 4;

  SIVAL(p,0,PTR_DIFF(p2,*rdata));
  strcpy(p2,lp_workgroup());
  p2 = skip_string(p2,1);
  p += 4;

  SCVAL(p,0,MAJOR_VERSION); 
  SCVAL(p,1,MINOR_VERSION); 
  p += 2;

  SIVAL(p,0,PTR_DIFF(p2,*rdata));
  strcpy(p2,lp_workgroup());	/* login domain?? */
  p2 = skip_string(p2,1);
  p += 4;

  SIVAL(p,0,PTR_DIFF(p2,*rdata));
  strcpy(p2,"");
  p2 = skip_string(p2,1);
  p += 4;

  *rdata_len = PTR_DIFF(p2,*rdata);

  SSVAL(*rparam,4,*rdata_len);

  return(True);
}


/****************************************************************************
  get info about a user
  ****************************************************************************/

#define USER_PRIV_GUEST 0
#define USER_PRIV_USER 1
#define USER_PRIV_ADMIN 2

static BOOL api_RNetUserGetInfo(int cnum,int uid, char *param,char *data,
				int mdrcnt,int mprcnt,
				char **rdata,char **rparam,
				int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *UserName = skip_string(str2,1);
  char *p = skip_string(UserName,1);
  int uLevel = SVAL(p,0);
  char *p2;

  *rparam_len = 6;
  *rparam = REALLOC(*rparam,*rparam_len);

  /* check it's a supported varient */
  if (strcmp(str1,"zWrLh") != 0) return False;
  switch( uLevel ) {
  case 0: p2 = "B21"; break;
  case 1: p2 = "B21BB16DWzzWz"; break;
  case 2: p2 = "B21BB16DWzzWzDzzzzDDDDWb21WWzWW"; break;
  case 10: p2 = "B21Bzzz"; break;
  case 11: p2 = "B21BzzzWDDzzDDWWzWzDWb21W"; break;
  default: return False;
  }
  if (strcmp(p2,str2) != 0) return False;

  *rdata_len = mdrcnt + 1024;
  *rdata = REALLOC(*rdata,*rdata_len);

  SSVAL(*rparam,0,NERR_Success);
  SSVAL(*rparam,2,0);		/* converter word */

  p = *rdata;
  p2 = p + 86;

  memset(p,0,21);
  strcpy(p,UserName);
  if (uLevel > 0) {
    SCVAL(p,21,0);
    *p2 = 0;
    if (uLevel >= 10) {
      SIVAL(p,22,PTR_DIFF(p2,p)); /* comment */
      strcpy(p2,"<Comment>");
      p2 = skip_string(p2,1);
      SIVAL(p,26,PTR_DIFF(p2,p)); /* user_comment */
      strcpy(p2,"<UserComment>");
      p2 = skip_string(p2,1);
      SIVAL(p,30,PTR_DIFF(p2,p)); /* full name */
      strcpy(p2,"<FullName>");
      p2 = skip_string(p2,1);
    }
    if (uLevel == 11) {         /* modelled after NTAS 3.51 reply */
      SSVAL(p,34,
	    Connections[cnum].admin_user?USER_PRIV_ADMIN:USER_PRIV_USER); 
      SIVAL(p,36,0);		/* auth flags */
      SIVALS(p,40,-1);		/* password age */
      SIVAL(p,44,PTR_DIFF(p2,p)); /* home dir */
      strcpy(p2,"\\\\%L\\HOMES");
      standard_sub_basic(p2);
      p2 = skip_string(p2,1);
      SIVAL(p,48,PTR_DIFF(p2,p)); /* parms */
      strcpy(p2,"");
      p2 = skip_string(p2,1);
      SIVAL(p,52,0);		/* last logon */
      SIVAL(p,56,0);		/* last logoff */
      SSVALS(p,60,-1);		/* bad pw counts */
      SSVALS(p,62,-1);		/* num logons */
      SIVAL(p,64,PTR_DIFF(p2,p)); /* logon server */
      strcpy(p2,"\\\\*");
      p2 = skip_string(p2,1);
      SSVAL(p,68,0);		/* country code */

      SIVAL(p,70,PTR_DIFF(p2,p)); /* workstations */
      strcpy(p2,"");
      p2 = skip_string(p2,1);

      SIVALS(p,74,-1);		/* max storage */
      SSVAL(p,78,168);		/* units per week */
      SIVAL(p,80,PTR_DIFF(p2,p)); /* logon hours */
      memset(p2,-1,21);
      SCVAL(p2,21,0);           /* fix zero termination */
      p2 = skip_string(p2,1);

      SSVAL(p,84,0);		/* code page */
    }
    if (uLevel == 1 || uLevel == 2) {
      memset(p+22,' ',16);	/* password */
      SIVALS(p,38,-1);		/* password age */
      SSVAL(p,42,
	    Connections[cnum].admin_user?USER_PRIV_ADMIN:USER_PRIV_USER);
      SIVAL(p,44,PTR_DIFF(p2,*rdata)); /* home dir */
      strcpy(p2,"\\\\%L\\HOMES");
      standard_sub_basic(p2);
      p2 = skip_string(p2,1);
      SIVAL(p,48,PTR_DIFF(p2,*rdata)); /* comment */
      *p2++ = 0;
      SSVAL(p,52,0);		/* flags */
      SIVAL(p,54,0);		/* script_path */
      if (uLevel == 2) {
	SIVAL(p,60,0);		/* auth_flags */
	SIVAL(p,64,PTR_DIFF(p2,*rdata)); /* full_name */
	strcpy(p2,"<Full Name>");
	p2 = skip_string(p2,1);
	SIVAL(p,68,0);		/* urs_comment */
	SIVAL(p,72,PTR_DIFF(p2,*rdata)); /* parms */
	strcpy(p2,"");
	p2 = skip_string(p2,1);
	SIVAL(p,76,0);		/* workstations */
	SIVAL(p,80,0);		/* last_logon */
	SIVAL(p,84,0);		/* last_logoff */
	SIVALS(p,88,-1);		/* acct_expires */
	SIVALS(p,92,-1);		/* max_storage */
	SSVAL(p,96,168);	/* units_per_week */
	SIVAL(p,98,PTR_DIFF(p2,*rdata)); /* logon_hours */
	memset(p2,-1,21);
	p2 += 21;
	SSVALS(p,102,-1);	/* bad_pw_count */
	SSVALS(p,104,-1);	/* num_logons */
	SIVAL(p,106,PTR_DIFF(p2,*rdata)); /* logon_server */
	strcpy(p2,"\\\\%L");
	standard_sub_basic(p2);
	p2 = skip_string(p2,1);
	SSVAL(p,110,49);	/* country_code */
	SSVAL(p,112,860);	/* code page */
      }
    }
  }

  *rdata_len = PTR_DIFF(p2,*rdata);

  SSVAL(*rparam,4,*rdata_len);	/* is this right?? */

  return(True);
}


/*******************************************************************
  get groups that a user is a member of
  ******************************************************************/
static BOOL api_NetUserGetGroups(int cnum,int uid, char *param,char *data,
				 int mdrcnt,int mprcnt,
				 char **rdata,char **rparam,
				 int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *UserName = skip_string(str2,1);
  char *p = skip_string(UserName,1);
  int uLevel = SVAL(p,0);
  char *p2;
  int count=0;

  *rparam_len = 8;
  *rparam = REALLOC(*rparam,*rparam_len);

  /* check it's a supported varient */
  if (strcmp(str1,"zWrLeh") != 0) return False;
  switch( uLevel ) {
  case 0: p2 = "B21"; break;
  default: return False;
  }
  if (strcmp(p2,str2) != 0) return False;

  *rdata_len = mdrcnt + 1024;
  *rdata = REALLOC(*rdata,*rdata_len);

  SSVAL(*rparam,0,NERR_Success);
  SSVAL(*rparam,2,0);		/* converter word */

  p = *rdata;

  /* XXXX we need a real SAM database some day */
  strcpy(p,"Users"); p += 21; count++;
  strcpy(p,"Domain Users"); p += 21; count++;
  strcpy(p,"Guests"); p += 21; count++;
  strcpy(p,"Domain Guests"); p += 21; count++;

  *rdata_len = PTR_DIFF(p,*rdata);

  SSVAL(*rparam,4,count);	/* is this right?? */
  SSVAL(*rparam,6,count);	/* is this right?? */

  return(True);
}


static BOOL api_WWkstaUserLogon(int cnum,int uid, char *param,char *data,
				int mdrcnt,int mprcnt,
				char **rdata,char **rparam,
				int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  int uLevel;
  struct pack_desc desc;
  char* name;

  uLevel = SVAL(p,0);
  name = p + 2;

  bzero(&desc,sizeof(desc));

  DEBUG(3,("WWkstaUserLogon uLevel=%d name=%s\n",uLevel,name));

  /* check it's a supported varient */
  if (strcmp(str1,"OOWb54WrLh") != 0) return False;
  if (uLevel != 1 || strcmp(str2,"WB21BWDWWDDDDDDDzzzD") != 0) return False;
  if (mdrcnt > 0) *rdata = REALLOC(*rdata,mdrcnt);
  desc.base = *rdata;
  desc.buflen = mdrcnt;
  desc.subformat = NULL;
  desc.format = str2;
  
  

  if (init_package(&desc,1,0)) {
    PACKI(&desc,"W",0);		/* code */
    PACKS(&desc,"B21",name);	/* eff. name */
    PACKS(&desc,"B","");		/* pad */
    PACKI(&desc,"W",
	  Connections[cnum].admin_user?USER_PRIV_ADMIN:USER_PRIV_USER);
    PACKI(&desc,"D",0);		/* auth flags XXX */
    PACKI(&desc,"W",0);		/* num logons */
    PACKI(&desc,"W",0);		/* bad pw count */
    PACKI(&desc,"D",-1);		/* last logon */
    PACKI(&desc,"D",-1);		/* last logoff */
    PACKI(&desc,"D",-1);		/* logoff time */
    PACKI(&desc,"D",-1);		/* kickoff time */
    PACKI(&desc,"D",0);		/* password age */
    PACKI(&desc,"D",0);		/* password can change */
    PACKI(&desc,"D",-1);		/* password must change */
    {
      fstring mypath;
      strcpy(mypath,"\\\\");
      strcat(mypath,local_machine);
      strupper(mypath);
      PACKS(&desc,"z",mypath); /* computer */
    }
    PACKS(&desc,"z",lp_workgroup());/* domain */
    PACKS(&desc,"z",lp_logon_script());		/* script path */
    PACKI(&desc,"D",0);		/* reserved */
  }

  *rdata_len = desc.usedlen;
  *rparam_len = 6;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVALS(*rparam,0,desc.errcode);
  SSVAL(*rparam,2,0);
  SSVAL(*rparam,4,desc.neededlen);

  DEBUG(4,("WWkstaUserLogon: errorcode %d\n",desc.errcode));
  return(True);
}


/****************************************************************************
  api_WAccessGetUserPerms
  ****************************************************************************/
static BOOL api_WAccessGetUserPerms(int cnum,int uid, char *param,char *data,
				    int mdrcnt,int mprcnt,
				    char **rdata,char **rparam,
				    int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *user = skip_string(str2,1);
  char *resource = skip_string(user,1);

  DEBUG(3,("WAccessGetUserPerms user=%s resource=%s\n",user,resource));

  /* check it's a supported varient */
  if (strcmp(str1,"zzh") != 0) return False;
  if (strcmp(str2,"") != 0) return False;

  *rparam_len = 6;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVALS(*rparam,0,0);		/* errorcode */
  SSVAL(*rparam,2,0);		/* converter word */
  SSVAL(*rparam,4,0x7f);	/* permission flags */

  return(True);
}

/****************************************************************************
  api_WPrintJobEnumerate
  ****************************************************************************/
static BOOL api_WPrintJobGetInfo(int cnum,int uid, char *param,char *data,
				 int mdrcnt,int mprcnt,
				 char **rdata,char **rparam,
				 int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  int uJobId = SVAL(p,0);
  int uLevel,cbBuf;
  int count;
  int i;
  int snum;
  int job;
  struct pack_desc desc;
  print_queue_struct *queue=NULL;
  print_status_struct status;

  uLevel = SVAL(p,2);
  cbBuf = SVAL(p,4);

  bzero(&desc,sizeof(desc));
  bzero(&status,sizeof(status));

  DEBUG(3,("WPrintJobGetInfo uLevel=%d uJobId=0x%X\n",uLevel,uJobId));

  /* check it's a supported varient */
  if (strcmp(str1,"WWrLh") != 0) return False;
  if (!check_printjob_info(&desc,uLevel,str2)) return False;

  snum = (unsigned int)uJobId >> 8; /*## valid serice number??*/
  job = uJobId & 0xFF;

  if (snum < 0 || !VALID_SNUM(snum)) return(False);

  count = get_printqueue(snum,cnum,&queue,&status);
  for (i = 0; i < count; i++) {
    if ((queue[i].job % 0xFF) == job) break;
  }
  if (mdrcnt > 0) *rdata = REALLOC(*rdata,mdrcnt);
  desc.base = *rdata;
  desc.buflen = mdrcnt;

  if (init_package(&desc,1,0)) {
    if (i < count) {
      fill_printjob_info(cnum,snum,uLevel,&desc,&queue[i],i);
      *rdata_len = desc.usedlen;
    }
    else {
      desc.errcode = NERR_JobNotFound;
      *rdata_len = 0;
    }
  }

  *rparam_len = 6;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVALS(*rparam,0,desc.errcode);
  SSVAL(*rparam,2,0);
  SSVAL(*rparam,4,desc.neededlen);

  if (queue) free(queue);

  DEBUG(4,("WPrintJobGetInfo: errorcode %d\n",desc.errcode));
  return(True);
}

static BOOL api_WPrintJobEnumerate(int cnum,int uid, char *param,char *data,
				   int mdrcnt,int mprcnt,
				   char **rdata,char **rparam,
				   int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  char* name = p;
  int uLevel,cbBuf;
  int count;
  int i, succnt=0;
  int snum;
  struct pack_desc desc;
  print_queue_struct *queue=NULL;
  print_status_struct status;

  bzero(&desc,sizeof(desc));
  bzero(&status,sizeof(status));

  p = skip_string(p,1);
  uLevel = SVAL(p,0);
  cbBuf = SVAL(p,2);

  DEBUG(3,("WPrintJobEnumerate uLevel=%d name=%s\n",uLevel,name));

  /* check it's a supported varient */
  if (strcmp(str1,"zWrLeh") != 0) return False;
  if (uLevel > 2) return False;	/* defined only for uLevel 0,1,2 */
  if (!check_printjob_info(&desc,uLevel,str2)) return False;

  snum = lp_servicenumber(name);
  if (snum < 0 && pcap_printername_ok(name,NULL)) {
    int pnum = lp_servicenumber(PRINTERS_NAME);
    if (pnum >= 0) {
      lp_add_printer(name,pnum);
      snum = lp_servicenumber(name);
    }
  }

  if (snum < 0 || !VALID_SNUM(snum)) return(False);

  count = get_printqueue(snum,cnum,&queue,&status);
  if (mdrcnt > 0) *rdata = REALLOC(*rdata,mdrcnt);
  desc.base = *rdata;
  desc.buflen = mdrcnt;

  if (init_package(&desc,count,0)) {
    succnt = 0;
    for (i = 0; i < count; i++) {
      fill_printjob_info(cnum,snum,uLevel,&desc,&queue[i],i);
      if (desc.errcode == NERR_Success) succnt = i+1;
    }
  }

  *rdata_len = desc.usedlen;

  *rparam_len = 8;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVALS(*rparam,0,desc.errcode);
  SSVAL(*rparam,2,0);
  SSVAL(*rparam,4,succnt);
  SSVAL(*rparam,6,count);

  if (queue) free(queue);

  DEBUG(4,("WPrintJobEnumerate: errorcode %d\n",desc.errcode));
  return(True);
}

static int check_printdest_info(struct pack_desc* desc,
				int uLevel, char* id)
{
  desc->subformat = NULL;
  switch( uLevel ) {
  case 0: desc->format = "B9"; break;
  case 1: desc->format = "B9B21WWzW"; break;
  case 2: desc->format = "z"; break;
  case 3: desc->format = "zzzWWzzzWW"; break;
  default: return False;
  }
  if (strcmp(desc->format,id) != 0) return False;
  return True;
}

static void fill_printdest_info(int cnum, int snum, int uLevel,
				struct pack_desc* desc)
{
  char buf[100];
  strcpy(buf,SERVICE(snum));
  strupper(buf);
  if (uLevel <= 1) {
    PACKS(desc,"B9",buf);	/* szName */
    if (uLevel == 1) {
      PACKS(desc,"B21","");	/* szUserName */
      PACKI(desc,"W",0);		/* uJobId */
      PACKI(desc,"W",0);		/* fsStatus */
      PACKS(desc,"z","");	/* pszStatus */
      PACKI(desc,"W",0);		/* time */
    }
  }
  if (uLevel == 2 || uLevel == 3) {
    PACKS(desc,"z",buf);		/* pszPrinterName */
    if (uLevel == 3) {
      PACKS(desc,"z","");	/* pszUserName */
      PACKS(desc,"z","");	/* pszLogAddr */
      PACKI(desc,"W",0);		/* uJobId */
      PACKI(desc,"W",0);		/* fsStatus */
      PACKS(desc,"z","");	/* pszStatus */
      PACKS(desc,"z","");	/* pszComment */
      PACKS(desc,"z","NULL"); /* pszDrivers */
      PACKI(desc,"W",0);		/* time */
      PACKI(desc,"W",0);		/* pad1 */
    }
  }
}

static BOOL api_WPrintDestGetInfo(int cnum,int uid, char *param,char *data,
				  int mdrcnt,int mprcnt,
				  char **rdata,char **rparam,
				  int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  char* PrinterName = p;
  int uLevel,cbBuf;
  struct pack_desc desc;
  int snum;

  bzero(&desc,sizeof(desc));

  p = skip_string(p,1);
  uLevel = SVAL(p,0);
  cbBuf = SVAL(p,2);

  DEBUG(3,("WPrintDestGetInfo uLevel=%d PrinterName=%s\n",uLevel,PrinterName));

  /* check it's a supported varient */
  if (strcmp(str1,"zWrLh") != 0) return False;
  if (!check_printdest_info(&desc,uLevel,str2)) return False;

  snum = lp_servicenumber(PrinterName);
  if (snum < 0 && pcap_printername_ok(PrinterName,NULL)) {
    int pnum = lp_servicenumber(PRINTERS_NAME);
    if (pnum >= 0) {
      lp_add_printer(PrinterName,pnum);
      snum = lp_servicenumber(PrinterName);
    }
  }

  if (snum < 0) {
    *rdata_len = 0;
    desc.errcode = NERR_DestNotFound;
    desc.neededlen = 0;
  }
  else {
    if (mdrcnt > 0) *rdata = REALLOC(*rdata,mdrcnt);
    desc.base = *rdata;
    desc.buflen = mdrcnt;
    if (init_package(&desc,1,0)) {
      fill_printdest_info(cnum,snum,uLevel,&desc);
    }
    *rdata_len = desc.usedlen;
  }

  *rparam_len = 6;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVALS(*rparam,0,desc.errcode);
  SSVAL(*rparam,2,0);
  SSVAL(*rparam,4,desc.neededlen);

  DEBUG(4,("WPrintDestGetInfo: errorcode %d\n",desc.errcode));
  return(True);
}

static BOOL api_WPrintDestEnum(int cnum,int uid, char *param,char *data,
			       int mdrcnt,int mprcnt,
			       char **rdata,char **rparam,
			       int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  int uLevel,cbBuf;
  int queuecnt;
  int i, n, succnt=0;
  struct pack_desc desc;
  int services = lp_numservices();

  bzero(&desc,sizeof(desc));

  uLevel = SVAL(p,0);
  cbBuf = SVAL(p,2);

  DEBUG(3,("WPrintDestEnum uLevel=%d\n",uLevel));

  /* check it's a supported varient */
  if (strcmp(str1,"WrLeh") != 0) return False;
  if (!check_printdest_info(&desc,uLevel,str2)) return False;

  queuecnt = 0;
  for (i = 0; i < services; i++)
    if (lp_snum_ok(i) && lp_print_ok(i) && lp_browseable(i))
      queuecnt++;

  if (mdrcnt > 0) *rdata = REALLOC(*rdata,mdrcnt);
  desc.base = *rdata;
  desc.buflen = mdrcnt;
  if (init_package(&desc,queuecnt,0)) {    
    succnt = 0;
    n = 0;
    for (i = 0; i < services; i++) {
      if (lp_snum_ok(i) && lp_print_ok(i) && lp_browseable(i)) {
	fill_printdest_info(cnum,i,uLevel,&desc);
	n++;
	if (desc.errcode == NERR_Success) succnt = n;
      }
    }
  }

  *rdata_len = desc.usedlen;

  *rparam_len = 8;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVALS(*rparam,0,desc.errcode);
  SSVAL(*rparam,2,0);
  SSVAL(*rparam,4,succnt);
  SSVAL(*rparam,6,queuecnt);

  DEBUG(4,("WPrintDestEnumerate: errorcode %d\n",desc.errcode));
  return(True);
}

static BOOL api_WPrintDriverEnum(int cnum,int uid, char *param,char *data,
				 int mdrcnt,int mprcnt,
				 char **rdata,char **rparam,
				 int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  int uLevel,cbBuf;
  int succnt;
  struct pack_desc desc;

  bzero(&desc,sizeof(desc));

  uLevel = SVAL(p,0);
  cbBuf = SVAL(p,2);

  DEBUG(3,("WPrintDriverEnum uLevel=%d\n",uLevel));

  /* check it's a supported varient */
  if (strcmp(str1,"WrLeh") != 0) return False;
  if (uLevel != 0 || strcmp(str2,"B41") != 0) return False;

  if (mdrcnt > 0) *rdata = REALLOC(*rdata,mdrcnt);
  desc.base = *rdata;
  desc.buflen = mdrcnt;
  if (init_package(&desc,1,0)) {
    PACKS(&desc,"B41","NULL");
  }

  succnt = (desc.errcode == NERR_Success ? 1 : 0);

  *rdata_len = desc.usedlen;

  *rparam_len = 8;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVALS(*rparam,0,desc.errcode);
  SSVAL(*rparam,2,0);
  SSVAL(*rparam,4,succnt);
  SSVAL(*rparam,6,1);

  DEBUG(4,("WPrintDriverEnum: errorcode %d\n",desc.errcode));
  return(True);
}

static BOOL api_WPrintQProcEnum(int cnum,int uid, char *param,char *data,
				int mdrcnt,int mprcnt,
				char **rdata,char **rparam,
				int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  int uLevel,cbBuf;
  int succnt;
  struct pack_desc desc;

  bzero(&desc,sizeof(desc));

  uLevel = SVAL(p,0);
  cbBuf = SVAL(p,2);

  DEBUG(3,("WPrintQProcEnum uLevel=%d\n",uLevel));

  /* check it's a supported varient */
  if (strcmp(str1,"WrLeh") != 0) return False;
  if (uLevel != 0 || strcmp(str2,"B13") != 0) return False;

  if (mdrcnt > 0) *rdata = REALLOC(*rdata,mdrcnt);
  desc.base = *rdata;
  desc.buflen = mdrcnt;
  desc.format = str2;
  if (init_package(&desc,1,0)) {
    PACKS(&desc,"B13","lpd");
  }

  succnt = (desc.errcode == NERR_Success ? 1 : 0);

  *rdata_len = desc.usedlen;

  *rparam_len = 8;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVALS(*rparam,0,desc.errcode);
  SSVAL(*rparam,2,0);
  SSVAL(*rparam,4,succnt);
  SSVAL(*rparam,6,1);

  DEBUG(4,("WPrintQProcEnum: errorcode %d\n",desc.errcode));
  return(True);
}

static BOOL api_WPrintPortEnum(int cnum,int uid, char *param,char *data,
			       int mdrcnt,int mprcnt,
			       char **rdata,char **rparam,
			       int *rdata_len,int *rparam_len)
{
  char *str1 = param+2;
  char *str2 = skip_string(str1,1);
  char *p = skip_string(str2,1);
  int uLevel,cbBuf;
  int succnt;
  struct pack_desc desc;

  bzero(&desc,sizeof(desc));

  uLevel = SVAL(p,0);
  cbBuf = SVAL(p,2);

  DEBUG(3,("WPrintPortEnum uLevel=%d\n",uLevel));

  /* check it's a supported varient */
  if (strcmp(str1,"WrLeh") != 0) return False;
  if (uLevel != 0 || strcmp(str2,"B9") != 0) return False;

  if (mdrcnt > 0) *rdata = REALLOC(*rdata,mdrcnt);
  bzero(&desc,sizeof(desc));
  desc.base = *rdata;
  desc.buflen = mdrcnt;
  desc.format = str2;
  if (init_package(&desc,1,0)) {
    PACKS(&desc,"B13","lp0");
  }

  succnt = (desc.errcode == NERR_Success ? 1 : 0);

  *rdata_len = desc.usedlen;

  *rparam_len = 8;
  *rparam = REALLOC(*rparam,*rparam_len);
  SSVALS(*rparam,0,desc.errcode);
  SSVAL(*rparam,2,0);
  SSVAL(*rparam,4,succnt);
  SSVAL(*rparam,6,1);

  DEBUG(4,("WPrintPortEnum: errorcode %d\n",desc.errcode));
  return(True);
}


struct
{
  char * name;
  char * pipename;
  int subcommand;
  BOOL (*fn) ();
} api_fd_commands [] =
  {
    { "SetNmdPpHndState",	"lsarpc",	1,	api_LsarpcSNPHS },
    { "TransactNmPipe",	"lsarpc",	0x26,	api_LsarpcTNP },
    { NULL,		NULL,		-1,	api_Unsupported }
  };

/****************************************************************************
  handle remote api calls delivered to a named pipe already opened.
  ****************************************************************************/
static int api_fd_reply(int cnum,int uid,char *outbuf,
		 	uint16 *setup,char *data,char *params,
		 	int suwcnt,int tdscnt,int tpscnt,int mdrcnt,int mprcnt)
{
  char *rdata = NULL;
  char *rparam = NULL;
  int rdata_len = 0;
  int rparam_len = 0;
  BOOL reply=False;
  int i;
  int fd;
  int subcommand;
  
  /* First find out the name of this file. */
  if (suwcnt != 2)
    {
      DEBUG(0,("Unexpected named pipe transaction.\n"));
      return(-1);
    }
  
  /* Get the file handle and hence the file name. */
  fd = setup[1];
  subcommand = setup[0];
  
  DEBUG(3,("Got API command %d on pipe %s ",subcommand,Files[fd].name));
  DEBUG(3,("(tdscnt=%d,tpscnt=%d,mdrcnt=%d,mprcnt=%d)\n",
	   tdscnt,tpscnt,mdrcnt,mprcnt));
  
  for (i=0;api_fd_commands[i].name;i++)
    if (strequal(api_fd_commands[i].pipename, Files[fd].name) &&
	api_fd_commands[i].subcommand == subcommand &&
	api_fd_commands[i].fn)
      {
	DEBUG(3,("Doing %s\n",api_fd_commands[i].name));
	break;
      }
  
  rdata = (char *)malloc(1024); if (rdata) bzero(rdata,1024);
  rparam = (char *)malloc(1024); if (rparam) bzero(rparam,1024);
  
  reply = api_fd_commands[i].fn(cnum,uid,params,data,mdrcnt,mprcnt,
			        &rdata,&rparam,&rdata_len,&rparam_len);
  
  if (rdata_len > mdrcnt ||
      rparam_len > mprcnt)
    {
      reply = api_TooSmall(cnum,uid,params,data,mdrcnt,mprcnt,
			   &rdata,&rparam,&rdata_len,&rparam_len);
    }
  
  
  /* if we get False back then it's actually unsupported */
  if (!reply)
    api_Unsupported(cnum,uid,params,data,mdrcnt,mprcnt,
		    &rdata,&rparam,&rdata_len,&rparam_len);
  
  /* now send the reply */
  send_trans_reply(outbuf,rdata,rparam,NULL,rdata_len,rparam_len,0);
  
  if (rdata)
    free(rdata);
  if (rparam)
    free(rparam);
  
  return(-1);
}



/****************************************************************************
  the buffer was too small
  ****************************************************************************/
static BOOL api_TooSmall(int cnum,int uid, char *param,char *data,
			 int mdrcnt,int mprcnt,
			 char **rdata,char **rparam,
			 int *rdata_len,int *rparam_len)
{
  *rparam_len = MIN(*rparam_len,mprcnt);
  *rparam = REALLOC(*rparam,*rparam_len);

  *rdata_len = 0;

  SSVAL(*rparam,0,NERR_BufTooSmall);

  DEBUG(3,("Supplied buffer too small in API command\n"));

  return(True);
}


/****************************************************************************
  the request is not supported
  ****************************************************************************/
static BOOL api_Unsupported(int cnum,int uid, char *param,char *data,
			    int mdrcnt,int mprcnt,
			    char **rdata,char **rparam,
			    int *rdata_len,int *rparam_len)
{
  *rparam_len = 4;
  *rparam = REALLOC(*rparam,*rparam_len);

  *rdata_len = 0;

  SSVAL(*rparam,0,NERR_notsupported);
  SSVAL(*rparam,2,0);		/* converter word */

  DEBUG(3,("Unsupported API command\n"));

  return(True);
}




struct
{
  char *name;
  int id;
  BOOL (*fn)();
  int flags;
} api_commands[] = {
  {"RNetShareEnum",	0,	api_RNetShareEnum,0},
  {"RNetShareGetInfo",	1,	api_RNetShareGetInfo,0},
  {"RNetServerGetInfo",	13,	api_RNetServerGetInfo,0},
  {"RNetUserGetInfo",	56,	api_RNetUserGetInfo,0},
  {"NetUserGetGroups",	59,	api_NetUserGetGroups,0},
  {"NetWkstaGetInfo",	63,	api_NetWkstaGetInfo,0},
  {"DosPrintQEnum",	69,	api_DosPrintQEnum,0},
  {"DosPrintQGetInfo",	70,	api_DosPrintQGetInfo,0},
  {"WPrintJobEnumerate",76,	api_WPrintJobEnumerate,0},
  {"WPrintJobGetInfo",	77,	api_WPrintJobGetInfo,0},
  {"RDosPrintJobDel",	81,	api_RDosPrintJobDel,0},
  {"RDosPrintJobPause",	82,	api_RDosPrintJobDel,0},
  {"RDosPrintJobResume",83,	api_RDosPrintJobDel,0},
  {"WPrintDestEnum",	84,	api_WPrintDestEnum,0},
  {"WPrintDestGetInfo",	85,	api_WPrintDestGetInfo,0},
  {"NetRemoteTOD",	91,	api_NetRemoteTOD,0},
  {"WPrintQueuePurge",	103,	api_WPrintQueuePurge,0},
  {"NetServerEnum",	104,	api_RNetServerEnum,0},
  {"WAccessGetUserPerms",105,	api_WAccessGetUserPerms,0},
  {"SetUserPassword",	115,	api_SetUserPassword,0},
  {"WWkstaUserLogon",	132,	api_WWkstaUserLogon,0},
  {"PrintJobInfo",	147,	api_PrintJobInfo,0},
  {"WPrintDriverEnum",	205,	api_WPrintDriverEnum,0},
  {"WPrintQProcEnum",	206,	api_WPrintQProcEnum,0},
  {"WPrintPortEnum",	207,	api_WPrintPortEnum,0},
  {NULL,		-1,	api_Unsupported,0}};


/****************************************************************************
  handle remote api calls
  ****************************************************************************/
static int api_reply(int cnum,int uid,char *outbuf,char *data,char *params,
		     int tdscnt,int tpscnt,int mdrcnt,int mprcnt)
{
  int api_command = SVAL(params,0);
  char *rdata = NULL;
  char *rparam = NULL;
  int rdata_len = 0;
  int rparam_len = 0;
  BOOL reply=False;
  int i;

  DEBUG(3,("Got API command %d of form <%s> <%s> (tdscnt=%d,tpscnt=%d,mdrcnt=%d,mprcnt=%d)\n",
	   api_command,params+2,skip_string(params+2,1),
	   tdscnt,tpscnt,mdrcnt,mprcnt));

  for (i=0;api_commands[i].name;i++)
    if (api_commands[i].id == api_command && api_commands[i].fn)
      {
	DEBUG(3,("Doing %s\n",api_commands[i].name));
	break;
      }

  rdata = (char *)malloc(1024); if (rdata) bzero(rdata,1024);
  rparam = (char *)malloc(1024); if (rparam) bzero(rparam,1024);

  reply = api_commands[i].fn(cnum,uid,params,data,mdrcnt,mprcnt,
			     &rdata,&rparam,&rdata_len,&rparam_len);


  if (rdata_len > mdrcnt ||
      rparam_len > mprcnt)
    {
      reply = api_TooSmall(cnum,uid,params,data,mdrcnt,mprcnt,
			   &rdata,&rparam,&rdata_len,&rparam_len);
    }
	    

  /* if we get False back then it's actually unsupported */
  if (!reply)
    api_Unsupported(cnum,uid,params,data,mdrcnt,mprcnt,
		    &rdata,&rparam,&rdata_len,&rparam_len);

      

  /* now send the reply */
  send_trans_reply(outbuf,rdata,rparam,NULL,rdata_len,rparam_len,0);

  if (rdata)
    free(rdata);
  if (rparam)
    free(rparam);
  
  return(-1);
}

/****************************************************************************
  handle named pipe commands
  ****************************************************************************/
static int named_pipe(int cnum,int uid, char *outbuf,char *name,
		      uint16 *setup,char *data,char *params,
		      int suwcnt,int tdscnt,int tpscnt,
		      int msrcnt,int mdrcnt,int mprcnt)
{

  if (strequal(name,"LANMAN"))
    return(api_reply(cnum,uid,outbuf,data,params,tdscnt,tpscnt,mdrcnt,mprcnt));

if (strlen(name) < 1)
  return(api_fd_reply(cnum,uid,outbuf,setup,data,params,suwcnt,tdscnt,tpscnt,mdrcnt,mprcnt));


  DEBUG(3,("named pipe command on <%s> 0x%X setup1=%d\n",
	   name,(int)setup[0],(int)setup[1]));
  
  return(0);
}


/****************************************************************************
  reply to a SMBtrans
  ****************************************************************************/
int reply_trans(char *inbuf,char *outbuf)
{
  fstring name;

  char *data=NULL,*params=NULL;
  uint16 *setup=NULL;

  int outsize = 0;
  int cnum = SVAL(inbuf,smb_tid);
  int uid = SVAL(inbuf,smb_uid);

  int tpscnt = SVAL(inbuf,smb_vwv0);
  int tdscnt = SVAL(inbuf,smb_vwv1);
  int mprcnt = SVAL(inbuf,smb_vwv2);
  int mdrcnt = SVAL(inbuf,smb_vwv3);
  int msrcnt = CVAL(inbuf,smb_vwv4);
  BOOL close_on_completion = BITSETW(inbuf+smb_vwv5,0);
  BOOL one_way = BITSETW(inbuf+smb_vwv5,1);
  int pscnt = SVAL(inbuf,smb_vwv9);
  int psoff = SVAL(inbuf,smb_vwv10);
  int dscnt = SVAL(inbuf,smb_vwv11);
  int dsoff = SVAL(inbuf,smb_vwv12);
  int suwcnt = CVAL(inbuf,smb_vwv13);

  StrnCpy(name,smb_buf(inbuf),sizeof(name)-1);
  
  if (tdscnt)
    {
      data = (char *)malloc(tdscnt);
      memcpy(data,smb_base(inbuf)+dsoff,dscnt);
    }
  if (tpscnt)
    {
      params = (char *)malloc(tpscnt);
      memcpy(params,smb_base(inbuf)+psoff,pscnt);
    }

  if (suwcnt)
    {
      int i;
      setup = (uint16 *)malloc(suwcnt*sizeof(setup[0]));
      for (i=0;i<suwcnt;i++)
	setup[i] = SVAL(inbuf,smb_vwv14+i*SIZEOFWORD);
    }


  if (pscnt < tpscnt || dscnt < tdscnt)
    {
      /* We need to send an interim response then receive the rest
	 of the parameter/data bytes */
      outsize = set_message(outbuf,0,0,True);
      show_msg(outbuf);
      send_smb(Client,outbuf);
    }

  /* receive the rest of the trans packet */
  while (pscnt < tpscnt || dscnt < tdscnt)
    {
      int pcnt,poff,dcnt,doff,pdisp,ddisp;
      
      if (!receive_smb(Client,inbuf, SMB_SECONDARY_WAIT) ||
	  CVAL(inbuf, smb_com) != SMBtrans)
	{
	  DEBUG(2,("Invalid secondary trans2 packet\n"));
	  if (params) free(params);
	  if (data) free(data);
	  if (setup) free(setup);
	  return(ERROR(ERRSRV,ERRerror));
	}

      show_msg(inbuf);
      
      tpscnt = SVAL(inbuf,smb_vwv0);
      tdscnt = SVAL(inbuf,smb_vwv1);

      pcnt = SVAL(inbuf,smb_vwv2);
      poff = SVAL(inbuf,smb_vwv3);
      pdisp = SVAL(inbuf,smb_vwv4);
      
      dcnt = SVAL(inbuf,smb_vwv5);
      doff = SVAL(inbuf,smb_vwv6);
      ddisp = SVAL(inbuf,smb_vwv7);
      
      pscnt += pcnt;
      dscnt += dcnt;

      if (pcnt)
	memcpy(params+pdisp,smb_base(inbuf)+poff,pcnt);
      if (dcnt)
	memcpy(data+ddisp,smb_base(inbuf)+doff,dcnt);      
    }


  DEBUG(3,("trans <%s> data=%d params=%d setup=%d\n",name,tdscnt,tpscnt,suwcnt));
  

  if (strncmp(name,"\\PIPE\\",strlen("\\PIPE\\")) == 0)
    outsize = named_pipe(cnum,uid,outbuf,name+strlen("\\PIPE\\"),setup,data,params,
			 suwcnt,tdscnt,tpscnt,msrcnt,mdrcnt,mprcnt);


  if (data) free(data);
  if (params) free(params);
  if (setup) free(setup);

  if (close_on_completion)
    close_cnum(cnum,uid);

  if (one_way)
    return(-1);
  
  if (outsize == 0)
    return(ERROR(ERRSRV,ERRnosupport));

  return(outsize);
}


