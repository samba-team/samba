/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
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

#include "includes.h"
#include "loadparm.h"

pstring scope = "";

int DEBUGLEVEL = 1;

BOOL passive = False;

int Protocol = PROTOCOL_COREPLUS;

int serverzone=0;

/* a default finfo structure to ensure all fields are sensible */
file_info def_finfo = {-1,0,0,0,0,0,0,""};

/* these are some file handles where debug info will be stored */
FILE *dbf = NULL;

/* the client file descriptor */
int Client = -1;

/* info on the client */
struct from_host Client_info=
{"UNKNOWN","0.0.0.0",NULL};

/* the last IP received from */
struct in_addr lastip;

/* the last port received from */
int lastport=0;

/* my IP, the broadcast IP and the Netmask */
struct in_addr myip;
struct in_addr bcast_ip;
struct in_addr Netmask;

int trans_num = 0;

/*
   case handling on filenames 
*/
int case_default = CASE_LOWER;


/* size of reads during a direct file to file transfer */
int ReadSize = 16*1024;

pstring debugf = "/tmp/log.samba";
int syslog_level;

/* the following control case operations - they are put here so the
   client can link easily */
BOOL case_sensitive;
BOOL case_preserve;
BOOL use_mangled_map = False;
BOOL short_case_preserve;
BOOL case_mangle;

fstring remote_machine="";
fstring local_machine="";
fstring remote_arch="UNKNOWN";
fstring remote_proto="UNKNOWN";
pstring myhostname="";
pstring user_socket_options="";   
pstring sesssetup_user="";


static char *filename_dos(char *path,char *buf);

static BOOL stdout_logging = False;


/*******************************************************************
  get ready for syslog stuff
  ******************************************************************/
void setup_logging(char *pname,BOOL interactive)
{
#ifdef SYSLOG
  if (!interactive) {
    char *p = strrchr(pname,'/');
    if (p) pname = p+1;
    openlog(pname, LOG_PID, LOG_DAEMON);
  }
#endif
  if (interactive) {
    stdout_logging = True;
    dbf = stdout;
  }
}


BOOL append_log=False;


/****************************************************************************
reopen the log files
****************************************************************************/
void reopen_logs(void)
{
  extern FILE *dbf;
  pstring fname;
  
  if (DEBUGLEVEL > 0)
    {
      strcpy(fname,debugf);
      if (lp_loaded() && (*lp_logfile()))
	strcpy(fname,lp_logfile());

      if (!strcsequal(fname,debugf) || !dbf || !file_exist(debugf,NULL))
	{
	  strcpy(debugf,fname);
	  if (dbf) fclose(dbf);
	  if (append_log)
	    dbf = fopen(debugf,"a");
	  else
	    dbf = fopen(debugf,"w");
	  if (dbf) setbuf(dbf,NULL);
	}
    }
  else
    {
      if (dbf)
	{
	  fclose(dbf);
	  dbf = NULL;
	}
    }
}


/*******************************************************************
check if the log has grown too big
********************************************************************/
static void check_log_size(void)
{
  static int debug_count=0;
  int maxlog;
  struct stat st;

  if (debug_count++ < 100) return;

  maxlog = lp_max_log_size() * 1024;
  if (!dbf || maxlog <= 0) return;

  if (fstat(fileno(dbf),&st) == 0 && st.st_size > maxlog) {
    fclose(dbf); dbf = NULL;
    reopen_logs();
    if (dbf && file_size(debugf) > maxlog) {
      pstring name;
      fclose(dbf); dbf = NULL;
      sprintf(name,"%s.old",debugf);
      sys_rename(debugf,name);
      reopen_logs();
    }
  }
  debug_count=0;
}


/*******************************************************************
write an debug message on the debugfile. This is called by the DEBUG
macro
********************************************************************/
#ifdef __STDC__
int Debug1(char *format_str, ...)
{
#else
int Debug1(va_alist)
va_dcl
{  
  char *format_str;
#endif
  va_list ap;  
  
  if (stdout_logging) {
#ifdef __STDC__
    va_start(ap, format_str);
#else
    va_start(ap);
    format_str = va_arg(ap,char *);
#endif
    vfprintf(dbf,format_str,ap);
    va_end(ap);
    return(0);
  }
  
#ifdef SYSLOG
  if (!lp_syslog_only())
#endif  
    {
      if (!dbf) 
	{
      	  dbf = fopen(debugf,"w");
	  if (dbf)
	    setbuf(dbf,NULL);
	  else
	    return(0);
	}
    }

#ifdef SYSLOG
  if (syslog_level < lp_syslog())
    {
      /* 
       * map debug levels to syslog() priorities
       * note that not all DEBUG(0, ...) calls are
       * necessarily errors
       */
      static int priority_map[] = { 
	LOG_ERR,     /* 0 */
	LOG_WARNING, /* 1 */
	LOG_NOTICE,  /* 2 */
	LOG_INFO,    /* 3 */
      };
      int priority;
      pstring msgbuf;
      
      if (syslog_level >= sizeof(priority_map) / sizeof(priority_map[0]) ||
	  syslog_level < 0)
	priority = LOG_DEBUG;
      else
	priority = priority_map[syslog_level];
      
#ifdef __STDC__
      va_start(ap, format_str);
#else
      va_start(ap);
      format_str = va_arg(ap,char *);
#endif
      vsprintf(msgbuf, format_str, ap);
      va_end(ap);
      
      msgbuf[255] = '\0';
      syslog(priority, "%s", msgbuf);
    }
#endif
  
#ifdef SYSLOG
  if (!lp_syslog_only())
#endif
    {
#ifdef __STDC__
      va_start(ap, format_str);
#else
      va_start(ap);
      format_str = va_arg(ap,char *);
#endif
      vfprintf(dbf,format_str,ap);
      va_end(ap);
      fflush(dbf);
    }

  check_log_size();

  return(0);
}

/****************************************************************************
routine to do file locking
****************************************************************************/
BOOL fcntl_lock(int fd,int op,uint32 offset,uint32 count,int type)
{
#if HAVE_FCNTL_LOCK
  struct flock lock;
  int ret;

#if 1
  uint32 mask = 0xC0000000;

  /* make sure the count is reasonable, we might kill the lockd otherwise */
  count &= ~mask;

  /* the offset is often strange - remove 2 of its bits if either of
     the top two bits are set. Shift the top ones by two bits. This
     still allows OLE2 apps to operate, but should stop lockd from
     dieing */
  if ((offset & mask) != 0)
    offset = (offset & ~mask) | ((offset & mask) >> 2);
#else
  unsigned long mask = ((unsigned)1<<31);

  /* interpret negative counts as large numbers */
  if (count < 0)
    count &= ~mask;

  /* no negative offsets */
  offset &= ~mask;

  /* count + offset must be in range */
  while ((offset < 0 || (offset + count < 0)) && mask)
    {
      offset &= ~mask;
      mask = mask >> 1;
    }
#endif


  DEBUG(5,("fcntl_lock %d %d %d %d %d\n",fd,op,(int)offset,(int)count,type));

  lock.l_type = type;
  lock.l_whence = SEEK_SET;
  lock.l_start = (int)offset;
  lock.l_len = (int)count;
  lock.l_pid = 0;

  errno = 0;

  ret = fcntl(fd,op,&lock);

  if (errno != 0)
    DEBUG(3,("fcntl lock gave errno %d (%s)\n",errno,strerror(errno)));

  /* a lock query */
  if (op == F_GETLK)
    {
      if ((ret != -1) &&
	  (lock.l_type != F_UNLCK) && 
	  (lock.l_pid != 0) && 
	  (lock.l_pid != getpid()))
	{
	  DEBUG(3,("fd %d is locked by pid %d\n",fd,lock.l_pid));
	  return(True);
	}

      /* it must be not locked or locked by me */
      return(False);
    }

  /* a lock set or unset */
  if (ret == -1)
    {
      DEBUG(3,("lock failed at offset %d count %d op %d type %d (%s)\n",
	       offset,count,op,type,strerror(errno)));

      /* perhaps it doesn't support this sort of locking?? */
      if (errno == EINVAL)
	{
	  DEBUG(3,("locking not supported? returning True\n"));
	  return(True);
	}

      return(False);
    }

  /* everything went OK */
  DEBUG(5,("Lock call successful\n"));

  return(True);
#else
  return(False);
#endif
}

/*******************************************************************
lock a file - returning a open file descriptor or -1 on failure
The timeout is in seconds. 0 means no timeout
********************************************************************/
int file_lock(char *name,int timeout)
{  
  int fd = open(name,O_RDWR|O_CREAT,0666);
  time_t t=0;
  if (fd < 0) return(-1);

#if HAVE_FCNTL_LOCK
  if (timeout) t = time(NULL);
  while (!timeout || (time(NULL)-t < timeout)) {
    if (fcntl_lock(fd,F_SETLK,0,1,F_WRLCK)) return(fd);    
    msleep(LOCK_RETRY_TIMEOUT);
  }
  return(-1);
#else
  return(fd);
#endif
}

/*******************************************************************
unlock a file locked by file_lock
********************************************************************/
void file_unlock(int fd)
{
  if (fd<0) return;
#if HAVE_FCNTL_LOCK
  fcntl_lock(fd,F_SETLK,0,1,F_UNLCK);
#endif
  close(fd);
}

/*******************************************************************
a gettimeofday wrapper
********************************************************************/
void GetTimeOfDay(struct timeval *tval)
{
#ifdef GETTIMEOFDAY1
  gettimeofday(tval);
#else
  gettimeofday(tval,NULL);
#endif
}

int extra_time_offset = 0;

static int timediff = 0;

/*******************************************************************
init the time differences
********************************************************************/
void TimeInit(void)
{
  struct tm tm_utc,tm_local;
  time_t t;

  t = time(NULL);

  tm_utc = *(gmtime(&t));
  tm_local = *(localtime(&t));

#ifdef HAVE_GMTOFF
  timediff = -tm_local.tm_gmtoff;  
#else
  timediff = mktime(&tm_utc) - mktime(&tm_local);
#endif

  if (serverzone == 0) {
    serverzone = timediff - DSTDiff(t);
    DEBUG(4,("Serverzone is %d\n",serverzone));
  }
}


/*******************************************************************
return the DST offset for a particular time
We keep a table of DST offsets to prevent calling localtime() on each 
call of this function. This saves a LOT of time on many unixes.
********************************************************************/
int DSTDiff(time_t t)
{
  static struct dst_table {time_t start,end; BOOL is_dst;} *dst_table = NULL;
  static int table_size = 0;
  int i;
  BOOL is_dst = False;

  if (t == 0) t = time(NULL);

#ifndef NO_ISDST
  for (i=0;i<table_size;i++)
    if (t >= dst_table[i].start && t <= dst_table[i].end) break;

  if (i<table_size) {
    is_dst = dst_table[i].is_dst;
  } else {
    time_t low,high;

    dst_table = (struct dst_table *)Realloc(dst_table,
					      sizeof(dst_table[0])*(i+1));
    if (!dst_table) {
      table_size = 0;
      return(0);
    }

    table_size++;

    dst_table[i].is_dst = is_dst = (localtime(&t)->tm_isdst?True:False);
    dst_table[i].start = dst_table[i].end = t;
    
    /* no entry will cover more than 6 months */
    low = t - 3*30*24*60*60;

    /* widen the new entry using two bisection searches */
    while (low+60*60 < dst_table[i].start) {
      t = low + (dst_table[i].start-low)/2;
      if ((localtime(&t)->tm_isdst?True:False) == is_dst)
	dst_table[i].start = t;
      else
	low = t;
    }

    high = low + 3*30*24*60*60;
    while (high-60*60 > dst_table[i].end) {
      t = high - (high-dst_table[i].end)/2;
      if ((localtime(&t)->tm_isdst?True:False) == is_dst)
	dst_table[i].end = t;
      else
	high = t;
    }    

/*
    DEBUG(1,("Added DST entry from %s ",
	     asctime(localtime(&dst_table[i].start))));
    DEBUG(1,("to %s (%d)\n",asctime(localtime(&dst_table[i].end)),
	     dst_table[i].is_dst));
*/
  }
#endif

  return((is_dst?60*60:0) - (extra_time_offset*60));
}

/****************************************************************************
return the difference between local and GMT time
****************************************************************************/
int TimeDiff(time_t t)
{
  static BOOL initialised = False;
  if (!initialised) {initialised=True; TimeInit();}
  return(timediff - DSTDiff(t));
}

/****************************************************************************
try to optimise the localtime call, it can be quite expenive on some machines
timemul is normally LOCAL_TO_GMT, GMT_TO_LOCAL or 0
****************************************************************************/
struct tm *LocalTime(time_t *t,int timemul)
{
  time_t t2 = *t;

  if (timemul)
    t2 += timemul * TimeDiff(t2);

  return(gmtime(&t2));
}


/****************************************************************************
determine if a file descriptor is in fact a socket
****************************************************************************/
BOOL is_a_socket(int fd)
{
  int v,l;
  l = sizeof(int);
  return(getsockopt(fd, SOL_SOCKET, SO_TYPE, (char *)&v, &l) == 0);
}


static char *last_ptr=NULL;

/****************************************************************************
  Get the next token from a string, return False if none found
  handles double-quotes. 
Based on a routine by GJC@VILLAGE.COM. 
Extensively modified by Andrew.Tridgell@anu.edu.au
****************************************************************************/
BOOL next_token(char **ptr,char *buff,char *sep)
{
  char *s;
  BOOL quoted;

  if (!ptr) ptr = &last_ptr;
  if (!ptr) return(False);

  s = *ptr;

  /* default to simple separators */
  if (!sep) sep = " \t\n\r";

  /* find the first non sep char */
  while(*s && strchr(sep,*s)) s++;

  /* nothing left? */
  if (! *s) return(False);

  /* copy over the token */
  for (quoted = False; *s && (quoted || !strchr(sep,*s)); s++)
    {
      if (*s == '\"') 
	quoted = !quoted;
      else
	*buff++ = *s;
    }

  *ptr = (*s) ? s+1 : s;  
  *buff = 0;
  last_ptr = *ptr;

  return(True);
}

/****************************************************************************
Convert list of tokens to array; dependent on above routine.
Uses last_ptr from above - bit of a hack.
****************************************************************************/
char **toktocliplist(int *ctok, char *sep)
{
  char *s=last_ptr;
  int ictok=0;
  char **ret, **iret;

  if (!sep) sep = " \t\n\r";

  while(*s && strchr(sep,*s)) s++;

  /* nothing left? */
  if (!*s) return(NULL);

  do {
    ictok++;
    while(*s && (!strchr(sep,*s))) s++;
    while(*s && strchr(sep,*s)) *s++=0;
  } while(*s);

  *ctok=ictok;
  s=last_ptr;

  if (!(ret=iret=malloc(ictok*sizeof(char *)))) return NULL;
  
  while(ictok--) {    
    *iret++=s;
    while(*s++);
    while(!*s) s++;
  }

  return ret;
}

#ifndef HAVE_MEMMOVE
/*******************************************************************
safely copies memory, ensuring no overlap problems.
this is only used if the machine does not have it's own memmove().
this is not the fastest algorithm in town, but it will do for our
needs.
********************************************************************/
void *MemMove(void *dest,void *src,int size)
{
  unsigned long d,s;
  int i;
  if (dest==src || !size) return(dest);

  d = (unsigned long)dest;
  s = (unsigned long)src;

  if ((d >= (s+size)) || (s >= (d+size))) {
    /* no overlap */
    memcpy(dest,src,size);
    return(dest);
  }

  if (d < s)
    {
      /* we can forward copy */
      if (s-d >= sizeof(int) && 
	  !(s%sizeof(int)) && !(d%sizeof(int)) && !(size%sizeof(int))) {
	/* do it all as words */
	int *idest = (int *)dest;
	int *isrc = (int *)src;
	size /= sizeof(int);
	for (i=0;i<size;i++) idest[i] = isrc[i];
      } else {
	/* simplest */
	char *cdest = (char *)dest;
	char *csrc = (char *)src;
	for (i=0;i<size;i++) cdest[i] = csrc[i];
      }
    }
  else
    {
      /* must backward copy */
      if (d-s >= sizeof(int) && 
	  !(s%sizeof(int)) && !(d%sizeof(int)) && !(size%sizeof(int))) {
	/* do it all as words */
	int *idest = (int *)dest;
	int *isrc = (int *)src;
	size /= sizeof(int);
	for (i=size-1;i>=0;i--) idest[i] = isrc[i];
      } else {
	/* simplest */
	char *cdest = (char *)dest;
	char *csrc = (char *)src;
	for (i=size-1;i>=0;i--) cdest[i] = csrc[i];
      }      
    }
  return(dest);
}
#endif


/****************************************************************************
prompte a dptr (to make it recently used)
****************************************************************************/
void array_promote(char *array,int elsize,int element)
{
  char *p;
  if (element == 0)
    return;

  p = (char *)malloc(elsize);

  if (!p)
    {
      DEBUG(5,("Ahh! Can't malloc\n"));
      return;
    }
  memcpy(p,array + element * elsize, elsize);
  memmove(array + elsize,array,elsize*element);
  memcpy(array,p,elsize);
  free(p);
}

enum SOCK_OPT_TYPES {OPT_BOOL,OPT_INT,OPT_ON};

struct
{
  char *name;
  int level;
  int option;
  int value;
  int opttype;
} socket_options[] = {
  {"SO_KEEPALIVE",      SOL_SOCKET,    SO_KEEPALIVE,    0,                 OPT_BOOL},
  {"SO_REUSEADDR",      SOL_SOCKET,    SO_REUSEADDR,    0,                 OPT_BOOL},
  {"SO_BROADCAST",      SOL_SOCKET,    SO_BROADCAST,    0,                 OPT_BOOL},
#ifdef TCP_NODELAY
  {"TCP_NODELAY",       IPPROTO_TCP,   TCP_NODELAY,     0,                 OPT_BOOL},
#endif
#ifdef IPTOS_LOWDELAY
  {"IPTOS_LOWDELAY",    IPPROTO_IP,    IP_TOS,          IPTOS_LOWDELAY,    OPT_ON},
#endif
#ifdef IPTOS_THROUGHPUT
  {"IPTOS_THROUGHPUT",  IPPROTO_IP,    IP_TOS,          IPTOS_THROUGHPUT,  OPT_ON},
#endif
#ifdef SO_SNDBUF
  {"SO_SNDBUF",         SOL_SOCKET,    SO_SNDBUF,       0,                 OPT_INT},
#endif
#ifdef SO_RCVBUF
  {"SO_RCVBUF",         SOL_SOCKET,    SO_RCVBUF,       0,                 OPT_INT},
#endif
#ifdef SO_SNDLOWAT
  {"SO_SNDLOWAT",       SOL_SOCKET,    SO_SNDLOWAT,     0,                 OPT_INT},
#endif
#ifdef SO_RCVLOWAT
  {"SO_RCVLOWAT",       SOL_SOCKET,    SO_RCVLOWAT,     0,                 OPT_INT},
#endif
  {NULL,0,0,0,0}};

	

/****************************************************************************
set user socket options
****************************************************************************/
void set_socket_options(int fd, char *options)
{
  string tok;

  while (next_token(&options,tok," \t,"))
    {
      int ret=0,i;
      int value = 1;
      char *p;
      BOOL got_value = False;

      if ((p = strchr(tok,'=')))
	{
	  *p = 0;
	  value = atoi(p+1);
	  got_value = True;
	}

      for (i=0;socket_options[i].name;i++)
	if (strequal(socket_options[i].name,tok))
	  break;

      if (!socket_options[i].name)
	{
	  DEBUG(0,("Unknown socket option %s\n",tok));
	  continue;
	}

      switch (socket_options[i].opttype)
	{
	case OPT_BOOL:
	case OPT_INT:
	  ret = setsockopt(fd,socket_options[i].level,
			   socket_options[i].option,(char *)&value,sizeof(int));
	  break;

	case OPT_ON:
	  if (got_value)
	    DEBUG(0,("syntax error - %s does not take a value\n",tok));

	  {
	    int on = socket_options[i].value;
	    ret = setsockopt(fd,socket_options[i].level,
			     socket_options[i].option,(char *)&on,sizeof(int));
	  }
	  break;	  
	}
      
      if (ret != 0)
	DEBUG(0,("Failed to set socket option %s\n",tok));
    }
}



/****************************************************************************
  close the socket communication
****************************************************************************/
void close_sockets(void )
{
  close(Client);
  Client = 0;
}

/****************************************************************************
  return the date and time as a string
****************************************************************************/
char *timestring(void )
{
  static char TimeBuf[100];
  time_t t;
  t = time(NULL);
#ifdef NO_STRFTIME
  strcpy(TimeBuf, asctime(LocalTime(&t,GMT_TO_LOCAL)));
#elif defined(CLIX) || defined(CONVEX)
  strftime(TimeBuf,100,"%m/%d/%y %I:%M:%S %p",LocalTime(&t,GMT_TO_LOCAL));
#elif defined(AMPM)
  strftime(TimeBuf,100,"%D %r",LocalTime(&t,GMT_TO_LOCAL));
#elif defined(TZ_TIME)
  {
    strftime(TimeBuf,100,"%D:%T",LocalTime(&t,0));
    sprintf(TimeBuf+strlen(TimeBuf)," %+03d%02d",
	    -TimeDiff(t)/(60*60),-(TimeDiff(t)/60)%60);
  }
#else
  strftime(TimeBuf,100,"%D %T",LocalTime(&t,GMT_TO_LOCAL));
#endif
  return(TimeBuf);
}

/****************************************************************************
determine whether we are in the specified group
****************************************************************************/
BOOL in_group(gid_t group, int current_gid, int ngroups, int *groups)
{
  int i;

  if (group == current_gid) return(True);

  for (i=0;i<ngroups;i++)
    if (group == groups[i])
      return(True);

  return(False);
}

/****************************************************************************
this is a safer strcpy(), meant to prevent core dumps when nasty things happen
****************************************************************************/
char *StrCpy(char *dest,char *src)
{
  char *d = dest;

#if AJT
  /* I don't want to get lazy with these ... */
  if (!dest || !src) {
    DEBUG(0,("ERROR: NULL StrCpy() called!\n"));
    ajt_panic();
  }
#endif

  if (!dest) return(NULL);
  if (!src) {
    *dest = 0;
    return(dest);
  }
  while ((*d++ = *src++)) ;
  return(dest);
}

/****************************************************************************
line strncpy but always null terminates. Make sure there is room!
****************************************************************************/
char *StrnCpy(char *dest,const char *src,int n)
{
  char *d = dest;
  if (!dest) return(NULL);
  if (!src) {
    *dest = 0;
    return(dest);
  }
  while (n-- && (*d++ = *src++)) ;
  *d = 0;
  return(dest);
}


/*******************************************************************
copy an IP address from one buffer to another
********************************************************************/
void putip(void *dest,void *src)
{
  memcpy(dest,src,4);
}


/****************************************************************************
interpret the weird netbios "name". Return the name type
****************************************************************************/
static int name_interpret(char *in,char *out)
{
  int ret;
  int len = (*in++) / 2;

  *out=0;

  if (len > 30 || len<1) return(0);

  while (len--)
    {
      if (in[0] < 'A' || in[0] > 'P' || in[1] < 'A' || in[1] > 'P') {
	*out = 0;
	return(0);
      }
      *out = ((in[0]-'A')<<4) + (in[1]-'A');
      in += 2;
      out++;
    }
  *out = 0;
  ret = out[-1];

#ifdef NETBIOS_SCOPE
  /* Handle any scope names */
  while(*in) 
    {
      *out++ = '.'; /* Scope names are separated by periods */
      len = *(unsigned char *)in++;
      StrnCpy(out, in, len);
      out += len;
      *out=0;
      in += len;
    }
#endif
  return(ret);
}

/****************************************************************************
mangle a name into netbios format
****************************************************************************/
int name_mangle(char *In,char *Out,char name_type)
{
  fstring name;
  char buf[20];
  char *in = (char *)&buf[0];
  char *out = (char *)Out;
  char *p, *label;
  int i;

  if (In[0] != '*') {
    StrnCpy(name,In,sizeof(name)-1);
    sprintf(buf,"%-15.15s%c",name,name_type);
  } else {
    buf[0]='*';
    memset(&buf[1],0,16);
  }

  *out++ = 32;
  for (i=0;i<16;i++) {
    char c = toupper(in[i]);
    out[i*2] = (c>>4) + 'A';
    out[i*2+1] = (c & 0xF) + 'A';
  }
  out[32]=0;
  out += 32;
  
  label = scope;
  while (*label)
    {
      p = strchr(label, '.');
      if (p == 0)
	p = label + strlen(label);
      *out++ = p - label;
      memcpy(out, label, p - label);
      out += p - label;
      label += p - label + (*p == '.');
    }
  *out = 0;
  return(name_len(Out));
}


/*******************************************************************
  check if a file exists
********************************************************************/
BOOL file_exist(char *fname,struct stat *sbuf)
{
  struct stat st;
  if (!sbuf) sbuf = &st;
  
  if (sys_stat(fname,sbuf) != 0) 
    return(False);

  return(S_ISREG(sbuf->st_mode));
}

/*******************************************************************
check a files mod time
********************************************************************/
time_t file_modtime(char *fname)
{
  struct stat st;
  
  if (sys_stat(fname,&st) != 0) 
    return(0);

  return(st.st_mtime);
}

/*******************************************************************
  check if a directory exists
********************************************************************/
BOOL directory_exist(char *dname,struct stat *st)
{
  struct stat st2;
  if (!st) st = &st2;

  if (sys_stat(dname,st) != 0) 
    return(False);

  return(S_ISDIR(st->st_mode));
}

/*******************************************************************
returns the size in bytes of the named file
********************************************************************/
uint32 file_size(char *file_name)
{
  struct stat buf;
  buf.st_size = 0;
  sys_stat(file_name,&buf);
  return(buf.st_size);
}

/****************************************************************************
check if it's a null mtime
****************************************************************************/
static BOOL null_mtime(time_t mtime)
{
  if (mtime == 0 || mtime == 0xFFFFFFFF)
    return(True);
  return(False);
}

/*******************************************************************
  create a 16 bit dos packed date
********************************************************************/
static uint16 make_dos_date1(time_t unixdate,struct tm *t)
{
  uint16 ret=0;
  ret = (((unsigned)(t->tm_mon+1)) >> 3) | ((t->tm_year-80) << 1);
  ret = ((ret&0xFF)<<8) | (t->tm_mday | (((t->tm_mon+1) & 0x7) << 5));
  return(ret);
}

/*******************************************************************
  create a 16 bit dos packed time
********************************************************************/
static uint16 make_dos_time1(time_t unixdate,struct tm *t)
{
  uint16 ret=0;
  ret = ((((unsigned)t->tm_min >> 3)&0x7) | (((unsigned)t->tm_hour) << 3));
  ret = ((ret&0xFF)<<8) | ((t->tm_sec/2) | ((t->tm_min & 0x7) << 5));
  return(ret);
}

/*******************************************************************
  create a 32 bit dos packed date/time from some parameters
  This takes a GMT time and returns a packed localtime structure
********************************************************************/
static uint32 make_dos_date(time_t unixdate)
{
  struct tm *t;
  uint32 ret=0;

  t = LocalTime(&unixdate,GMT_TO_LOCAL);

  ret = make_dos_date1(unixdate,t);
  ret = ((ret&0xFFFF)<<16) | make_dos_time1(unixdate,t);

  return(ret);
}

/*******************************************************************
put a dos date into a buffer (time/date format)
This takes GMT time and puts local time in the buffer
********************************************************************/
void put_dos_date(char *buf,int offset,time_t unixdate)
{
  uint32 x = make_dos_date(unixdate);
  SIVAL(buf,offset,x);
}

/*******************************************************************
put a dos date into a buffer (date/time format)
This takes GMT time and puts local time in the buffer
********************************************************************/
void put_dos_date2(char *buf,int offset,time_t unixdate)
{
  uint32 x = make_dos_date(unixdate);
  x = ((x&0xFFFF)<<16) | ((x&0xFFFF0000)>>16);
  SIVAL(buf,offset,x);
}

/*******************************************************************
put a dos 32 bit "unix like" date into a buffer. This routine takes
GMT and converts it to LOCAL time before putting it (most SMBs assume
localtime for this sort of date)
********************************************************************/
void put_dos_date3(char *buf,int offset,time_t unixdate)
{
  if (!null_mtime(unixdate))
    unixdate += GMT_TO_LOCAL*TimeDiff(unixdate);
  SIVAL(buf,offset,unixdate);
}

/*******************************************************************
  interpret a 32 bit dos packed date/time to some parameters
********************************************************************/
static void interpret_dos_date(uint32 date,int *year,int *month,int *day,int *hour,int *minute,int *second)
{
  uint32 p0,p1,p2,p3;

  p0=date&0xFF; p1=((date&0xFF00)>>8)&0xFF; 
  p2=((date&0xFF0000)>>16)&0xFF; p3=((date&0xFF000000)>>24)&0xFF;

  *second = 2*(p0 & 0x1F);
  *minute = ((p0>>5)&0xFF) + ((p1&0x7)<<3);
  *hour = (p1>>3)&0xFF;
  *day = (p2&0x1F);
  *month = ((p2>>5)&0xFF) + ((p3&0x1)<<3) - 1;
  *year = ((p3>>1)&0xFF) + 80;
}

/*******************************************************************
  create a unix date (int GMT) from a dos date (which is actually in
  localtime)
********************************************************************/
time_t make_unix_date(void *date_ptr)
{
  uint32 dos_date=0;
  struct tm t;
  time_t ret;

  dos_date = IVAL(date_ptr,0);

  if (dos_date == 0) return(0);
  
  interpret_dos_date(dos_date,&t.tm_year,&t.tm_mon,
		     &t.tm_mday,&t.tm_hour,&t.tm_min,&t.tm_sec);
  t.tm_wday = 1;
  t.tm_yday = 1;
  t.tm_isdst = -1;
  
  /* mktime() also does the local to GMT time conversion for us. XXXXX
     Do all unixes do this the same?? */
  ret = mktime(&t);

  return(ret);
}

/*******************************************************************
like make_unix_date() but the words are reversed
********************************************************************/
time_t make_unix_date2(void *date_ptr)
{
  uint32 x,x2;

  x = IVAL(date_ptr,0);
  x2 = ((x&0xFFFF)<<16) | ((x&0xFFFF0000)>>16);
  SIVAL(&x,0,x2);

  return(make_unix_date((void *)&x));
}

/*******************************************************************
  create a unix GMT date from a dos date in 32 bit "unix like" format
these generally arrive as localtimes, with corresponding DST
********************************************************************/
time_t make_unix_date3(void *date_ptr)
{
  time_t t = IVAL(date_ptr,0);
  if (!null_mtime(t))
    t += LOCAL_TO_GMT*TimeDiff(t);
  return(t);
}

/*******************************************************************
return a string representing an attribute for a file
********************************************************************/
char *attrib_string(int mode)
{
  static char attrstr[10];

  attrstr[0] = 0;

  if (mode & aVOLID) strcat(attrstr,"V");
  if (mode & aDIR) strcat(attrstr,"D");
  if (mode & aARCH) strcat(attrstr,"A");
  if (mode & aHIDDEN) strcat(attrstr,"H");
  if (mode & aSYSTEM) strcat(attrstr,"S");
  if (mode & aRONLY) strcat(attrstr,"R");	  

  return(attrstr);
}


/*******************************************************************
  case insensitive string compararison
********************************************************************/
int StrCaseCmp(char *s, char *t)
{
  for (; tolower(*s) == tolower(*t); ++s, ++t)
    if (!*s) return 0;

  return tolower(*s) - tolower(*t);
}

/*******************************************************************
  case insensitive string compararison, length limited
********************************************************************/
int StrnCaseCmp(char *s, char *t, int n)
{
  while (n-- && *s && *t) {
    if (tolower(*s) != tolower(*t)) return(tolower(*s) - tolower(*t));
    s++; t++;
  }
  if (n) return(tolower(*s) - tolower(*t));

  return(0);
}

/*******************************************************************
  compare 2 strings 
********************************************************************/
BOOL strequal(char *s1,char *s2)
{
  if (s1 == s2) return(True);
  if (!s1 || !s2) return(False);
  
  return(StrCaseCmp(s1,s2)==0);
}

/*******************************************************************
  compare 2 strings up to and including the nth char.
  ******************************************************************/
BOOL strnequal(char *s1,char *s2,int n)
{
  if (s1 == s2) return(True);
  if (!s1 || !s2 || !n) return(False);
  
  return(StrnCaseCmp(s1,s2,n)==0);
}

/*******************************************************************
  compare 2 strings (case sensitive)
********************************************************************/
BOOL strcsequal(char *s1,char *s2)
{
  if (s1 == s2) return(True);
  if (!s1 || !s2) return(False);
  
  return(strcmp(s1,s2)==0);
}


/*******************************************************************
  convert a string to lower case
********************************************************************/
void strlower(char *s)
{
  while (*s)
    {
#ifdef KANJI
	if (is_shift_jis (*s)) {
	    s += 2;
	} else if (is_kana (*s)) {
	    s++;
	} else {
	    if (isupper(*s))
		*s = tolower(*s);
	    s++;
	}
#else
      if (isupper(*s))
	  *s = tolower(*s);
      s++;
#endif /* KANJI */
    }
}

/*******************************************************************
  convert a string to upper case
********************************************************************/
void strupper(char *s)
{
  while (*s)
    {
#ifdef KANJI
	if (is_shift_jis (*s)) {
	    s += 2;
	} else if (is_kana (*s)) {
	    s++;
	} else {
	    if (islower(*s))
		*s = toupper(*s);
	    s++;
	}
#else
      if (islower(*s))
	*s = toupper(*s);
      s++;
#endif
    }
}

/*******************************************************************
  convert a string to "normal" form
********************************************************************/
void strnorm(char *s)
{
  if (case_default == CASE_UPPER)
    strupper(s);
  else
    strlower(s);
}

/*******************************************************************
check if a string is in "normal" case
********************************************************************/
BOOL strisnormal(char *s)
{
  if (case_default == CASE_UPPER)
    return(!strhaslower(s));

  return(!strhasupper(s));
}


/****************************************************************************
  string replace
****************************************************************************/
void string_replace(char *s,char oldc,char newc)
{
  while (*s)
    {
#ifdef KANJI
	if (is_shift_jis (*s)) {
	    s += 2;
	} else if (is_kana (*s)) {
	    s++;
	} else {
	    if (oldc == *s)
		*s = newc;
	    s++;
	}
#else
      if (oldc == *s)
	*s = newc;
      s++;
#endif /* KANJI */
    }
}

/****************************************************************************
  make a file into unix format
****************************************************************************/
void unix_format(char *fname)
{
  pstring namecopy;
  string_replace(fname,'\\','/');
#ifndef KANJI
  dos2unix_format(fname, True);
#endif /* KANJI */

  if (*fname == '/')
    {
      strcpy(namecopy,fname);
      strcpy(fname,".");
      strcat(fname,namecopy);
    }  
}

/****************************************************************************
  make a file into dos format
****************************************************************************/
void dos_format(char *fname)
{
#ifndef KANJI
  unix2dos_format(fname, True);
#endif /* KANJI */
  string_replace(fname,'/','\\');
}


/*******************************************************************
  show a smb message structure
********************************************************************/
void show_msg(char *buf)
{
  int i;
  int bcc=0;
  if (DEBUGLEVEL < 5)
    return;

  DEBUG(5,("size=%d\nsmb_com=0x%x\nsmb_rcls=%d\nsmb_reh=%d\nsmb_err=%d\nsmb_flg=%d\nsmb_flg2=%d\n",
	  smb_len(buf),
	  (int)CVAL(buf,smb_com),
	  (int)CVAL(buf,smb_rcls),
	  (int)CVAL(buf,smb_reh),
	  (int)SVAL(buf,smb_err),
	  (int)CVAL(buf,smb_flg),
	  (int)SVAL(buf,smb_flg2)));
  DEBUG(5,("smb_tid=%d\nsmb_pid=%d\nsmb_uid=%d\nsmb_mid=%d\nsmt_wct=%d\n",
	  (int)SVAL(buf,smb_tid),
	  (int)SVAL(buf,smb_pid),
	  (int)SVAL(buf,smb_uid),
	  (int)SVAL(buf,smb_mid),
	  (int)CVAL(buf,smb_wct)));
  for (i=0;i<(int)CVAL(buf,smb_wct);i++)
    DEBUG(5,("smb_vwv[%d]=%d (0x%X)\n",i,
	  SVAL(buf,smb_vwv+2*i),SVAL(buf,smb_vwv+2*i)));
  bcc = (int)SVAL(buf,smb_vwv+2*(CVAL(buf,smb_wct)));
  DEBUG(5,("smb_bcc=%d\n",bcc));
  if (DEBUGLEVEL < 10)
    return;
  for (i=0;i<MIN(bcc,128);i++)
    DEBUG(10,("%X ",CVAL(smb_buf(buf),i)));
  DEBUG(10,("\n"));  
}

/*******************************************************************
  return the length of an smb packet
********************************************************************/
int smb_len(char *buf)
{
  return( PVAL(buf,3) | (PVAL(buf,2)<<8) | ((PVAL(buf,1)&1)<<16) );
}

/*******************************************************************
  set the length of an smb packet
********************************************************************/
void _smb_setlen(char *buf,int len)
{
  buf[0] = 0;
  buf[1] = (len&0x10000)>>16;
  buf[2] = (len&0xFF00)>>8;
  buf[3] = len&0xFF;
}

/*******************************************************************
  set the length and marker of an smb packet
********************************************************************/
void smb_setlen(char *buf,int len)
{
  _smb_setlen(buf,len);

  CVAL(buf,4) = 0xFF;
  CVAL(buf,5) = 'S';
  CVAL(buf,6) = 'M';
  CVAL(buf,7) = 'B';
}

/*******************************************************************
  setup the word count and byte count for a smb message
********************************************************************/
int set_message(char *buf,int num_words,int num_bytes,BOOL zero)
{
  if (zero)
    bzero(buf + smb_size,num_words*2 + num_bytes);
  CVAL(buf,smb_wct) = num_words;
  SSVAL(buf,smb_vwv + num_words*SIZEOFWORD,num_bytes);  
  smb_setlen(buf,smb_size + num_words*2 + num_bytes - 4);
  return (smb_size + num_words*2 + num_bytes);
}

/*******************************************************************
return the number of smb words
********************************************************************/
int smb_numwords(char *buf)
{
  return (CVAL(buf,smb_wct));
}

/*******************************************************************
return the size of the smb_buf region of a message
********************************************************************/
int smb_buflen(char *buf)
{
  return(SVAL(buf,smb_vwv0 + smb_numwords(buf)*2));
}

/*******************************************************************
  return a pointer to the smb_buf data area
********************************************************************/
int smb_buf_ofs(char *buf)
{
  return (smb_size + CVAL(buf,smb_wct)*2);
}

/*******************************************************************
  return a pointer to the smb_buf data area
********************************************************************/
char *smb_buf(char *buf)
{
  return (buf + smb_buf_ofs(buf));
}

/*******************************************************************
return the SMB offset into an SMB buffer
********************************************************************/
int smb_offset(char *p,char *buf)
{
  return(PTR_DIFF(p,buf+4));
}


/*******************************************************************
skip past some strings in a buffer
********************************************************************/
char *skip_string(char *buf,int n)
{
  while (n--)
    buf += strlen(buf) + 1;
  return(buf);
}

/*******************************************************************
trim the specified elements off the front and back of a string
********************************************************************/
BOOL trim_string(char *s,char *front,char *back)
{
  BOOL ret = False;
  while (front && *front && strncmp(s,front,strlen(front)) == 0)
    {
      char *p = s;
      ret = True;
      while (1)
	{
	  if (!(*p = p[strlen(front)]))
	    break;
	  p++;
	}
    }
  while (back && *back && strlen(s) >= strlen(back) && 
	 (strncmp(s+strlen(s)-strlen(back),back,strlen(back))==0))  
    {
      ret = True;
      s[strlen(s)-strlen(back)] = 0;
    }
  return(ret);
}


/*******************************************************************
reduce a file name, removing .. elements.
********************************************************************/
void dos_clean_name(char *s)
{
  char *p=NULL;

  DEBUG(3,("dos_clean_name [%s]\n",s));

  /* remove any double slashes */
  string_sub(s, "\\\\", "\\");

  while ((p = strstr(s,"\\..\\")) != NULL)
    {
      pstring s1;

      *p = 0;
      strcpy(s1,p+3);

      if ((p=strrchr(s,'\\')) != NULL)
	*p = 0;
      else
	*s = 0;
      strcat(s,s1);
    }  

  trim_string(s,NULL,"\\..");

  string_sub(s, "\\.\\", "\\");
}

/*******************************************************************
reduce a file name, removing .. elements. 
********************************************************************/
void unix_clean_name(char *s)
{
  char *p=NULL;

  DEBUG(3,("unix_clean_name [%s]\n",s));

  /* remove any double slashes */
  string_sub(s, "//","/");

  while ((p = strstr(s,"/../")) != NULL)
    {
      pstring s1;

      *p = 0;
      strcpy(s1,p+3);

      if ((p=strrchr(s,'/')) != NULL)
	*p = 0;
      else
	*s = 0;
      strcat(s,s1);
    }  

  trim_string(s,NULL,"/..");
}


/*******************************************************************
a wrapper for the normal chdir() function
********************************************************************/
int ChDir(char *path)
{
  int res;
  static pstring LastDir="";

  if (strcsequal(path,".")) return(0);

  if (*path == '/' && strcsequal(LastDir,path)) return(0);
  DEBUG(3,("chdir to %s\n",path));
  res = sys_chdir(path);
  if (!res)
    strcpy(LastDir,path);
  return(res);
}


/*******************************************************************
  return the absolute current directory path. A dumb version.
********************************************************************/
static char *Dumb_GetWd(char *s)
{
#ifdef USE_GETCWD
    return ((char *)getcwd(s,sizeof(pstring)));
#else
    return ((char *)getwd(s));
#endif
}


/* number of list structures for a caching GetWd function. */
#define MAX_GETWDCACHE (50)

struct
{
  ino_t inode;
  dev_t dev;
  char *text;
  BOOL valid;
} ino_list[MAX_GETWDCACHE];

BOOL use_getwd_cache=True;

/*******************************************************************
  return the absolute current directory path
********************************************************************/
char *GetWd(char *str)
{
  pstring s;
  static BOOL getwd_cache_init = False;
  struct stat st, st2;
  int i;

  *s = 0;

  if (!use_getwd_cache)
    return(Dumb_GetWd(str));

  /* init the cache */
  if (!getwd_cache_init)
    {
      getwd_cache_init = True;
      for (i=0;i<MAX_GETWDCACHE;i++)
	{
	  string_init(&ino_list[i].text,"");
	  ino_list[i].valid = False;
	}
    }

  /*  Get the inode of the current directory, if this doesn't work we're
      in trouble :-) */

  if (stat(".",&st) == -1) 
    {
      DEBUG(0,("Very strange, couldn't stat \".\"\n"));
      return(Dumb_GetWd(str));
    }


  for (i=0; i<MAX_GETWDCACHE; i++)
    if (ino_list[i].valid)
      {

	/*  If we have found an entry with a matching inode and dev number
	    then find the inode number for the directory in the cached string.
	    If this agrees with that returned by the stat for the current
	    directory then all is o.k. (but make sure it is a directory all
	    the same...) */
      
	if (st.st_ino == ino_list[i].inode &&
	    st.st_dev == ino_list[i].dev)
	  {
	    if (stat(ino_list[i].text,&st2) == 0)
	      {
		if (st.st_ino == st2.st_ino &&
		    st.st_dev == st2.st_dev &&
		    (st2.st_mode & S_IFMT) == S_IFDIR)
		  {
		    strcpy (str, ino_list[i].text);

		    /* promote it for future use */
		    array_promote((char *)&ino_list[0],sizeof(ino_list[0]),i);
		    return (str);
		  }
		else
		  {
		    /*  If the inode is different then something's changed, 
			scrub the entry and start from scratch. */
		    ino_list[i].valid = False;
		  }
	      }
	  }
      }


  /*  We don't have the information to hand so rely on traditional methods.
      The very slow getcwd, which spawns a process on some systems, or the
      not quite so bad getwd. */

  if (!Dumb_GetWd(s))
    {
      DEBUG(0,("Getwd failed, errno %d\n",errno));
      return (NULL);
    }

  strcpy(str,s);

  DEBUG(5,("GetWd %s, inode %d, dev %x\n",s,(int)st.st_ino,(int)st.st_dev));

  /* add it to the cache */
  i = MAX_GETWDCACHE - 1;
  string_set(&ino_list[i].text,s);
  ino_list[i].dev = st.st_dev;
  ino_list[i].inode = st.st_ino;
  ino_list[i].valid = True;

  /* put it at the top of the list */
  array_promote((char *)&ino_list[0],sizeof(ino_list[0]),i);

  return (str);
}



/*******************************************************************
reduce a file name, removing .. elements and checking that 
it is below dir in the heirachy. This uses GetWd() and so must be run
on the system that has the referenced file system.

widelinks are allowed if widelinks is true
********************************************************************/
BOOL reduce_name(char *s,char *dir,BOOL widelinks)
{
#ifndef REDUCE_PATHS
  return True;
#else
  pstring dir2;
  pstring wd;
  pstring basename;
  pstring newname;
  char *p=NULL;
  BOOL relative = (*s != '/');

  *dir2 = *wd = *basename = *newname = 0;

  if (widelinks)
    {
      unix_clean_name(s);
      /* can't have a leading .. */
      if (strncmp(s,"..",2) == 0 && (s[2]==0 || s[2]=='/'))
	{
	  DEBUG(3,("Illegal file name? (%s)\n",s));
	  return(False);
	}
      return(True);
    }
  
  DEBUG(3,("reduce_name [%s] [%s]\n",s,dir));

  /* remove any double slashes */
  string_sub(s,"//","/");

  strcpy(basename,s);
  p = strrchr(basename,'/');

  if (!p)
    return(True);

  if (!GetWd(wd))
    {
      DEBUG(0,("couldn't getwd for %s %s\n",s,dir));
      return(False);
    }

  if (ChDir(dir) != 0)
    {
      DEBUG(0,("couldn't chdir to %s\n",dir));
      return(False);
    }

  if (!GetWd(dir2))
    {
      DEBUG(0,("couldn't getwd for %s\n",dir));
      ChDir(wd);
      return(False);
    }


    if (p && (p != basename))
      {
	*p = 0;
	if (strcmp(p+1,".")==0)
	  p[1]=0;
	if (strcmp(p+1,"..")==0)
	  *p = '/';
      }

  if (ChDir(basename) != 0)
    {
      ChDir(wd);
      DEBUG(3,("couldn't chdir for %s %s basename=%s\n",s,dir,basename));
      return(False);
    }

  if (!GetWd(newname))
    {
      ChDir(wd);
      DEBUG(2,("couldn't get wd for %s %s\n",s,dir2));
      return(False);
    }

  if (p && (p != basename))
    {
      strcat(newname,"/");
      strcat(newname,p+1);
    }

  {
    int l = strlen(dir2);    
    if (dir2[l-1] == '/')
      l--;

    if (strncmp(newname,dir2,l) != 0)
      {
	ChDir(wd);
	DEBUG(2,("Bad access attempt? s=%s dir=%s newname=%s l=%d\n",s,dir2,newname,l));
	return(False);
      }

    if (relative)
      {
	if (newname[l] == '/')
	  strcpy(s,newname + l + 1);
	else
	  strcpy(s,newname+l);
      }
    else
      strcpy(s,newname);
  }

  ChDir(wd);

  if (strlen(s) == 0)
    strcpy(s,"./");

  DEBUG(3,("reduced to %s\n",s));
  return(True);
#endif
}

/****************************************************************************
expand some *s 
****************************************************************************/
static void expand_one(char *Mask,int len)
{
  char *p1;
  while ((p1 = strchr(Mask,'*')) != NULL)
    {
      int lfill = (len+1) - strlen(Mask);
      int l1= (p1 - Mask);
      pstring tmp;
      strcpy(tmp,Mask);  
      memset(tmp+l1,'?',lfill);
      strcpy(tmp + l1 + lfill,Mask + l1 + 1);	
      strcpy(Mask,tmp);      
    }
}

/****************************************************************************
expand a wildcard expression, replacing *s with ?s
****************************************************************************/
void expand_mask(char *Mask,BOOL doext)
{
  pstring mbeg,mext;
  pstring dirpart;
  pstring filepart;
  BOOL hasdot = False;
  char *p1;
  BOOL absolute = (*Mask == '\\');

  *mbeg = *mext = *dirpart = *filepart = 0;

  /* parse the directory and filename */
  if (strchr(Mask,'\\'))
    dirname_dos(Mask,dirpart);

  filename_dos(Mask,filepart);

  strcpy(mbeg,filepart);
  if ((p1 = strchr(mbeg,'.')) != NULL)
    {
      hasdot = True;
      *p1 = 0;
      p1++;
      strcpy(mext,p1);
    }
  else
    {
      strcpy(mext,"");
      if (strlen(mbeg) > 8)
	{
	  strcpy(mext,mbeg + 8);
	  mbeg[8] = 0;
	}
    }

  if (*mbeg == 0)
    strcpy(mbeg,"????????");
  if ((*mext == 0) && doext && !hasdot)
    strcpy(mext,"???");

  if (strequal(mbeg,"*") && *mext==0) 
    strcpy(mext,"*");

  /* expand *'s */
  expand_one(mbeg,8);
  if (*mext)
    expand_one(mext,3);

  strcpy(Mask,dirpart);
  if (*dirpart || absolute) strcat(Mask,"\\");
  strcat(Mask,mbeg);
  strcat(Mask,".");
  strcat(Mask,mext);

  DEBUG(6,("Mask expanded to [%s]\n",Mask));
}  


/****************************************************************************
does a string have any uppercase chars in it?
****************************************************************************/
BOOL strhasupper(char *s)
{
  while (*s) 
    {
#ifdef KANJI
	if (is_shift_jis (*s)) {
	    s += 2;
	} else if (is_kana (*s)) {
	    s++;
	} else {
	    if (isupper(*s)) return(True);
	    s++;
	}
#else 
      if (isupper(*s)) return(True);
      s++;
#endif /* KANJI */
    }
  return(False);
}

/****************************************************************************
does a string have any lowercase chars in it?
****************************************************************************/
BOOL strhaslower(char *s)
{
  while (*s) 
    {
#ifdef KANJI
	if (is_shift_jis (*s)) {
	    s += 2;
	} else if (is_kana (*s)) {
	    s++;
	} else {
	    if (islower(*s)) return(True);
	    s++;
	}
#else 
      if (islower(*s)) return(True);
      s++;
#endif /* KANJI */
    }
  return(False);
}

/****************************************************************************
find the number of chars in a string
****************************************************************************/
int count_chars(char *s,char c)
{
  int count=0;
  while (*s) 
    {
      if (*s == c)
	count++;
      s++;
    }
  return(count);
}


/****************************************************************************
  make a dir struct
****************************************************************************/
void make_dir_struct(char *buf,char *mask,char *fname,unsigned int size,int mode,time_t date)
{  
  char *p;
  pstring mask2;

  strcpy(mask2,mask);

  if ((mode & aDIR) != 0)
    size = 0;

  memset(buf+1,' ',11);
  if ((p = strchr(mask2,'.')) != NULL)
    {
      *p = 0;
      memcpy(buf+1,mask2,MIN(strlen(mask2),8));
      memcpy(buf+9,p+1,MIN(strlen(p+1),3));
      *p = '.';
    }
  else
    memcpy(buf+1,mask2,MIN(strlen(mask2),11));

  bzero(buf+21,DIR_STRUCT_SIZE-21);
  CVAL(buf,21) = mode;
  put_dos_date(buf,22,date);
  SSVAL(buf,26,size & 0xFFFF);
  SSVAL(buf,28,size >> 16);
  StrnCpy(buf+30,fname,12);
  if (!case_sensitive)
    strupper(buf+30);
  DEBUG(8,("put name [%s] into dir struct\n",buf+30));
}


/*******************************************************************
close the low 3 fd's and open dev/null in their place
********************************************************************/
void close_low_fds(void)
{
  int fd;
  int i;
  close(0); close(1); close(2);
  /* try and use up these file descriptors, so silly
     library routines writing to stdout etc won't cause havoc */
  for (i=0;i<3;i++) {
    fd = open("/dev/null",O_RDWR,0);
    if (fd < 0) fd = open("/dev/null",O_WRONLY,0);
    if (fd < 0) {
      DEBUG(0,("Can't open /dev/null\n"));
      return;
    }
    if (fd != i) {
      DEBUG(0,("Didn't get file descriptor %d\n",i));
      return;
    }
  }
}


/****************************************************************************
write to a socket
****************************************************************************/
int write_socket(int fd,char *buf,int len)
{
  int ret=0;

  if (passive)
    return(len);
  DEBUG(6,("write_socket(%d,%d)\n",fd,len));
  ret = write_data(fd,buf,len);
      
  DEBUG(6,("write_socket(%d,%d) wrote %d\n",fd,len,ret));
  return(ret);
}

/****************************************************************************
read from a socket
****************************************************************************/
int read_udp_socket(int fd,char *buf,int len)
{
  int ret;
  struct sockaddr sock;
  int socklen;
  
  socklen = sizeof(sock);
  bzero((char *)&sock,socklen);
  bzero((char *)&lastip,sizeof(lastip));
  ret = recvfrom(fd,buf,len,0,&sock,&socklen);
  if (ret <= 0)
    {
      DEBUG(2,("read socket failed. ERRNO=%d\n",errno));
      return(0);
    }

  lastip = *(struct in_addr *) &sock.sa_data[2];
  lastport = ntohs(((struct sockaddr_in *)&sock)->sin_port);

  return(ret);
}

/****************************************************************************
Set a fd into blocking/nonblocking mode. Uses POSIX O_NONBLOCK if available,
else
if SYSV use O_NDELAY
if BSD use FNDELAY
****************************************************************************/
int set_blocking(int fd, BOOL set)
{
int val;
#ifdef O_NONBLOCK
#define FLAG_TO_SET O_NONBLOCK
#else
#ifdef SYSV
#define FLAG_TO_SET O_NDELAY
#else /* BSD */
#define FLAG_TO_SET FNDELAY
#endif
#endif

  if((val = fcntl(fd, F_GETFL, 0))==-1)
	return -1;
  if(set) /* Turn blocking on - ie. clear nonblock flag */
	val &= ~FLAG_TO_SET;
  else
    val |= FLAG_TO_SET;
  return fcntl( fd, F_SETFL, val);
#undef FLAG_TO_SET
}


/****************************************************************************
Calculate the difference in timeout values. Return 1 if val1 > val2,
0 if val1 == val2, -1 if val1 < val2. Stores result in retval. retval
may be == val1 or val2
****************************************************************************/
static int tval_sub( struct timeval *retval, struct timeval *val1, struct timeval *val2)
{
  int usecdiff = val1->tv_usec - val2->tv_usec;
  int secdiff = val1->tv_sec - val2->tv_sec;
  if(usecdiff < 0) {
    usecdiff = 1000000 + usecdiff;
    secdiff--;
  }
  retval->tv_sec = secdiff;
  retval->tv_usec = usecdiff;
  if(secdiff < 0)
    return -1;
  if(secdiff > 0)
    return 1;
  return (usecdiff < 0 ) ? -1 : ((usecdiff > 0 ) ? 1 : 0);
}

/****************************************************************************
read data from a device with a timout in msec.
mincount = if timeout, minimum to read before returning
maxcount = number to be read.
****************************************************************************/
int read_with_timeout(int fd,char *buf,int mincnt,int maxcnt,long time_out,BOOL exact)
{
  fd_set fds;
  int selrtn;
  int readret;
  int nread = 0;
  struct timeval timeout, tval1, tval2, tvaldiff;
  int error_limit = 5;

  /* just checking .... */
  if (maxcnt <= 0) return(0);

  if(time_out == -2)
    time_out = DEFAULT_PIPE_TIMEOUT;

  /* Blocking read */
  if(time_out < 0) {
    if (mincnt == 0) mincnt = maxcnt;

    while (nread < mincnt)
      {
	readret = read(fd, buf + nread, maxcnt - nread);
	if (readret <= 0) return(nread);
	nread += readret;
      }
    return(nread);
  }
  
  /* Non blocking read */
  if(time_out == 0) {
    set_blocking(fd, False);
    nread = read_data(fd, buf, mincnt);
    if (nread < maxcnt)
      nread += read(fd,buf+nread,maxcnt-nread);
    if(nread == -1 && errno == EWOULDBLOCK)
      nread = 0;
    set_blocking(fd,True);
    return nread;
  }

  /* Most difficult - timeout read */
  /* If this is ever called on a disk file and 
	 mincnt is greater then the filesize then
	 system performance will suffer severely as 
	 select always return true on disk files */

  /* Set initial timeout */
  timeout.tv_sec = time_out / 1000;
  timeout.tv_usec = 1000 * (time_out % 1000);

  /* As most UNIXes don't modify the value of timeout
     when they return from select we need to get the timeofday (in usec)
     now, and also after the select returns so we know
     how much time has elapsed */

  if (exact)
    GetTimeOfDay( &tval1);
  nread = 0; /* Number of bytes we have read */

  for(;;) 
    {      
      FD_ZERO(&fds);
      FD_SET(fd,&fds);
      
      selrtn = sys_select(&fds,&timeout);
      
      /* Check if error */
      if(selrtn == -1) {
	errno = EBADF;
	return -1;
      }
      
      /* Did we timeout ? */
      if (selrtn == 0) {
	if (nread < mincnt) return -1;
	break; /* Yes */
      }
      
      readret = read(fd, buf+nread, maxcnt-nread);
      if (readret == 0 && nread < mincnt) {
	/* error_limit should not really be needed, but some systems
	   do strange things ...  I don't want to just continue
	   indefinately in case we get an infinite loop */
	if (error_limit--) continue;
	return(-1);
      }

      if (readret < 0) {
	/* force a particular error number for
	   portability */
	DEBUG(5,("read gave error %s\n",strerror(errno)));
	errno = EBADF;
	return -1;
      }
      
      nread += readret;
      
      /* If we have read more than mincnt then return */
      if (nread >= mincnt)
	break;

      /* We need to do another select - but first reduce the
	 time_out by the amount of time already elapsed - if
	 this is less than zero then return */
      if (exact) {
	GetTimeOfDay(&tval2);
	(void)tval_sub( &tvaldiff, &tval2, &tval1);
      
	if (tval_sub(&timeout, &timeout, &tvaldiff) <= 0) 
	  break; /* We timed out */
      }
      
      /* Save the time of day as we need to do the select 
	 again (saves a system call) */
      tval1 = tval2;
    }

  /* Return the number we got */
  return(nread);
}

/****************************************************************************
read data from the client. Maxtime is in milliseconds
****************************************************************************/
int read_max_udp(int fd,char *buffer,int bufsize,int maxtime)
{
  fd_set fds;
  int selrtn;
  int nread;
  struct timeval timeout;
 
  FD_ZERO(&fds);
  FD_SET(fd,&fds);

  timeout.tv_sec = maxtime / 1000;
  timeout.tv_usec = (maxtime % 1000) * 1000;

  selrtn = sys_select(&fds,maxtime>0?&timeout:NULL);

  if (!FD_ISSET(fd,&fds))
    return 0;

  nread = read_udp_socket(fd, buffer, bufsize);

  /* return the number got */
  return(nread);
}

/*******************************************************************
find the difference in milliseconds between two struct timeval
values
********************************************************************/
int TvalDiff(struct timeval *tvalold,struct timeval *tvalnew)
{
  return((tvalnew->tv_sec - tvalold->tv_sec)*1000 + 
	 ((int)tvalnew->tv_usec - (int)tvalold->tv_usec)/1000);	 
}

/****************************************************************************
send a keepalive packet (rfc1002)
****************************************************************************/
BOOL send_keepalive(int client)
{
  unsigned char buf[4];

  buf[0] = 0x85;
  buf[1] = buf[2] = buf[3] = 0;

  return(write_data(client,(char *)buf,4) == 4);
}



/****************************************************************************
  read data from the client, reading exactly N bytes. 
****************************************************************************/
int read_data(int fd,char *buffer,int N)
{
  int  ret;
  int total=0;  
 
  while (total < N)
    {
      ret = read(fd,buffer + total,N - total);

      /* this is for portability */
      if (ret < 0)
	errno = EBADF;

      if (ret <= 0)
	return total;
      total += ret;
    }
  return total;
}


/****************************************************************************
  write data to a fd 
****************************************************************************/
int write_data(int fd,char *buffer,int N)
{
  int total=0;
  int ret;

  while (total < N)
    {
      ret = write(fd,buffer + total,N - total);

      if (ret <= 0)
	return total;

      total += ret;
    }
  return total;
}


/* variables used by the read prediction module */
int rp_fd = -1;
int rp_offset = 0;
int rp_length = 0;
int rp_alloced = 0;
int rp_predict_fd = -1;
int rp_predict_offset = 0;
int rp_predict_length = 0;
int rp_timeout = 5;
time_t rp_time = 0;
char *rp_buffer = NULL;
BOOL predict_skip=False;
time_t smb_last_time=(time_t)0;

/****************************************************************************
handle read prediction on a file
****************************************************************************/
int read_predict(int fd,int offset,char *buf,char **ptr,int num)
{
  int ret = 0;
  int possible = rp_length - (offset - rp_offset);

  possible = MIN(possible,num);

  /* give data if possible */
  if (fd == rp_fd && 
      offset >= rp_offset && 
      possible>0 &&
      smb_last_time-rp_time < rp_timeout)
    {
      ret = possible;
      if (buf)
	memcpy(buf,rp_buffer + (offset-rp_offset),possible);
      else
	*ptr = rp_buffer + (offset-rp_offset);
      DEBUG(5,("read-prediction gave %d bytes of %d\n",ret,num));
    }

  if (ret == num) {
    predict_skip = True;
  } else {
    predict_skip = False;

    /* prepare the next prediction */
    rp_predict_fd = fd;
    rp_predict_offset = offset + num;
    rp_predict_length = num;
  }

  if (ret < 0) ret = 0;

  return(ret);
}

/****************************************************************************
pre-read some data
****************************************************************************/
void do_read_prediction()
{
  if (predict_skip) return;

  if (rp_predict_fd == -1) 
    return;

  rp_fd = rp_predict_fd;
  rp_offset = rp_predict_offset;
  rp_length = 0;

  rp_predict_fd = -1;

  rp_predict_length = MIN(rp_predict_length,2*ReadSize);
  rp_predict_length = MAX(rp_predict_length,1024);
  rp_offset = (rp_offset/1024)*1024;
  rp_predict_length = (rp_predict_length/1024)*1024;

  if (rp_predict_length > rp_alloced)
    {
      rp_buffer = Realloc(rp_buffer,rp_predict_length);
      rp_alloced = rp_predict_length;
      if (!rp_buffer)
	{
	  DEBUG(0,("can't allocate read-prediction buffer\n"));
	  rp_predict_fd = -1;
	  rp_fd = -1;
	  rp_alloced = 0;
	  return;
	}
    }

  if (lseek(rp_fd,rp_offset,SEEK_SET) != rp_offset) {
    rp_fd = -1;
    rp_predict_fd = -1;
    return;
  }

  rp_length = read(rp_fd,rp_buffer,rp_predict_length);
  rp_time = time(NULL);
  if (rp_length < 0)
    rp_length = 0;
}

/****************************************************************************
invalidate read-prediction on a fd
****************************************************************************/
void invalidate_read_prediction(int fd)
{
 if (rp_fd == fd) 
   rp_fd = -1;
 if (rp_predict_fd == fd)
   rp_predict_fd = -1;
}


/****************************************************************************
transfer some data between two fd's
****************************************************************************/
int transfer_file(int infd,int outfd,int n,char *header,int headlen,int align)
{
  static char *buf=NULL;  
  char *buf1,*abuf;
  static int size = 0;
  int total = 0;

  DEBUG(4,("transfer_file %d  (head=%d) called\n",n,headlen));

  if ((size < ReadSize) && buf) {
    free(buf);
    buf = NULL;
  }

  size = MAX(ReadSize,1024);

  while (!buf && size>0) {
    buf = (char *)Realloc(buf,size+8);
    if (!buf) size /= 2;
  }
  if (!buf) {
    DEBUG(0,("Can't allocate transfer buffer!\n"));
    exit(1);
  }

  abuf = buf + (align%8);

  if (header)
    n += headlen;

  while (n > 0)
    {
      int s = MIN(n,size);
      int ret,ret2=0;

      ret = 0;

      if (header && (headlen >= MIN(s,1024))) {
	buf1 = header;
	s = headlen;
	ret = headlen;
	headlen = 0;
	header = NULL;
      } else {
	buf1 = abuf;
      }

      if (header && headlen > 0)
	{
	  ret = MIN(headlen,size);
	  memcpy(buf1,header,ret);
	  headlen -= ret;
	  header += ret;
	  if (headlen <= 0) header = NULL;
	}

      if (s > ret)
	ret += read(infd,buf1+ret,s-ret);

      if (ret > 0)
	{
	  ret2 = (outfd>=0?write_data(outfd,buf1,ret):ret);
	  if (ret2 > 0) total += ret2;
	  /* if we can't write then dump excess data */
	  if (ret2 != ret)
	    transfer_file(infd,-1,n-(ret+headlen),NULL,0,0);
	}
      if (ret <= 0 || ret2 != ret)
	return(total);
      n -= ret;
    }
  return(total);
}


/****************************************************************************
read 4 bytes of a smb packet and return the smb length of the packet
possibly store the result in the buffer
****************************************************************************/
int read_smb_length(int fd,char *inbuf,int timeout)
{
  char *buffer;
  char buf[4];
  int len=0, msg_type;
  BOOL ok=False;

  if (inbuf)
    buffer = inbuf;
  else
    buffer = buf;

  while (!ok)
    {
      if (timeout > 0)
	ok = (read_with_timeout(fd,buffer,4,4,timeout,False) == 4);
      else	
	ok = (read_data(fd,buffer,4) == 4);

      if (!ok)
	{
	  if (timeout>0)
	    {
	      DEBUG(10,("select timeout (%d)\n", timeout));
	      return(-1);
	    }
	  else
	    {
	      DEBUG(6,("couldn't read from client\n"));
	      exit(1);
	    }
	}

      len = smb_len(buffer);
      msg_type = CVAL(buffer,0);

      if (msg_type == 0x85) 
	{
	  DEBUG(5,( "Got keepalive packet\n"));
	  ok = False;
	}
    }

  DEBUG(10,("got smb length of %d\n",len));

  return(len);
}



/****************************************************************************
  read an smb from a fd and return it's length
The timeout is in milli seconds
****************************************************************************/
BOOL receive_smb(int fd,char *buffer,int timeout)
{
  int len;
  BOOL ok;

  bzero(buffer,smb_size + 100);

  len = read_smb_length(fd,buffer,timeout);
  if (len == -1)
    return(False);

  if (len > BUFFER_SIZE)
    {
      DEBUG(0,("Invalid packet length! (%d bytes)\n",len));
      if (len > BUFFER_SIZE + (SAFETY_MARGIN/2))
	exit(1);
    }

  ok = (read_data(fd,buffer+4,len) == len);

  if (!ok)
    {
      close_sockets();
      exit(1);
    }

  return(True);
}


/****************************************************************************
  send an smb to a fd 
****************************************************************************/
BOOL send_smb(int fd,char *buffer)
{
  int len;
  int ret,nwritten=0;
  len = smb_len(buffer) + 4;

  while (nwritten < len)
    {
      ret = write_socket(fd,buffer+nwritten,len - nwritten);
      if (ret <= 0)
	{
	  DEBUG(0,("Error writing %d bytes to client. %d. Exiting\n",len,ret));
          close_sockets();
	  exit(1);
	}
      nwritten += ret;
    }


  return True;
}


/****************************************************************************
find a pointer to a netbios name
****************************************************************************/
char *name_ptr(char *buf,int ofs)
{
  unsigned char c = *(unsigned char *)(buf+ofs);

  if ((c & 0xC0) == 0xC0)
    {
      uint16 l;
      char p[2];
      memcpy(p,buf+ofs,2);
      p[0] &= ~0xC0;
      l = RSVAL(p,0);
      DEBUG(5,("name ptr to pos %d from %d is %s\n",l,ofs,buf+l));
      return(buf + l);
    }
  else
    return(buf+ofs);
}  

/****************************************************************************
extract a netbios name from a buf
****************************************************************************/
int name_extract(char *buf,int ofs,char *name)
{
  char *p = name_ptr(buf,ofs);
  int d = PTR_DIFF(p,buf+ofs);
  strcpy(name,"");
  if (d < -50 || d > 50) return(0);
  return(name_interpret(p,name));
}  
  

/****************************************************************************
return the total storage length of a mangled name
****************************************************************************/
int name_len(char *s)
{
  char *s0=s;
  unsigned char c = *(unsigned char *)s;
  if ((c & 0xC0) == 0xC0)
    return(2);
  while (*s) s += (*s)+1;
  return(PTR_DIFF(s,s0)+1);
}

/****************************************************************************
send a single packet to a port on another machine
****************************************************************************/
BOOL send_one_packet(char *buf,int len,struct in_addr ip,int port,int type)
{
  BOOL ret;
  int out_fd;
  struct sockaddr_in sock_out;

  if (passive)
    return(True);

  /* create a socket to write to */
  out_fd = socket(AF_INET, type, 0);
  if (out_fd == -1) 
    {
      DEBUG(0,("socket failed"));
      return False;
    }

  /* set the address and port */
  bzero((char *)&sock_out,sizeof(sock_out));
  putip((char *)&sock_out.sin_addr,(char *)&ip);
  sock_out.sin_port = htons( port );
  sock_out.sin_family = AF_INET;
  
  if (DEBUGLEVEL > 0)
    DEBUG(3,("sending a packet of len %d to (%s) on port %d of type %s\n",
	     len,inet_ntoa(ip),port,type==SOCK_DGRAM?"DGRAM":"STREAM"));
	
  /* send it */
  ret = (sendto(out_fd,buf,len,0,(struct sockaddr *)&sock_out,sizeof(sock_out)) >= 0);

  if (!ret)
    DEBUG(0,("Packet send to %s(%d) failed ERRNO=%d\n",
	     inet_ntoa(ip),port,errno));

  close(out_fd);
  return(ret);
}

/*******************************************************************
sleep for a specified number of milliseconds
********************************************************************/
void msleep(int t)
{
  int tdiff=0;
  struct timeval tval,t1,t2;  
  fd_set fds;

  GetTimeOfDay(&t1);
  GetTimeOfDay(&t2);
  
  while (tdiff < t) {
    tval.tv_sec = (t-tdiff)/1000;
    tval.tv_usec = 1000*((t-tdiff)%1000);
 
    FD_ZERO(&fds);
    errno = 0;
    sys_select(&fds,&tval);

    GetTimeOfDay(&t2);
    tdiff = TvalDiff(&t1,&t2);
  }
}

/****************************************************************************
check if a string is part of a list
****************************************************************************/
BOOL in_list(char *s,char *list,BOOL casesensitive)
{
  pstring tok;
  char *p=list;

  if (!list) return(False);

  while (next_token(&p,tok,LIST_SEP))
    {
      if (casesensitive) {
	if (strcmp(tok,s) == 0)
	  return(True);
      } else {
	if (StrCaseCmp(tok,s) == 0)
	  return(True);
      }
    }
  return(False);
}

/* this is used to prevent lots of mallocs of size 1 */
static char *null_string = NULL;

/****************************************************************************
set a string value, allocing the space for the string
****************************************************************************/
BOOL string_init(char **dest,char *src)
{
  int l;
  if (!src)     
    src = "";

  l = strlen(src);

  if (l == 0)
    {
      if (!null_string)
	null_string = (char *)malloc(1);

      *null_string = 0;
      *dest = null_string;
    }
  else
    {
      *dest = (char *)malloc(l+1);
      strcpy(*dest,src);
    }
  return(True);
}

/****************************************************************************
free a string value
****************************************************************************/
void string_free(char **s)
{
  if (!s || !(*s)) return;
  if (*s == null_string)
    *s = NULL;
  if (*s) free(*s);
  *s = NULL;
}

/****************************************************************************
set a string value, allocing the space for the string, and deallocating any 
existing space
****************************************************************************/
BOOL string_set(char **dest,char *src)
{
  string_free(dest);

  return(string_init(dest,src));
}

/****************************************************************************
substitute a string for a pattern in another string. Make sure there is 
enough room!

This routine looks for pattern in s and replaces it with 
insert. It may do multiple replacements.

return True if a substitution was done.
****************************************************************************/
BOOL string_sub(char *s,char *pattern,char *insert)
{
  BOOL ret = False;
  char *p;
  int ls,lp,li;

  if (!insert || !pattern || !s) return(False);

  ls = strlen(s);
  lp = strlen(pattern);
  li = strlen(insert);

  if (!*pattern) return(False);

  while (lp <= ls && (p = strstr(s,pattern)))
    {
      ret = True;
      memmove(p+li,p+lp,ls + 1 - (PTR_DIFF(p,s) + lp));
      memcpy(p,insert,li);
      s = p + li;
      ls = strlen(s);
    }
  return(ret);
}



/*********************************************************
* Recursive routine that is called by mask_match.
* Does the actual matching.
*********************************************************/
BOOL do_match(char *str, char *regexp, int case_sig)
{
  char *p;

  for( p = regexp; *p && *str; ) {
    switch(*p) {
    case '?':
      str++; p++;
      break;

    case '*':
      /* Look for a character matching 
	 the one after the '*' */
      p++;
      if(!*p)
	return True; /* Automatic match */
      while(*str) {
	while(*str && (case_sig ? (*p != *str) : (toupper(*p)!=toupper(*str))))
	  str++;
	if(do_match(str,p,case_sig))
	  return True;
	if(!*str)
	  return False;
	else
	  str++;
      }
      return False;

    default:
      if(case_sig) {
	if(*str != *p)
	  return False;
      } else {
	if(toupper(*str) != toupper(*p))
	  return False;
      }
      str++, p++;
      break;
    }
  }
  if(!*p && !*str)
    return True;

  if (!*p && str[0] == '.' && str[1] == 0)
    return(True);
  
  if (!*str && *p == '?')
    {
      while (*p == '?') p++;
      return(!*p);
    }

  if(!*str && (*p == '*' && p[1] == '\0'))
    return True;
  return False;
}


/*********************************************************
* Routine to match a given string with a regexp - uses
* simplified regexp that takes * and ? only. Case can be
* significant or not.
*********************************************************/
BOOL mask_match(char *str, char *regexp, int case_sig,BOOL trans2)
{
  char *p;
  pstring p1, p2;
  fstring ebase,eext,sbase,sext;

  BOOL matched;

  /* Make local copies of str and regexp */
  StrnCpy(p1,regexp,sizeof(pstring)-1);
  StrnCpy(p2,str,sizeof(pstring)-1);

  if (!strchr(p2,'.')) {
    strcat(p2,".");
  }

/*
  if (!strchr(p1,'.')) {
    strcat(p1,".");
  }
*/

#if 0
  if (strchr(p1,'.'))
    {
      string_sub(p1,"*.*","*");
      string_sub(p1,".*","*");
    }
#endif

  /* Remove any *? and ** as they are meaningless */
  for(p = p1; *p; p++)
    while( *p == '*' && (p[1] == '?' ||p[1] == '*'))
      (void)strcpy( &p[1], &p[2]);

  if (strequal(p1,"*")) return(True);

  DEBUG(5,("mask_match str=<%s> regexp=<%s>, case_sig = %d\n", p2, p1, case_sig));

  if (trans2) {
    strcpy(ebase,p1);
    strcpy(sbase,p2);
  } else {
    if ((p=strrchr(p1,'.'))) {
      *p = 0;
      strcpy(ebase,p1);
      strcpy(eext,p+1);
    } else {
      strcpy(ebase,p1);
      eext[0] = 0;
    }

  if (!strequal(p2,".") && !strequal(p2,"..") && (p=strrchr(p2,'.'))) {
    *p = 0;
    strcpy(sbase,p2);
    strcpy(sext,p+1);
  } else {
    strcpy(sbase,p2);
    strcpy(sext,"");
  }
  }

  matched = do_match(sbase,ebase,case_sig) && 
    (trans2 || do_match(sext,eext,case_sig));

  DEBUG(5,("mask_match returning %d\n", matched));

  return matched;
}



/****************************************************************************
become a daemon, discarding the controlling terminal
****************************************************************************/
void become_daemon(void)
{
#ifndef NO_FORK_DEBUG
  if (fork())
    exit(0);

  /* detach from the terminal */
#ifdef USE_SETSID
  setsid();
#else
#ifdef TIOCNOTTY
  {
    int i = open("/dev/tty", O_RDWR);
    if (i >= 0) 
      {
	ioctl(i, (int) TIOCNOTTY, (char *)0);      
	close(i);
      }
  }
#endif
#endif
#endif
}

/****************************************************************************
calculate the default netmask for an address
****************************************************************************/
static void default_netmask(struct in_addr *inm, struct in_addr *iad)
{
  unsigned long ad = ntohl(iad->s_addr);
  unsigned long nm;
  /*
  ** Guess a netmask based on the class of the IP address given.
  */
  if ( (ad & 0x80000000) == 0 ) {
    /* class A address */
    nm = 0xFF000000;
  } else if ( (ad & 0xC0000000) == 0x80000000 ) {
    /* class B address */
    nm = 0xFFFF0000;
  } else if ( (ad & 0xE0000000) == 0xC0000000 ) {
    /* class C address */
    nm = 0xFFFFFF00;
  }  else {
    /* class D or E; netmask doesn't make much sense - guess 4 bits */
    nm =  0xFFFFFFF0;
  }
  inm->s_addr = htonl(nm);
}

/****************************************************************************
  get the broadcast address for our address 
(troyer@saifr00.ateng.az.honeywell.com)
****************************************************************************/
void get_broadcast(struct in_addr *if_ipaddr,
                    struct in_addr *if_bcast,
                    struct in_addr *if_nmask)
{  
  BOOL found = False;
#ifndef NO_GET_BROADCAST
  int sock = -1;               /* AF_INET raw socket desc */
  char buff[1024];
  struct ifreq *ifr=NULL;
  int i;

#if defined(EVEREST)
  int n_interfaces;
  struct ifconf ifc;
  struct ifreq  *ifreqs;
#elif defined(USE_IFREQ)
  struct ifreq ifreq;
  struct strioctl strioctl;
  struct ifconf *ifc;
#else
  struct ifconf ifc;
#endif
#endif

  /* get a default netmask and broadcast */
  default_netmask(if_nmask, if_ipaddr);

#ifndef NO_GET_BROADCAST  
  /* Create a socket to the INET kernel. */
#if USE_SOCKRAW
  if ((sock = socket(AF_INET, SOCK_RAW, PF_INET )) < 0)
#else
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0 )) < 0)
#endif
      {
        DEBUG(0,( "Unable to open socket to get broadcast address\n"));
        return;
      }
  
  /* Get a list of the configured interfaces */
#ifdef EVEREST
  /* This is part of SCO Openserver 5: The ioctls are no longer part
     if the lower level STREAMS interface glue. They are now real
     ioctl calls */

  if (ioctl(sock, SIOCGIFANUM, &n_interfaces) < 0) {
    DEBUG(0,( "SIOCGIFANUM: %s\n", strerror(errno)));
  } else {
    DEBUG(0,( "number of interfaces returned is: %d\n", n_interfaces));

    ifc.ifc_len = sizeof(struct ifreq) * n_interfaces;
    ifc.ifc_buf = (caddr_t) alloca(ifc.ifc_len);

    if (ioctl(sock, SIOCGIFCONF, &ifc) < 0)
      DEBUG(0, ( "SIOCGIFCONF: %s\n", strerror(errno)));
    else {
      ifr = ifc.ifc_req;

      for (i = 0; i < n_interfaces; ++i) {
	if (if_ipaddr->s_addr ==
	    ((struct sockaddr_in *) &ifr[i].ifr_addr)->sin_addr.s_addr) {
	  found = True;
	  break;
	}
      }
    }
  }
#elif defined(USE_IFREQ)
  ifc = (struct ifconf *)buff;
  ifc->ifc_len = BUFSIZ - sizeof(struct ifconf);
  strioctl.ic_cmd = SIOCGIFCONF;
  strioctl.ic_dp  = (char *)ifc;
  strioctl.ic_len = sizeof(buff);
  if (ioctl(sock, I_STR, &strioctl) < 0) {
    DEBUG(0,( "I_STR/SIOCGIFCONF: %s\n", strerror(errno)));
  } else {
    ifr = (struct ifreq *)ifc->ifc_req;  

    /* Loop through interfaces, looking for given IP address */
    for (i = ifc->ifc_len / sizeof(struct ifreq); --i >= 0; ifr++) {
      if (if_ipaddr->s_addr ==
	  (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr.s_addr) {
	found = True;
	break;
      }
    }
  }
#elif defined(__FreeBSD__) || defined(NETBSD)
  ifc.ifc_len = sizeof(buff);
  ifc.ifc_buf = buff;
  if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
    DEBUG(0,("SIOCGIFCONF: %s\n", strerror(errno)));
  } else {
    ifr = ifc.ifc_req;
    /* Loop through interfaces, looking for given IP address */
    i = ifc.ifc_len;
    while (i > 0) {
      if (if_ipaddr->s_addr ==
	  (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr.s_addr) {
	found = True;
	break;
      }
      i -= ifr->ifr_addr.sa_len + IFNAMSIZ;
      ifr = (struct ifreq*) ((char*) ifr + ifr->ifr_addr.sa_len + IFNAMSIZ);
    }
  }
#else
  ifc.ifc_len = sizeof(buff);
  ifc.ifc_buf = buff;
  if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
    DEBUG(0,("SIOCGIFCONF: %s\n", strerror(errno)));
  } else {
    ifr = ifc.ifc_req;
  
    /* Loop through interfaces, looking for given IP address */
    for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; ifr++) {
#ifdef BSDI
      if (ioctl(sock, SIOCGIFADDR, ifr) < 0) break;
#endif
      if (if_ipaddr->s_addr ==
	  (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr.s_addr) {
	found = True;
	break;
      }
    }
  }
#endif
  
  if (!found) {
    DEBUG(0,("No interface found for address %s\n", inet_ntoa(*if_ipaddr)));
  } else {
    /* Get the netmask address from the kernel */
#ifdef USE_IFREQ
    ifreq = *ifr;
  
    strioctl.ic_cmd = SIOCGIFNETMASK;
    strioctl.ic_dp  = (char *)&ifreq;
    strioctl.ic_len = sizeof(struct ifreq);
    if (ioctl(sock, I_STR, &strioctl) < 0)
      DEBUG(0,("Failed I_STR/SIOCGIFNETMASK: %s\n", strerror(errno)));
    else
      *if_nmask = ((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr;
#else
    if (ioctl(sock, SIOCGIFNETMASK, ifr) < 0)
      DEBUG(0,("SIOCGIFNETMASK failed\n"));
    else
      *if_nmask = ((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr;
#endif

    DEBUG(2,("Netmask for %s = %s\n", ifr->ifr_name,
	     inet_ntoa(*if_nmask)));
  }

  /* Close up shop */
  (void) close(sock);
  
#endif

  /* sanity check on the netmask */
  {
    unsigned long nm = ntohl(if_nmask->s_addr);
    if ((nm >> 24) != 0xFF) {
      DEBUG(0,("Impossible netmask %s - using defaults\n",inet_ntoa(*if_nmask)));
      default_netmask(if_nmask, if_ipaddr);      
    }
  }

  /* derive the broadcast assuming a 1's broadcast, as this is what
     all MS operating systems do, we have to comply even if the unix
     box is setup differently */
  {
    unsigned long ad = ntohl(if_ipaddr->s_addr);
    unsigned long nm = ntohl(if_nmask->s_addr);
    unsigned long bc = (ad & nm) | (0xffffffff & ~nm);
    if_bcast->s_addr = htonl(bc);
  }
  
  DEBUG(2,("Derived broadcast address %s\n", inet_ntoa(*if_bcast)));
}  /* get_broadcast */


/****************************************************************************
put up a yes/no prompt
****************************************************************************/
BOOL yesno(char *p)
{
  pstring ans;
  printf("%s",p);

  if (!fgets(ans,sizeof(ans)-1,stdin))
    return(False);

  if (*ans == 'y' || *ans == 'Y')
    return(True);

  return(False);
}

/****************************************************************************
read a line from a file with possible \ continuation chars. 
Blanks at the start or end of a line are stripped.
The string will be allocated if s2 is NULL
****************************************************************************/
char *fgets_slash(char *s2,int maxlen,FILE *f)
{
  char *s=s2;
  int len = 0;
  int c;
  BOOL start_of_line = True;

  if (feof(f))
    return(NULL);

  if (!s2)
    {
      maxlen = MIN(maxlen,8);
      s = (char *)Realloc(s,maxlen);
    }

  if (!s || maxlen < 2) return(NULL);

  *s = 0;

  while (len < maxlen-1)
    {
      c = getc(f);
      switch (c)
	{
	case '\r':
	  break;
	case '\n':
	  while (len > 0 && s[len-1] == ' ')
	    {
	      s[--len] = 0;
	    }
	  if (len > 0 && s[len-1] == '\\')
	    {
	      s[--len] = 0;
	      start_of_line = True;
	      break;
	    }
	  return(s);
	case EOF:
	  if (len <= 0 && !s2) 
	    free(s);
	  return(len>0?s:NULL);
	case ' ':
	  if (start_of_line)
	    break;
	default:
	  start_of_line = False;
	  s[len++] = c;
	  s[len] = 0;
	}
      if (!s2 && len > maxlen-3)
	{
	  maxlen *= 2;
	  s = (char *)Realloc(s,maxlen);
	  if (!s) return(NULL);
	}
    }
  return(s);
}



/****************************************************************************
set the length of a file from a filedescriptor.
Returns 0 on success, -1 on failure.
****************************************************************************/
int set_filelen(int fd, long len)
{
/* According to W. R. Stevens advanced UNIX prog. Pure 4.3 BSD cannot
   extend a file with ftruncate. Provide alternate implementation
   for this */

#if FTRUNCATE_CAN_EXTEND
  return ftruncate(fd, len);
#else
  struct stat st;
  char c = 0;
  long currpos = lseek(fd, 0L, SEEK_CUR);

  if(currpos < 0)
    return -1;
  /* Do an fstat to see if the file is longer than
     the requested size (call ftruncate),
     or shorter, in which case seek to len - 1 and write 1
     byte of zero */
  if(fstat(fd, &st)<0)
    return -1;

#ifdef S_ISFIFO
  if (S_ISFIFO(st.st_mode)) return 0;
#endif

  if(st.st_size == len)
    return 0;
  if(st.st_size > len)
    return ftruncate(fd, len);

  if(lseek(fd, len-1, SEEK_SET) != len -1)
    return -1;
  if(write(fd, &c, 1)!=1)
    return -1;
  /* Seek to where we were */
  lseek(fd, currpos, SEEK_SET);
  return 0;
#endif
}


/****************************************************************************
return the byte checksum of some data
****************************************************************************/
int byte_checksum(char *buf,int len)
{
  unsigned char *p = (unsigned char *)buf;
  int ret = 0;
  while (len--)
    ret += *p++;
  return(ret);
}



#ifdef HPUX
/****************************************************************************
this is a version of setbuffer() for those machines that only have setvbuf
****************************************************************************/
void setbuffer(FILE *f,char *buf,int bufsize)
{
  setvbuf(f,buf,_IOFBF,bufsize);
}
#endif


/****************************************************************************
parse out a directory name from a path name. Assumes dos style filenames.
****************************************************************************/
char *dirname_dos(char *path,char *buf)
{
  char *p = strrchr(path,'\\');

  if (!p)
    strcpy(buf,path);
  else
    {
      *p = 0;
      strcpy(buf,path);
      *p = '\\';
    }

  return(buf);
}


/****************************************************************************
parse out a filename from a path name. Assumes dos style filenames.
****************************************************************************/
static char *filename_dos(char *path,char *buf)
{
  char *p = strrchr(path,'\\');

  if (!p)
    strcpy(buf,path);
  else
    strcpy(buf,p+1);

  return(buf);
}



/****************************************************************************
expand a pointer to be a particular size
****************************************************************************/
void *Realloc(void *p,int size)
{
  void *ret=NULL;
  if (!p)
    ret = (void *)malloc(size);
  else
    ret = (void *)realloc(p,size);

  if (!ret)
    DEBUG(0,("Memory allocation error: failed to expand to %d bytes\n",size));

  return(ret);
}

/****************************************************************************
set the time on a file
****************************************************************************/
BOOL set_filetime(char *fname,time_t mtime)
{  
  struct utimbuf times;

  if (null_mtime(mtime)) return(True);

  times.modtime = times.actime = mtime;

  if (sys_utime(fname,&times)) {
    DEBUG(4,("set_filetime(%s) failed: %s\n",fname,strerror(errno)));
  }
    
  return(True);
}


#ifdef NOSTRDUP
/****************************************************************************
duplicate a string
****************************************************************************/
char *strdup(char *s)
{
  char *ret = NULL;
  if (!s) return(NULL);
  ret = (char *)malloc(strlen(s)+1);
  if (!ret) return(NULL);
  strcpy(ret,s);
  return(ret);
}
#endif


/****************************************************************************
  Signal handler for SIGPIPE (write on a disconnected socket) 
****************************************************************************/
void Abort(void )
{
  DEBUG(0,("Probably got SIGPIPE\nExiting\n"));
  exit(2);
}


#ifdef REPLACE_STRLEN
/****************************************************************************
a replacement strlen() that returns int for solaris
****************************************************************************/
int Strlen(char *s)
{
  int ret=0;
  if (!s) return(0);
  while (*s++) ret++;
  return(ret);
}
#endif


/****************************************************************************
return a time at the start of the current month
****************************************************************************/
time_t start_of_month(void)
{
  time_t t = time(NULL);
  struct tm *t2;
  
  t2 = gmtime(&t);
  
  t2->tm_mday = 1;
  t2->tm_hour = 0;
  t2->tm_min = 0;
  t2->tm_sec = 0;
  
  return(mktime(t2));
}


/*******************************************************************
  check for a sane unix date
********************************************************************/
BOOL sane_unix_date(time_t unixdate)
{
  struct tm t,today;
  time_t t_today = time(NULL);
  
  t = *(LocalTime(&unixdate,LOCAL_TO_GMT));
  today = *(LocalTime(&t_today,LOCAL_TO_GMT));
  
  if (t.tm_year < 80)
    return(False);
  
  if (t.tm_year >  today.tm_year)
    return(False);
  
  if (t.tm_year == today.tm_year &&
      t.tm_mon > today.tm_mon)
    return(False);
  
  
  if (t.tm_year == today.tm_year &&
      t.tm_mon == today.tm_mon &&
      t.tm_mday > (today.tm_mday+1))
    return(False);
  
  return(True);
}



#ifdef NO_FTRUNCATE
 /*******************************************************************
ftruncate for operating systems that don't have it
********************************************************************/
int ftruncate(int f,long l)
{
      struct  flock   fl;

      fl.l_whence = 0;
      fl.l_len = 0;
      fl.l_start = l;
      fl.l_type = F_WRLCK;
      return fcntl(f, F_FREESP, &fl);
}
#endif



/****************************************************************************
get my own name and IP
****************************************************************************/
BOOL get_myname(char *myname,struct in_addr *ip)
{
  struct hostent *hp;
  pstring hostname;

  *hostname = 0;

  /* get my host name */
  if (gethostname(hostname, MAXHOSTNAMELEN) == -1) 
    {
      DEBUG(0,("gethostname failed\n"));
      return False;
    } 

  /* get host info */
  if ((hp = Get_Hostbyname(hostname)) == 0) 
    {
      DEBUG(0,( "Get_Hostbyname: Unknown host %s.\n",hostname));
      return False;
    }

  if (myname)
    {
      /* split off any parts after an initial . */
      char *p = strchr(hostname,'.');
      if (p) *p = 0;

      strcpy(myname,hostname);
    }

  if (ip)
    putip((char *)ip,(char *)hp->h_addr);

  return(True);
}


/****************************************************************************
true if two IP addresses are equal
****************************************************************************/
BOOL ip_equal(struct in_addr ip1,struct in_addr ip2)
{
  unsigned long a1,a2;
  a1 = ntohl(ip1.s_addr);
  a2 = ntohl(ip2.s_addr);
  return(a1 == a2);
}


/****************************************************************************
open a socket of the specified type, port and address for incoming data
****************************************************************************/
int open_socket_in(int type, int port, int dlevel)
{
  struct hostent *hp;
  struct sockaddr_in sock;
  pstring host_name;
  int res;

  /* get my host name */
#ifdef MAXHOSTNAMELEN
  if (gethostname(host_name, MAXHOSTNAMELEN) == -1) 
#else
  if (gethostname(host_name, sizeof(host_name)) == -1) 
#endif
    { DEBUG(0,("gethostname failed\n")); return -1; } 

  /* get host info */
  if ((hp = Get_Hostbyname(host_name)) == 0) 
    {
      DEBUG(0,( "Get_Hostbyname: Unknown host. %s\n",host_name));
      return -1;
    }
  
  bzero((char *)&sock,sizeof(sock));
  memcpy((char *)&sock.sin_addr,(char *)hp->h_addr, hp->h_length);
#if defined(__FreeBSD__) || defined(NETBSD) /* XXX not the right ifdef */
  sock.sin_len = sizeof(sock);
#endif
  sock.sin_port = htons( port );
  sock.sin_family = hp->h_addrtype;
  sock.sin_addr.s_addr = INADDR_ANY;
  res = socket(hp->h_addrtype, type, 0);
  if (res == -1) 
    { DEBUG(0,("socket failed\n")); return -1; }

  {
    int one=1;
    setsockopt(res,SOL_SOCKET,SO_REUSEADDR,(char *)&one,sizeof(one));
  }

  /* now we've got a socket - we need to bind it */
  if (bind(res, (struct sockaddr * ) &sock,sizeof(sock)) < 0) 
    { 
      if (port) {
	if (port == 139 || port == 137)
	  DEBUG(dlevel,("bind failed on port %d (%s)\n",
			port,strerror(errno))); 
	close(res); 

	if (dlevel > 0 && port < 1000)
	  port = 7999;

	if (port >= 1000 && port < 9000)
	  return(open_socket_in(type,port+1,dlevel));
      }

      return(-1); 
    }
  DEBUG(3,("bind succeeded on port %d\n",port));

  return res;
}


/****************************************************************************
  create an outgoing socket
  **************************************************************************/
int open_socket_out(int type, struct in_addr *addr, int port )
{
  struct sockaddr_in sock_out;
  int res;

  /* create a socket to write to */
  res = socket(PF_INET, type, 0);
  if (res == -1) 
    { DEBUG(0,("socket error\n")); return -1; }

  if (type != SOCK_STREAM) return(res);
  
  bzero((char *)&sock_out,sizeof(sock_out));
  putip((char *)&sock_out.sin_addr,(char *)addr);
  
  sock_out.sin_port = htons( port );
  sock_out.sin_family = PF_INET;

  DEBUG(3,("Connecting to %s at port %d\n",inet_ntoa(*addr),port));
  
  /* and connect it to the destination */
  if (connect(res,(struct sockaddr *)&sock_out,sizeof(sock_out))<0) {
    DEBUG(0,("connect error: %s\n",strerror(errno))); 
    close(res); 
    return(-1);
  }

  return res;
}


/****************************************************************************
interpret a protocol description string, with a default
****************************************************************************/
int interpret_protocol(char *str,int def)
{
  if (strequal(str,"NT1"))
    return(PROTOCOL_NT1);
  if (strequal(str,"LANMAN2"))
    return(PROTOCOL_LANMAN2);
  if (strequal(str,"LANMAN1"))
    return(PROTOCOL_LANMAN1);
  if (strequal(str,"CORE"))
    return(PROTOCOL_CORE);
  if (strequal(str,"COREPLUS"))
    return(PROTOCOL_COREPLUS);
  if (strequal(str,"CORE+"))
    return(PROTOCOL_COREPLUS);
  
  DEBUG(0,("Unrecognised protocol level %s\n",str));
  
  return(def);
}

/****************************************************************************
interpret a security level
****************************************************************************/
int interpret_security(char *str,int def)
{
  if (strequal(str,"SERVER"))
    return(SEC_SERVER);
  if (strequal(str,"USER"))
    return(SEC_USER);
  if (strequal(str,"SHARE"))
    return(SEC_SHARE);
  
  DEBUG(0,("Unrecognised security level %s\n",str));
  
  return(def);
}


/****************************************************************************
interpret an internet address or name into an IP address in 4 byte form
****************************************************************************/
unsigned long interpret_addr(char *str)
{
  struct hostent *hp;
  unsigned long res;

  if (strcmp(str,"0.0.0.0") == 0) return(0);
  if (strcmp(str,"255.255.255.255") == 0) return(0xFFFFFFFF);

  /* if it's in the form of an IP address then get the lib to interpret it */
  if (isdigit(str[0])) {
    res = inet_addr(str);
  } else {
    /* otherwise assume it's a network name of some sort and use Get_Hostbyname */
    if ((hp = Get_Hostbyname(str)) == 0) {
      DEBUG(3,("Get_Hostbyname: Unknown host. %s\n",str));
      return 0;
    }
    putip((char *)&res,(char *)hp->h_addr);
  }

  if (res == (unsigned long)-1) return(0);

  return(res);
}

/*******************************************************************
  a convenient addition to interpret_addr()
  ******************************************************************/
struct in_addr *interpret_addr2(char *str)
{
  static struct in_addr ret;
  unsigned long a = interpret_addr(str);
  putip((char *)&ret,(char *)&a);
  return(&ret);
}

/*******************************************************************
  check if an IP is the 0.0.0.0
  ******************************************************************/
BOOL zero_ip(struct in_addr ip)
{
  unsigned long a;
  putip((char *)&a,(char *)&ip);
  return(a == 0);
}

#define TIME_FIXUP_CONSTANT (369.0*365.25*24*60*60-(3.0*24*60*60+6.0*60*60))

/****************************************************************************
interpret an 8 byte "filetime" structure to a time_t
It's originally in "100ns units since jan 1st 1601"

It appears to be kludge-GMT (at least for file listings). This means
its the GMT you get by taking a localtime and adding the
serverzone. This is NOT the same as GMT in some cases. This routine
converts this to real GMT.
****************************************************************************/
time_t interpret_long_date(char *p)
{
  double d;
  time_t ret;
  uint32 tlow,thigh;
  tlow = IVAL(p,0);
  thigh = IVAL(p,4);

  if (thigh == 0) return(0);

  d = ((double)thigh)*4.0*(double)(1<<30);
  d += (tlow&0xFFF00000);
  d *= 1.0e-7;
 
  /* now adjust by 369 years to make the secs since 1970 */
  d -= TIME_FIXUP_CONSTANT;

  if (d>=MAXINT)
    return(0);

  ret = (time_t)(d+0.5);

  /* this takes us from kludge-GMT to real GMT */
  ret += TimeDiff(ret) - serverzone;

  return(ret);
}


/****************************************************************************
put a 8 byte filetime from a time_t
This takes real GMT as input and converts to kludge-GMT
****************************************************************************/
void put_long_date(char *p,time_t t)
{
  uint32 tlow,thigh;
  double d;

  if (t==0) {
    SIVAL(p,0,0); SIVAL(p,4,0);
    return;
  }

  /* this converts GMT to kludge-GMT */
  t -= TimeDiff(t) - serverzone; 

  d = (double) (t);

  d += TIME_FIXUP_CONSTANT;

  d *= 1.0e7;

  thigh = (uint32)(d * (1.0/(4.0*(double)(1<<30))));
  tlow = (uint32)(d - ((double)thigh)*4.0*(double)(1<<30));

  SIVAL(p,0,tlow);
  SIVAL(p,4,thigh);
}

/*******************************************************************
sub strings with useful parameters
********************************************************************/
void standard_sub_basic(char *s)
{
  if (!strchr(s,'%')) return;

  string_sub(s,"%R",remote_proto);
  string_sub(s,"%a",remote_arch);
  string_sub(s,"%m",remote_machine);
  string_sub(s,"%L",local_machine);

  if (!strchr(s,'%')) return;

  string_sub(s,"%v",VERSION);
  string_sub(s,"%h",myhostname);
  string_sub(s,"%U",sesssetup_user);

  if (!strchr(s,'%')) return;

  string_sub(s,"%I",Client_info.addr);
  string_sub(s,"%M",Client_info.name);
  string_sub(s,"%T",timestring());

  if (!strchr(s,'%')) return;

  {
    char pidstr[10];
    sprintf(pidstr,"%d",(int)getpid());
    string_sub(s,"%d",pidstr);
  }

  if (!strchr(s,'%')) return;

  {
    struct passwd *pass = Get_Pwnam(sesssetup_user,False);
    if (pass) {
      string_sub(s,"%G",gidtoname(pass->pw_gid));
    }
  }
}


/*******************************************************************
write a string in unicoode format
********************************************************************/
int PutUniCode(char *dst,char *src)
{
  int ret = 0;
  while (*src) {
    dst[ret++] = src[0];
    dst[ret++] = 0;    
    src++;
  }
  dst[ret++]=0;
  dst[ret++]=0;
  return(ret);
}


pstring smbrun_path = SMBRUN;

/****************************************************************************
run a command via system() using smbrun
****************************************************************************/
int smbrun(char *cmd,char *outfile)
{
  int ret;
  pstring syscmd;  

  if (!file_exist(smbrun_path,NULL))
    {
      DEBUG(0,("SMBRUN ERROR: Can't find %s. Installation problem?\n",smbrun_path));
      return(1);
    }

  sprintf(syscmd,"%s \"(%s 2>&1) > %s\"",
	  smbrun_path,cmd,
	  outfile?outfile:"/dev/null");

  DEBUG(5,("smbrun - running %s ",syscmd));
  ret = system(syscmd);
  DEBUG(5,("gave %d\n",ret));
  return(ret);
}


/****************************************************************************
a wrapper for gethostbyname() that tries with all lower and all upper case 
if the initial name fails
****************************************************************************/
struct hostent *Get_Hostbyname(char *name)
{
  char *name2 = strdup(name);
  struct hostent *ret;

  if (!name2)
    {
      DEBUG(0,("Memory allocation error in Get_Hostbyname! panic\n"));
      exit(0);
    }

  if (!isalnum(*name2))
    {
      free(name2);
      return(NULL);
    }

  ret = gethostbyname(name2);
  if (ret != NULL)
    {
      free(name2);
      return(ret);
    }

  /* try with all lowercase */
  strlower(name2);
  ret = gethostbyname(name2);
  if (ret != NULL)
    {
      free(name2);
      return(ret);
    }

  /* try with all uppercase */
  strupper(name2);
  ret = gethostbyname(name2);
  if (ret != NULL)
    {
      free(name2);
      return(ret);
    }
  
  /* nothing works :-( */
  free(name2);
  return(NULL);
}


/****************************************************************************
check if a process exists. Does this work on all unixes?
****************************************************************************/
BOOL process_exists(int pid)
{
#ifdef LINUX
  fstring s;
  sprintf(s,"/proc/%d",pid);
  return(directory_exist(s,NULL));
#else
  {
    static BOOL tested=False;
    static BOOL ok=False;
    fstring s;
    if (!tested) {
      tested = True;
      sprintf(s,"/proc/%05d",getpid());
      ok = file_exist(s,NULL);
    }
    if (ok) {
      sprintf(s,"/proc/%05d",pid);
      return(file_exist(s,NULL));
    }
  }

  /* a best guess for non root access */
  if (geteuid() != 0) return(True);

  /* otherwise use kill */
  return(pid == getpid() || kill(pid,0) == 0);
#endif
}


/*******************************************************************
turn a uid into a user name
********************************************************************/
char *uidtoname(int uid)
{
  static char name[40];
  struct passwd *pass = getpwuid(uid);
  if (pass) return(pass->pw_name);
  sprintf(name,"%d",uid);
  return(name);
}

/*******************************************************************
turn a gid into a group name
********************************************************************/
char *gidtoname(int gid)
{
  static char name[40];
  struct group *grp = getgrgid(gid);
  if (grp) return(grp->gr_name);
  sprintf(name,"%d",gid);
  return(name);
}

/*******************************************************************
block sigs
********************************************************************/
void BlockSignals(BOOL block)
{
#ifdef USE_SIGBLOCK
  int block_mask = (sigmask(SIGTERM)|sigmask(SIGQUIT)|sigmask(SIGSEGV)
		    |sigmask(SIGCHLD)|sigmask(SIGQUIT)|sigmask(SIGBUS)|
		    sigmask(SIGINT));
  if (block) 
    sigblock(block_mask);
  else
    sigunblock(block_mask);
#endif
}

#if AJT
/*******************************************************************
my own panic function - not suitable for general use
********************************************************************/
void ajt_panic(void)
{
  pstring cmd = "/usr/bin/X11/xedit -display :0 /tmp/ERROR_FAULT &";
  smbrun(cmd,NULL);
}
#endif

#ifdef USE_DIRECT
#define DIRECT direct
#else
#define DIRECT dirent
#endif

/*******************************************************************
a readdir wrapper which just returns the file name
also return the inode number if requested
********************************************************************/
char *readdirname(void *p)
{
  struct DIRECT *ptr;
  char *dname;

  if (!p) return(NULL);
  
  ptr = (struct DIRECT *)readdir(p);
  if (!ptr) return(NULL);

  dname = ptr->d_name;

#ifdef KANJI
  {
    static pstring buf;
    strcpy(buf, dname);
    unix_to_dos(buf, True);
    dname = buf;
  }
#endif

#ifdef NEXT2
  if (telldir(p) < 0) return(NULL);
#endif

#ifdef SUNOS5
  /* this handles a broken compiler setup, causing a mixture
   of BSD and SYSV headers and libraries */
  {
    static BOOL broken_readdir = False;
    if (!broken_readdir && !(*(dname)) && strequal("..",dname-2))
      {
	DEBUG(0,("Your readdir() is broken. You have somehow mixed SYSV and BSD headers and libraries\n"));
	broken_readdir = True;
      }
    if (broken_readdir)
      return(dname-2);
  }
#endif

  return(dname);
}



#if (defined(SecureWare) && defined(SCO))
/* This is needed due to needing the nap() function but we don't want
   to include the Xenix libraries since that will break other things...
   BTW: system call # 0x0c28 is the same as calling nap() */
long nap(long milliseconds) {
  return syscall(0x0c28, milliseconds);
}
#endif

#ifdef NO_INITGROUPS
#include <sys/types.h>
#include <limits.h>
#include <grp.h>

#ifndef NULL
#define NULL (void *)0
#endif

/****************************************************************************
 some systems don't have an initgroups call 
****************************************************************************/
int initgroups(char *name,gid_t id)
{
#ifdef NO_SETGROUPS
  /* yikes! no SETGROUPS or INITGROUPS? how can this work? */
  return(0);
#else
  gid_t  grouplst[NGROUPS_MAX];
  int    i,j;
  struct group *g;
  char   *gr;

  grouplst[0] = id;
  i = 1;
  while (i < NGROUPS_MAX && 
	 ((g = (struct group *)getgrent()) != (struct group *)NULL)) 
    {
      if (g->gr_gid == id)
	continue;
      j = 0;
      gr = g->gr_mem[0];
      while (gr && (*gr != (char)NULL)) {
	if (strcmp(name,gr) == 0) {
	  grouplst[i] = g->gr_gid;
	  i++;
	  gr = (char *)NULL;
	  break;
	}
	gr = g->gr_mem[++j];
      }
    }
  endgrent();
  return(setgroups(i,grouplst));
#endif
}
#endif


#if WRAP_MALLOC

/* undo the wrapping temporarily */
#undef malloc
#undef realloc
#undef free

/****************************************************************************
wrapper for malloc() to catch memory errors
****************************************************************************/
void *malloc_wrapped(int size,char *file,int line)
{
#ifdef xx_old_malloc
  void *res = xx_old_malloc(size);
#else
  void *res = malloc(size);
#endif
  DEBUG(3,("Malloc called from %s(%d) with size=%d gave ptr=0x%X\n",
	file,line,
	size,(unsigned int)res));
  return(res);
}

/****************************************************************************
wrapper for realloc() to catch memory errors
****************************************************************************/
void *realloc_wrapped(void *ptr,int size,char *file,int line)
{
#ifdef xx_old_realloc
  void *res = xx_old_realloc(ptr,size);
#else
  void *res = realloc(ptr,size);
#endif
  DEBUG(3,("Realloc\n"));
  DEBUG(3,("free called from %s(%d) with ptr=0x%X\n",
	file,line,
	(unsigned int)ptr));
  DEBUG(3,("Malloc called from %s(%d) with size=%d gave ptr=0x%X\n",
	file,line,
	size,(unsigned int)res));
  return(res);
}

/****************************************************************************
wrapper for free() to catch memory errors
****************************************************************************/
void free_wrapped(void *ptr,char *file,int line)
{
#ifdef xx_old_free
  xx_old_free(ptr);
#else
  free(ptr);
#endif
  DEBUG(3,("free called from %s(%d) with ptr=0x%X\n",
	file,line,(unsigned int)ptr));
  return;
}

/* and re-do the define for spots lower in this file */
#define malloc(size) malloc_wrapped(size,__FILE__,__LINE__)
#define realloc(ptr,size) realloc_wrapped(ptr,size,__FILE__,__LINE__)
#define free(ptr) free_wrapped(ptr,__FILE__,__LINE__)

#endif

#ifdef REPLACE_STRSTR
/****************************************************************************
Mips version of strstr doesn't seem to work correctly.
There is a #define in includes.h to redirect calls to this function.
****************************************************************************/
char *Strstr(char *s, char *p)
{
	int len = strlen(p);

	while ( *s != '\0' ) {
		if ( strncmp(s, p, len) == 0 )
		return s;
		s++;
	}

	return NULL;
}
#endif /* REPLACE_STRSTR */


#ifdef REPLACE_MKTIME
/*******************************************************************
a mktime() replacement for those who don't have it - contributed by 
C.A. Lademann <cal@zls.com>
********************************************************************/
#define  MINUTE  60
#define  HOUR    60*MINUTE
#define  DAY             24*HOUR
#define  YEAR    365*DAY
time_t Mktime(struct tm      *t)
{
  struct tm       *u;
  time_t  epoch = 0;
  int             mon [] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
  y, m, i;

  if(t->tm_year < 70)
    return((time_t)-1);

  epoch = (t->tm_year - 70) * YEAR + 
    (t->tm_year / 4 - 70 / 4 - t->tm_year / 100) * DAY;

  y = t->tm_year;
  m = 0;

  for(i = 0; i < t->tm_mon; i++) {
    epoch += mon [m] * DAY;
    if(m == 1 && y % 4 == 0 && (y % 100 != 0 || y % 400 == 0))
      epoch += DAY;
    
    if(++m > 11) {
      m = 0;
      y++;
    }
  }

  epoch += (t->tm_mday - 1) * DAY;
  epoch += t->tm_hour * HOUR + t->tm_min * MINUTE + t->tm_sec;
  
  if((u = localtime(&epoch)) != NULL) {
    t->tm_sec = u->tm_sec;
    t->tm_min = u->tm_min;
    t->tm_hour = u->tm_hour;
    t->tm_mday = u->tm_mday;
    t->tm_mon = u->tm_mon;
    t->tm_year = u->tm_year;
    t->tm_wday = u->tm_wday;
    t->tm_yday = u->tm_yday;
    t->tm_isdst = u->tm_isdst;
#ifndef NO_TM_NAME
    memcpy(t->tm_name, u->tm_name, LTZNMAX);
#endif
  }

  return(epoch);
}
#endif /* REPLACE_MKTIME */



#ifdef REPLACE_RENAME
/* Rename a file. (from libiberty in GNU binutils)  */
int
rename (zfrom, zto)
     const char *zfrom;
     const char *zto;
{
  if (link (zfrom, zto) < 0)
    {
      if (errno != EEXIST)
	return -1;
      if (unlink (zto) < 0
	  || link (zfrom, zto) < 0)
	return -1;
    }
  return unlink (zfrom);
}
#endif


#ifdef REPLACE_INNETGR
/*
 * Search for a match in a netgroup. This replaces it on broken systems.
 */
int InNetGr(group, host, user, dom)
        char *group, *host, *user, *dom;
{
  char *hst, *usr, *dm;
  
  setnetgrent(group);
  while (getnetgrent(&hst, &usr, &dm))
    if (((host == 0) || (hst == 0) || !strcmp(host, hst)) &&
	((user == 0) || (usr == 0) || !strcmp(user, usr)) &&
	((dom == 0) || (dm == 0) || !strcmp(dom, dm))) {
      endnetgrent();
      return (1);
    }
  endnetgrent();
  return (0);
}
#endif


#if WRAP_MEMCPY
#undef memcpy
/*******************************************************************
a wrapper around memcpy for diagnostic purposes
********************************************************************/
void *memcpy_wrapped(void *d,void *s,int l,char *fname,int line)
{
  if (l>64 && (((int)d)%4) != (((int)s)%4))
    DEBUG(4,("Misaligned memcpy(0x%X,0x%X,%d) at %s(%d)\n",d,s,l,fname,line));
#ifdef xx_old_memcpy  
  return(xx_old_memcpy(d,s,l));
#else
  return(memcpy(d,s,l));
#endif
}
#define memcpy(d,s,l) memcpy_wrapped(d,s,l,__FILE__,__LINE__)
#endif



