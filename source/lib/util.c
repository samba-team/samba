/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
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
*/

#include "includes.h"

#if (defined(NETGROUP) && defined (AUTOMOUNT))
#ifdef NISPLUS
#include <rpcsvc/nis.h>
#else
#include "rpcsvc/ypclnt.h"
#endif
#endif

pstring scope = "";

int DEBUGLEVEL = 1;

BOOL passive = False;

int Protocol = PROTOCOL_COREPLUS;

/* a default finfo structure to ensure all fields are sensible */
file_info def_finfo = {-1,0,0,0,0,0,0,""};

/* these are some file handles where debug info will be stored */
FILE *dbf = NULL;

/* the client file descriptor */
int Client = -1;

/* the last IP received from */
struct in_addr lastip;

/* the last port received from */
int lastport=0;

/* this is used by the chaining code */
int chain_size = 0;

int trans_num = 0;

/*
   case handling on filenames 
*/
int case_default = CASE_LOWER;

pstring debugf = "";
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
static enum remote_arch_types ra_type = RA_UNKNOWN;
fstring remote_proto="UNKNOWN";
pstring myhostname="";
pstring user_socket_options="";   

pstring sesssetup_user="";
pstring samlogon_user="";

BOOL sam_logon_in_ssb = False;

pstring myname = "";
fstring myworkgroup = "";
char **my_netbios_names;

int smb_read_error = 0;

static BOOL stdout_logging = False;

static char *filename_dos(char *path,char *buf);

#if defined(SIGUSR2)
/**************************************************************************** **
 catch a sigusr2 - decrease the debug log level.
 **************************************************************************** */
int sig_usr2(void)
{  
  BlockSignals( True, SIGUSR2);
 
  DEBUGLEVEL--; 
   
  if(DEBUGLEVEL < 0) 
    DEBUGLEVEL = 0; 

  DEBUG( 0, ( "Got SIGUSR2 set debug level to %d.\n", DEBUGLEVEL ) );
   
  BlockSignals( False, SIGUSR2);
#ifndef DONT_REINSTALL_SIG
  signal(SIGUSR2, SIGNAL_CAST sig_usr2);
#endif 
  return(0);
}  
#endif /* SIGUSR1 */
   
#if defined(SIGUSR1)
/**************************************************************************** **
 catch a sigusr1 - increase the debug log level. 
 **************************************************************************** */
int sig_usr1(void)
{
  BlockSignals( True, SIGUSR1);
 
  DEBUGLEVEL++;

  if(DEBUGLEVEL > 10)
    DEBUGLEVEL = 10;

  DEBUG( 0, ( "Got SIGUSR1 set debug level to %d.\n", DEBUGLEVEL ) );

  BlockSignals( False, SIGUSR1);
#ifndef DONT_REINSTALL_SIG
  signal(SIGUSR1, SIGNAL_CAST sig_usr1);
#endif
  return(0);
}
#endif /* SIGUSR1 */


/*******************************************************************
  get ready for syslog stuff
  ******************************************************************/
void setup_logging(char *pname,BOOL interactive)
{
#ifdef SYSLOG
  if (!interactive) {
    char *p = strrchr(pname,'/');
    if (p) pname = p+1;
#ifdef LOG_DAEMON
    openlog(pname, LOG_PID, SYSLOG_FACILITY);
#else /* for old systems that have no facility codes. */
    openlog(pname, LOG_PID);
#endif
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
  pstring fname;
  
  if (DEBUGLEVEL > 0)
    {
      pstrcpy(fname,debugf);
      if (lp_loaded() && (*lp_logfile()))
	pstrcpy(fname,lp_logfile());

      if (!strcsequal(fname,debugf) || !dbf || !file_exist(debugf,NULL))
	{
	  int oldumask = umask(022);
	  pstrcpy(debugf,fname);
	  if (dbf) fclose(dbf);
	  if (append_log)
	    dbf = fopen(debugf,"a");
	  else
	    dbf = fopen(debugf,"w");
	  if (dbf) setbuf(dbf,NULL);
	  umask(oldumask);
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

  if (debug_count++ < 100 || getuid() != 0) return;

  maxlog = lp_max_log_size() * 1024;
  if (!dbf || maxlog <= 0) return;

  if (fstat(fileno(dbf),&st) == 0 && st.st_size > maxlog) {
    fclose(dbf); dbf = NULL;
    reopen_logs();
    if (dbf && file_size(debugf) > maxlog) {
      pstring name;
      fclose(dbf); dbf = NULL;
      slprintf(name,sizeof(name)-1,"%s.old",debugf);
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
  int old_errno = errno;

  if (stdout_logging) {
#ifdef __STDC__
    va_start(ap, format_str);
#else
    va_start(ap);
    format_str = va_arg(ap,char *);
#endif
    vfprintf(dbf,format_str,ap);
    va_end(ap);
    errno = old_errno;
    return(0);
  }
  
#ifdef SYSLOG
  if (!lp_syslog_only())
#endif  
    {
      if (!dbf) {
	      int oldumask = umask(022);
              if(append_log)
                dbf = fopen(debugf,"a");
              else
                dbf = fopen(debugf,"w");
	      umask(oldumask);
	      if (dbf) {
		      setbuf(dbf,NULL);
	      } else {
		      errno = old_errno;
		      return(0);
	      }
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
      vslprintf(msgbuf, sizeof(msgbuf)-1,format_str, ap);
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

  errno = old_errno;

  return(0);
}

/****************************************************************************
  find a suitable temporary directory. The result should be copied immediately
  as it may be overwritten by a subsequent call
  ****************************************************************************/
char *tmpdir(void)
{
  char *p;
  if ((p = getenv("TMPDIR"))) {
    return p;
  }
  return "/tmp";
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
#ifdef SO_SNDTIMEO
  {"SO_SNDTIMEO",       SOL_SOCKET,    SO_SNDTIMEO,     0,                 OPT_INT},
#endif
#ifdef SO_RCVTIMEO
  {"SO_RCVTIMEO",       SOL_SOCKET,    SO_RCVTIMEO,     0,                 OPT_INT},
#endif
  {NULL,0,0,0,0}};

	

/****************************************************************************
set user socket options
****************************************************************************/
void set_socket_options(int fd, char *options)
{
  fstring tok;

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
char *StrnCpy(char *dest,char *src,int n)
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

  Note:  <Out> must be (33 + strlen(scope) + 2) bytes long, at minimum.
****************************************************************************/
int name_mangle( char *In, char *Out, char name_type )
  {
  int   i;
  int   c;
  int   len;
  char  buf[20];
  char *p = Out;

  /* Safely copy the input string, In, into buf[]. */
  (void)memset( buf, 0, 20 );
  if( '*' == In[0] )
    buf[0] = '*';
  else
    (void)slprintf( buf, sizeof(buf)-1, "%-15.15s%c", In, name_type );

  /* Place the length of the first field into the output buffer. */
  p[0] = 32;
  p++;

  /* Now convert the name to the rfc1001/1002 format. */
  for( i = 0; i < 16; i++ )
    {
    c = toupper( buf[i] );
    p[i*2]     = ( (c >> 4) & 0x000F ) + 'A';
    p[(i*2)+1] = (c & 0x000F) + 'A';
    }
  p += 32;
  p[0] = '\0';

  /* Add the scope string. */
  for( i = 0, len = 0; NULL != scope; i++, len++ )
    {
    switch( scope[i] )
      {
      case '\0':
        p[0]     = len;
        if( len > 0 )
          p[len+1] = 0;
        return( name_len(Out) );
      case '.':
        p[0] = len;
        p   += (len + 1);
        len  = 0;
        break;
      default:
        p[len+1] = scope[i];
        break;
      }
    }

  return( name_len(Out) );
  } /* name_mangle */

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
  BOOL ret;

  if (!st) st = &st2;

  if (sys_stat(dname,st) != 0) 
    return(False);

  ret = S_ISDIR(st->st_mode);
  if(!ret)
    errno = ENOTDIR;
  return ret;
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

/*******************************************************************
return a string representing an attribute for a file
********************************************************************/
char *attrib_string(int mode)
{
  static fstring attrstr;

  attrstr[0] = 0;

  if (mode & aVOLID) fstrcat(attrstr,"V");
  if (mode & aDIR) fstrcat(attrstr,"D");
  if (mode & aARCH) fstrcat(attrstr,"A");
  if (mode & aHIDDEN) fstrcat(attrstr,"H");
  if (mode & aSYSTEM) fstrcat(attrstr,"S");
  if (mode & aRONLY) fstrcat(attrstr,"R");	  

  return(attrstr);
}


/*******************************************************************
  case insensitive string compararison
********************************************************************/
int StrCaseCmp(char *s, char *t)
{
  /* compare until we run out of string, either t or s, or find a difference */
  /* We *must* use toupper rather than tolower here due to the
     asynchronous upper to lower mapping.
   */
#if !defined(KANJI_WIN95_COMPATIBILITY)
  /*
   * For completeness we should put in equivalent code for code pages
   * 949 (Korean hangul) and 950 (Big5 Traditional Chinese) here - but
   * doubt anyone wants Samba to behave differently from Win95 and WinNT
   * here. They both treat full width ascii characters as case senstive
   * filenames (ie. they don't do the work we do here).
   * JRA.
   */

  if(lp_client_code_page() == KANJI_CODEPAGE)
  {
    /* Win95 treats full width ascii characters as case sensitive. */
    int diff;
    for (;;)
    {
      if (!*s || !*t)
	    return toupper (*s) - toupper (*t);
      else if (is_sj_alph (*s) && is_sj_alph (*t))
      {
        diff = sj_toupper2 (*(s+1)) - sj_toupper2 (*(t+1));
        if (diff)
          return diff;
        s += 2;
        t += 2;
      }
      else if (is_shift_jis (*s) && is_shift_jis (*t))
      {
        diff = ((int) (unsigned char) *s) - ((int) (unsigned char) *t);
        if (diff)
          return diff;
        diff = ((int) (unsigned char) *(s+1)) - ((int) (unsigned char) *(t+1));
        if (diff)
          return diff;
        s += 2;
        t += 2;
      }
      else if (is_shift_jis (*s))
        return 1;
      else if (is_shift_jis (*t))
        return -1;
      else 
      {
        diff = toupper (*s) - toupper (*t);
        if (diff)
          return diff;
        s++;
        t++;
      }
    }
  }
  else
#endif /* KANJI_WIN95_COMPATIBILITY */
  {
    while (*s && *t && toupper(*s) == toupper(*t))
    {
      s++;
      t++;
    }

    return(toupper(*s) - toupper(*t));
  }
}

/*******************************************************************
  case insensitive string compararison, length limited
********************************************************************/
int StrnCaseCmp(char *s, char *t, int n)
{
  /* compare until we run out of string, either t or s, or chars */
  /* We *must* use toupper rather than tolower here due to the
     asynchronous upper to lower mapping.
   */
#if !defined(KANJI_WIN95_COMPATIBILITY)
  /*
   * For completeness we should put in equivalent code for code pages
   * 949 (Korean hangul) and 950 (Big5 Traditional Chinese) here - but
   * doubt anyone wants Samba to behave differently from Win95 and WinNT
   * here. They both treat full width ascii characters as case senstive
   * filenames (ie. they don't do the work we do here).
   * JRA. 
   */

  if(lp_client_code_page() == KANJI_CODEPAGE)
  {
    /* Win95 treats full width ascii characters as case sensitive. */
    int diff;
    for (;n > 0;)
    {
      if (!*s || !*t)
        return toupper (*s) - toupper (*t);
      else if (is_sj_alph (*s) && is_sj_alph (*t))
      {
        diff = sj_toupper2 (*(s+1)) - sj_toupper2 (*(t+1));
        if (diff)
          return diff;
        s += 2;
        t += 2;
        n -= 2;
      }
      else if (is_shift_jis (*s) && is_shift_jis (*t))
      {
        diff = ((int) (unsigned char) *s) - ((int) (unsigned char) *t);
        if (diff)
          return diff;
        diff = ((int) (unsigned char) *(s+1)) - ((int) (unsigned char) *(t+1));
        if (diff)
          return diff;
        s += 2;
        t += 2;
        n -= 2;
      }
      else if (is_shift_jis (*s))
        return 1;
      else if (is_shift_jis (*t))
        return -1;
      else 
      {
        diff = toupper (*s) - toupper (*t);
        if (diff)
          return diff;
        s++;
        t++;
        n--;
      }
    }
    return 0;
  }
  else
#endif /* KANJI_WIN95_COMPATIBILITY */
  {
    while (n && *s && *t && toupper(*s) == toupper(*t))
    {
      s++;
      t++;
      n--;
    }

    /* not run out of chars - strings are different lengths */
    if (n) 
      return(toupper(*s) - toupper(*t));

    /* identical up to where we run out of chars, 
       and strings are same length */
    return(0);
  }
}

/*******************************************************************
  compare 2 strings 
********************************************************************/
BOOL strequal(char *s1, char *s2)
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
#if !defined(KANJI_WIN95_COMPATIBILITY)
  /*
   * For completeness we should put in equivalent code for code pages
   * 949 (Korean hangul) and 950 (Big5 Traditional Chinese) here - but
   * doubt anyone wants Samba to behave differently from Win95 and WinNT
   * here. They both treat full width ascii characters as case senstive
   * filenames (ie. they don't do the work we do here).
   * JRA. 
   */

    if(lp_client_code_page() == KANJI_CODEPAGE)
    {
      /* Win95 treats full width ascii characters as case sensitive. */
      if (is_shift_jis (*s))
      {
        if (is_sj_upper (s[0], s[1]))
          s[1] = sj_tolower2 (s[1]);
        s += 2;
      }
      else if (is_kana (*s))
      {
        s++;
      }
      else
      {
        if (isupper(*s))
          *s = tolower(*s);
        s++;
      }
    }
    else
#endif /* KANJI_WIN95_COMPATIBILITY */
    {
      int skip = skip_multibyte_char( *s );
      if( skip != 0 )
        s += skip;
      else
      {
        if (isupper(*s))
          *s = tolower(*s);
        s++;
      }
    }
  }
}

/*******************************************************************
  convert a string to upper case
********************************************************************/
void strupper(char *s)
{
  while (*s)
  {
#if !defined(KANJI_WIN95_COMPATIBILITY)
  /*
   * For completeness we should put in equivalent code for code pages
   * 949 (Korean hangul) and 950 (Big5 Traditional Chinese) here - but
   * doubt anyone wants Samba to behave differently from Win95 and WinNT
   * here. They both treat full width ascii characters as case senstive
   * filenames (ie. they don't do the work we do here).
   * JRA. 
   */

    if(lp_client_code_page() == KANJI_CODEPAGE)
    {
      /* Win95 treats full width ascii characters as case sensitive. */
      if (is_shift_jis (*s))
      {
        if (is_sj_lower (s[0], s[1]))
          s[1] = sj_toupper2 (s[1]);
        s += 2;
      }
      else if (is_kana (*s))
      {
        s++;
      }
      else
      {
        if (islower(*s))
          *s = toupper(*s);
        s++;
      }
    }
    else
#endif /* KANJI_WIN95_COMPATIBILITY */
    {
      int skip = skip_multibyte_char( *s );
      if( skip != 0 )
        s += skip;
      else
      {
        if (islower(*s))
          *s = toupper(*s);
        s++;
      }
    }
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
  int skip;
  while (*s)
  {
    skip = skip_multibyte_char( *s );
    if( skip != 0 )
      s += skip;
    else
    {
      if (oldc == *s)
        *s = newc;
      s++;
    }
  }
}

/****************************************************************************
  make a file into unix format
****************************************************************************/
void unix_format(char *fname)
{
  pstring namecopy;
  string_replace(fname,'\\','/');

  if (*fname == '/')
    {
      pstrcpy(namecopy,fname);
      pstrcpy(fname,".");
      pstrcat(fname,namecopy);
    }  
}

/****************************************************************************
  make a file into dos format
****************************************************************************/
void dos_format(char *fname)
{
  string_replace(fname,'/','\\');
}


/*******************************************************************
  show a smb message structure
********************************************************************/
void show_msg(char *buf)
{
  int i;
  int bcc=0;

  if (DEBUGLEVEL < 5) return;

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

  if (DEBUGLEVEL < 10) return;

  dump_data(10, smb_buf(buf), MIN(bcc, 512));
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
  return(PTR_DIFF(p,buf+4) + chain_size);
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
      pstrcpy(s1,p+3);

      if ((p=strrchr(s,'\\')) != NULL)
	*p = 0;
      else
	*s = 0;
      pstrcat(s,s1);
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

  /* Remove leading ./ characters */
  if(strncmp(s, "./", 2) == 0) {
    trim_string(s, "./", NULL);
    if(*s == 0)
      pstrcpy(s,"./");
  }

  while ((p = strstr(s,"/../")) != NULL)
    {
      pstring s1;

      *p = 0;
      pstrcpy(s1,p+3);

      if ((p=strrchr(s,'/')) != NULL)
	*p = 0;
      else
	*s = 0;
      pstrcat(s,s1);
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
    pstrcpy(LastDir,path);
  return(res);
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
    return(sys_getwd(str));

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
      return(sys_getwd(str));
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
		    pstrcpy (str, ino_list[i].text);

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

  if (!sys_getwd(s))
    {
      DEBUG(0,("Getwd failed, errno %s\n",strerror(errno)));
      return (NULL);
    }

  pstrcpy(str,s);

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
  pstring base_name;
  pstring newname;
  char *p=NULL;
  BOOL relative = (*s != '/');

  *dir2 = *wd = *base_name = *newname = 0;

  if (widelinks)
    {
      unix_clean_name(s);
      /* can't have a leading .. */
      if (strncmp(s,"..",2) == 0 && (s[2]==0 || s[2]=='/'))
	{
	  DEBUG(3,("Illegal file name? (%s)\n",s));
	  return(False);
	}

      if (strlen(s) == 0)
        pstrcpy(s,"./");

      return(True);
    }
  
  DEBUG(3,("reduce_name [%s] [%s]\n",s,dir));

  /* remove any double slashes */
  string_sub(s,"//","/");

  pstrcpy(base_name,s);
  p = strrchr(base_name,'/');

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


    if (p && (p != base_name))
      {
	*p = 0;
	if (strcmp(p+1,".")==0)
	  p[1]=0;
	if (strcmp(p+1,"..")==0)
	  *p = '/';
      }

  if (ChDir(base_name) != 0)
    {
      ChDir(wd);
      DEBUG(3,("couldn't chdir for %s %s basename=%s\n",s,dir,base_name));
      return(False);
    }

  if (!GetWd(newname))
    {
      ChDir(wd);
      DEBUG(2,("couldn't get wd for %s %s\n",s,dir2));
      return(False);
    }

  if (p && (p != base_name))
    {
      pstrcat(newname,"/");
      pstrcat(newname,p+1);
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
	  pstrcpy(s,newname + l + 1);
	else
	  pstrcpy(s,newname+l);
      }
    else
      pstrcpy(s,newname);
  }

  ChDir(wd);

  if (strlen(s) == 0)
    pstrcpy(s,"./");

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
      pstrcpy(tmp,Mask);  
      memset(tmp+l1,'?',lfill);
      pstrcpy(tmp + l1 + lfill,Mask + l1 + 1);	
      pstrcpy(Mask,tmp);      
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

  pstrcpy(mbeg,filepart);
  if ((p1 = strchr(mbeg,'.')) != NULL)
    {
      hasdot = True;
      *p1 = 0;
      p1++;
      pstrcpy(mext,p1);
    }
  else
    {
      pstrcpy(mext,"");
      if (strlen(mbeg) > 8)
	{
	  pstrcpy(mext,mbeg + 8);
	  mbeg[8] = 0;
	}
    }

  if (*mbeg == 0)
    pstrcpy(mbeg,"????????");
  if ((*mext == 0) && doext && !hasdot)
    pstrcpy(mext,"???");

  if (strequal(mbeg,"*") && *mext==0) 
    pstrcpy(mext,"*");

  /* expand *'s */
  expand_one(mbeg,8);
  if (*mext)
    expand_one(mext,3);

  pstrcpy(Mask,dirpart);
  if (*dirpart || absolute) pstrcat(Mask,"\\");
  pstrcat(Mask,mbeg);
  pstrcat(Mask,".");
  pstrcat(Mask,mext);

  DEBUG(6,("Mask expanded to [%s]\n",Mask));
}  


/****************************************************************************
does a string have any uppercase chars in it?
****************************************************************************/
BOOL strhasupper(char *s)
{
  while (*s) 
  {
#if !defined(KANJI_WIN95_COMPATIBILITY)
  /*
   * For completeness we should put in equivalent code for code pages
   * 949 (Korean hangul) and 950 (Big5 Traditional Chinese) here - but
   * doubt anyone wants Samba to behave differently from Win95 and WinNT
   * here. They both treat full width ascii characters as case senstive
   * filenames (ie. they don't do the work we do here).
   * JRA. 
   */

    if(lp_client_code_page() == KANJI_CODEPAGE)
    {
      /* Win95 treats full width ascii characters as case sensitive. */
      if (is_shift_jis (*s))
        s += 2;
      else if (is_kana (*s))
        s++;
      else
      {
        if (isupper(*s))
          return(True);
        s++;
      }
    }
    else
#endif /* KANJI_WIN95_COMPATIBILITY */
    {
      int skip = skip_multibyte_char( *s );
      if( skip != 0 )
        s += skip;
      else {
        if (isupper(*s))
          return(True);
        s++;
      }
    }
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
#if !defined(KANJI_WIN95_COMPATIBILITY)
  /*
   * For completeness we should put in equivalent code for code pages
   * 949 (Korean hangul) and 950 (Big5 Traditional Chinese) here - but
   * doubt anyone wants Samba to behave differently from Win95 and WinNT
   * here. They both treat full width ascii characters as case senstive
   * filenames (ie. they don't do the work we do here).
   * JRA. 
   */

    if(lp_client_code_page() == KANJI_CODEPAGE)
    {
      /* Win95 treats full width ascii characters as case sensitive. */
      if (is_shift_jis (*s))
      {
        if (is_sj_upper (s[0], s[1]))
          return(True);
        if (is_sj_lower (s[0], s[1]))
          return (True);
        s += 2;
      }
      else if (is_kana (*s))
      {
        s++;
      }
      else
      {
        if (islower(*s))
          return(True);
        s++;
      }
    }
    else
#endif /* KANJI_WIN95_COMPATIBILITY */
    {
      int skip = skip_multibyte_char( *s );
      if( skip != 0 )
        s += skip;
      else {
        if (islower(*s))
          return(True);
        s++;
      }
    }
  }
  return(False);
}

/****************************************************************************
find the number of chars in a string
****************************************************************************/
int count_chars(char *s,char c)
{
  int count=0;

#if !defined(KANJI_WIN95_COMPATIBILITY)
  /*
   * For completeness we should put in equivalent code for code pages
   * 949 (Korean hangul) and 950 (Big5 Traditional Chinese) here - but
   * doubt anyone wants Samba to behave differently from Win95 and WinNT
   * here. They both treat full width ascii characters as case senstive
   * filenames (ie. they don't do the work we do here).
   * JRA. 
   */

  if(lp_client_code_page() == KANJI_CODEPAGE)
  {
    /* Win95 treats full width ascii characters as case sensitive. */
    while (*s) 
    {
      if (is_shift_jis (*s))
        s += 2;
      else 
      {
        if (*s == c)
          count++;
        s++;
      }
    }
  }
  else
#endif /* KANJI_WIN95_COMPATIBILITY */
  {
    while (*s) 
    {
      int skip = skip_multibyte_char( *s );
      if( skip != 0 )
        s += skip;
      else {
        if (*s == c)
          count++;
        s++;
      }
    }
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

  pstrcpy(mask2,mask);

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

  if((val = fcntl(fd, F_GETFL, 0)) == -1)
	return -1;
  if(set) /* Turn blocking on - ie. clear nonblock flag */
	val &= ~FLAG_TO_SET;
  else
    val |= FLAG_TO_SET;
  return fcntl( fd, F_SETFL, val);
#undef FLAG_TO_SET
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
  if(ret <= 0)
    DEBUG(0,("write_socket: Error writing %d bytes to socket %d: ERRNO = %s\n", 
       len, fd, strerror(errno) ));

  return(ret);
}

/****************************************************************************
read from a socket
****************************************************************************/
int read_udp_socket(int fd,char *buf,int len)
{
  int ret;
  struct sockaddr_in sock;
  int socklen;
  
  socklen = sizeof(sock);
  bzero((char *)&sock,socklen);
  bzero((char *)&lastip,sizeof(lastip));
  ret = recvfrom(fd,buf,len,0,(struct sockaddr *)&sock,&socklen);
  if (ret <= 0) {
    DEBUG(2,("read socket failed. ERRNO=%s\n",strerror(errno)));
    return(0);
  }

  lastip = sock.sin_addr;
  lastport = ntohs(sock.sin_port);

  DEBUG(10,("read_udp_socket: lastip %s lastport %d read: %d\n",
             inet_ntoa(lastip), lastport, ret));

  return(ret);
}

/****************************************************************************
read data from a device with a timout in msec.
mincount = if timeout, minimum to read before returning
maxcount = number to be read.
****************************************************************************/
int read_with_timeout(int fd,char *buf,int mincnt,int maxcnt,long time_out)
{
  fd_set fds;
  int selrtn;
  int readret;
  int nread = 0;
  struct timeval timeout;

  /* just checking .... */
  if (maxcnt <= 0) return(0);

  smb_read_error = 0;

  /* Blocking read */
  if (time_out <= 0) {
    if (mincnt == 0) mincnt = maxcnt;

    while (nread < mincnt) {
      readret = read(fd, buf + nread, maxcnt - nread);
      if (readret == 0) {
	smb_read_error = READ_EOF;
	return -1;
      }

      if (readret == -1) {
	smb_read_error = READ_ERROR;
	return -1;
      }
      nread += readret;
    }
    return(nread);
  }
  
  /* Most difficult - timeout read */
  /* If this is ever called on a disk file and 
	 mincnt is greater then the filesize then
	 system performance will suffer severely as 
	 select always return true on disk files */

  /* Set initial timeout */
  timeout.tv_sec = time_out / 1000;
  timeout.tv_usec = 1000 * (time_out % 1000);

  for (nread=0; nread<mincnt; ) 
    {      
      FD_ZERO(&fds);
      FD_SET(fd,&fds);
      
      selrtn = sys_select(&fds,&timeout);

      /* Check if error */
      if(selrtn == -1) {
	/* something is wrong. Maybe the socket is dead? */
	smb_read_error = READ_ERROR;
	return -1;
      }
      
      /* Did we timeout ? */
      if (selrtn == 0) {
	smb_read_error = READ_TIMEOUT;
	return -1;
      }
      
      readret = read(fd, buf+nread, maxcnt-nread);
      if (readret == 0) {
	/* we got EOF on the file descriptor */
	smb_read_error = READ_EOF;
	return -1;
      }

      if (readret == -1) {
	/* the descriptor is probably dead */
	smb_read_error = READ_ERROR;
	return -1;
      }
      
      nread += readret;
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
 
  smb_read_error = 0;

  while (total < N)
    {
      ret = read(fd,buffer + total,N - total);
      if (ret == 0) {
	smb_read_error = READ_EOF;
	return 0;
      }
      if (ret == -1) {
	smb_read_error = READ_ERROR;
	return -1;
      }
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

      if (ret == -1) return -1;
      if (ret == 0) return total;

      total += ret;
    }
  return total;
}


/****************************************************************************
transfer some data between two fd's
****************************************************************************/
int transfer_file(int infd,int outfd,int n,char *header,int headlen,int align)
{
  static char *buf=NULL;  
  static int size=0;
  char *buf1,*abuf;
  int total = 0;

  DEBUG(4,("transfer_file %d  (head=%d) called\n",n,headlen));

  if (size == 0) {
    size = lp_readsize();
    size = MAX(size,1024);
  }

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
store the result in the buffer
This version of the function will return a length of zero on receiving
a keepalive packet.
****************************************************************************/
static int read_smb_length_return_keepalive(int fd,char *inbuf,int timeout)
{
  int len=0, msg_type;
  BOOL ok=False;

  while (!ok)
    {
      if (timeout > 0)
	ok = (read_with_timeout(fd,inbuf,4,4,timeout) == 4);
      else 
	ok = (read_data(fd,inbuf,4) == 4);

      if (!ok)
	return(-1);

      len = smb_len(inbuf);
      msg_type = CVAL(inbuf,0);

      if (msg_type == 0x85) 
        DEBUG(5,("Got keepalive packet\n"));
    }

  DEBUG(10,("got smb length of %d\n",len));

  return(len);
}

/****************************************************************************
read 4 bytes of a smb packet and return the smb length of the packet
store the result in the buffer. This version of the function will
never return a session keepalive (length of zero).
****************************************************************************/
int read_smb_length(int fd,char *inbuf,int timeout)
{
  int len;

  for(;;)
  {
    len = read_smb_length_return_keepalive(fd, inbuf, timeout);

    if(len < 0)
      return len;

    /* Ignore session keepalives. */
    if(CVAL(inbuf,0) != 0x85)
      break;
  }

  return len;
}

/****************************************************************************
  read an smb from a fd. Note that the buffer *MUST* be of size
  BUFFER_SIZE+SAFETY_MARGIN.
  The timeout is in milli seconds. 

  This function will return on a
  receipt of a session keepalive packet.
****************************************************************************/
BOOL receive_smb(int fd,char *buffer, int timeout)
{
  int len,ret;

  smb_read_error = 0;

  bzero(buffer,smb_size + 100);

  len = read_smb_length_return_keepalive(fd,buffer,timeout);
  if (len < 0)
    return(False);

  if (len > BUFFER_SIZE) {
    DEBUG(0,("Invalid packet length! (%d bytes).\n",len));
    if (len > BUFFER_SIZE + (SAFETY_MARGIN/2))
      exit(1);
  }

  if(len > 0) {
    ret = read_data(fd,buffer+4,len);
    if (ret != len) {
      smb_read_error = READ_ERROR;
      return False;
    }
  }
  return(True);
}

/****************************************************************************
  read an smb from a fd ignoring all keepalive packets. Note that the buffer 
  *MUST* be of size BUFFER_SIZE+SAFETY_MARGIN.
  The timeout is in milli seconds

  This is exactly the same as receive_smb except that it never returns
  a session keepalive packet (just as receive_smb used to do).
  receive_smb was changed to return keepalives as the oplock processing means this call
  should never go into a blocking read.
****************************************************************************/

BOOL client_receive_smb(int fd,char *buffer, int timeout)
{
  BOOL ret;

  for(;;)
  {
    ret = receive_smb(fd, buffer, timeout);

    if(ret == False)
      return ret;

    /* Ignore session keepalive packets. */
    if(CVAL(buffer,0) != 0x85)
      break;
  }
  return ret;
}

/****************************************************************************
  read a message from a udp fd.
The timeout is in milli seconds
****************************************************************************/
BOOL receive_local_message(int fd, char *buffer, int buffer_len, int timeout)
{
  struct sockaddr_in from;
  int fromlen = sizeof(from);
  int32 msg_len = 0;

  smb_read_error = 0;

  if(timeout != 0)
  {
    struct timeval to;
    fd_set fds;
    int selrtn;

    FD_ZERO(&fds);
    FD_SET(fd,&fds);

    to.tv_sec = timeout / 1000;
    to.tv_usec = (timeout % 1000) * 1000;

    selrtn = sys_select(&fds,&to);

    /* Check if error */
    if(selrtn == -1) 
    {
      /* something is wrong. Maybe the socket is dead? */
      smb_read_error = READ_ERROR;
      return False;
    } 
    
    /* Did we timeout ? */
    if (selrtn == 0) 
    {
      smb_read_error = READ_TIMEOUT;
      return False;
    }
  }

  /*
   * Read a loopback udp message.
   */
  msg_len = recvfrom(fd, &buffer[UDP_CMD_HEADER_LEN], 
                     buffer_len - UDP_CMD_HEADER_LEN, 0,
                     (struct sockaddr *)&from, &fromlen);

  if(msg_len < 0)
  {
    DEBUG(0,("receive_local_message. Error in recvfrom. (%s).\n",strerror(errno)));
    return False;
  }

  /* Validate message length. */
  if(msg_len > (buffer_len - UDP_CMD_HEADER_LEN))
  {
    DEBUG(0,("receive_local_message: invalid msg_len (%d) max can be %d\n",
              msg_len, 
              buffer_len  - UDP_CMD_HEADER_LEN));
    return False;
  }

  /* Validate message from address (must be localhost). */
  if(from.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
  {
    DEBUG(0,("receive_local_message: invalid 'from' address \
(was %x should be 127.0.0.1\n", from.sin_addr.s_addr));
   return False;
  }

  /* Setup the message header */
  SIVAL(buffer,UDP_CMD_LEN_OFFSET,msg_len);
  SSVAL(buffer,UDP_CMD_PORT_OFFSET,ntohs(from.sin_port));

  return True;
}

/****************************************************************************
 structure to hold a linked list of local messages.
 for processing.
****************************************************************************/

typedef struct _message_list {
   struct _message_list *msg_next;
   char *msg_buf;
   int msg_len;
} pending_message_list;

static pending_message_list *smb_msg_head = NULL;

/****************************************************************************
 Function to push a linked list of local messages ready
 for processing.
****************************************************************************/

static BOOL push_local_message(pending_message_list **pml, char *buf, int msg_len)
{
  pending_message_list *msg = (pending_message_list *)
                               malloc(sizeof(pending_message_list));

  if(msg == NULL)
  {
    DEBUG(0,("push_message: malloc fail (1)\n"));
    return False;
  }

  msg->msg_buf = (char *)malloc(msg_len);
  if(msg->msg_buf == NULL)
  {
    DEBUG(0,("push_local_message: malloc fail (2)\n"));
    free((char *)msg);
    return False;
  }

  memcpy(msg->msg_buf, buf, msg_len);
  msg->msg_len = msg_len;

  msg->msg_next = *pml;
  *pml = msg;

  return True;
}

/****************************************************************************
 Function to push a linked list of local smb messages ready
 for processing.
****************************************************************************/

BOOL push_smb_message(char *buf, int msg_len)
{
  return push_local_message(&smb_msg_head, buf, msg_len);
}

/****************************************************************************
  Do a select on an two fd's - with timeout. 

  If a local udp message has been pushed onto the
  queue (this can only happen during oplock break
  processing) return this first.

  If a pending smb message has been pushed onto the
  queue (this can only happen during oplock break
  processing) return this next.

  If the first smbfd is ready then read an smb from it.
  if the second (loopback UDP) fd is ready then read a message
  from it and setup the buffer header to identify the length
  and from address.
  Returns False on timeout or error.
  Else returns True.

The timeout is in milli seconds
****************************************************************************/
BOOL receive_message_or_smb(int smbfd, int oplock_fd, 
                           char *buffer, int buffer_len, 
                           int timeout, BOOL *got_smb)
{
  fd_set fds;
  int selrtn;
  struct timeval to;

  smb_read_error = 0;

  *got_smb = False;

  /*
   * Check to see if we already have a message on the smb queue.
   * If so - copy and return it.
   */
  
  if(smb_msg_head)
  {
    pending_message_list *msg = smb_msg_head;
    memcpy(buffer, msg->msg_buf, MIN(buffer_len, msg->msg_len));
    smb_msg_head = msg->msg_next;
  
    /* Free the message we just copied. */
    free((char *)msg->msg_buf);
    free((char *)msg);
    *got_smb = True;

    DEBUG(5,("receive_message_or_smb: returning queued smb message.\n"));
    return True;
  }

  FD_ZERO(&fds);
  FD_SET(smbfd,&fds);
  FD_SET(oplock_fd,&fds);

  to.tv_sec = timeout / 1000;
  to.tv_usec = (timeout % 1000) * 1000;

  selrtn = sys_select(&fds,timeout>0?&to:NULL);

  /* Check if error */
  if(selrtn == -1) {
    /* something is wrong. Maybe the socket is dead? */
    smb_read_error = READ_ERROR;
    return False;
  } 
    
  /* Did we timeout ? */
  if (selrtn == 0) {
    smb_read_error = READ_TIMEOUT;
    return False;
  }

  if (FD_ISSET(smbfd,&fds))
  {
    *got_smb = True;
    return receive_smb(smbfd, buffer, 0);
  }
  else
  {
    return receive_local_message(oplock_fd, buffer, buffer_len, 0);
  }
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
  pstrcpy(name,"");
  if (d < -50 || d > 50) return(0);
  return(name_interpret(p,name));
}
  
/****************************************************************************
return the total storage length of a mangled name
****************************************************************************/
int name_len( char *s )
  {
  int len;

  /* If the two high bits of the byte are set, return 2. */
  if( 0xC0 == (*(unsigned char *)s & 0xC0) )
    return(2);

  /* Add up the length bytes. */
  for( len = 1; (*s); s += (*s) + 1 )
    {
    len += *s + 1;
    }

  return( len );
  } /* name_len */

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
    DEBUG(0,("Packet send to %s(%d) failed ERRNO=%s\n",
	     inet_ntoa(ip),port,strerror(errno)));

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
      (*dest) = (char *)malloc(l+1);
      if ((*dest) == NULL) {
	      DEBUG(0,("Out of memory in string_init\n"));
	      return False;
      }

      pstrcpy(*dest,src);
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
* Does the actual matching. Returns True if matched,
* False if failed.
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
        /* Now eat all characters that match, as
           we want the *last* character to match. */
        while(*str && (case_sig ? (*p == *str) : (toupper(*p)==toupper(*str))))
          str++;
        str--; /* We've eaten the match char after the '*' */
        if(do_match(str,p,case_sig)) {
          return True;
        }
        if(!*str) {
          return False;
        } else {
          str++;
        }
      }
      return False;

    default:
      if(case_sig) {
        if(*str != *p) {
          return False;
        }
      } else {
        if(toupper(*str) != toupper(*p)) {
          return False;
        }
      }
      str++, p++;
      break;
    }
  }

  if(!*p && !*str)
    return True;

  if (!*p && str[0] == '.' && str[1] == 0) {
    return(True);
  }
  
  if (!*str && *p == '?') {
    while (*p == '?')
      p++;
    return(!*p);
  }

  if(!*str && (*p == '*' && p[1] == '\0')) {
    return True;
  }
 
  return False;
}


/*********************************************************
* Routine to match a given string with a regexp - uses
* simplified regexp that takes * and ? only. Case can be
* significant or not.
* The 8.3 handling was rewritten by Ums Harald <Harald.Ums@pro-sieben.de>
*********************************************************/

BOOL mask_match(char *str, char *regexp, int case_sig,BOOL trans2)
{
  char *p;
  pstring t_pattern, t_filename, te_pattern, te_filename;
  fstring ebase,eext,sbase,sext;

  BOOL matched = False;

  /* Make local copies of str and regexp */
  pstrcpy(t_pattern,regexp);
  pstrcpy(t_filename,str);

#if 0
  /* 
   * Not sure if this is a good idea. JRA.
   */
  if(trans2 && is_8_3(t_pattern,False) && is_8_3(t_filename,False))
    trans2 = False;
#endif

#if 0
  if (!strchr(t_filename,'.')) {
    pstrcat(t_filename,".");
  }
#endif

  /* Remove any *? and ** as they are meaningless */
  string_sub(t_pattern, "*?", "*");
  string_sub(t_pattern, "**", "*");

  if (strequal(t_pattern,"*"))
    return(True);

  DEBUG(8,("mask_match str=<%s> regexp=<%s>, case_sig = %d\n", t_filename, t_pattern, case_sig));

  if(trans2) {
    /*
     * Match each component of the regexp, split up by '.'
     * characters.
     */
    char *fp, *rp, *cp2, *cp1;
    BOOL last_wcard_was_star = False;
    int num_path_components, num_regexp_components;

    pstrcpy(te_pattern,t_pattern);
    pstrcpy(te_filename,t_filename);
    /*
     * Remove multiple "*." patterns.
     */
    string_sub(te_pattern, "*.*.", "*.");
    num_regexp_components = count_chars(te_pattern, '.');
    num_path_components = count_chars(te_filename, '.');

    /* 
     * Check for special 'hack' case of "DIR a*z". - needs to match a.b.c...z
     */
    if(num_regexp_components == 0)
      matched = do_match( te_filename, te_pattern, case_sig);
    else {
      for( cp1 = te_pattern, cp2 = te_filename; cp1;) {
        fp = strchr(cp2, '.');
        if(fp)
          *fp = '\0';
        rp = strchr(cp1, '.');
        if(rp)
          *rp = '\0';

        if(cp1[strlen(cp1)-1] == '*')
          last_wcard_was_star = True;
        else
          last_wcard_was_star = False;

        if(!do_match(cp2, cp1, case_sig))
          break;

        cp1 = rp ? rp + 1 : NULL;
        cp2 = fp ? fp + 1 : "";

        if(last_wcard_was_star || ((cp1 != NULL) && (*cp1 == '*'))) {
          /* Eat the extra path components. */
          int i;

          for(i = 0; i < num_path_components - num_regexp_components; i++) {
            fp = strchr(cp2, '.');
            if(fp)
              *fp = '\0';

            if((cp1 != NULL) && do_match( cp2, cp1, case_sig)) {
              cp2 = fp ? fp + 1 : "";
              break;
            }
            cp2 = fp ? fp + 1 : "";
          }
          num_path_components -= i;
        }
      } 
      if(cp1 == NULL && ((*cp2 == '\0') || last_wcard_was_star))
        matched = True;
    }
  } else {

    /* -------------------------------------------------
     * Behaviour of Win95
     * for 8.3 filenames and 8.3 Wildcards
     * -------------------------------------------------
     */
    if (strequal (t_filename, ".")) {
      /*
       *  Patterns:  *.*  *. ?. ?  are valid
       *
       */
      if(strequal(t_pattern, "*.*") || strequal(t_pattern, "*.") ||
         strequal(t_pattern, "?.") || strequal(t_pattern, "?"))
        matched = True;
    } else if (strequal (t_filename, "..")) {
      /*
       *  Patterns:  *.*  *. ?. ? *.? are valid
       *
       */
      if(strequal(t_pattern, "*.*") || strequal(t_pattern, "*.") ||
         strequal(t_pattern, "?.") || strequal(t_pattern, "?") ||
         strequal(t_pattern, "*.?") || strequal(t_pattern, "?.*"))
        matched = True;
    } else {

      if ((p = strrchr (t_pattern, '.'))) {
        /*
         * Wildcard has a suffix.
         */
        *p = 0;
        fstrcpy (ebase, t_pattern);
        if (p[1]) {
          fstrcpy (eext, p + 1);
        } else {
          /* pattern ends in DOT: treat as if there is no DOT */
          *eext = 0;
          if (strequal (ebase, "*"))
            return (True);
        }
      } else {
        /*
         * No suffix for wildcard.
         */
        fstrcpy (ebase, t_pattern);
        eext[0] = 0;
      }

      p = strrchr (t_filename, '.');
      if (p && (p[1] == 0)	) {
        /*
         * Filename has an extension of '.' only.
         */
        *p = 0; /* nuke dot at end of string */
        p = 0;  /* and treat it as if there is no extension */
      }

      if (p) {
        /*
         * Filename has an extension.
         */
        *p = 0;
        fstrcpy (sbase, t_filename);
        fstrcpy (sext, p + 1);
        if (*eext) {
          matched = do_match(sbase, ebase, case_sig)
                    && do_match(sext, eext, case_sig);
        } else {
          /* pattern has no extension */
          /* Really: match complete filename with pattern ??? means exactly 3 chars */
          matched = do_match(str, ebase, case_sig);
        }
      } else {
        /* 
         * Filename has no extension.
         */
        fstrcpy (sbase, t_filename);
        fstrcpy (sext, "");
        if (*eext) {
          /* pattern has extension */
          matched = do_match(sbase, ebase, case_sig)
                    && do_match(sext, eext, case_sig);
        } else {
          matched = do_match(sbase, ebase, case_sig);
#ifdef EMULATE_WEIRD_W95_MATCHING
          /*
           * Even Microsoft has some problems
           * Behaviour Win95 -> local disk 
           * is different from Win95 -> smb drive from Nt 4.0
           * This branch would reflect the Win95 local disk behaviour
           */
          if (!matched) {
            /* a? matches aa and a in w95 */
            fstrcat (sbase, ".");
            matched = do_match(sbase, ebase, case_sig);
          }
#endif
        }
      }
    }
  }

  DEBUG(8,("mask_match returning %d\n", matched));

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
#else /* USE_SETSID */
#ifdef TIOCNOTTY
  {
    int i = open("/dev/tty", O_RDWR);
    if (i >= 0) 
      {
	ioctl(i, (int) TIOCNOTTY, (char *)0);      
	close(i);
      }
  }
#endif /* TIOCNOTTY */
#endif /* USE_SETSID */
  /* Close fd's 0,1,2. Needed if started by rsh */
  close_low_fds();
#endif /* NO_FORK_DEBUG */
}


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
    pstrcpy(buf,path);
  else
    {
      *p = 0;
      pstrcpy(buf,path);
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
    pstrcpy(buf,path);
  else
    pstrcpy(buf,p+1);

  return(buf);
}



/****************************************************************************
expand a pointer to be a particular size
****************************************************************************/
void *Realloc(void *p,int size)
{
  void *ret=NULL;

  if (size == 0) {
    if (p) free(p);
    DEBUG(5,("Realloc asked for 0 bytes\n"));
    return NULL;
  }

  if (!p)
    ret = (void *)malloc(size);
  else
    ret = (void *)realloc(p,size);

  if (!ret)
    DEBUG(0,("Memory allocation error: failed to expand to %d bytes\n",size));

  return(ret);
}

#ifdef NOSTRDUP
/****************************************************************************
duplicate a string
****************************************************************************/
 char *strdup(char *s)
{
  char *ret = NULL;
  int len;
  if (!s) return(NULL);
  ret = (char *)malloc((len = strlen(s))+1);
  if (!ret) return(NULL);
  safe_strcpy(ret,s,len);
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

/****************************************************************************
get my own name and IP
****************************************************************************/
BOOL get_myname(char *my_name,struct in_addr *ip)
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

  if (my_name)
    {
      /* split off any parts after an initial . */
      char *p = strchr(hostname,'.');
      if (p) *p = 0;

      fstrcpy(my_name,hostname);
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
  uint32 a1,a2;
  a1 = ntohl(ip1.s_addr);
  a2 = ntohl(ip2.s_addr);
  return(a1 == a2);
}


/****************************************************************************
open a socket of the specified type, port and address for incoming data
****************************************************************************/
int open_socket_in(int type, int port, int dlevel,uint32 socket_addr)
{
  struct hostent *hp;
  struct sockaddr_in sock;
  pstring host_name;
  int res;

  /* get my host name */
  if (gethostname(host_name, MAXHOSTNAMELEN) == -1) 
    { DEBUG(0,("gethostname failed\n")); return -1; } 

  /* get host info */
  if ((hp = Get_Hostbyname(host_name)) == 0) 
    {
      DEBUG(0,( "Get_Hostbyname: Unknown host. %s\n",host_name));
      return -1;
    }
  
  bzero((char *)&sock,sizeof(sock));
  memcpy((char *)&sock.sin_addr,(char *)hp->h_addr, hp->h_length);
#if defined(__FreeBSD__) || defined(NETBSD) || defined(__OpenBSD__) /* XXX not the right ifdef */
  sock.sin_len = sizeof(sock);
#endif
  sock.sin_port = htons( port );
  sock.sin_family = hp->h_addrtype;
  sock.sin_addr.s_addr = socket_addr;
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
	if (port == SMB_PORT || port == NMB_PORT)
	  DEBUG(dlevel,("bind failed on port %d socket_addr=%s (%s)\n",
			port,inet_ntoa(sock.sin_addr),strerror(errno))); 
	close(res); 

	if (dlevel > 0 && port < 1000)
	  port = 7999;

	if (port >= 1000 && port < 9000)
	  return(open_socket_in(type,port+1,dlevel,socket_addr));
      }

      return(-1); 
    }
  DEBUG(3,("bind succeeded on port %d\n",port));

  return res;
}


/****************************************************************************
  create an outgoing socket
  **************************************************************************/
int open_socket_out(int type, struct in_addr *addr, int port ,int timeout)
{
  struct sockaddr_in sock_out;
  int res,ret;
  int connect_loop = 250; /* 250 milliseconds */
  int loops = (timeout * 1000) / connect_loop;

  /* create a socket to write to */
  res = socket(PF_INET, type, 0);
  if (res == -1) 
    { DEBUG(0,("socket error\n")); return -1; }

  if (type != SOCK_STREAM) return(res);
  
  bzero((char *)&sock_out,sizeof(sock_out));
  putip((char *)&sock_out.sin_addr,(char *)addr);
  
  sock_out.sin_port = htons( port );
  sock_out.sin_family = PF_INET;

  /* set it non-blocking */
  set_blocking(res,False);

  DEBUG(3,("Connecting to %s at port %d\n",inet_ntoa(*addr),port));
  
  /* and connect it to the destination */
connect_again:
  ret = connect(res,(struct sockaddr *)&sock_out,sizeof(sock_out));

  /* Some systems return EAGAIN when they mean EINPROGRESS */
  if (ret < 0 && (errno == EINPROGRESS || errno == EALREADY ||
        errno == EAGAIN) && loops--) {
    msleep(connect_loop);
    goto connect_again;
  }

  if (ret < 0 && (errno == EINPROGRESS || errno == EALREADY ||
         errno == EAGAIN)) {
      DEBUG(1,("timeout connecting to %s:%d\n",inet_ntoa(*addr),port));
      close(res);
      return -1;
  }

#ifdef EISCONN
  if (ret < 0 && errno == EISCONN) {
    errno = 0;
    ret = 0;
  }
#endif

  if (ret < 0) {
    DEBUG(1,("error connecting to %s:%d (%s)\n",
	     inet_ntoa(*addr),port,strerror(errno)));
    close(res);
    return -1;
  }

  /* set it blocking again */
  set_blocking(res,True);

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
uint32 interpret_addr(char *str)
{
  struct hostent *hp;
  uint32 res;
  int i;
  BOOL pure_address = True;

  if (strcmp(str,"0.0.0.0") == 0) return(0);
  if (strcmp(str,"255.255.255.255") == 0) return(0xFFFFFFFF);

  for (i=0; pure_address && str[i]; i++)
    if (!(isdigit(str[i]) || str[i] == '.')) 
      pure_address = False;

  /* if it's in the form of an IP address then get the lib to interpret it */
  if (pure_address) {
    res = inet_addr(str);
  } else {
    /* otherwise assume it's a network name of some sort and use 
       Get_Hostbyname */
    if ((hp = Get_Hostbyname(str)) == 0) {
      DEBUG(3,("Get_Hostbyname: Unknown host. %s\n",str));
      return 0;
    }
    if(hp->h_addr == NULL) {
      DEBUG(3,("Get_Hostbyname: host address is invalid for host %s.\n",str));
      return 0;
    }
    putip((char *)&res,(char *)hp->h_addr);
  }

  if (res == (uint32)-1) return(0);

  return(res);
}

/*******************************************************************
  a convenient addition to interpret_addr()
  ******************************************************************/
struct in_addr *interpret_addr2(char *str)
{
  static struct in_addr ret;
  uint32 a = interpret_addr(str);
  ret.s_addr = a;
  return(&ret);
}

/*******************************************************************
  check if an IP is the 0.0.0.0
  ******************************************************************/
BOOL zero_ip(struct in_addr ip)
{
  uint32 a;
  putip((char *)&a,(char *)&ip);
  return(a == 0);
}


/*******************************************************************
 matchname - determine if host name matches IP address 
 ******************************************************************/
static BOOL matchname(char *remotehost,struct in_addr  addr)
{
  struct hostent *hp;
  int     i;
  
  if ((hp = Get_Hostbyname(remotehost)) == 0) {
    DEBUG(0,("Get_Hostbyname(%s): lookup failure", remotehost));
    return False;
  } 

  /*
   * Make sure that gethostbyname() returns the "correct" host name.
   * Unfortunately, gethostbyname("localhost") sometimes yields
   * "localhost.domain". Since the latter host name comes from the
   * local DNS, we just have to trust it (all bets are off if the local
   * DNS is perverted). We always check the address list, though.
   */
  
  if (strcasecmp(remotehost, hp->h_name)
      && strcasecmp(remotehost, "localhost")) {
    DEBUG(0,("host name/name mismatch: %s != %s",
	     remotehost, hp->h_name));
    return False;
  }
	
  /* Look up the host address in the address list we just got. */
  for (i = 0; hp->h_addr_list[i]; i++) {
    if (memcmp(hp->h_addr_list[i], (caddr_t) & addr, sizeof(addr)) == 0)
      return True;
  }

  /*
   * The host name does not map to the original host address. Perhaps
   * someone has compromised a name server. More likely someone botched
   * it, but that could be dangerous, too.
   */
  
  DEBUG(0,("host name/address mismatch: %s != %s",
	   inet_ntoa(addr), hp->h_name));
  return False;
}

/*******************************************************************
 Reset the 'done' variables so after a client process is created
 from a fork call these calls will be re-done. This should be
 expanded if more variables need reseting.
 ******************************************************************/

static BOOL global_client_name_done = False;
static BOOL global_client_addr_done = False;

void reset_globals_after_fork(void)
{
  global_client_name_done = False;
  global_client_addr_done = False;
}
 
/*******************************************************************
 return the DNS name of the client 
 ******************************************************************/
char *client_name(void)
{
  struct sockaddr sa;
  struct sockaddr_in *sockin = (struct sockaddr_in *) (&sa);
  int     length = sizeof(sa);
  static pstring name_buf;
  struct hostent *hp;

  if (global_client_name_done) 
    return name_buf;

  pstrcpy(name_buf,"UNKNOWN");

  if (Client == -1) {
	  return name_buf;
  }

  if (getpeername(Client, &sa, &length) < 0) {
    DEBUG(0,("getpeername failed\n"));
    return name_buf;
  }

  /* Look up the remote host name. */
  if ((hp = gethostbyaddr((char *) &sockin->sin_addr,
			  sizeof(sockin->sin_addr),
			  AF_INET)) == 0) {
    DEBUG(1,("Gethostbyaddr failed for %s\n",client_addr()));
    StrnCpy(name_buf,client_addr(),sizeof(name_buf) - 1);
  } else {
    StrnCpy(name_buf,(char *)hp->h_name,sizeof(name_buf) - 1);
    if (!matchname(name_buf, sockin->sin_addr)) {
      DEBUG(0,("Matchname failed on %s %s\n",name_buf,client_addr()));
      pstrcpy(name_buf,"UNKNOWN");
    }
  }
  global_client_name_done = True;
  return name_buf;
}

/*******************************************************************
 return the IP addr of the client as a string 
 ******************************************************************/
char *client_addr(void)
{
  struct sockaddr sa;
  struct sockaddr_in *sockin = (struct sockaddr_in *) (&sa);
  int     length = sizeof(sa);
  static fstring addr_buf;

  if (global_client_addr_done) 
    return addr_buf;

  fstrcpy(addr_buf,"0.0.0.0");

  if (Client == -1) {
	  return addr_buf;
  }

  if (getpeername(Client, &sa, &length) < 0) {
    DEBUG(0,("getpeername failed\n"));
    return addr_buf;
  }

  fstrcpy(addr_buf,(char *)inet_ntoa(sockin->sin_addr));

  global_client_addr_done = True;
  return addr_buf;
}

/*******************************************************************
 Patch from jkf@soton.ac.uk
 Split Luke's automount_server into YP lookup and string splitter
 so can easily implement automount_path(). 
 As we may end up doing both, cache the last YP result. 
*******************************************************************/

#if (defined(NETGROUP) && defined(AUTOMOUNT))
#ifdef NISPLUS
static char *automount_lookup(char *user_name)
{
  static fstring last_key = "";
  static pstring last_value = "";
 
  char *nis_map = (char *)lp_nis_home_map_name();
 
  char nis_domain[NIS_MAXNAMELEN + 1];
  char buffer[NIS_MAXATTRVAL + 1];
  nis_result *result;
  nis_object *object;
  entry_obj  *entry;
 
  strncpy(nis_domain, (char *)nis_local_directory(), NIS_MAXNAMELEN);
  nis_domain[NIS_MAXNAMELEN] = '\0';
 
  DEBUG(5, ("NIS+ Domain: %s\n", nis_domain));
 
  if (strcmp(user_name, last_key))
  {
    slprintf(buffer, sizeof(buffer)-1, "[%s=%s]%s.%s", "key", user_name, nis_map, nis_domain);
    DEBUG(5, ("NIS+ querystring: %s\n", buffer));
 
    if (result = nis_list(buffer, RETURN_RESULT, NULL, NULL))
    {
       if (result->status != NIS_SUCCESS)
      {
        DEBUG(3, ("NIS+ query failed: %s\n", nis_sperrno(result->status)));
        fstrcpy(last_key, ""); pstrcpy(last_value, "");
      }
      else
      {
        object = result->objects.objects_val;
        if (object->zo_data.zo_type == ENTRY_OBJ)
        {
           entry = &object->zo_data.objdata_u.en_data;
           DEBUG(5, ("NIS+ entry type: %s\n", entry->en_type));
           DEBUG(3, ("NIS+ result: %s\n", entry->en_cols.en_cols_val[1].ec_value.ec_value_val));
 
           pstrcpy(last_value, entry->en_cols.en_cols_val[1].ec_value.ec_value_val);
           string_sub(last_value, "&", user_name);
           fstrcpy(last_key, user_name);
        }
      }
    }
    nis_freeresult(result);
  }
  DEBUG(4, ("NIS+ Lookup: %s resulted in %s\n", user_name, last_value));
  return last_value;
}
#else /* NISPLUS */
static char *automount_lookup(char *user_name)
{
  static fstring last_key = "";
  static pstring last_value = "";

  int nis_error;        /* returned by yp all functions */
  char *nis_result;     /* yp_match inits this */
  int nis_result_len;  /* and set this */
  char *nis_domain;     /* yp_get_default_domain inits this */
  char *nis_map = (char *)lp_nis_home_map_name();

  if ((nis_error = yp_get_default_domain(&nis_domain)) != 0)
  {
    DEBUG(3, ("YP Error: %s\n", yperr_string(nis_error)));
    return last_value;
  }

  DEBUG(5, ("NIS Domain: %s\n", nis_domain));

  if (!strcmp(user_name, last_key))
  {
    nis_result = last_value;
    nis_result_len = strlen(last_value);
    nis_error = 0;
  }
  else
  {
    if ((nis_error = yp_match(nis_domain, nis_map,
                              user_name, strlen(user_name),
                              &nis_result, &nis_result_len)) != 0)
    {
      DEBUG(3, ("YP Error: \"%s\" while looking up \"%s\" in map \"%s\"\n", 
               yperr_string(nis_error), user_name, nis_map));
    }
    if (!nis_error && nis_result_len >= sizeof(pstring))
    {
      nis_result_len = sizeof(pstring)-1;
    }
    fstrcpy(last_key, user_name);
    strncpy(last_value, nis_result, nis_result_len);
    last_value[nis_result_len] = '\0';
  }

  DEBUG(4, ("YP Lookup: %s resulted in %s\n", user_name, last_value));
  return last_value;
}
#endif /* NISPLUS */
#endif

/*******************************************************************
 Patch from jkf@soton.ac.uk
 This is Luke's original function with the NIS lookup code
 moved out to a separate function.
*******************************************************************/

char *automount_server(char *user_name)
{
	static pstring server_name;

#if (defined(NETGROUP) && defined (AUTOMOUNT))
	int home_server_len;

	/* set to default of local machine */
	pstrcpy(server_name, local_machine);

	if (lp_nis_home_map())
	{
		char *automount_value = automount_lookup(user_name);
		home_server_len = strcspn(automount_value,":");
		DEBUG(5, ("NIS lookup succeeded.  Home server length: %d\n",home_server_len));
		if (home_server_len > sizeof(pstring))
		{
			home_server_len = sizeof(pstring);
		}
		strncpy(server_name, automount_value, home_server_len);
                server_name[home_server_len] = '\0';
	}
#else
	/* use the local machine name instead of the auto-map server */
	pstrcpy(server_name, local_machine);
#endif

	DEBUG(4,("Home server: %s\n", server_name));

	return server_name;
}

/*******************************************************************
 Patch from jkf@soton.ac.uk
 Added this to implement %p (NIS auto-map version of %H)
*******************************************************************/

char *automount_path(char *user_name)
{
	static pstring server_path;

#if (defined(NETGROUP) && defined (AUTOMOUNT))
	char *home_path_start;

	/* set to default of no string */
	server_path[0] = 0;

	if (lp_nis_home_map())
	{
		char *automount_value = automount_lookup(user_name);
		home_path_start = strchr(automount_value,':');
		if (home_path_start != NULL)
		{
		  DEBUG(5, ("NIS lookup succeeded.  Home path is: %s\n",
		        home_path_start?(home_path_start+1):""));
		  pstrcpy(server_path, home_path_start+1);
		}
	}
#else
	/* use the passwd entry instead of the auto-map server entry */
	/* pstrcpy() copes with get_home_dir() returning NULL */
	pstrcpy(server_path, get_home_dir(user_name));
#endif

	DEBUG(4,("Home server path: %s\n", server_path));

	return server_path;
}


/*******************************************************************
sub strings with useful parameters
Rewritten by Stefaan A Eeckels <Stefaan.Eeckels@ecc.lu> and
Paul Rippin <pr3245@nopc.eurostat.cec.be>
********************************************************************/
void standard_sub_basic(char *str)
{
	char *s, *p;
	char pidstr[10];
        struct passwd *pass;
        char *username = sam_logon_in_ssb ? samlogon_user : sesssetup_user;

	for (s = str ; s && *s && (p = strchr(s,'%')); s = p )
	{
		switch (*(p+1))
		{
                        case 'G' :
                        {
                                if ((pass = Get_Pwnam(username,False))!=NULL)
                                {
                                        string_sub(p,"%G",gidtoname(pass->pw_gid));
                                }
                                else
                                {
                                        p += 2;
                                }
                                break;
                        }
                        case 'N' : string_sub(p,"%N", automount_server(username)); break;
			case 'I' : string_sub(p,"%I", client_addr()); break;
			case 'L' : string_sub(p,"%L", local_machine); break;
			case 'M' : string_sub(p,"%M", client_name()); break;
			case 'R' : string_sub(p,"%R", remote_proto); break;
			case 'T' : string_sub(p,"%T", timestring()); break;
			case 'a' : string_sub(p,"%a", remote_arch); break;
                        case 'U' : string_sub(p,"%U", username); break;
			case 'd' :
			{
				slprintf(pidstr,sizeof(pidstr)-1,"%d",(int)getpid());
				string_sub(p,"%d", pidstr);
				break;
			}
			case 'h' : string_sub(p,"%h", myhostname); break;
			case 'm' : string_sub(p,"%m", remote_machine); break;
			case 'v' : string_sub(p,"%v", VERSION); break;
                        case '$' : /* Expand environment variables */
                        {
                          /* Contributed by Branko Cibej <branko.cibej@hermes.si> */
                          fstring envname;
                          char *envval;
                          char *q, *r;
                          int copylen;
 
                          if (*(p+2) != '(') { p+=2; break; }
                          if ((q = strchr(p,')')) == NULL)
                          {
                            DEBUG(0,("standard_sub_basic: Unterminated environment \
variable [%s]\n", p));
                            p+=2; break;
                          }
 
                          r = p+3;
                          copylen = MIN((q-r),(sizeof(envname)-1));
                          strncpy(envname,r,copylen);
                          envname[copylen] = '\0';
                          if ((envval = getenv(envname)) == NULL)
                          {
                            DEBUG(0,("standard_sub_basic: Environment variable [%s] not set\n",
                                     envname));
                            p+=2; break;
                          }
                          copylen = MIN((q+1-p),(sizeof(envname)-1));
                          strncpy(envname,p,copylen);
                          envname[copylen] = '\0';
                          string_sub(p,envname,envval);
                          break;
                        }
			case '\0': p++; break; /* don't run off end if last character is % */
			default  : p+=2; break;
		}
	}
	return;
}

/*******************************************************************
are two IPs on the same subnet?
********************************************************************/
BOOL same_net(struct in_addr ip1,struct in_addr ip2,struct in_addr mask)
{
  uint32 net1,net2,nmask;

  nmask = ntohl(mask.s_addr);
  net1  = ntohl(ip1.s_addr);
  net2  = ntohl(ip2.s_addr);
            
  return((net1 & nmask) == (net2 & nmask));
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

  /*
   * This next test is redundent and causes some systems (with
   * broken isalnum() calls) problems.
   * JRA.
   */

#if 0
  if (!isalnum(*name2))
    {
      free(name2);
      return(NULL);
    }
#endif /* 0 */

  ret = sys_gethostbyname(name2);
  if (ret != NULL)
    {
      free(name2);
      return(ret);
    }

  /* try with all lowercase */
  strlower(name2);
  ret = sys_gethostbyname(name2);
  if (ret != NULL)
    {
      free(name2);
      return(ret);
    }

  /* try with all uppercase */
  strupper(name2);
  ret = sys_gethostbyname(name2);
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
	return(kill(pid,0) == 0 || errno != ESRCH);
}


/*******************************************************************
turn a uid into a user name
********************************************************************/
char *uidtoname(int uid)
{
  static char name[40];
  struct passwd *pass = getpwuid(uid);
  if (pass) return(pass->pw_name);
  slprintf(name,sizeof(name)-1,"%d",uid);
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
  slprintf(name,sizeof(name)-1,"%d",gid);
  return(name);
}

/*******************************************************************
block sigs
********************************************************************/
void BlockSignals(BOOL block,int signum)
{
#ifdef USE_SIGBLOCK
  int block_mask = sigmask(signum);
  static int oldmask = 0;
  if (block) 
    oldmask = sigblock(block_mask);
  else
    sigsetmask(oldmask);
#elif defined(USE_SIGPROCMASK)
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set,signum);
  sigprocmask(block?SIG_BLOCK:SIG_UNBLOCK,&set,NULL);
#endif
}

#if AJT
/*******************************************************************
my own panic function - not suitable for general use
********************************************************************/
void ajt_panic(void)
{
  system("/usr/bin/X11/xedit -display solen:0 /tmp/ERROR_FAULT");
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
      dname = dname - 2;
  }
#endif

  {
    static pstring buf;
    pstrcpy(buf, dname);
    unix_to_dos(buf, True);
    dname = buf;
  }

  return(dname);
}

/*******************************************************************
 Utility function used to decide if the last component 
 of a path matches a (possibly wildcarded) entry in a namelist.
********************************************************************/

BOOL is_in_path(char *name, name_compare_entry *namelist)
{
  pstring last_component;
  char *p;

  DEBUG(8, ("is_in_path: %s\n", name));

  /* if we have no list it's obviously not in the path */
  if((namelist == NULL ) || ((namelist != NULL) && (namelist[0].name == NULL))) 
  {
    DEBUG(8,("is_in_path: no name list.\n"));
    return False;
  }

  /* Get the last component of the unix name. */
  p = strrchr(name, '/');
  strncpy(last_component, p ? ++p : name, sizeof(last_component)-1);
  last_component[sizeof(last_component)-1] = '\0'; 

  for(; namelist->name != NULL; namelist++)
  {
    if(namelist->is_wild)
    {
      /* look for a wildcard match. */
      if (mask_match(last_component, namelist->name, case_sensitive, False))
      {
         DEBUG(8,("is_in_path: mask match succeeded\n"));
         return True;
      }
    }
    else
    {
      if((case_sensitive && (strcmp(last_component, namelist->name) == 0))||
       (!case_sensitive && (StrCaseCmp(last_component, namelist->name) == 0)))
        {
         DEBUG(8,("is_in_path: match succeeded\n"));
         return True;
        }
    }
  }
  DEBUG(8,("is_in_path: match not found\n"));
 
  return False;
}

/*******************************************************************
 Strip a '/' separated list into an array of 
 name_compare_enties structures suitable for 
 passing to is_in_path(). We do this for
 speed so we can pre-parse all the names in the list 
 and don't do it for each call to is_in_path().
 namelist is modified here and is assumed to be 
 a copy owned by the caller.
 We also check if the entry contains a wildcard to
 remove a potentially expensive call to mask_match
 if possible.
********************************************************************/
 
void set_namearray(name_compare_entry **ppname_array, char *namelist)
{
  char *name_end;
  char *nameptr = namelist;
  int num_entries = 0;
  int i;

  (*ppname_array) = NULL;

  if((nameptr == NULL ) || ((nameptr != NULL) && (*nameptr == '\0'))) 
    return;

  /* We need to make two passes over the string. The
     first to count the number of elements, the second
     to split it.
   */
  while(*nameptr) 
    {
      if ( *nameptr == '/' ) 
        {
          /* cope with multiple (useless) /s) */
          nameptr++;
          continue;
        }
      /* find the next / */
      name_end = strchr(nameptr, '/');

      /* oops - the last check for a / didn't find one. */
      if (name_end == NULL)
        break;

      /* next segment please */
      nameptr = name_end + 1;
      num_entries++;
    }

  if(num_entries == 0)
    return;

  if(( (*ppname_array) = (name_compare_entry *)malloc( 
           (num_entries + 1) * sizeof(name_compare_entry))) == NULL)
        {
    DEBUG(0,("set_namearray: malloc fail\n"));
    return;
        }

  /* Now copy out the names */
  nameptr = namelist;
  i = 0;
  while(*nameptr)
             {
      if ( *nameptr == '/' ) 
      {
          /* cope with multiple (useless) /s) */
          nameptr++;
          continue;
      }
      /* find the next / */
      if ((name_end = strchr(nameptr, '/')) != NULL) 
      {
          *name_end = 0;
         }

      /* oops - the last check for a / didn't find one. */
      if(name_end == NULL) 
        break;

      (*ppname_array)[i].is_wild = ((strchr( nameptr, '?')!=NULL) ||
                                (strchr( nameptr, '*')!=NULL));
      if(((*ppname_array)[i].name = strdup(nameptr)) == NULL)
      {
        DEBUG(0,("set_namearray: malloc fail (1)\n"));
        return;
      }

      /* next segment please */
      nameptr = name_end + 1;
      i++;
    }
  
  (*ppname_array)[i].name = NULL;

  return;
}

/****************************************************************************
routine to free a namearray.
****************************************************************************/

void free_namearray(name_compare_entry *name_array)
{
  if(name_array == 0)
    return;

  if(name_array->name != NULL)
    free(name_array->name);

  free((char *)name_array);
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
  uint32 mask = ((unsigned)1<<31);

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


  DEBUG(8,("fcntl_lock %d %d %d %d %d\n",fd,op,(int)offset,(int)count,type));

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
  DEBUG(8,("Lock call successful\n"));

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
is the name specified one of my netbios names
returns true is it is equal, false otherwise
********************************************************************/
BOOL is_myname(char *s)
{
  int n;
  BOOL ret = False;

  for (n=0; my_netbios_names[n]; n++) {
    if (strequal(my_netbios_names[n], s))
      ret=True;
  }
  DEBUG(8, ("is_myname(\"%s\") returns %d\n", s, ret));
  return(ret);
}

/*******************************************************************
set the horrid remote_arch string based on an enum.
********************************************************************/
void set_remote_arch(enum remote_arch_types type)
{
  ra_type = type;
  switch( type )
  {
  case RA_WFWG:
    fstrcpy(remote_arch, "WfWg");
    return;
  case RA_OS2:
    fstrcpy(remote_arch, "OS2");
    return;
  case RA_WIN95:
    fstrcpy(remote_arch, "Win95");
    return;
  case RA_WINNT:
    fstrcpy(remote_arch, "WinNT");
    return;
  case RA_SAMBA:
    fstrcpy(remote_arch,"Samba");
    return;
  default:
    ra_type = RA_UNKNOWN;
    fstrcpy(remote_arch, "UNKNOWN");
    break;
  }
}

/*******************************************************************
 Get the remote_arch type.
********************************************************************/
enum remote_arch_types get_remote_arch(void)
{
  return ra_type;
}


/*******************************************************************
skip past some unicode strings in a buffer
********************************************************************/
char *skip_unicode_string(char *buf,int n)
{
  while (n--)
  {
    while (*buf)
      buf += 2;
    buf += 2;
  }
  return(buf);
}

/*******************************************************************
Return a ascii version of a unicode string
Hack alert: uses fixed buffer(s) and only handles ascii strings
********************************************************************/
#define MAXUNI 1024
char *unistrn2(uint16 *buf, int len)
{
	static char lbufs[8][MAXUNI];
	static int nexti;
	char *lbuf = lbufs[nexti];
	char *p;

	nexti = (nexti+1)%8;

	DEBUG(10, ("unistrn2: "));

	for (p = lbuf; *buf && p-lbuf < MAXUNI-2 && len > 0; len--, p++, buf++)
	{
		DEBUG(10, ("%4x ", *buf));
		*p = *buf;
	}

	DEBUG(10,("\n"));

	*p = 0;
	return lbuf;
}

/*******************************************************************
Return a ascii version of a unicode string
Hack alert: uses fixed buffer(s) and only handles ascii strings
********************************************************************/
#define MAXUNI 1024
char *unistr2(uint16 *buf)
{
	static char lbufs[8][MAXUNI];
	static int nexti;
	char *lbuf = lbufs[nexti];
	char *p;

	nexti = (nexti+1)%8;

	DEBUG(10, ("unistr2: "));

	for (p = lbuf; *buf && p-lbuf < MAXUNI-2; p++, buf++)
	{
		DEBUG(10, ("%4x ", *buf));
		*p = *buf;
	}

	DEBUG(10,("\n"));

	*p = 0;
	return lbuf;
}

/*******************************************************************
create a null-terminated unicode string from a null-terminated ascii string.
return number of unicode chars copied, excluding the null character.

only handles ascii strings
********************************************************************/
#define MAXUNI 1024
int struni2(uint16 *p, char *buf)
{
	int len = 0;

	if (p == NULL) return 0;

	DEBUG(10, ("struni2: "));

	if (buf != NULL)
	{
		for (; *buf && len < MAXUNI-2; len++, p++, buf++)
		{
			DEBUG(10, ("%2x ", *buf));
			*p = *buf;
		}

		DEBUG(10,("\n"));
	}

	*p = 0;

	return len;
}

/*******************************************************************
Return a ascii version of a unicode string
Hack alert: uses fixed buffer(s) and only handles ascii strings
********************************************************************/
#define MAXUNI 1024
char *unistr(char *buf)
{
	static char lbufs[8][MAXUNI];
	static int nexti;
	char *lbuf = lbufs[nexti];
	char *p;

	nexti = (nexti+1)%8;

	for (p = lbuf; *buf && p-lbuf < MAXUNI-2; p++, buf += 2)
	{
		*p = *buf;
	}
	*p = 0;
	return lbuf;
}

/*******************************************************************
strncpy for unicode strings
********************************************************************/
int unistrncpy(char *dst, char *src, int len)
{
	int num_wchars = 0;

	while (*src && len > 0)
	{
		*dst++ = *src++;
		*dst++ = *src++;
		len--;
		num_wchars++;
	}
	*dst++ = 0;
	*dst++ = 0;

	return num_wchars;
}


/*******************************************************************
strcpy for unicode strings.  returns length (in num of wide chars)
********************************************************************/
int unistrcpy(char *dst, char *src)
{
	int num_wchars = 0;

	while (*src)
	{
		*dst++ = *src++;
		*dst++ = *src++;
		num_wchars++;
	}
	*dst++ = 0;
	*dst++ = 0;

	return num_wchars;
}

/*******************************************************************
safe string copy into a known length string. maxlength does not
include the terminating zero.
********************************************************************/
char *safe_strcpy(char *dest, char *src, int maxlength)
{
    int len;

    if (!dest) {
        DEBUG(0,("ERROR: NULL dest in safe_strcpy\n"));
        return NULL;
    }

    if (!src) {
        *dest = 0;
        return dest;
    } 

    len = strlen(src);

    if (len > maxlength) {
            DEBUG(0,("ERROR: string overflow by %d in safe_strcpy [%.50s]\n",
                     len-maxlength, src));
            len = maxlength;
    }

    memcpy(dest, src, len);
    dest[len] = 0;
    return dest;
} 

/*******************************************************************
safe string cat into a string. maxlength does not
include the terminating zero.
********************************************************************/
char *safe_strcat(char *dest, char *src, int maxlength)
{
    int src_len, dest_len;

    if (!dest) {
        DEBUG(0,("ERROR: NULL dest in safe_strcat\n"));
        return NULL;
    }

    if (!src) {
        return dest;
    }

    src_len = strlen(src);
    dest_len = strlen(dest);

    if (src_len + dest_len > maxlength) {
            DEBUG(0,("ERROR: string overflow by %d in safe_strcat [%.50s]\n",
                     src_len + dest_len - maxlength, src));
            src_len = maxlength - dest_len;
    }

    memcpy(&dest[dest_len], src, src_len);
    dest[dest_len + src_len] = 0;
    return dest;
}


/*******************************************************************
align a pointer to a multiple of 4 bytes
********************************************************************/
char *align4(char *q, char *base)
{
	if ((q - base) & 3)
	{
		q += 4 - ((q - base) & 3);
	}
	return q;
}

/*******************************************************************
align a pointer to a multiple of 2 bytes
********************************************************************/
char *align2(char *q, char *base)
{
	if ((q - base) & 1)
	{
		q++;
	}
	return q;
}

/*******************************************************************
align a pointer to a multiple of align_offset bytes.  looks like it
will work for offsets of 0, 2 and 4...
********************************************************************/
char *align_offset(char *q, char *base, int align_offset_len)
{
	int mod = ((q - base) & (align_offset_len-1));
	if (align_offset_len != 0 && mod != 0)
	{
		q += align_offset_len - mod;
	}
	return q;
}

void print_asc(int level, unsigned char *buf,int len)
{
	int i;
	for (i=0;i<len;i++)
		DEBUG(level,("%c", isprint(buf[i])?buf[i]:'.'));
}

void dump_data(int level,char *buf1,int len)
{
  unsigned char *buf = (unsigned char *)buf1;
  int i=0;
  if (len<=0) return;

  DEBUG(level,("[%03X] ",i));
  for (i=0;i<len;) {
    DEBUG(level,("%02X ",(int)buf[i]));
    i++;
    if (i%8 == 0) DEBUG(level,(" "));
    if (i%16 == 0) {      
      print_asc(level,&buf[i-16],8); DEBUG(level,(" "));
      print_asc(level,&buf[i-8],8); DEBUG(level,("\n"));
      if (i<len) DEBUG(level,("[%03X] ",i));
    }
  }
  if (i%16) {
    int n;

    n = 16 - (i%16);
    DEBUG(level,(" "));
    if (n>8) DEBUG(level,(" "));
    while (n--) DEBUG(level,("   "));

    n = MIN(8,i%16);
    print_asc(level,&buf[i-(i%16)],n); DEBUG(level,(" "));
    n = (i%16) - n;
    if (n>0) print_asc(level,&buf[i-n],n); 
    DEBUG(level,("\n"));    
  }
}

char *tab_depth(int depth)
{
	static pstring spaces;
	memset(spaces, ' ', depth * 4);
	spaces[depth * 4] = 0;
	return spaces;
}


