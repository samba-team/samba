/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Main SMB server routines
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
#include "trans2.h"

pstring servicesf = CONFIGFILE;
extern pstring debugf;
extern pstring sesssetup_user;
extern fstring myworkgroup;

char *InBuffer = NULL;
char *OutBuffer = NULL;
char *last_inbuf = NULL;

int am_parent = 1;
int atexit_set = 0;

/* the last message the was processed */
int last_message = -1;

/* a useful macro to debug the last message processed */
#define LAST_MESSAGE() smb_fn_name(last_message)

extern pstring scope;
extern int DEBUGLEVEL;
extern int case_default;
extern BOOL case_sensitive;
extern BOOL case_preserve;
extern BOOL use_mangled_map;
extern BOOL short_case_preserve;
extern BOOL case_mangle;
time_t smb_last_time=(time_t)0;

extern int smb_read_error;

extern pstring user_socket_options;

#ifdef DFS_AUTH
extern int dcelogin_atmost_once;
#endif /* DFS_AUTH */

connection_struct Connections[MAX_CONNECTIONS];
files_struct Files[MAX_OPEN_FILES];

/*
 * Indirection for file fd's. Needed as POSIX locking
 * is based on file/process, not fd/process.
 */
file_fd_struct FileFd[MAX_OPEN_FILES];
int max_file_fd_used = 0;

extern int Protocol;

/* 
 * Size of data we can send to client. Set
 *  by the client for all protocols above CORE.
 *  Set by us for CORE protocol.
 */
int max_send = BUFFER_SIZE;
/*
 * Size of the data we can receive. Set by us.
 * Can be modified by the max xmit parameter.
 */
int max_recv = BUFFER_SIZE;

/* a fnum to use when chaining */
int chain_fnum = -1;

/* number of open connections */
static int num_connections_open = 0;

/* Oplock ipc UDP socket. */
int oplock_sock = -1;
uint16 oplock_port = 0;
/* Current number of oplocks we have outstanding. */
int32 global_oplocks_open = 0;

BOOL global_oplock_break = False;

extern fstring remote_machine;

extern pstring OriginalDir;

/* these can be set by some functions to override the error codes */
int unix_ERR_class=SMB_SUCCESS;
int unix_ERR_code=0;


extern int extra_time_offset;

extern pstring myhostname;

static int find_free_connection(int hash);

/* for readability... */
#define IS_DOS_READONLY(test_mode) (((test_mode) & aRONLY) != 0)
#define IS_DOS_DIR(test_mode) (((test_mode) & aDIR) != 0)
#define IS_DOS_ARCHIVE(test_mode) (((test_mode) & aARCH) != 0)
#define IS_DOS_SYSTEM(test_mode) (((test_mode) & aSYSTEM) != 0)
#define IS_DOS_HIDDEN(test_mode) (((test_mode) & aHIDDEN) != 0)

/****************************************************************************
  when exiting, take the whole family
****************************************************************************/
void  *dflt_sig(void)
{
  exit_server("caught signal");
  return 0; /* Keep -Wall happy :-) */
}
/****************************************************************************
  Send a SIGTERM to our process group.
*****************************************************************************/
void  killkids(void)
{
  if(am_parent) kill(0,SIGTERM);
}

/****************************************************************************
  change a dos mode to a unix mode
    base permission for files:
         everybody gets read bit set
         dos readonly is represented in unix by removing everyone's write bit
         dos archive is represented in unix by the user's execute bit
         dos system is represented in unix by the group's execute bit
         dos hidden is represented in unix by the other's execute bit
         Then apply create mask,
         then add force bits.
    base permission for directories:
         dos directory is represented in unix by unix's dir bit and the exec bit
         Then apply create mask,
         then add force bits.
****************************************************************************/
mode_t unix_mode(int cnum,int dosmode)
{
  mode_t result = (S_IRUSR | S_IRGRP | S_IROTH);

  if ( !IS_DOS_READONLY(dosmode) )
    result |= (S_IWUSR | S_IWGRP | S_IWOTH);
 
  if (IS_DOS_DIR(dosmode)) {
    /* We never make directories read only for the owner as under DOS a user
       can always create a file in a read-only directory. */
    result |= (S_IFDIR | S_IXUSR | S_IXGRP | S_IXOTH | S_IWUSR);
    /* Apply directory mask */
    result &= lp_dir_mode(SNUM(cnum));
    /* Add in force bits */
    result |= lp_force_dir_mode(SNUM(cnum));
  } else { 
    if (MAP_ARCHIVE(cnum) && IS_DOS_ARCHIVE(dosmode))
      result |= S_IXUSR;

    if (MAP_SYSTEM(cnum) && IS_DOS_SYSTEM(dosmode))
      result |= S_IXGRP;
 
    if (MAP_HIDDEN(cnum) && IS_DOS_HIDDEN(dosmode))
      result |= S_IXOTH;  
 
    /* Apply mode mask */
    result &= lp_create_mode(SNUM(cnum));
    /* Add in force bits */
    result |= lp_force_create_mode(SNUM(cnum));
  }
  return(result);
}


/****************************************************************************
  change a unix mode to a dos mode
****************************************************************************/
int dos_mode(int cnum,char *path,struct stat *sbuf)
{
  int result = 0;
  extern struct current_user current_user;

  DEBUG(8,("dos_mode: %d %s\n", cnum, path));

  if (CAN_WRITE(cnum) && !lp_alternate_permissions(SNUM(cnum))) {
    if (!((sbuf->st_mode & S_IWOTH) ||
	  Connections[cnum].admin_user ||
	  ((sbuf->st_mode & S_IWUSR) && current_user.uid==sbuf->st_uid) ||
	  ((sbuf->st_mode & S_IWGRP) && 
	   in_group(sbuf->st_gid,current_user.gid,
		    current_user.ngroups,current_user.igroups))))
      result |= aRONLY;
  } else {
    if ((sbuf->st_mode & S_IWUSR) == 0)
      result |= aRONLY;
  }

  if (MAP_ARCHIVE(cnum) && ((sbuf->st_mode & S_IXUSR) != 0))
    result |= aARCH;

  if (MAP_SYSTEM(cnum) && ((sbuf->st_mode & S_IXGRP) != 0))
    result |= aSYSTEM;

  if (MAP_HIDDEN(cnum) && ((sbuf->st_mode & S_IXOTH) != 0))
    result |= aHIDDEN;   
  
  if (S_ISDIR(sbuf->st_mode))
    result = aDIR | (result & aRONLY);

#ifdef S_ISLNK
#if LINKS_READ_ONLY
  if (S_ISLNK(sbuf->st_mode) && S_ISDIR(sbuf->st_mode))
    result |= aRONLY;
#endif
#endif

  /* hide files with a name starting with a . */
  if (lp_hide_dot_files(SNUM(cnum)))
    {
      char *p = strrchr(path,'/');
      if (p)
	p++;
      else
	p = path;
      
      if (p[0] == '.' && p[1] != '.' && p[1] != 0)
	result |= aHIDDEN;
    }

  /* Optimization : Only call is_hidden_path if it's not already
     hidden. */
  if (!(result & aHIDDEN) && IS_HIDDEN_PATH(cnum,path))
  {
    result |= aHIDDEN;
  }

  DEBUG(8,("dos_mode returning "));

  if (result & aHIDDEN) DEBUG(8, ("h"));
  if (result & aRONLY ) DEBUG(8, ("r"));
  if (result & aSYSTEM) DEBUG(8, ("s"));
  if (result & aDIR   ) DEBUG(8, ("d"));
  if (result & aARCH  ) DEBUG(8, ("a"));

  DEBUG(8,("\n"));

  return(result);
}

/*******************************************************************
chmod a file - but preserve some bits
********************************************************************/
int dos_chmod(int cnum,char *fname,int dosmode,struct stat *st)
{
  struct stat st1;
  int mask=0;
  int tmp;
  int unixmode;

  if (!st) {
    st = &st1;
    if (sys_stat(fname,st)) return(-1);
  }

  if (S_ISDIR(st->st_mode)) dosmode |= aDIR;

  if (dos_mode(cnum,fname,st) == dosmode) return(0);

  unixmode = unix_mode(cnum,dosmode);

  /* preserve the s bits */
  mask |= (S_ISUID | S_ISGID);

  /* preserve the t bit */
#ifdef S_ISVTX
  mask |= S_ISVTX;
#endif

  /* possibly preserve the x bits */
  if (!MAP_ARCHIVE(cnum)) mask |= S_IXUSR;
  if (!MAP_SYSTEM(cnum)) mask |= S_IXGRP;
  if (!MAP_HIDDEN(cnum)) mask |= S_IXOTH;

  unixmode |= (st->st_mode & mask);

  /* if we previously had any r bits set then leave them alone */
  if ((tmp = st->st_mode & (S_IRUSR|S_IRGRP|S_IROTH))) {
    unixmode &= ~(S_IRUSR|S_IRGRP|S_IROTH);
    unixmode |= tmp;
  }

  /* if we previously had any w bits set then leave them alone 
   if the new mode is not rdonly */
  if (!IS_DOS_READONLY(dosmode) &&
      (tmp = st->st_mode & (S_IWUSR|S_IWGRP|S_IWOTH))) {
    unixmode &= ~(S_IWUSR|S_IWGRP|S_IWOTH);
    unixmode |= tmp;
  }

  return(sys_chmod(fname,unixmode));
}

/*******************************************************************
Wrapper around sys_utime that possibly allows DOS semantics rather
than POSIX.
*******************************************************************/

int file_utime(int cnum, char *fname, struct utimbuf *times)
{
  extern struct current_user current_user;
  struct stat sb;
  int ret = -1;

  errno = 0;

  if(sys_utime(fname, times) == 0)
    return 0;

  if((errno != EPERM) && (errno != EACCES))
    return -1;

  if(!lp_dos_filetimes(SNUM(cnum)))
    return -1;

  /* We have permission (given by the Samba admin) to
     break POSIX semantics and allow a user to change
     the time on a file they don't own but can write to
     (as DOS does).
   */

  if(sys_stat(fname,&sb) != 0)
    return -1;

  /* Check if we have write access. */
  if (CAN_WRITE(cnum)) {
	  if (((sb.st_mode & S_IWOTH) ||
	       Connections[cnum].admin_user ||
	       ((sb.st_mode & S_IWUSR) && current_user.uid==sb.st_uid) ||
	       ((sb.st_mode & S_IWGRP) &&
		in_group(sb.st_gid,current_user.gid,
			 current_user.ngroups,current_user.igroups)))) {
		  /* We are allowed to become root and change the filetime. */
		  become_root(False);
		  ret = sys_utime(fname, times);
		  unbecome_root(False);
	  }
  }

  return ret;
}
  
/*******************************************************************
Change a filetime - possibly allowing DOS semantics.
*******************************************************************/

BOOL set_filetime(int cnum, char *fname, time_t mtime)
{
  struct utimbuf times;

  if (null_mtime(mtime)) return(True);

  times.modtime = times.actime = mtime;

  if (file_utime(cnum, fname, &times)) {
    DEBUG(4,("set_filetime(%s) failed: %s\n",fname,strerror(errno)));
  }
  
  return(True);
} 

/****************************************************************************
check if two filenames are equal

this needs to be careful about whether we are case sensitive
****************************************************************************/
static BOOL fname_equal(char *name1, char *name2)
{
  int l1 = strlen(name1);
  int l2 = strlen(name2);

  /* handle filenames ending in a single dot */
  if (l1-l2 == 1 && name1[l1-1] == '.' && lp_strip_dot())
    {
      BOOL ret;
      name1[l1-1] = 0;
      ret = fname_equal(name1,name2);
      name1[l1-1] = '.';
      return(ret);
    }

  if (l2-l1 == 1 && name2[l2-1] == '.' && lp_strip_dot())
    {
      BOOL ret;
      name2[l2-1] = 0;
      ret = fname_equal(name1,name2);
      name2[l2-1] = '.';
      return(ret);
    }

  /* now normal filename handling */
  if (case_sensitive)
    return(strcmp(name1,name2) == 0);

  return(strequal(name1,name2));
}


/****************************************************************************
mangle the 2nd name and check if it is then equal to the first name
****************************************************************************/
static BOOL mangled_equal(char *name1, char *name2)
{
  pstring tmpname;

  if (is_8_3(name2, True))
    return(False);

  pstrcpy(tmpname,name2);
  mangle_name_83(tmpname,sizeof(pstring)-1);

  return(strequal(name1,tmpname));
}


/****************************************************************************
scan a directory to find a filename, matching without case sensitivity

If the name looks like a mangled name then try via the mangling functions
****************************************************************************/
static BOOL scan_directory(char *path, char *name,int cnum,BOOL docache)
{
  void *cur_dir;
  char *dname;
  BOOL mangled;
  pstring name2;

  mangled = is_mangled(name);

  /* handle null paths */
  if (*path == 0)
    path = ".";

  if (docache && (dname = DirCacheCheck(path,name,SNUM(cnum)))) {
    pstrcpy(name, dname);	
    return(True);
  }      

  /*
   * The incoming name can be mangled, and if we de-mangle it
   * here it will not compare correctly against the filename (name2)
   * read from the directory and then mangled by the name_map_mangle()
   * call. We need to mangle both names or neither.
   * (JRA).
   */
  if (mangled)
    mangled = !check_mangled_stack(name);

  /* open the directory */
  if (!(cur_dir = OpenDir(cnum, path, True))) 
    {
      DEBUG(3,("scan dir didn't open dir [%s]\n",path));
      return(False);
    }

  /* now scan for matching names */
  while ((dname = ReadDirName(cur_dir))) 
    {
      if (*dname == '.' &&
	  (strequal(dname,".") || strequal(dname,"..")))
	continue;

      pstrcpy(name2,dname);
      if (!name_map_mangle(name2,False,SNUM(cnum))) continue;

      if ((mangled && mangled_equal(name,name2))
	  || fname_equal(name, name2))
	{
	  /* we've found the file, change it's name and return */
	  if (docache) DirCacheAdd(path,name,dname,SNUM(cnum));
	  pstrcpy(name, dname);
	  CloseDir(cur_dir);
	  return(True);
	}
    }

  CloseDir(cur_dir);
  return(False);
}

/****************************************************************************
This routine is called to convert names from the dos namespace to unix
namespace. It needs to handle any case conversions, mangling, format
changes etc.

We assume that we have already done a chdir() to the right "root" directory
for this service.

The function will return False if some part of the name except for the last
part cannot be resolved

If the saved_last_component != 0, then the unmodified last component
of the pathname is returned there. This is used in an exceptional
case in reply_mv (so far). If saved_last_component == 0 then nothing
is returned there.

The bad_path arg is set to True if the filename walk failed. This is
used to pick the correct error code to return between ENOENT and ENOTDIR
as Windows applications depend on ERRbadpath being returned if a component
of a pathname does not exist.
****************************************************************************/
BOOL unix_convert(char *name,int cnum,pstring saved_last_component, BOOL *bad_path)
{
  struct stat st;
  char *start, *end;
  pstring dirpath;
  int saved_errno;

  *dirpath = 0;
  *bad_path = False;

  if(saved_last_component)
    *saved_last_component = 0;

  /* convert to basic unix format - removing \ chars and cleaning it up */
  unix_format(name);
  unix_clean_name(name);

  /* names must be relative to the root of the service - trim any leading /.
   also trim trailing /'s */
  trim_string(name,"/","/");

  /*
   * Ensure saved_last_component is valid even if file exists.
   */
  if(saved_last_component) {
    end = strrchr(name, '/');
    if(end)
      pstrcpy(saved_last_component, end + 1);
    else
      pstrcpy(saved_last_component, name);
  }

  if (!case_sensitive && 
      (!case_preserve || (is_8_3(name, False) && !short_case_preserve)))
    strnorm(name);

  /* check if it's a printer file */
  if (Connections[cnum].printer)
    {
      if ((! *name) || strchr(name,'/') || !is_8_3(name, True))
	{
	  char *s;
	  fstring name2;
	  slprintf(name2,sizeof(name2)-1,"%.6s.XXXXXX",remote_machine);
	  /* sanitise the name */
	  for (s=name2 ; *s ; s++)
	    if (!issafe(*s)) *s = '_';
	  pstrcpy(name,(char *)mktemp(name2));	  
	}      
      return(True);
    }

  /* stat the name - if it exists then we are all done! */
  if (sys_stat(name,&st) == 0)
    return(True);

  saved_errno = errno;

  DEBUG(5,("unix_convert(%s,%d)\n",name,cnum));

  /* a special case - if we don't have any mangling chars and are case
     sensitive then searching won't help */
  if (case_sensitive && !is_mangled(name) && 
      !lp_strip_dot() && !use_mangled_map && (saved_errno != ENOENT))
    return(False);

  /* now we need to recursively match the name against the real 
     directory structure */

  start = name;
  while (strncmp(start,"./",2) == 0)
    start += 2;

  /* now match each part of the path name separately, trying the names
     as is first, then trying to scan the directory for matching names */
  for (;start;start = (end?end+1:(char *)NULL)) 
    {
      /* pinpoint the end of this section of the filename */
      end = strchr(start, '/');

      /* chop the name at this point */
      if (end) 	*end = 0;

      if(saved_last_component != 0)
        pstrcpy(saved_last_component, end ? end + 1 : start);

      /* check if the name exists up to this point */
      if (sys_stat(name, &st) == 0) 
	{
	  /* it exists. it must either be a directory or this must be
	     the last part of the path for it to be OK */
	  if (end && !(st.st_mode & S_IFDIR)) 
	    {
	      /* an intermediate part of the name isn't a directory */
	      DEBUG(5,("Not a dir %s\n",start));
	      *end = '/';
	      return(False);
	    }
	}
      else 
	{
	  pstring rest;

	  *rest = 0;

	  /* remember the rest of the pathname so it can be restored
	     later */
	  if (end) pstrcpy(rest,end+1);

	  /* try to find this part of the path in the directory */
	  if (strchr(start,'?') || strchr(start,'*') ||
	      !scan_directory(dirpath, start, cnum, end?True:False))
	    {
	      if (end) 
		{
		  /* an intermediate part of the name can't be found */
		  DEBUG(5,("Intermediate not found %s\n",start));
		  *end = '/';
                  /* We need to return the fact that the intermediate
                     name resolution failed. This is used to return an
                     error of ERRbadpath rather than ERRbadfile. Some
                     Windows applications depend on the difference between
                     these two errors.
                   */
                  *bad_path = True;
		  return(False);
		}
	      
	      /* just the last part of the name doesn't exist */
	      /* we may need to strupper() or strlower() it in case
		 this conversion is being used for file creation 
		 purposes */
	      /* if the filename is of mixed case then don't normalise it */
	      if (!case_preserve && 
		  (!strhasupper(start) || !strhaslower(start)))		
		strnorm(start);

	      /* check on the mangled stack to see if we can recover the 
		 base of the filename */
	      if (is_mangled(start))
		check_mangled_stack(start);

	      DEBUG(5,("New file %s\n",start));
	      return(True); 
	    }

	  /* restore the rest of the string */
	  if (end) 
	    {
	      pstrcpy(start+strlen(start)+1,rest);
	      end = start + strlen(start);
	    }
	}

      /* add to the dirpath that we have resolved so far */
      if (*dirpath) pstrcat(dirpath,"/");
      pstrcat(dirpath,start);

      /* restore the / that we wiped out earlier */
      if (end) *end = '/';
    }
  
  /* the name has been resolved */
  DEBUG(5,("conversion finished %s\n",name));
  return(True);
}


/****************************************************************************
normalise for DOS usage 
****************************************************************************/
static void disk_norm(int *bsize,int *dfree,int *dsize)
{
  /* check if the disk is beyond the max disk size */
  int maxdisksize = lp_maxdisksize();
  if (maxdisksize) {
    /* convert to blocks - and don't overflow */
    maxdisksize = ((maxdisksize*1024)/(*bsize))*1024;
    if (*dsize > maxdisksize) *dsize = maxdisksize;
    if (*dfree > maxdisksize) *dfree = maxdisksize-1; /* the -1 should stop 
							 applications getting 
							 div by 0 errors */
  }  

  while (*dfree > WORDMAX || *dsize > WORDMAX || *bsize < 512) 
    {
      *dfree /= 2;
      *dsize /= 2;
      *bsize *= 2;
      if (*bsize > WORDMAX )
	{
	  *bsize = WORDMAX;
	  if (*dsize > WORDMAX)
	    *dsize = WORDMAX;
	  if (*dfree >  WORDMAX)
	    *dfree = WORDMAX;
	  break;
	}
    }
}

/****************************************************************************
  return number of 1K blocks available on a path and total number 
****************************************************************************/
int disk_free(char *path,int *bsize,int *dfree,int *dsize)
{
  char *df_command = lp_dfree_command();
  int dfree_retval;
#ifdef QUOTAS
  int dfreeq_retval;
  int dfreeq = 0;
  int bsizeq = *bsize;
  int dsizeq = *dsize;
#endif

#ifndef NO_STATFS
#ifdef USE_STATVFS
  struct statvfs fs;
#else
#ifdef ULTRIX
  struct fs_data fs;
#else
  struct statfs fs;
#endif
#endif
#endif

  /* possibly use system() to get the result */
  if (df_command && *df_command)
    {
      int ret;
      pstring syscmd;
      pstring outfile;
	  
      slprintf(outfile,sizeof(outfile)-1, "%s/dfree.smb.%d",tmpdir(),(int)getpid());
      slprintf(syscmd,sizeof(syscmd)-1,"%s %s",df_command,path);
      standard_sub_basic(syscmd);

      ret = smbrun(syscmd,outfile,False);
      DEBUG(3,("Running the command `%s' gave %d\n",syscmd,ret));
	  
      {
        FILE *f = fopen(outfile,"r");	
        *dsize = 0;
        *dfree = 0;
        *bsize = 1024;
        if (f)
          {
            fscanf(f,"%d %d %d",dsize,dfree,bsize);
            fclose(f);
          }
        else
          DEBUG(0,("Can't open %s\n",outfile));
      }
	  
      unlink(outfile);
      disk_norm(bsize,dfree,dsize);
      dfree_retval = ((*bsize)/1024)*(*dfree);
#ifdef QUOTAS
      /* Ensure we return the min value between the users quota and
         what's free on the disk. Thanks to Albrecht Gebhardt 
         <albrecht.gebhardt@uni-klu.ac.at> for this fix.
      */
      if (disk_quotas(path, &bsizeq, &dfreeq, &dsizeq))
        {
          disk_norm(&bsizeq, &dfreeq, &dsizeq);
          dfreeq_retval = ((bsizeq)/1024)*(dfreeq);
          dfree_retval =  ( dfree_retval < dfreeq_retval ) ? 
                           dfree_retval : dfreeq_retval ;
          /* maybe dfree and dfreeq are calculated using different bsizes 
             so convert dfree from bsize into bsizeq */
          /* avoid overflows due to multiplication, so do not:
                *dfree = ((*dfree) * (*bsize)) / (bsizeq); 
             bsize and bsizeq are powers of 2 so its better to
             to divide them getting a multiplication or division factor
             for dfree. Rene Nieuwenhuizen (07-10-1997) */
          if (*bsize >= bsizeq) 
            *dfree = *dfree * (*bsize / bsizeq);
          else 
            *dfree = *dfree / (bsizeq / *bsize);
          *dfree = ( *dfree < dfreeq ) ? *dfree : dfreeq ; 
          *bsize = bsizeq;
          *dsize = dsizeq;
        }
#endif
      return(dfree_retval);
    }

#ifdef NO_STATFS
  DEBUG(1,("Warning - no statfs function\n"));
  return(1);
#else
#ifdef STATFS4
  if (statfs(path,&fs,sizeof(fs),0) != 0)
#else
#ifdef USE_STATVFS
    if (statvfs(path, &fs))
#else
#ifdef STATFS3
      if (statfs(path,&fs,sizeof(fs)) == -1)	 
#else
	if (statfs(path,&fs) == -1)
#endif /* STATFS3 */
#endif /* USE_STATVFS */
#endif /* STATFS4 */
	  {
	    DEBUG(3,("dfree call failed code errno=%d\n",errno));
	    *bsize = 1024;
	    *dfree = 1;
	    *dsize = 1;
	    return(((*bsize)/1024)*(*dfree));
	  }

#ifdef ULTRIX
  *bsize = 1024;
  *dfree = fs.fd_req.bfree;
  *dsize = fs.fd_req.btot;
#else
#ifdef USE_STATVFS
  *bsize = fs.f_frsize;
#else
#ifdef USE_F_FSIZE
  /* eg: osf1 has f_fsize = fundamental filesystem block size, 
     f_bsize = optimal transfer block size (MX: 94-04-19) */
  *bsize = fs.f_fsize;
#else
  *bsize = fs.f_bsize;
#endif /* STATFS3 */
#endif /* USE_STATVFS */

#ifdef STATFS4
  *dfree = fs.f_bfree;
#else
  *dfree = fs.f_bavail;
#endif /* STATFS4 */
  *dsize = fs.f_blocks;
#endif /* ULTRIX */

#if defined(SCO) || defined(ISC) || defined(MIPS)
  *bsize = 512;
#endif

/* handle rediculous bsize values - some OSes are broken */
if ((*bsize) < 512 || (*bsize)>0xFFFF) *bsize = 1024;

  disk_norm(bsize,dfree,dsize);

  if (*bsize < 256)
    *bsize = 512;
  if ((*dsize)<1)
    {
      DEBUG(0,("dfree seems to be broken on your system\n"));
      *dsize = 20*1024*1024/(*bsize);
      *dfree = MAX(1,*dfree);
    }
  dfree_retval = ((*bsize)/1024)*(*dfree);
#ifdef QUOTAS
  /* Ensure we return the min value between the users quota and
     what's free on the disk. Thanks to Albrecht Gebhardt 
     <albrecht.gebhardt@uni-klu.ac.at> for this fix.
  */
  if (disk_quotas(path, &bsizeq, &dfreeq, &dsizeq))
    {
      disk_norm(&bsizeq, &dfreeq, &dsizeq);
      dfreeq_retval = ((bsizeq)/1024)*(dfreeq);
      dfree_retval = ( dfree_retval < dfreeq_retval ) ? 
                       dfree_retval : dfreeq_retval ;
      /* maybe dfree and dfreeq are calculated using different bsizes 
         so convert dfree from bsize into bsizeq */
      /* avoid overflows due to multiplication, so do not:
              *dfree = ((*dfree) * (*bsize)) / (bsizeq); 
       bsize and bsizeq are powers of 2 so its better to
       to divide them getting a multiplication or division factor
       for dfree. Rene Nieuwenhuizen (07-10-1997) */
      if (*bsize >= bsizeq)
        *dfree = *dfree * (*bsize / bsizeq);
      else
        *dfree = *dfree / (bsizeq / *bsize);
      *dfree = ( *dfree < dfreeq ) ? *dfree : dfreeq ;
      *bsize = bsizeq;
      *dsize = dsizeq;
    }
#endif
  return(dfree_retval);
#endif
}


/****************************************************************************
wrap it to get filenames right
****************************************************************************/
int sys_disk_free(char *path,int *bsize,int *dfree,int *dsize)
{
  return(disk_free(dos_to_unix(path,False),bsize,dfree,dsize));
}



/****************************************************************************
check a filename - possibly caling reducename

This is called by every routine before it allows an operation on a filename.
It does any final confirmation necessary to ensure that the filename is
a valid one for the user to access.
****************************************************************************/
BOOL check_name(char *name,int cnum)
{
  BOOL ret;

  errno = 0;

  if( IS_VETO_PATH(cnum, name)) 
    {
      DEBUG(5,("file path name %s vetoed\n",name));
      return(0);
    }

  ret = reduce_name(name,Connections[cnum].connectpath,lp_widelinks(SNUM(cnum)));

  /* Check if we are allowing users to follow symlinks */
  /* Patch from David Clerc <David.Clerc@cui.unige.ch>
     University of Geneva */

#ifdef S_ISLNK
  if (!lp_symlinks(SNUM(cnum)))
    {
      struct stat statbuf;
      if ( (sys_lstat(name,&statbuf) != -1) &&
          (S_ISLNK(statbuf.st_mode)) )
        {
          DEBUG(3,("check_name: denied: file path name %s is a symlink\n",name));
          ret=0; 
        }
    }
#endif

  if (!ret)
    DEBUG(5,("check_name on %s failed\n",name));

  return(ret);
}

/****************************************************************************
check a filename - possibly caling reducename
****************************************************************************/
static void check_for_pipe(char *fname)
{
  /* special case of pipe opens */
  char s[10];
  StrnCpy(s,fname,9);
  strlower(s);
  if (strstr(s,"pipe/"))
    {
      DEBUG(3,("Rejecting named pipe open for %s\n",fname));
      unix_ERR_class = ERRSRV;
      unix_ERR_code = ERRaccess;
    }
}

/****************************************************************************
fd support routines - attempt to do a sys_open
****************************************************************************/
static int fd_attempt_open(char *fname, int flags, int mode)
{
  int fd = sys_open(fname,flags,mode);

  /* Fix for files ending in '.' */
  if((fd == -1) && (errno == ENOENT) &&
     (strchr(fname,'.')==NULL))
    {
      pstrcat(fname,".");
      fd = sys_open(fname,flags,mode);
    }

#if (defined(ENAMETOOLONG) && defined(HAVE_PATHCONF))
  if ((fd == -1) && (errno == ENAMETOOLONG))
    {
      int max_len;
      char *p = strrchr(fname, '/');

      if (p == fname)   /* name is "/xxx" */
        {
          max_len = pathconf("/", _PC_NAME_MAX);
          p++;
        }
      else if ((p == NULL) || (p == fname))
        {
          p = fname;
          max_len = pathconf(".", _PC_NAME_MAX);
        }
      else
        {
          *p = '\0';
          max_len = pathconf(fname, _PC_NAME_MAX);
          *p = '/';
          p++;
        }
      if (strlen(p) > max_len)
        {
          char tmp = p[max_len];

          p[max_len] = '\0';
          if ((fd = sys_open(fname,flags,mode)) == -1)
            p[max_len] = tmp;
        }
    }
#endif
  return fd;
}

/****************************************************************************
Cache a uid_t currently with this file open. This is an optimization only
used when multiple sessionsetup's have been done to one smbd.
****************************************************************************/
static void fd_add_to_uid_cache(file_fd_struct *fd_ptr, uid_t u)
{
  if(fd_ptr->uid_cache_count >= sizeof(fd_ptr->uid_users_cache)/sizeof(uid_t))
    return;
  fd_ptr->uid_users_cache[fd_ptr->uid_cache_count++] = u;
}

/****************************************************************************
Remove a uid_t that currently has this file open. This is an optimization only
used when multiple sessionsetup's have been done to one smbd.
****************************************************************************/
static void fd_remove_from_uid_cache(file_fd_struct *fd_ptr, uid_t u)
{
  int i;
  for(i = 0; i < fd_ptr->uid_cache_count; i++)
    if(fd_ptr->uid_users_cache[i] == u) {
      if(i < (fd_ptr->uid_cache_count-1))
        memmove((char *)&fd_ptr->uid_users_cache[i], (char *)&fd_ptr->uid_users_cache[i+1],
               sizeof(uid_t)*(fd_ptr->uid_cache_count-1-i) );
      fd_ptr->uid_cache_count--;
    }
  return;
}

/****************************************************************************
Check if a uid_t that currently has this file open is present. This is an
optimization only used when multiple sessionsetup's have been done to one smbd.
****************************************************************************/
static BOOL fd_is_in_uid_cache(file_fd_struct *fd_ptr, uid_t u)
{
  int i;
  for(i = 0; i < fd_ptr->uid_cache_count; i++)
    if(fd_ptr->uid_users_cache[i] == u)
      return True;
  return False;
}

/****************************************************************************
fd support routines - attempt to find an already open file by dev
and inode - increments the ref_count of the returned file_fd_struct *.
****************************************************************************/
static file_fd_struct *fd_get_already_open(struct stat *sbuf)
{
  int i;
  file_fd_struct *fd_ptr;

  if(sbuf == 0)
    return 0;

  for(i = 0; i <= max_file_fd_used; i++) {
    fd_ptr = &FileFd[i];
    if((fd_ptr->ref_count > 0) &&
       (((uint32)sbuf->st_dev) == fd_ptr->dev) &&
       (((uint32)sbuf->st_ino) == fd_ptr->inode)) {
      fd_ptr->ref_count++;
      DEBUG(3,
       ("Re-used file_fd_struct %d, dev = %x, inode = %x, ref_count = %d\n",
        i, fd_ptr->dev, fd_ptr->inode, fd_ptr->ref_count));
      return fd_ptr;
    }
  }
  return 0;
}

/****************************************************************************
fd support routines - attempt to find a empty slot in the FileFd array.
Increments the ref_count of the returned entry.
****************************************************************************/
static file_fd_struct *fd_get_new(void)
{
  extern struct current_user current_user;
  int i;
  file_fd_struct *fd_ptr;

  for(i = 0; i < MAX_OPEN_FILES; i++) {
    fd_ptr = &FileFd[i];
    if(fd_ptr->ref_count == 0) {
      fd_ptr->dev = (uint32)-1;
      fd_ptr->inode = (uint32)-1;
      fd_ptr->fd = -1;
      fd_ptr->fd_readonly = -1;
      fd_ptr->fd_writeonly = -1;
      fd_ptr->real_open_flags = -1;
      fd_ptr->uid_cache_count = 0;
      fd_add_to_uid_cache(fd_ptr, (uid_t)current_user.uid);
      fd_ptr->ref_count++;
      /* Increment max used counter if neccessary, cuts down
         on search time when re-using */
      if(i > max_file_fd_used)
        max_file_fd_used = i;
      DEBUG(3,("Allocated new file_fd_struct %d, dev = %x, inode = %x\n",
               i, fd_ptr->dev, fd_ptr->inode));
      return fd_ptr;
    }
  }
  DEBUG(1,("ERROR! Out of file_fd structures - perhaps increase MAX_OPEN_FILES?\n"));
  return 0;
}

/****************************************************************************
fd support routines - attempt to re-open an already open fd as O_RDWR.
Save the already open fd (we cannot close due to POSIX file locking braindamage.
****************************************************************************/
static void fd_attempt_reopen(char *fname, int mode, file_fd_struct *fd_ptr)
{
  int fd = sys_open( fname, O_RDWR, mode);

  if(fd == -1)
    return;

  if(fd_ptr->real_open_flags == O_RDONLY)
    fd_ptr->fd_readonly = fd_ptr->fd;
  if(fd_ptr->real_open_flags == O_WRONLY)
    fd_ptr->fd_writeonly = fd_ptr->fd;

  fd_ptr->fd = fd;
  fd_ptr->real_open_flags = O_RDWR;
}

/****************************************************************************
fd support routines - attempt to close the file referenced by this fd.
Decrements the ref_count and returns it.
****************************************************************************/
static int fd_attempt_close(file_fd_struct *fd_ptr)
{
  extern struct current_user current_user;

  DEBUG(3,("fd_attempt_close on file_fd_struct %d, fd = %d, dev = %x, inode = %x, open_flags = %d, ref_count = %d.\n",
          fd_ptr - &FileFd[0],
          fd_ptr->fd, fd_ptr->dev, fd_ptr->inode,
          fd_ptr->real_open_flags,
          fd_ptr->ref_count));
  if(fd_ptr->ref_count > 0) {
    fd_ptr->ref_count--;
    if(fd_ptr->ref_count == 0) {
      if(fd_ptr->fd != -1)
        close(fd_ptr->fd);
      if(fd_ptr->fd_readonly != -1)
        close(fd_ptr->fd_readonly);
      if(fd_ptr->fd_writeonly != -1)
        close(fd_ptr->fd_writeonly);
      fd_ptr->fd = -1;
      fd_ptr->fd_readonly = -1;
      fd_ptr->fd_writeonly = -1;
      fd_ptr->real_open_flags = -1;
      fd_ptr->dev = (uint32)-1;
      fd_ptr->inode = (uint32)-1;
      fd_ptr->uid_cache_count = 0;
    } else
      fd_remove_from_uid_cache(fd_ptr, (uid_t)current_user.uid);
  } 
 return fd_ptr->ref_count;
}

/****************************************************************************
fd support routines - check that current user has permissions
to open this file. Used when uid not found in optimization cache.
This is really ugly code, as due to POSIX locking braindamage we must
fork and then attempt to open the file, and return success or failure
via an exit code.
****************************************************************************/
static BOOL check_access_allowed_for_current_user( char *fname, int accmode )
{
  pid_t child_pid;

  if((child_pid = fork()) < 0) {
    DEBUG(0,("check_access_allowed_for_current_user: fork failed.\n"));
    return False;
  }

  if(child_pid) {
    /*
     * Parent.
     */
    pid_t wpid;
    int status_code;
    if ((wpid = sys_waitpid(child_pid, &status_code, 0)) < 0) {
      DEBUG(0,("check_access_allowed_for_current_user: The process is no longer waiting!\n"));
      return(False);
    }

    if (child_pid != wpid) {
      DEBUG(0,("check_access_allowed_for_current_user: We were waiting for the wrong process ID\n"));
      return(False);
    }
#if defined(WIFEXITED) && defined(WEXITSTATUS)
    if (WIFEXITED(status_code) == 0) {
      DEBUG(0,("check_access_allowed_for_current_user: The process exited while we were waiting\n"));
      return(False);
    }
    if (WEXITSTATUS(status_code) != 0) {
      DEBUG(9,("check_access_allowed_for_current_user: The status of the process exiting was %d. Returning access denied.\n", status_code));
      return(False);
    }
#else /* defined(WIFEXITED) && defined(WEXITSTATUS) */
    if(status_code != 0) {
      DEBUG(9,("check_access_allowed_for_current_user: The status of the process exiting was %d. Returning access denied.\n", status_code));
      return(False);
    }
#endif /* defined(WIFEXITED) && defined(WEXITSTATUS) */

    /*
     * Success - the child could open the file.
     */
    DEBUG(9,("check_access_allowed_for_current_user: The status of the process exiting was %d. Returning access allowed.\n", status_code));
    return True;
  } else {
    /*
     * Child.
     */
    int fd;
    DEBUG(9,("check_access_allowed_for_current_user: Child - attempting to open %s with mode %d.\n", fname, accmode ));
    if((fd = fd_attempt_open( fname, accmode, 0)) < 0) {
      /* Access denied. */
      _exit(EACCES);
    }
    close(fd);
    DEBUG(9,("check_access_allowed_for_current_user: Child - returning ok.\n"));
    _exit(0);
  }

  return False;
}

/****************************************************************************
open a file
****************************************************************************/
static void open_file(int fnum,int cnum,char *fname1,int flags,int mode, struct stat *sbuf)
{
  extern struct current_user current_user;
  pstring fname;
  struct stat statbuf;
  file_fd_struct *fd_ptr;
  files_struct *fsp = &Files[fnum];
  int accmode = (flags & (O_RDONLY | O_WRONLY | O_RDWR));

  fsp->open = False;
  fsp->fd_ptr = 0;
  fsp->granted_oplock = False;
  errno = EPERM;

  pstrcpy(fname,fname1);

  /* check permissions */

  /*
   * This code was changed after seeing a client open request 
   * containing the open mode of (DENY_WRITE/read-only) with
   * the 'create if not exist' bit set. The previous code
   * would fail to open the file read only on a read-only share
   * as it was checking the flags parameter  directly against O_RDONLY,
   * this was failing as the flags parameter was set to O_RDONLY|O_CREAT.
   * JRA.
   */

  if (!CAN_WRITE(cnum) && !Connections[cnum].printer) {
    /* It's a read-only share - fail if we wanted to write. */
    if(accmode != O_RDONLY) {
      DEBUG(3,("Permission denied opening %s\n",fname));
      check_for_pipe(fname);
      return;
    }
    else if(flags & O_CREAT) {
      /* We don't want to write - but we must make sure that O_CREAT
         doesn't create the file if we have write access into the
         directory.
       */
      flags &= ~O_CREAT;
    }
  }

  /* this handles a bug in Win95 - it doesn't say to create the file when it 
     should */
  if (Connections[cnum].printer)
    flags |= O_CREAT;

/*
  if (flags == O_WRONLY)
    DEBUG(3,("Bug in client? Set O_WRONLY without O_CREAT\n"));
*/

  /*
   * Ensure we have a valid struct stat so we can search the
   * open fd table.
   */
  if(sbuf == 0) {
    if(stat(fname, &statbuf) < 0) {
      if(errno != ENOENT) {
        DEBUG(3,("Error doing stat on file %s (%s)\n",
                 fname,strerror(errno)));

        check_for_pipe(fname);
        return;
      }
      sbuf = 0;
    } else {
      sbuf = &statbuf;
    }
  }

  /*
   * Check to see if we have this file already
   * open. If we do, just use the already open fd and increment the
   * reference count (fd_get_already_open increments the ref_count).
   */
  if((fd_ptr = fd_get_already_open(sbuf))!= 0) {
    /*
     * File was already open.
     */

    /* 
     * Check it wasn't open for exclusive use.
     */
    if((flags & O_CREAT) && (flags & O_EXCL)) {
      fd_ptr->ref_count--;
      errno = EEXIST;
      return;
    }

    /*
     * Ensure that the user attempting to open
     * this file has permissions to do so, if
     * the user who originally opened the file wasn't
     * the same as the current user.
     */

    if(!fd_is_in_uid_cache(fd_ptr, (uid_t)current_user.uid)) {
      if(!check_access_allowed_for_current_user( fname, accmode )) {
        /* Error - permission denied. */
        DEBUG(3,("Permission denied opening file %s (flags=%d, accmode = %d)\n",
              fname, flags, accmode));
        /* Ensure the ref_count is decremented. */
        fd_ptr->ref_count--;
        fd_remove_from_uid_cache(fd_ptr, (uid_t)current_user.uid);
        errno = EACCES;
        return;
      }
    }

    fd_add_to_uid_cache(fd_ptr, (uid_t)current_user.uid);

    /* 
     * If not opened O_RDWR try
     * and do that here - a chmod may have been done
     * between the last open and now. 
     */
    if(fd_ptr->real_open_flags != O_RDWR)
      fd_attempt_reopen(fname, mode, fd_ptr);

    /*
     * Ensure that if we wanted write access
     * it has been opened for write, and if we wanted read it
     * was open for read. 
     */
    if(((accmode == O_WRONLY) && (fd_ptr->real_open_flags == O_RDONLY)) ||
       ((accmode == O_RDONLY) && (fd_ptr->real_open_flags == O_WRONLY)) ||
       ((accmode == O_RDWR) && (fd_ptr->real_open_flags != O_RDWR))) {
      DEBUG(3,("Error opening (already open for flags=%d) file %s (%s) (flags=%d)\n",
               fd_ptr->real_open_flags, fname,strerror(EACCES),flags));
      check_for_pipe(fname);
      fd_remove_from_uid_cache(fd_ptr, (uid_t)current_user.uid);
      fd_ptr->ref_count--;
      return;
    }

  } else {
    int open_flags;
    /* We need to allocate a new file_fd_struct (this increments the
       ref_count). */
    if((fd_ptr = fd_get_new()) == 0)
      return;
    /*
     * Whatever the requested flags, attempt read/write access,
     * as we don't know what flags future file opens may require.
     * If this fails, try again with the required flags. 
     * Even if we open read/write when only read access was 
     * requested the setting of the can_write flag in
     * the file_struct will protect us from errant
     * write requests. We never need to worry about O_APPEND
     * as this is not set anywhere in Samba.
     */
    fd_ptr->real_open_flags = O_RDWR;
    /* Set the flags as needed without the read/write modes. */
    open_flags = flags & ~(O_RDWR|O_WRONLY|O_RDONLY);
    fd_ptr->fd = fd_attempt_open(fname, open_flags|O_RDWR, mode);
    /*
     * On some systems opening a file for R/W access on a read only
     * filesystems sets errno to EROFS.
     */
#ifdef EROFS
    if((fd_ptr->fd == -1) && ((errno == EACCES) || (errno == EROFS))) {
#else /* No EROFS */
    if((fd_ptr->fd == -1) && (errno == EACCES)) {
#endif /* EROFS */
      if(flags & O_WRONLY) {
        fd_ptr->fd = fd_attempt_open(fname, open_flags|O_WRONLY, mode);
        fd_ptr->real_open_flags = O_WRONLY;
      } else {
        fd_ptr->fd = fd_attempt_open(fname, open_flags|O_RDONLY, mode);
        fd_ptr->real_open_flags = O_RDONLY;
      }
    }
  }

  if ((fd_ptr->fd >=0) && 
      Connections[cnum].printer && lp_minprintspace(SNUM(cnum))) {
    pstring dname;
    int dum1,dum2,dum3;
    char *p;
    pstrcpy(dname,fname);
    p = strrchr(dname,'/');
    if (p) *p = 0;
    if (sys_disk_free(dname,&dum1,&dum2,&dum3) < 
	lp_minprintspace(SNUM(cnum))) {
      fd_attempt_close(fd_ptr);
      fsp->fd_ptr = 0;
      if(fd_ptr->ref_count == 0)
        sys_unlink(fname);
      errno = ENOSPC;
      return;
    }
  }
    
  if (fd_ptr->fd < 0)
  {
    DEBUG(3,("Error opening file %s (%s) (flags=%d)\n",
      fname,strerror(errno),flags));
    /* Ensure the ref_count is decremented. */
    fd_attempt_close(fd_ptr);
    check_for_pipe(fname);
    return;
  }

  if (fd_ptr->fd >= 0)
  {
    if(sbuf == 0) {
      /* Do the fstat */
      if(fstat(fd_ptr->fd, &statbuf) == -1) {
        /* Error - backout !! */
        DEBUG(3,("Error doing fstat on fd %d, file %s (%s)\n",
                 fd_ptr->fd, fname,strerror(errno)));
        /* Ensure the ref_count is decremented. */
        fd_attempt_close(fd_ptr);
        return;
      }
      sbuf = &statbuf;
    }

    /* Set the correct entries in fd_ptr. */
    fd_ptr->dev = (uint32)sbuf->st_dev;
    fd_ptr->inode = (uint32)sbuf->st_ino;

    fsp->fd_ptr = fd_ptr;
    Connections[cnum].num_files_open++;
    fsp->mode = sbuf->st_mode;
    GetTimeOfDay(&fsp->open_time);
    fsp->vuid = current_user.vuid;
    fsp->size = 0;
    fsp->pos = -1;
    fsp->open = True;
    fsp->mmap_ptr = NULL;
    fsp->mmap_size = 0;
    fsp->can_lock = True;
    fsp->can_read = ((flags & O_WRONLY)==0);
    fsp->can_write = ((flags & (O_WRONLY|O_RDWR))!=0);
    fsp->share_mode = 0;
    fsp->print_file = Connections[cnum].printer;
    fsp->modified = False;
    fsp->granted_oplock = False;
    fsp->sent_oplock_break = False;
    fsp->cnum = cnum;
    string_set(&fsp->name,dos_to_unix(fname,False));
    fsp->wbmpx_ptr = NULL;      

    /*
     * If the printer is marked as postscript output a leading
     * file identifier to ensure the file is treated as a raw
     * postscript file.
     * This has a similar effect as CtrlD=0 in WIN.INI file.
     * tim@fsg.com 09/06/94
     */
    if (fsp->print_file && POSTSCRIPT(cnum) && fsp->can_write) 
    {
      DEBUG(3,("Writing postscript line\n"));
      write_file(fnum,"%!\n",3);
    }
      
    DEBUG(2,("%s %s opened file %s read=%s write=%s (numopen=%d fnum=%d)\n",
          timestring(),
          *sesssetup_user ? sesssetup_user : Connections[cnum].user,fname,
          BOOLSTR(fsp->can_read),BOOLSTR(fsp->can_write),
          Connections[cnum].num_files_open,fnum));

  }

#if USE_MMAP
  /* mmap it if read-only */
  if (!fsp->can_write)
  {
    fsp->mmap_size = file_size(fname);
    fsp->mmap_ptr = (char *)mmap(NULL,fsp->mmap_size,
                                 PROT_READ,MAP_SHARED,fsp->fd_ptr->fd,0);

    if (fsp->mmap_ptr == (char *)-1 || !fsp->mmap_ptr)
    {
      DEBUG(3,("Failed to mmap() %s - %s\n",fname,strerror(errno)));
      fsp->mmap_ptr = NULL;
    }
  }
#endif
}

/*******************************************************************
sync a file
********************************************************************/
void sync_file(int fnum)
{
#ifndef NO_FSYNC
  fsync(Files[fnum].fd_ptr->fd);
#endif
}

/****************************************************************************
run a file if it is a magic script
****************************************************************************/
static void check_magic(int fnum,int cnum)
{
  if (!*lp_magicscript(SNUM(cnum)))
    return;

  DEBUG(5,("checking magic for %s\n",Files[fnum].name));

  {
    char *p;
    if (!(p = strrchr(Files[fnum].name,'/')))
      p = Files[fnum].name;
    else
      p++;

    if (!strequal(lp_magicscript(SNUM(cnum)),p))
      return;
  }

  {
    int ret;
    pstring magic_output;
    pstring fname;
    pstrcpy(fname,Files[fnum].name);

    if (*lp_magicoutput(SNUM(cnum)))
      pstrcpy(magic_output,lp_magicoutput(SNUM(cnum)));
    else
      slprintf(magic_output,sizeof(fname)-1, "%s.out",fname);

    chmod(fname,0755);
    ret = smbrun(fname,magic_output,False);
    DEBUG(3,("Invoking magic command %s gave %d\n",fname,ret));
    unlink(fname);
  }
}


/****************************************************************************
close a file - possibly invalidating the read prediction

If normal_close is 1 then this came from a normal SMBclose (or equivalent)
operation otherwise it came as the result of some other operation such as
the closing of the connection. In the latter case printing and
magic scripts are not run
****************************************************************************/
void close_file(int fnum, BOOL normal_close)
{
  files_struct *fs_p = &Files[fnum];
  int cnum = fs_p->cnum;
  uint32 dev = fs_p->fd_ptr->dev;
  uint32 inode = fs_p->fd_ptr->inode;
  int token;

  Files[fnum].reserved = False;

#if USE_READ_PREDICTION
  invalidate_read_prediction(fs_p->fd_ptr->fd);
#endif

  fs_p->open = False;
  Connections[cnum].num_files_open--;
  if(fs_p->wbmpx_ptr) 
  {
    free((char *)fs_p->wbmpx_ptr);
    fs_p->wbmpx_ptr = NULL;
  }

#if USE_MMAP
  if(fs_p->mmap_ptr) 
  {
    munmap(fs_p->mmap_ptr,fs_p->mmap_size);
    fs_p->mmap_ptr = NULL;
  }
#endif

  if (lp_share_modes(SNUM(cnum)))
  {
    lock_share_entry( cnum, dev, inode, &token);
    del_share_mode(token, fnum);
  }

  fd_attempt_close(fs_p->fd_ptr);

  if (lp_share_modes(SNUM(cnum)))
    unlock_share_entry( cnum, dev, inode, token);

  /* NT uses smbclose to start a print - weird */
  if (normal_close && fs_p->print_file)
    print_file(fnum);

  /* check for magic scripts */
  if (normal_close)
    check_magic(fnum,cnum);

  if(fs_p->granted_oplock == True)
    global_oplocks_open--;

  fs_p->sent_oplock_break = False;

  DEBUG(2,("%s %s closed file %s (numopen=%d)\n",
	   timestring(),Connections[cnum].user,fs_p->name,
	   Connections[cnum].num_files_open));

  if (fs_p->name) {
	  string_free(&fs_p->name);
  }

  /* we will catch bugs faster by zeroing this structure */
  memset(fs_p, 0, sizeof(*fs_p));
}

enum {AFAIL,AREAD,AWRITE,AALL};

/*******************************************************************
reproduce the share mode access table
********************************************************************/
static int access_table(int new_deny,int old_deny,int old_mode,
			int share_pid,char *fname)
{
  if (new_deny == DENY_ALL || old_deny == DENY_ALL) return(AFAIL);

  if (new_deny == DENY_DOS || old_deny == DENY_DOS) {
    int pid = getpid();
    if (old_deny == new_deny && share_pid == pid) 
	return(AALL);    

    if (old_mode == 0) return(AREAD);

    /* the new smbpub.zip spec says that if the file extension is
       .com, .dll, .exe or .sym then allow the open. I will force
       it to read-only as this seems sensible although the spec is
       a little unclear on this. */
    if ((fname = strrchr(fname,'.'))) {
      if (strequal(fname,".com") ||
	  strequal(fname,".dll") ||
	  strequal(fname,".exe") ||
	  strequal(fname,".sym"))
	return(AREAD);
    }

    return(AFAIL);
  }

  switch (new_deny) 
    {
    case DENY_WRITE:
      if (old_deny==DENY_WRITE && old_mode==0) return(AREAD);
      if (old_deny==DENY_READ && old_mode==0) return(AWRITE);
      if (old_deny==DENY_NONE && old_mode==0) return(AALL);
      return(AFAIL);
    case DENY_READ:
      if (old_deny==DENY_WRITE && old_mode==1) return(AREAD);
      if (old_deny==DENY_READ && old_mode==1) return(AWRITE);
      if (old_deny==DENY_NONE && old_mode==1) return(AALL);
      return(AFAIL);
    case DENY_NONE:
      if (old_deny==DENY_WRITE) return(AREAD);
      if (old_deny==DENY_READ) return(AWRITE);
      if (old_deny==DENY_NONE) return(AALL);
      return(AFAIL);      
    }
  return(AFAIL);      
}

/*******************************************************************
check if the share mode on a file allows it to be deleted or unlinked
return True if sharing doesn't prevent the operation
********************************************************************/
BOOL check_file_sharing(int cnum,char *fname, BOOL rename_op)
{
  int i;
  int ret = False;
  share_mode_entry *old_shares = 0;
  int num_share_modes;
  struct stat sbuf;
  int token;
  int pid = getpid();
  uint32 dev, inode;

  if(!lp_share_modes(SNUM(cnum)))
    return True;

  if (stat(fname,&sbuf) == -1) return(True);

  dev = (uint32)sbuf.st_dev;
  inode = (uint32)sbuf.st_ino;

  lock_share_entry(cnum, dev, inode, &token);
  num_share_modes = get_share_modes(cnum, token, dev, inode, &old_shares);

  /*
   * Check if the share modes will give us access.
   */

  if(num_share_modes != 0)
  {
    BOOL broke_oplock;

    do
    {

      broke_oplock = False;
      for(i = 0; i < num_share_modes; i++)
      {
        share_mode_entry *share_entry = &old_shares[i];

        /* 
         * Break oplocks before checking share modes. See comment in
         * open_file_shared for details. 
         * Check if someone has an oplock on this file. If so we must 
         * break it before continuing. 
         */
        if(share_entry->op_type & BATCH_OPLOCK)
        {

          /*
           * It appears that the NT redirector may have a bug, in that
           * it tries to do an SMBmv on a file that it has open with a
           * batch oplock, and then fails to respond to the oplock break
           * request. This only seems to occur when the client is doing an
           * SMBmv to the smbd it is using - thus we try and detect this
           * condition by checking if the file being moved is open and oplocked by
           * this smbd process, and then not sending the oplock break in this
           * special case. If the file was open with a deny mode that 
           * prevents the move the SMBmv will fail anyway with a share
           * violation error. JRA.
           */
          if(rename_op && (share_entry->pid == pid))
          {
            DEBUG(0,("check_file_sharing: NT redirector workaround - rename attempted on \
batch oplocked file %s, dev = %x, inode = %x\n", fname, dev, inode));
            /* 
             * This next line is a test that allows the deny-mode
             * processing to be skipped. This seems to be needed as
             * NT insists on the rename succeeding (in Office 9x no less !).
             * This should be removed as soon as (a) MS fix the redirector
             * bug or (b) NT SMB support in Samba makes NT not issue the
             * call (as is my fervent hope). JRA.
             */ 
            continue;
          }
          else
          {
            DEBUG(5,("check_file_sharing: breaking oplock (%x) on file %s, \
dev = %x, inode = %x\n", share_entry->op_type, fname, dev, inode));

            /* Oplock break.... */
            unlock_share_entry(cnum, dev, inode, token);
            if(request_oplock_break(share_entry, dev, inode) == False)
            {
              free((char *)old_shares);
              DEBUG(0,("check_file_sharing: FAILED when breaking oplock (%x) on file %s, \
dev = %x, inode = %x\n", old_shares[i].op_type, fname, dev, inode));
              return False;
            }
            lock_share_entry(cnum, dev, inode, &token);
            broke_oplock = True;
            break;
          }
        }

        /* someone else has a share lock on it, check to see 
           if we can too */
        if ((share_entry->share_mode != DENY_DOS) || (share_entry->pid != pid))
          goto free_and_exit;

      } /* end for */

      if(broke_oplock)
      {
        free((char *)old_shares);
        num_share_modes = get_share_modes(cnum, token, dev, inode, &old_shares);
      }
    } while(broke_oplock);
  }

  /* XXXX exactly what share mode combinations should be allowed for
     deleting/renaming? */
  /* If we got here then either there were no share modes or
     all share modes were DENY_DOS and the pid == getpid() */
  ret = True;

free_and_exit:

  unlock_share_entry(cnum, dev, inode, token);
  if(old_shares != NULL)
    free((char *)old_shares);
  return(ret);
}

/****************************************************************************
  C. Hoch 11/22/95
  Helper for open_file_shared. 
  Truncate a file after checking locking; close file if locked.
  **************************************************************************/
static void truncate_unless_locked(int fnum, int cnum, int token, 
				   BOOL *share_locked)
{
  if (Files[fnum].can_write){
    if (is_locked(fnum,cnum,0x3FFFFFFF,0)){
      /* If share modes are in force for this connection we
         have the share entry locked. Unlock it before closing. */
      if (*share_locked && lp_share_modes(SNUM(cnum)))
        unlock_share_entry( cnum, Files[fnum].fd_ptr->dev, 
                            Files[fnum].fd_ptr->inode, token);
      close_file(fnum,False);   
      /* Share mode no longer locked. */
      *share_locked = False;
      errno = EACCES;
      unix_ERR_class = ERRDOS;
      unix_ERR_code = ERRlock;
    }
    else
      ftruncate(Files[fnum].fd_ptr->fd,0); 
  }
}

/****************************************************************************
check if we can open a file with a share mode
****************************************************************************/
int check_share_mode( share_mode_entry *share, int deny_mode, char *fname,
                      BOOL fcbopen, int *flags)
{
  int old_open_mode = share->share_mode &0xF;
  int old_deny_mode = (share->share_mode >>4)&7;

  if (old_deny_mode > 4 || old_open_mode > 2)
  {
    DEBUG(0,("Invalid share mode found (%d,%d,%d) on file %s\n",
               deny_mode,old_deny_mode,old_open_mode,fname));
    return False;
  }

  {
    int access_allowed = access_table(deny_mode,old_deny_mode,old_open_mode,
                                share->pid,fname);

    if ((access_allowed == AFAIL) ||
        (!fcbopen && (access_allowed == AREAD && *flags == O_RDWR)) ||
        (access_allowed == AREAD && *flags == O_WRONLY) ||
        (access_allowed == AWRITE && *flags == O_RDONLY))
    {
      DEBUG(2,("Share violation on file (%d,%d,%d,%d,%s,fcbopen = %d, flags = %d) = %d\n",
                deny_mode,old_deny_mode,old_open_mode,
                share->pid,fname, fcbopen, *flags, access_allowed));
      return False;
    }

    if (access_allowed == AREAD)
      *flags = O_RDONLY;

    if (access_allowed == AWRITE)
      *flags = O_WRONLY;

  }
  return True;
}

/****************************************************************************
open a file with a share mode
****************************************************************************/
void open_file_shared(int fnum,int cnum,char *fname,int share_mode,int ofun,
		      int mode,int oplock_request, int *Access,int *action)
{
  files_struct *fs_p = &Files[fnum];
  int flags=0;
  int flags2=0;
  int deny_mode = (share_mode>>4)&7;
  struct stat sbuf;
  BOOL file_existed = file_exist(fname,&sbuf);
  BOOL share_locked = False;
  BOOL fcbopen = False;
  int token;
  uint32 dev = 0;
  uint32 inode = 0;
  int num_share_modes = 0;

  fs_p->open = False;
  fs_p->fd_ptr = 0;

  /* this is for OS/2 EAs - try and say we don't support them */
  if (strstr(fname,".+,;=[].")) 
  {
    unix_ERR_class = ERRDOS;
    /* OS/2 Workplace shell fix may be main code stream in a later release. */ 
#if 1 /* OS2_WPS_FIX - Recent versions of OS/2 need this. */
    unix_ERR_code = ERRcannotopen;
#else /* OS2_WPS_FIX */
    unix_ERR_code = ERROR_EAS_NOT_SUPPORTED;
#endif /* OS2_WPS_FIX */

    return;
  }

  if ((ofun & 0x3) == 0 && file_existed)  
  {
    errno = EEXIST;
    return;
  }
      
  if (ofun & 0x10)
    flags2 |= O_CREAT;
  if ((ofun & 0x3) == 2)
    flags2 |= O_TRUNC;

  /* note that we ignore the append flag as 
     append does not mean the same thing under dos and unix */

  switch (share_mode&0xF)
  {
    case 1: 
      flags = O_WRONLY; 
      break;
    case 0xF: 
      fcbopen = True;
      flags = O_RDWR; 
      break;
    case 2: 
      flags = O_RDWR; 
      break;
    default:
      flags = O_RDONLY;
      break;
  }
  
  if (flags != O_RDONLY && file_existed && 
      (!CAN_WRITE(cnum) || IS_DOS_READONLY(dos_mode(cnum,fname,&sbuf)))) 
  {
    if (!fcbopen) 
    {
      errno = EACCES;
      return;
    }
    flags = O_RDONLY;
  }

  if (deny_mode > DENY_NONE && deny_mode!=DENY_FCB) 
  {
    DEBUG(2,("Invalid deny mode %d on file %s\n",deny_mode,fname));
    errno = EINVAL;
    return;
  }

  if (deny_mode == DENY_FCB) deny_mode = DENY_DOS;

  if (lp_share_modes(SNUM(cnum))) 
  {
    int i;
    share_mode_entry *old_shares = 0;

    if (file_existed)
    {
      dev = (uint32)sbuf.st_dev;
      inode = (uint32)sbuf.st_ino;
      lock_share_entry(cnum, dev, inode, &token);
      share_locked = True;
      num_share_modes = get_share_modes(cnum, token, dev, inode, &old_shares);
    }

    /*
     * Check if the share modes will give us access.
     */

    if(share_locked && (num_share_modes != 0))
    {
      BOOL broke_oplock;

      do
      {

        broke_oplock = False;
        for(i = 0; i < num_share_modes; i++)
        {
          share_mode_entry *share_entry = &old_shares[i];

          /* 
           * By observation of NetBench, oplocks are broken *before* share
           * modes are checked. This allows a file to be closed by the client
           * if the share mode would deny access and the client has an oplock. 
           * Check if someone has an oplock on this file. If so we must break 
           * it before continuing. 
           */
          if(share_entry->op_type & (EXCLUSIVE_OPLOCK|BATCH_OPLOCK))
          {

            DEBUG(5,("open_file_shared: breaking oplock (%x) on file %s, \
dev = %x, inode = %x\n", share_entry->op_type, fname, dev, inode));

            /* Oplock break.... */
            unlock_share_entry(cnum, dev, inode, token);
            if(request_oplock_break(share_entry, dev, inode) == False)
            {
              free((char *)old_shares);
              DEBUG(0,("open_file_shared: FAILED when breaking oplock (%x) on file %s, \
dev = %x, inode = %x\n", old_shares[i].op_type, fname, dev, inode));
              errno = EACCES;
              unix_ERR_class = ERRDOS;
              unix_ERR_code = ERRbadshare;
              return;
            }
            lock_share_entry(cnum, dev, inode, &token);
            broke_oplock = True;
            break;
          }

          /* someone else has a share lock on it, check to see 
             if we can too */
          if(check_share_mode(share_entry, deny_mode, fname, fcbopen, &flags) == False)
          {
            free((char *)old_shares);
            unlock_share_entry(cnum, dev, inode, token);
            errno = EACCES;
            unix_ERR_class = ERRDOS;
            unix_ERR_code = ERRbadshare;
            return;
          }

        } /* end for */

        if(broke_oplock)
        {
          free((char *)old_shares);
          num_share_modes = get_share_modes(cnum, token, dev, inode, &old_shares);
        }
      } while(broke_oplock);
    }

    if(old_shares != 0)
      free((char *)old_shares);
  }

  DEBUG(4,("calling open_file with flags=0x%X flags2=0x%X mode=0%o\n",
	   flags,flags2,mode));

  open_file(fnum,cnum,fname,flags|(flags2&~(O_TRUNC)),mode,file_existed ? &sbuf : 0);
  if (!fs_p->open && flags==O_RDWR && errno!=ENOENT && fcbopen) 
  {
    flags = O_RDONLY;
    open_file(fnum,cnum,fname,flags,mode,file_existed ? &sbuf : 0 );
  }

  if (fs_p->open) 
  {
    int open_mode=0;

    if((share_locked == False) && lp_share_modes(SNUM(cnum)))
    {
      /* We created the file - thus we must now lock the share entry before creating it. */
      dev = fs_p->fd_ptr->dev;
      inode = fs_p->fd_ptr->inode;
      lock_share_entry(cnum, dev, inode, &token);
      share_locked = True;
    }

    switch (flags) 
    {
      case O_RDONLY:
        open_mode = 0;
        break;
      case O_RDWR:
        open_mode = 2;
        break;
      case O_WRONLY:
        open_mode = 1;
        break;
    }

    fs_p->share_mode = (deny_mode<<4) | open_mode;

    if (Access)
      (*Access) = open_mode;

    if (action) 
    {
      if (file_existed && !(flags2 & O_TRUNC)) *action = 1;
      if (!file_existed) *action = 2;
      if (file_existed && (flags2 & O_TRUNC)) *action = 3;
    }
    /* We must create the share mode entry before truncate as
       truncate can fail due to locking and have to close the
       file (which expects the share_mode_entry to be there).
     */
    if (lp_share_modes(SNUM(cnum)))
    {
      uint16 port = 0;
      /* JRA. Currently this only services Exlcusive and batch
         oplocks (no other opens on this file). This needs to
         be extended to level II oplocks (multiple reader
         oplocks). */

      if(oplock_request && (num_share_modes == 0) && lp_oplocks(SNUM(cnum)) && 
	      !IS_VETO_OPLOCK_PATH(cnum,fname))
      {
        fs_p->granted_oplock = True;
        fs_p->sent_oplock_break = False;
        global_oplocks_open++;
        port = oplock_port;

        DEBUG(5,("open_file_shared: granted oplock (%x) on file %s, \
dev = %x, inode = %x\n", oplock_request, fname, dev, inode));

      }
      else
      {
        port = 0;
        oplock_request = 0;
      }
      set_share_mode(token, fnum, port, oplock_request);
    }

    if ((flags2&O_TRUNC) && file_existed)
      truncate_unless_locked(fnum,cnum,token,&share_locked);
  }

  if (share_locked && lp_share_modes(SNUM(cnum)))
    unlock_share_entry( cnum, dev, inode, token);
}

/****************************************************************************
seek a file. Try to avoid the seek if possible
****************************************************************************/
int seek_file(int fnum,uint32 pos)
{
  uint32 offset = 0;
  if (Files[fnum].print_file && POSTSCRIPT(Files[fnum].cnum))
    offset = 3;

  Files[fnum].pos = (int)(lseek(Files[fnum].fd_ptr->fd,pos+offset,SEEK_SET) 
                                  - offset);
  return(Files[fnum].pos);
}

/****************************************************************************
read from a file
****************************************************************************/
int read_file(int fnum,char *data,uint32 pos,int n)
{
  int ret=0,readret;

#if USE_READ_PREDICTION
  if (!Files[fnum].can_write)
    {
      ret = read_predict(Files[fnum].fd_ptr->fd,pos,data,NULL,n);

      data += ret;
      n -= ret;
      pos += ret;
    }
#endif

#if USE_MMAP
  if (Files[fnum].mmap_ptr)
    {
      int num = (Files[fnum].mmap_size > pos) ? (Files[fnum].mmap_size - pos) : -1;
      num = MIN(n,num);
      if (num > 0)
	{
	  memcpy(data,Files[fnum].mmap_ptr+pos,num);
	  data += num;
	  pos += num;
	  n -= num;
	  ret += num;
	}
    }
#endif

  if (n <= 0)
    return(ret);

  if (seek_file(fnum,pos) != pos)
    {
      DEBUG(3,("Failed to seek to %d\n",pos));
      return(ret);
    }
  
  if (n > 0) {
    readret = read(Files[fnum].fd_ptr->fd,data,n);
    if (readret > 0) ret += readret;
  }

  return(ret);
}


/****************************************************************************
write to a file
****************************************************************************/
int write_file(int fnum,char *data,int n)
{
  if (!Files[fnum].can_write) {
    errno = EPERM;
    return(0);
  }

  if (!Files[fnum].modified) {
    struct stat st;
    Files[fnum].modified = True;
    if (fstat(Files[fnum].fd_ptr->fd,&st) == 0) {
      int dosmode = dos_mode(Files[fnum].cnum,Files[fnum].name,&st);
      if (MAP_ARCHIVE(Files[fnum].cnum) && !IS_DOS_ARCHIVE(dosmode)) {	
	dos_chmod(Files[fnum].cnum,Files[fnum].name,dosmode | aARCH,&st);
      }
    }  
  }

  return(write_data(Files[fnum].fd_ptr->fd,data,n));
}


/****************************************************************************
load parameters specific to a connection/service
****************************************************************************/
BOOL become_service(int cnum,BOOL do_chdir)
{
  extern char magic_char;
  static int last_cnum = -1;
  int snum;

  if (!OPEN_CNUM(cnum))
    {
      last_cnum = -1;
      return(False);
    }

  Connections[cnum].lastused = smb_last_time;

  snum = SNUM(cnum);
  
  if (do_chdir &&
      ChDir(Connections[cnum].connectpath) != 0 &&
      ChDir(Connections[cnum].origpath) != 0)
    {
      DEBUG(0,("%s chdir (%s) failed cnum=%d\n",timestring(),
	    Connections[cnum].connectpath,cnum));     
      return(False);
    }

  if (cnum == last_cnum)
    return(True);

  last_cnum = cnum;

  case_default = lp_defaultcase(snum);
  case_preserve = lp_preservecase(snum);
  short_case_preserve = lp_shortpreservecase(snum);
  case_mangle = lp_casemangle(snum);
  case_sensitive = lp_casesensitive(snum);
  magic_char = lp_magicchar(snum);
  use_mangled_map = (*lp_mangled_map(snum) ? True:False);
  return(True);
}


/****************************************************************************
  find a service entry
****************************************************************************/
int find_service(char *service)
{
   int iService;

   string_sub(service,"\\","/");

   iService = lp_servicenumber(service);

   /* now handle the special case of a home directory */
   if (iService < 0)
   {
      char *phome_dir = get_home_dir(service);

      if(!phome_dir)
      {
        /*
         * Try mapping the servicename, it may
         * be a Windows to unix mapped user name.
         */
        if(map_username(service))
          phome_dir = get_home_dir(service);
      }

      DEBUG(3,("checking for home directory %s gave %s\n",service,
	    phome_dir?phome_dir:"(NULL)"));
      if (phome_dir)
      {   
	 int iHomeService;
	 if ((iHomeService = lp_servicenumber(HOMES_NAME)) >= 0)
	 {
	    lp_add_home(service,iHomeService,phome_dir);
	    iService = lp_servicenumber(service);
	 }
      }
   }

   /* If we still don't have a service, attempt to add it as a printer. */
   if (iService < 0)
   {
      int iPrinterService;

      if ((iPrinterService = lp_servicenumber(PRINTERS_NAME)) >= 0)
      {
         char *pszTemp;

         DEBUG(3,("checking whether %s is a valid printer name...\n", service));
         pszTemp = PRINTCAP;
         if ((pszTemp != NULL) && pcap_printername_ok(service, pszTemp))
         {
            DEBUG(3,("%s is a valid printer name\n", service));
            DEBUG(3,("adding %s as a printer service\n", service));
            lp_add_printer(service,iPrinterService);
            iService = lp_servicenumber(service);
            if (iService < 0)
               DEBUG(0,("failed to add %s as a printer service!\n", service));
         }
         else
            DEBUG(3,("%s is not a valid printer name\n", service));
      }
   }

   /* just possibly it's a default service? */
   if (iService < 0) 
     {
       char *pdefservice = lp_defaultservice();
       if (pdefservice && *pdefservice && !strequal(pdefservice,service)) {
         /*
          * We need to do a local copy here as lp_defaultservice() 
          * returns one of the rotating lp_string buffers that
          * could get overwritten by the recursive find_service() call
          * below. Fix from Josef Hinteregger <joehtg@joehtg.co.at>.
          */
         pstring defservice;
         pstrcpy(defservice, pdefservice);
	 iService = find_service(defservice);
	 if (iService >= 0) {
	   string_sub(service,"_","/");
	   iService = lp_add_service(service,iService);
	 }
       }
     }

   if (iService >= 0)
      if (!VALID_SNUM(iService))
      {
         DEBUG(0,("Invalid snum %d for %s\n",iService,service));
	 iService = -1;
      }

   if (iService < 0)
      DEBUG(3,("find_service() failed to find service %s\n", service));

   return (iService);
}


/****************************************************************************
  create an error packet from a cached error.
****************************************************************************/
int cached_error_packet(char *inbuf,char *outbuf,int fnum,int line)
{
  write_bmpx_struct *wbmpx = Files[fnum].wbmpx_ptr;

  int32 eclass = wbmpx->wr_errclass;
  int32 err = wbmpx->wr_error;

  /* We can now delete the auxiliary struct */
  free((char *)wbmpx);
  Files[fnum].wbmpx_ptr = NULL;
  return error_packet(inbuf,outbuf,eclass,err,line);
}


struct
{
  int unixerror;
  int smbclass;
  int smbcode;
} unix_smb_errmap[] =
{
  {EPERM,ERRDOS,ERRnoaccess},
  {EACCES,ERRDOS,ERRnoaccess},
  {ENOENT,ERRDOS,ERRbadfile},
  {ENOTDIR,ERRDOS,ERRbadpath},
  {EIO,ERRHRD,ERRgeneral},
  {EBADF,ERRSRV,ERRsrverror},
  {EINVAL,ERRSRV,ERRsrverror},
  {EEXIST,ERRDOS,ERRfilexists},
  {ENFILE,ERRDOS,ERRnofids},
  {EMFILE,ERRDOS,ERRnofids},
  {ENOSPC,ERRHRD,ERRdiskfull},
#ifdef EDQUOT
  {EDQUOT,ERRHRD,ERRdiskfull},
#endif
#ifdef ENOTEMPTY
  {ENOTEMPTY,ERRDOS,ERRnoaccess},
#endif
#ifdef EXDEV
  {EXDEV,ERRDOS,ERRdiffdevice},
#endif
  {EROFS,ERRHRD,ERRnowrite},
  {0,0,0}
};

/****************************************************************************
  create an error packet from errno
****************************************************************************/
int unix_error_packet(char *inbuf,char *outbuf,int def_class,uint32 def_code,int line)
{
  int eclass=def_class;
  int ecode=def_code;
  int i=0;

  if (unix_ERR_class != SMB_SUCCESS)
    {
      eclass = unix_ERR_class;
      ecode = unix_ERR_code;
      unix_ERR_class = SMB_SUCCESS;
      unix_ERR_code = 0;
    }
  else
    {
      while (unix_smb_errmap[i].smbclass != 0)
      {
	    if (unix_smb_errmap[i].unixerror == errno)
	    {
	      eclass = unix_smb_errmap[i].smbclass;
	      ecode = unix_smb_errmap[i].smbcode;
	      break;
	    }
	  i++;
      }
    }

  return(error_packet(inbuf,outbuf,eclass,ecode,line));
}


/****************************************************************************
  create an error packet. Normally called using the ERROR() macro
****************************************************************************/
int error_packet(char *inbuf,char *outbuf,int error_class,uint32 error_code,int line)
{
  int outsize = set_message(outbuf,0,0,True);
  int cmd;
  cmd = CVAL(inbuf,smb_com);
  
  CVAL(outbuf,smb_rcls) = error_class;
  SSVAL(outbuf,smb_err,error_code);  
  
  DEBUG(3,("%s error packet at line %d cmd=%d (%s) eclass=%d ecode=%d\n",
	   timestring(),
	   line,
	   (int)CVAL(inbuf,smb_com),
	   smb_fn_name(CVAL(inbuf,smb_com)),
	   error_class,
	   error_code));

  if (errno != 0)
    DEBUG(3,("error string = %s\n",strerror(errno)));
  
  return(outsize);
}


#ifndef SIGCLD_IGNORE
/****************************************************************************
this prevents zombie child processes
****************************************************************************/
static int sig_cld(void)
{
  static int depth = 0;
  if (depth != 0)
    {
      DEBUG(0,("ERROR: Recursion in sig_cld? Perhaps you need `#define USE_WAITPID'?\n"));
      depth=0;
      return(0);
    }
  depth++;

  BlockSignals(True,SIGCLD);
  DEBUG(5,("got SIGCLD\n"));

#ifdef USE_WAITPID
  while (sys_waitpid((pid_t)-1,(int *)NULL, WNOHANG) > 0);
#endif

  /* Stop zombies */
  /* Stevens, Adv. Unix Prog. says that on system V you must call
     wait before reinstalling the signal handler, because the kernel
     calls the handler from within the signal-call when there is a
     child that has exited. This would lead to an infinite recursion
     if done vice versa. */
        
#ifndef DONT_REINSTALL_SIG
#ifdef SIGCLD_IGNORE
  signal(SIGCLD, SIG_IGN);  
#else
  signal(SIGCLD, SIGNAL_CAST sig_cld);
#endif
#endif

#ifndef USE_WAITPID
  while (wait3(WAIT3_CAST1 NULL, WNOHANG, WAIT3_CAST2 NULL) > 0);
#endif
  depth--;
  BlockSignals(False,SIGCLD);
  return 0;
}
#endif

/****************************************************************************
  this is called when the client exits abruptly
  **************************************************************************/
static int sig_pipe(void)
{
	struct cli_state *cli;
	BlockSignals(True,SIGPIPE);

	if ((cli = server_client()) && cli->initialised) {
		DEBUG(3,("lost connection to password server\n"));
		cli_shutdown(cli);
#ifndef DONT_REINSTALL_SIG
		signal(SIGPIPE, SIGNAL_CAST sig_pipe);
#endif
		BlockSignals(False,SIGPIPE);
		return 0;
	}

	exit_server("Got sigpipe\n");
	return(0);
}

/****************************************************************************
  open the socket communication
****************************************************************************/
static BOOL open_sockets(BOOL is_daemon,int port)
{
  extern int Client;

  if (is_daemon)
  {
    int num_interfaces = iface_count();
    int fd_listenset[FD_SETSIZE];
    fd_set listen_set;
    int s;
    int i;

    /* Stop zombies */
#ifdef SIGCLD_IGNORE
    signal(SIGCLD, SIG_IGN);
#else
    signal(SIGCLD, SIGNAL_CAST sig_cld);
#endif

    if(atexit_set == 0)
      atexit(killkids);

    FD_ZERO(&listen_set);

    if(lp_interfaces() && lp_bind_interfaces_only())
    {
       /* We have been given an interfaces line, and been 
          told to only bind to those interfaces. Create a
          socket per interface and bind to only these.
        */

      if(num_interfaces > FD_SETSIZE)
      {
        DEBUG(0,("open_sockets: Too many interfaces specified to bind to. Number was %d \
max can be %d\n", num_interfaces, FD_SETSIZE));
        return False;
      }

      /* Now open a listen socket for each of the interfaces. */
      for(i = 0; i < num_interfaces; i++)
      {
        struct in_addr *ifip = iface_n_ip(i);

        if(ifip == NULL)
        {
          DEBUG(0,("open_sockets: interface %d has NULL IP address !\n", i));
          continue;
        }
        s = fd_listenset[i] = open_socket_in(SOCK_STREAM, port, 0, ifip->s_addr);
        if(s == -1)
          return False;
        /* ready to listen */
        if (listen(s, 5) == -1) 
        {
          DEBUG(0,("listen: %s\n",strerror(errno)));
          close(s);
          return False;
        }
        FD_SET(s,&listen_set);
      }
    }
    else
    {
      /* Just bind to 0.0.0.0 - accept connections from anywhere. */
      num_interfaces = 1;

      /* open an incoming socket */
      s = open_socket_in(SOCK_STREAM, port, 0,interpret_addr(lp_socket_address()));
      if (s == -1)
        return(False);

      /* ready to listen */
      if (listen(s, 5) == -1) 
      {
        DEBUG(0,("open_sockets: listen: %s\n",strerror(errno)));
        close(s);
        return False;
      }

      fd_listenset[0] = s;
      FD_SET(s,&listen_set);
    }      

    /* now accept incoming connections - forking a new process
       for each incoming connection */
    DEBUG(2,("waiting for a connection\n"));
    while (1)
    {
      fd_set lfds;
      int num;

      memcpy((char *)&lfds, (char *)&listen_set, sizeof(listen_set));

      num = sys_select(&lfds,NULL);

      if (num == -1 && errno == EINTR)
        continue;

      /* Find the sockets that are read-ready - accept on these. */
      for( ; num > 0; num--)
      {
        struct sockaddr addr;
        int in_addrlen = sizeof(addr);

        s = -1;
        for(i = 0; i < num_interfaces; i++)
        {
          if(FD_ISSET(fd_listenset[i],&lfds))
          {
            s = fd_listenset[i];
            /* Clear this so we don't look at it again. */
            FD_CLR(fd_listenset[i],&lfds);
            break;
          }
        }

        Client = accept(s,&addr,&in_addrlen);

        if (Client == -1 && errno == EINTR)
          continue;

        if (Client == -1)
        {
          DEBUG(0,("open_sockets: accept: %s\n",strerror(errno)));
          continue;
        }

#ifdef NO_FORK_DEBUG
#ifndef NO_SIGNAL_TEST
        signal(SIGPIPE, SIGNAL_CAST sig_pipe);
        signal(SIGCLD, SIGNAL_CAST SIG_DFL);
#endif /* NO_SIGNAL_TEST */
        return True;
#else /* NO_FORK_DEBUG */
        if (Client != -1 && fork()==0)
        {
          /* Child code ... */

#ifndef NO_SIGNAL_TEST
          signal(SIGPIPE, SIGNAL_CAST sig_pipe);
          signal(SIGCLD, SIGNAL_CAST SIG_DFL);
#endif /* NO_SIGNAL_TEST */
          /* close the listening socket(s) */
          for(i = 0; i < num_interfaces; i++)
            close(fd_listenset[i]);

          /* close our standard file descriptors */
          close_low_fds();
          am_parent = 0;
  
          set_socket_options(Client,"SO_KEEPALIVE");
          set_socket_options(Client,user_socket_options);

          /* Reset global variables in util.c so that
             client substitutions will be done correctly
             in the process.
           */
          reset_globals_after_fork();
          return True; 
        }
        close(Client); /* The parent doesn't need this socket */
#endif /* NO_FORK_DEBUG */
      } /* end for num */
    } /* end while 1 */
  } /* end if is_daemon */
  else
  {
    /* Started from inetd. fd 0 is the socket. */
    /* We will abort gracefully when the client or remote system 
       goes away */
#ifndef NO_SIGNAL_TEST
    signal(SIGPIPE, SIGNAL_CAST sig_pipe);
#endif
    Client = dup(0);

    /* close our standard file descriptors */
    close_low_fds();

    set_socket_options(Client,"SO_KEEPALIVE");
    set_socket_options(Client,user_socket_options);
  }

  return True;
}

/****************************************************************************
  process an smb from the client - split out from the process() code so
  it can be used by the oplock break code.
****************************************************************************/

static void process_smb(char *inbuf, char *outbuf)
{
  extern int Client;
  static int trans_num;
  int msg_type = CVAL(inbuf,0);
  int32 len = smb_len(inbuf);
  int nread = len + 4;

  if (trans_num == 0) {
	  /* on the first packet, check the global hosts allow/ hosts
	     deny parameters before doing any parsing of the packet
	     passed to us by the client.  This prevents attacks on our
	     parsing code from hosts not in the hosts allow list */
	  if (!check_access(-1)) {
		  /* send a negative session response "not listining on calling
		   name" */
		  static unsigned char buf[5] = {0x83, 0, 0, 1, 0x81};
		  DEBUG(1,("%s Connection denied from %s\n",
			   timestring(),client_addr()));
		  send_smb(Client,(char *)buf);
		  exit_server("connection denied");
	  }
  }

  DEBUG(6,("got message type 0x%x of len 0x%x\n",msg_type,len));
  DEBUG(3,("%s Transaction %d of length %d\n",timestring(),trans_num,nread));

#ifdef WITH_VTP
  if(trans_num == 1 && VT_Check(inbuf)) 
  {
    VT_Process();
    return;
  }
#endif

  if (msg_type == 0)
    show_msg(inbuf);
  else if(msg_type == 0x85)
    return; /* Keepalive packet. */

  nread = construct_reply(inbuf,outbuf,nread,max_send);
      
  if(nread > 0) 
  {
    if (CVAL(outbuf,0) == 0)
      show_msg(outbuf);
	
    if (nread != smb_len(outbuf) + 4) 
    {
      DEBUG(0,("ERROR: Invalid message response size! %d %d\n",
                 nread, smb_len(outbuf)));
    }
    else
      send_smb(Client,outbuf);
  }
  trans_num++;
}

/****************************************************************************
  open the oplock IPC socket communication
****************************************************************************/
static BOOL open_oplock_ipc(void)
{
  struct sockaddr_in sock_name;
  int len = sizeof(sock_name);

  DEBUG(3,("open_oplock_ipc: opening loopback UDP socket.\n"));

  /* Open a lookback UDP socket on a random port. */
  oplock_sock = open_socket_in(SOCK_DGRAM, 0, 0, htonl(INADDR_LOOPBACK));
  if (oplock_sock == -1)
  {
    DEBUG(0,("open_oplock_ipc: Failed to get local UDP socket for \
address %x. Error was %s\n", htonl(INADDR_LOOPBACK), strerror(errno)));
    oplock_port = 0;
    return(False);
  }

  /* Find out the transient UDP port we have been allocated. */
  if(getsockname(oplock_sock, (struct sockaddr *)&sock_name, &len)<0)
  {
    DEBUG(0,("open_oplock_ipc: Failed to get local UDP port. Error was %s\n",
            strerror(errno)));
    close(oplock_sock);
    oplock_sock = -1;
    oplock_port = 0;
    return False;
  }
  oplock_port = ntohs(sock_name.sin_port);

  DEBUG(3,("open_oplock ipc: pid = %d, oplock_port = %u\n", 
            getpid(), oplock_port));

  return True;
}

/****************************************************************************
  process an oplock break message.
****************************************************************************/
static BOOL process_local_message(int sock, char *buffer, int buf_size)
{
  int32 msg_len;
  uint16 from_port;
  char *msg_start;

  msg_len = IVAL(buffer,UDP_CMD_LEN_OFFSET);
  from_port = SVAL(buffer,UDP_CMD_PORT_OFFSET);

  msg_start = &buffer[UDP_CMD_HEADER_LEN];

  DEBUG(5,("process_local_message: Got a message of length %d from port (%d)\n", 
            msg_len, from_port));

  /* Switch on message command - currently OPLOCK_BREAK_CMD is the
     only valid request. */

  switch(SVAL(msg_start,UDP_MESSAGE_CMD_OFFSET))
  {
    case OPLOCK_BREAK_CMD:
      /* Ensure that the msg length is correct. */
      if(msg_len != OPLOCK_BREAK_MSG_LEN)
      {
        DEBUG(0,("process_local_message: incorrect length for OPLOCK_BREAK_CMD (was %d, \
should be %d).\n", msg_len, OPLOCK_BREAK_MSG_LEN));
        return False;
      }
      {
        uint32 remotepid = IVAL(msg_start,OPLOCK_BREAK_PID_OFFSET);
        uint32 dev = IVAL(msg_start,OPLOCK_BREAK_DEV_OFFSET);
        uint32 inode = IVAL(msg_start, OPLOCK_BREAK_INODE_OFFSET);
        struct timeval tval;
        struct sockaddr_in toaddr;

        tval.tv_sec = IVAL(msg_start, OPLOCK_BREAK_SEC_OFFSET);
        tval.tv_usec = IVAL(msg_start, OPLOCK_BREAK_USEC_OFFSET);

        DEBUG(5,("process_local_message: oplock break request from \
pid %d, port %d, dev = %x, inode = %x\n", remotepid, from_port, dev, inode));

        /*
         * If we have no record of any currently open oplocks,
         * it's not an error, as a close command may have
         * just been issued on the file that was oplocked.
         * Just return success in this case.
         */

        if(global_oplocks_open != 0)
        {
          if(oplock_break(dev, inode, &tval) == False)
          {
            DEBUG(0,("process_local_message: oplock break failed - \
not returning udp message.\n"));
            return False;
          }
        }
        else
        {
          DEBUG(3,("process_local_message: oplock break requested with no outstanding \
oplocks. Returning success.\n"));
        }

        /* Send the message back after OR'ing in the 'REPLY' bit. */
        SSVAL(msg_start,UDP_MESSAGE_CMD_OFFSET,OPLOCK_BREAK_CMD | CMD_REPLY);
  
        bzero((char *)&toaddr,sizeof(toaddr));
        toaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        toaddr.sin_port = htons(from_port);
        toaddr.sin_family = AF_INET;

        if(sendto( sock, msg_start, OPLOCK_BREAK_MSG_LEN, 0,
                (struct sockaddr *)&toaddr, sizeof(toaddr)) < 0) 
        {
          DEBUG(0,("process_local_message: sendto process %d failed. Errno was %s\n",
                    remotepid, strerror(errno)));
          return False;
        }

        DEBUG(5,("process_local_message: oplock break reply sent to \
pid %d, port %d, for file dev = %x, inode = %x\n", remotepid, 
                from_port, dev, inode));

      }
      break;
    /* 
     * Keep this as a debug case - eventually we can remove it.
     */
    case 0x8001:
      DEBUG(0,("process_local_message: Received unsolicited break \
reply - dumping info.\n"));

      if(msg_len != OPLOCK_BREAK_MSG_LEN)
      {
        DEBUG(0,("process_local_message: ubr: incorrect length for reply \
(was %d, should be %d).\n", msg_len, OPLOCK_BREAK_MSG_LEN));
        return False;
      }

      {
        uint32 remotepid = IVAL(msg_start,OPLOCK_BREAK_PID_OFFSET);
        uint32 dev = IVAL(msg_start,OPLOCK_BREAK_DEV_OFFSET);
        uint32 inode = IVAL(msg_start, OPLOCK_BREAK_INODE_OFFSET);

        DEBUG(0,("process_local_message: unsolicited oplock break reply from \
pid %d, port %d, dev = %x, inode = %x\n", remotepid, from_port, dev, inode));

       }
       return False;

    default:
      DEBUG(0,("process_local_message: unknown UDP message command code (%x) - ignoring.\n",
                (unsigned int)SVAL(msg_start,0)));
      return False;
  }
  return True;
}

/****************************************************************************
 Process an oplock break directly.
****************************************************************************/
BOOL oplock_break(uint32 dev, uint32 inode, struct timeval *tval)
{
  extern struct current_user current_user;
  extern int Client;
  char *inbuf = NULL;
  char *outbuf = NULL;
  files_struct *fsp = NULL;
  int fnum;
  time_t start_time;
  BOOL shutdown_server = False;
  int saved_cnum;
  int saved_vuid;
  pstring saved_dir; 

  DEBUG(3,("%s oplock_break: called for dev = %x, inode = %x. Current \
global_oplocks_open = %d\n", timestring(), dev, inode, global_oplocks_open));

  /* We need to search the file open table for the
     entry containing this dev and inode, and ensure
     we have an oplock on it. */
  for( fnum = 0; fnum < MAX_OPEN_FILES; fnum++)
  {
    if(OPEN_FNUM(fnum))
    {
      if((Files[fnum].fd_ptr->dev == dev) && (Files[fnum].fd_ptr->inode == inode) &&
         (Files[fnum].open_time.tv_sec == tval->tv_sec) && 
         (Files[fnum].open_time.tv_usec == tval->tv_usec)) {
	      fsp = &Files[fnum];
	      break;
      }
    }
  }

  if(fsp == NULL)
  {
    /* The file could have been closed in the meantime - return success. */
    DEBUG(0,("%s oplock_break: cannot find open file with dev = %x, inode = %x (fnum = %d) \
allowing break to succeed.\n", timestring(), dev, inode, fnum));
    return True;
  }

  /* Ensure we have an oplock on the file */

  /* There is a potential race condition in that an oplock could
     have been broken due to another udp request, and yet there are
     still oplock break messages being sent in the udp message
     queue for this file. So return true if we don't have an oplock,
     as we may have just freed it.
   */

  if(!fsp->granted_oplock)
  {
    DEBUG(0,("%s oplock_break: file %s (fnum = %d, dev = %x, inode = %x) has no oplock. Allowing break to succeed regardless.\n", timestring(), fsp->name, fnum, dev, inode));
    return True;
  }

  /* mark the oplock break as sent - we don't want to send twice! */
  if (fsp->sent_oplock_break)
  {
    DEBUG(0,("%s oplock_break: ERROR: oplock_break already sent for file %s (fnum = %d, dev = %x, inode = %x)\n", timestring(), fsp->name, fnum, dev, inode));

    /* We have to fail the open here as we cannot send another oplock break on this
       file whilst we are awaiting a response from the client - neither can we
       allow another open to succeed while we are waiting for the client. */
    return False;
  }

  /* Now comes the horrid part. We must send an oplock break to the client,
     and then process incoming messages until we get a close or oplock release.
     At this point we know we need a new inbuf/outbuf buffer pair.
     We cannot use these staticaly as we may recurse into here due to
     messages crossing on the wire.
   */

  if((inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN))==NULL)
  {
    DEBUG(0,("oplock_break: malloc fail for input buffer.\n"));
    return False;
  }

  if((outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN))==NULL)
  {
    DEBUG(0,("oplock_break: malloc fail for output buffer.\n"));
    free(inbuf);
    inbuf = NULL;
    return False;
  }

  /* Prepare the SMBlockingX message. */
  bzero(outbuf,smb_size);
  set_message(outbuf,8,0,True);

  SCVAL(outbuf,smb_com,SMBlockingX);
  SSVAL(outbuf,smb_tid,fsp->cnum);
  SSVAL(outbuf,smb_pid,0xFFFF);
  SSVAL(outbuf,smb_uid,0);
  SSVAL(outbuf,smb_mid,0xFFFF);
  SCVAL(outbuf,smb_vwv0,0xFF);
  SSVAL(outbuf,smb_vwv2,fnum);
  SCVAL(outbuf,smb_vwv3,LOCKING_ANDX_OPLOCK_RELEASE);
  /* Change this when we have level II oplocks. */
  SCVAL(outbuf,smb_vwv3+1,OPLOCKLEVEL_NONE);
 
  send_smb(Client, outbuf);

  /* Remember we just sent an oplock break on this file. */
  fsp->sent_oplock_break = True;

  /* We need this in case a readraw crosses on the wire. */
  global_oplock_break = True;
 
  /* Process incoming messages. */

  /* JRA - If we don't get a break from the client in OPLOCK_BREAK_TIMEOUT
     seconds we should just die.... */

  start_time = time(NULL);

  /*
   * Save the information we need to re-become the
   * user, then unbecome the user whilst we're doing this.
   */
  saved_cnum = fsp->cnum;
  saved_vuid = current_user.vuid;
  GetWd(saved_dir);
  unbecome_user();

  while(OPEN_FNUM(fnum) && fsp->granted_oplock)
  {
    if(receive_smb(Client,inbuf,OPLOCK_BREAK_TIMEOUT * 1000) == False)
    {
      /*
       * Die if we got an error.
       */

      if (smb_read_error == READ_EOF)
        DEBUG(0,("%s oplock_break: end of file from client\n", timestring()));
 
      if (smb_read_error == READ_ERROR)
        DEBUG(0,("%s oplock_break: receive_smb error (%s)\n",
                  timestring(), strerror(errno)));

      if (smb_read_error == READ_TIMEOUT)
        DEBUG(0,("%s oplock_break: receive_smb timed out after %d seconds.\n",
                  timestring(), OPLOCK_BREAK_TIMEOUT));

      DEBUG(0,("%s oplock_break failed for file %s (fnum = %d, dev = %x, \
inode = %x).\n", timestring(), fsp->name, fnum, dev, inode));
      shutdown_server = True;
      break;
    }

    /*
     * There are certain SMB requests that we shouldn't allow
     * to recurse. opens, renames and deletes are the obvious
     * ones. This is handled in the switch_message() function.
     * If global_oplock_break is set they will push the packet onto
     * the pending smb queue and return -1 (no reply).
     * JRA.
     */

    process_smb(inbuf, outbuf);

    /*
     * Die if we go over the time limit.
     */

    if((time(NULL) - start_time) > OPLOCK_BREAK_TIMEOUT)
    {
      DEBUG(0,("%s oplock_break: no break received from client within \
%d seconds.\n", timestring(), OPLOCK_BREAK_TIMEOUT));
      DEBUG(0,("%s oplock_break failed for file %s (fnum = %d, dev = %x, \
inode = %x).\n", timestring(), fsp->name, fnum, dev, inode));
      shutdown_server = True;
      break;
    }
  }

  /*
   * Go back to being the user who requested the oplock
   * break.
   */
  if(!become_user(&Connections[saved_cnum], saved_cnum, saved_vuid))
  {
    DEBUG(0,("%s oplock_break: unable to re-become user ! Shutting down server\n",
          timestring()));
    close_sockets();
    close(oplock_sock);
    exit_server("unable to re-become user");
  }
  /* Including the directory. */
  ChDir(saved_dir);

  /* Free the buffers we've been using to recurse. */
  free(inbuf);
  free(outbuf);

  /* We need this in case a readraw crossed on the wire. */
  if(global_oplock_break)
    global_oplock_break = False;

  /*
   * If the client did not respond we must die.
   */

  if(shutdown_server)
  {
    DEBUG(0,("%s oplock_break: client failure in break - shutting down this smbd.\n",
          timestring()));
    close_sockets();
    close(oplock_sock);
    exit_server("oplock break failure");
  }

  if(OPEN_FNUM(fnum))
  {
    /* The lockingX reply will have removed the oplock flag 
       from the sharemode. */
    /* Paranoia.... */
    fsp->granted_oplock = False;
    fsp->sent_oplock_break = False;
    global_oplocks_open--;
  }

  /* Santity check - remove this later. JRA */
  if(global_oplocks_open < 0)
  {
    DEBUG(0,("oplock_break: global_oplocks_open < 0 (%d). PANIC ERROR\n",
              global_oplocks_open));
    exit_server("oplock_break: global_oplocks_open < 0");
  }

  DEBUG(3,("%s oplock_break: returning success for fnum = %d, dev = %x, inode = %x. Current \
global_oplocks_open = %d\n", timestring(), fnum, dev, inode, global_oplocks_open));

  return True;
}

/****************************************************************************
Send an oplock break message to another smbd process. If the oplock is held 
by the local smbd then call the oplock break function directly.
****************************************************************************/

BOOL request_oplock_break(share_mode_entry *share_entry, 
                          uint32 dev, uint32 inode)
{
  char op_break_msg[OPLOCK_BREAK_MSG_LEN];
  struct sockaddr_in addr_out;
  int pid = getpid();
  time_t start_time;
  int time_left;

  if(pid == share_entry->pid)
  {
    /* We are breaking our own oplock, make sure it's us. */
    if(share_entry->op_port != oplock_port)
    {
      DEBUG(0,("request_oplock_break: corrupt share mode entry - pid = %d, port = %d \
should be %d\n", pid, share_entry->op_port, oplock_port));
      return False;
    }

    DEBUG(5,("request_oplock_break: breaking our own oplock\n"));

    /* Call oplock break direct. */
    return oplock_break(dev, inode, &share_entry->time);
  }

  /* We need to send a OPLOCK_BREAK_CMD message to the
     port in the share mode entry. */

  SSVAL(op_break_msg,UDP_MESSAGE_CMD_OFFSET,OPLOCK_BREAK_CMD);
  SIVAL(op_break_msg,OPLOCK_BREAK_PID_OFFSET,pid);
  SIVAL(op_break_msg,OPLOCK_BREAK_DEV_OFFSET,dev);
  SIVAL(op_break_msg,OPLOCK_BREAK_INODE_OFFSET,inode);
  SIVAL(op_break_msg,OPLOCK_BREAK_SEC_OFFSET,(uint32)share_entry->time.tv_sec);
  SIVAL(op_break_msg,OPLOCK_BREAK_USEC_OFFSET,(uint32)share_entry->time.tv_usec);

  /* set the address and port */
  bzero((char *)&addr_out,sizeof(addr_out));
  addr_out.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr_out.sin_port = htons( share_entry->op_port );
  addr_out.sin_family = AF_INET;
   
  DEBUG(3,("%s request_oplock_break: sending a oplock break message to pid %d on port %d \
for dev = %x, inode = %x\n", timestring(), share_entry->pid, share_entry->op_port, dev, inode));

  if(sendto(oplock_sock,op_break_msg,OPLOCK_BREAK_MSG_LEN,0,
         (struct sockaddr *)&addr_out,sizeof(addr_out)) < 0)
  {
    DEBUG(0,("%s request_oplock_break: failed when sending a oplock break message \
to pid %d on port %d for dev = %x, inode = %x. Error was %s\n",
         timestring(), share_entry->pid, share_entry->op_port, dev, inode,
         strerror(errno)));
    return False;
  }

  /*
   * Now we must await the oplock broken message coming back
   * from the target smbd process. Timeout if it fails to
   * return in (OPLOCK_BREAK_TIMEOUT + OPLOCK_BREAK_TIMEOUT_FUDGEFACTOR) seconds.
   * While we get messages that aren't ours, loop.
   */

  start_time = time(NULL);
  time_left = OPLOCK_BREAK_TIMEOUT+OPLOCK_BREAK_TIMEOUT_FUDGEFACTOR;

  while(time_left >= 0)
  {
    char op_break_reply[UDP_CMD_HEADER_LEN+OPLOCK_BREAK_MSG_LEN];
    int32 reply_msg_len;
    uint16 reply_from_port;
    char *reply_msg_start;

    if(receive_local_message(oplock_sock, op_break_reply, sizeof(op_break_reply),
               time_left ? time_left * 1000 : 1) == False)
    {
      if(smb_read_error == READ_TIMEOUT)
      {
        DEBUG(0,("%s request_oplock_break: no response received to oplock break request to \
pid %d on port %d for dev = %x, inode = %x\n", timestring(), share_entry->pid, 
                           share_entry->op_port, dev, inode));
        /*
         * This is a hack to make handling of failing clients more robust.
         * If a oplock break response message is not received in the timeout
         * period we may assume that the smbd servicing that client holding
         * the oplock has died and the client changes were lost anyway, so
         * we should continue to try and open the file.
         */
        break;
      }
      else
        DEBUG(0,("%s request_oplock_break: error in response received to oplock break request to \
pid %d on port %d for dev = %x, inode = %x. Error was (%s).\n", timestring, share_entry->pid, 
                         share_entry->op_port, dev, inode, strerror(errno)));
      return False;
    }

    reply_msg_len = IVAL(op_break_reply,UDP_CMD_LEN_OFFSET);
    reply_from_port = SVAL(op_break_reply,UDP_CMD_PORT_OFFSET);

    reply_msg_start = &op_break_reply[UDP_CMD_HEADER_LEN];

    if(reply_msg_len != OPLOCK_BREAK_MSG_LEN)
    {
      /* Ignore it. */
      DEBUG(0,("%s request_oplock_break: invalid message length received. Ignoring\n",
             timestring()));
      continue;
    }

    /*
     * Test to see if this is the reply we are awaiting.
     */

    if((SVAL(reply_msg_start,UDP_MESSAGE_CMD_OFFSET) & CMD_REPLY) &&
       (reply_from_port == share_entry->op_port) && 
       (memcmp(&reply_msg_start[OPLOCK_BREAK_PID_OFFSET], 
               &op_break_msg[OPLOCK_BREAK_PID_OFFSET],
               OPLOCK_BREAK_MSG_LEN - OPLOCK_BREAK_PID_OFFSET) == 0))
    {
      /*
       * This is the reply we've been waiting for.
       */
      break;
    }
    else
    {
      /*
       * This is another message - probably a break request.
       * Process it to prevent potential deadlock.
       * Note that the code in switch_message() prevents
       * us from recursing into here as any SMB requests
       * we might process that would cause another oplock
       * break request to be made will be queued.
       * JRA.
       */

      process_local_message(oplock_sock, op_break_reply, sizeof(op_break_reply));
    }

    time_left -= (time(NULL) - start_time);
  }

  DEBUG(3,("%s request_oplock_break: broke oplock.\n", timestring()));

  return True;
}

/****************************************************************************
Get the next SMB packet, doing the local message processing automatically.
****************************************************************************/

BOOL receive_next_smb(int smbfd, int oplockfd, char *inbuf, int bufsize, int timeout)
{
  BOOL got_smb = False;
  BOOL ret;

  do
  {
    ret = receive_message_or_smb(smbfd,oplockfd,inbuf,bufsize,
                                 timeout,&got_smb);

    if(ret && !got_smb)
    {
      /* Deal with oplock break requests from other smbd's. */
      process_local_message(oplock_sock, inbuf, bufsize);
      continue;
    }

    if(ret && (CVAL(inbuf,0) == 0x85))
    {
      /* Keepalive packet. */
      got_smb = False;
    }

  }
  while(ret && !got_smb);

  return ret;
}

/****************************************************************************
check if a snum is in use
****************************************************************************/
BOOL snum_used(int snum)
{
  int i;
  for (i=0;i<MAX_CONNECTIONS;i++)
    if (OPEN_CNUM(i) && (SNUM(i) == snum))
      return(True);
  return(False);
}

/****************************************************************************
  reload the services file
  **************************************************************************/
BOOL reload_services(BOOL test)
{
  BOOL ret;

  if (lp_loaded())
    {
      pstring fname;
      pstrcpy(fname,lp_configfile());
      if (file_exist(fname,NULL) && !strcsequal(fname,servicesf))
	{
	  pstrcpy(servicesf,fname);
	  test = False;
	}
    }

  reopen_logs();

  if (test && !lp_file_list_changed())
    return(True);

  lp_killunused(snum_used);

  ret = lp_load(servicesf,False);

  /* perhaps the config filename is now set */
  if (!test)
    reload_services(True);

  reopen_logs();

  load_interfaces();

  {
    extern int Client;
    if (Client != -1) {      
      set_socket_options(Client,"SO_KEEPALIVE");
      set_socket_options(Client,user_socket_options);
    }
  }

  reset_mangled_stack( lp_mangledstack() );

  /* this forces service parameters to be flushed */
  become_service(-1,True);

  return(ret);
}



/****************************************************************************
this prevents zombie child processes
****************************************************************************/
static int sig_hup(void)
{
  BlockSignals(True,SIGHUP);
  DEBUG(0,("Got SIGHUP\n"));
  reload_services(False);
#ifndef DONT_REINSTALL_SIG
  signal(SIGHUP,SIGNAL_CAST sig_hup);
#endif
  BlockSignals(False,SIGHUP);
  return(0);
}

/****************************************************************************
Setup the groups a user belongs to.
****************************************************************************/
int setup_groups(char *user, int uid, int gid, int *p_ngroups, 
		 int **p_igroups, gid_t **p_groups,
         int **p_attrs)
{
  if (-1 == initgroups(user,gid))
    {
      if (getuid() == 0)
	{
	  DEBUG(0,("Unable to initgroups!\n"));
	  if (gid < 0 || gid > 16000 || uid < 0 || uid > 16000)
	    DEBUG(0,("This is probably a problem with the account %s\n",user));
	}
    }
  else
    {
      int i,ngroups;
      int *igroups;
      int *attrs;
      gid_t grp = 0;
      ngroups = getgroups(0,&grp);
      if (ngroups <= 0)
        ngroups = 32;
      igroups = (int *)malloc(sizeof(int)*ngroups);
      attrs   = (int *)malloc(sizeof(int)*ngroups);
      for (i=0;i<ngroups;i++)
      {
        attrs  [i] = 0x7; /* XXXX don't know what NT user attributes are yet! */
        igroups[i] = 0x42424242;
      }
      ngroups = getgroups(ngroups,(gid_t *)igroups);

      if (igroups[0] == 0x42424242)
        ngroups = 0;

      *p_ngroups = ngroups;
      *p_attrs   = attrs;

      /* The following bit of code is very strange. It is due to the
         fact that some OSes use int* and some use gid_t* for
         getgroups, and some (like SunOS) use both, one in prototypes,
         and one in man pages and the actual code. Thus we detect it
         dynamically using some very ugly code */
      if (ngroups > 0)
        {
	  /* does getgroups return ints or gid_t ?? */
	  static BOOL groups_use_ints = True;

	  if (groups_use_ints && 
	      ngroups == 1 && 
	      SVAL(igroups,2) == 0x4242)
	    groups_use_ints = False;
	  
          for (i=0;groups_use_ints && i<ngroups;i++)
            if (igroups[i] == 0x42424242)
    	      groups_use_ints = False;
	      
          if (groups_use_ints)
          {
    	      *p_igroups = igroups;
    	      *p_groups = (gid_t *)igroups;	  
          }
          else
          {
	      gid_t *groups = (gid_t *)igroups;
	      igroups = (int *)malloc(sizeof(int)*ngroups);
	      for (i=0;i<ngroups;i++)
          {
	        igroups[i] = groups[i];
          }
	      *p_igroups = igroups;
	      *p_groups = (gid_t *)groups;
	    }
	}
      DEBUG(3,("%s is in %d groups\n",user,ngroups));
      for (i=0;i<ngroups;i++)
        DEBUG(3,("%d ",igroups[i]));
      DEBUG(3,("\n"));
    }
  return 0;
}

/****************************************************************************
  make a connection to a service
****************************************************************************/
int make_connection(char *service,char *user,char *password, int pwlen, char *dev,uint16 vuid)
{
  int cnum;
  int snum;
  struct passwd *pass = NULL;
  connection_struct *pcon;
  BOOL guest = False;
  BOOL force = False;
  static BOOL first_connection = True;

  strlower(service);

  snum = find_service(service);
  if (snum < 0)
    {
      if (strequal(service,"IPC$"))
	{	  
	  DEBUG(3,("%s refusing IPC connection\n",timestring()));
	  return(-3);
	}

      DEBUG(0,("%s %s (%s) couldn't find service %s\n",timestring(),remote_machine,client_addr(),service));      
      return(-2);
    }

  if (strequal(service,HOMES_NAME))
    {
      if (*user && Get_Pwnam(user,True))
	return(make_connection(user,user,password,pwlen,dev,vuid));

      if(lp_security() != SEC_SHARE)
      {
        if (validated_username(vuid))
        {
          pstrcpy(user,validated_username(vuid));
          return(make_connection(user,user,password,pwlen,dev,vuid));
        }
      }
      else
      {
        /*
         * Security = share. Try with sesssetup_user as the username.
         */
        if(*sesssetup_user)
        {
          pstrcpy(user,sesssetup_user);
          return(make_connection(user,user,password,pwlen,dev,vuid));
        }
      }
    }

  if (!lp_snum_ok(snum) || !check_access(snum)) {    
    return(-4);
  }

  /* you can only connect to the IPC$ service as an ipc device */
  if (strequal(service,"IPC$"))
    pstrcpy(dev,"IPC");

  if (*dev == '?' || !*dev)
    {
      if (lp_print_ok(snum))
	pstrcpy(dev,"LPT1:");
      else
	pstrcpy(dev,"A:");
    }

  /* if the request is as a printer and you can't print then refuse */
  strupper(dev);
  if (!lp_print_ok(snum) && (strncmp(dev,"LPT",3) == 0)) {
    DEBUG(1,("Attempt to connect to non-printer as a printer\n"));
    return(-6);
  }

  /* lowercase the user name */
  strlower(user);

  /* add it as a possible user name */
  add_session_user(service);

  /* shall we let them in? */
  if (!authorise_login(snum,user,password,pwlen,&guest,&force,vuid))
    {
      DEBUG(2,("%s invalid username/password for %s\n",timestring(),service));
      return(-1);
    }
  
  cnum = find_free_connection(str_checksum(service) + str_checksum(user));
  if (cnum < 0)
    {
      DEBUG(0,("%s couldn't find free connection\n",timestring()));      
      return(-1);
    }

  pcon = &Connections[cnum];
  bzero((char *)pcon,sizeof(*pcon));

  /* find out some info about the user */
  pass = Get_Pwnam(user,True);

  if (pass == NULL)
    {
      DEBUG(0,("%s couldn't find account %s\n",timestring(),user)); 
      return(-7);
    }

  pcon->read_only = lp_readonly(snum);

  {
    pstring list;
    StrnCpy(list,lp_readlist(snum),sizeof(pstring)-1);
    string_sub(list,"%S",service);

    if (user_in_list(user,list))
      pcon->read_only = True;

    StrnCpy(list,lp_writelist(snum),sizeof(pstring)-1);
    string_sub(list,"%S",service);

    if (user_in_list(user,list))
      pcon->read_only = False;    
  }

  /* admin user check */

  /* JRA - original code denied admin user if the share was
     marked read_only. Changed as I don't think this is needed,
     but old code left in case there is a problem here.
   */
  if (user_in_list(user,lp_admin_users(snum)) 
#if 0
      && !pcon->read_only)
#else
      )
#endif
    {
      pcon->admin_user = True;
      DEBUG(0,("%s logged in as admin user (root privileges)\n",user));
    }
  else
    pcon->admin_user = False;
    
  pcon->force_user = force;
  pcon->vuid = vuid;
  pcon->uid = pass->pw_uid;
  pcon->gid = pass->pw_gid;
  pcon->num_files_open = 0;
  pcon->lastused = time(NULL);
  pcon->service = snum;
  pcon->used = True;
  pcon->printer = (strncmp(dev,"LPT",3) == 0);
  pcon->ipc = (strncmp(dev,"IPC",3) == 0);
  pcon->dirptr = NULL;
  pcon->veto_list = NULL;
  pcon->hide_list = NULL;
  pcon->veto_oplock_list = NULL;
  string_set(&pcon->dirpath,"");
  string_set(&pcon->user,user);

#if HAVE_GETGRNAM 
  if (*lp_force_group(snum))
    {
      struct group *gptr;
      pstring gname;

      StrnCpy(gname,lp_force_group(snum),sizeof(pstring)-1);
      /* default service may be a group name 		*/
      string_sub(gname,"%S",service);
      gptr = (struct group *)getgrnam(gname);

      if (gptr)
	{
	  pcon->gid = gptr->gr_gid;
	  DEBUG(3,("Forced group %s\n",gname));
	}
      else
	DEBUG(1,("Couldn't find group %s\n",gname));
    }
#endif

  if (*lp_force_user(snum))
    {
      struct passwd *pass2;
      fstring fuser;
      fstrcpy(fuser,lp_force_user(snum));
      pass2 = (struct passwd *)Get_Pwnam(fuser,True);
      if (pass2)
	{
	  pcon->uid = pass2->pw_uid;
	  string_set(&pcon->user,fuser);
	  fstrcpy(user,fuser);
	  pcon->force_user = True;
	  DEBUG(3,("Forced user %s\n",fuser));	  
	}
      else
	DEBUG(1,("Couldn't find user %s\n",fuser));
    }

  {
    pstring s;
    pstrcpy(s,lp_pathname(snum));
    standard_sub(cnum,s);
    string_set(&pcon->connectpath,s);
    DEBUG(3,("Connect path is %s\n",s));
  }

  /* groups stuff added by ih */
  pcon->ngroups = 0;
  pcon->igroups = NULL;
  pcon->groups = NULL;
  pcon->attrs = NULL;

  if (!IS_IPC(cnum))
    {
      /* Find all the groups this uid is in and store them. Used by become_user() */
      setup_groups(pcon->user,pcon->uid,pcon->gid,
                  &pcon->ngroups,&pcon->igroups,&pcon->groups,&pcon->attrs);
      
      /* check number of connections */
      if (!claim_connection(cnum,
			    lp_servicename(SNUM(cnum)),
			    lp_max_connections(SNUM(cnum)),False))
	{
	  DEBUG(1,("too many connections - rejected\n"));
	  return(-8);
	}  

      if (lp_status(SNUM(cnum)))
	claim_connection(cnum,"STATUS.",MAXSTATUS,first_connection);

      first_connection = False;
    } /* IS_IPC */

  pcon->open = True;

  /* execute any "root preexec = " line */
  if (*lp_rootpreexec(SNUM(cnum)))
    {
      pstring cmd;
      pstrcpy(cmd,lp_rootpreexec(SNUM(cnum)));
      standard_sub(cnum,cmd);
      DEBUG(5,("cmd=%s\n",cmd));
      smbrun(cmd,NULL,False);
    }

  if (!become_user(&Connections[cnum], cnum,pcon->vuid))
    {
      DEBUG(0,("Can't become connected user!\n"));
      pcon->open = False;
      if (!IS_IPC(cnum)) {
	yield_connection(cnum,
			 lp_servicename(SNUM(cnum)),
			 lp_max_connections(SNUM(cnum)));
	if (lp_status(SNUM(cnum))) yield_connection(cnum,"STATUS.",MAXSTATUS);
      }
      return(-1);
    }

  if (ChDir(pcon->connectpath) != 0)
    {
      DEBUG(0,("Can't change directory to %s (%s)\n",
	       pcon->connectpath,strerror(errno)));
      pcon->open = False;
      unbecome_user();
      if (!IS_IPC(cnum)) {
	yield_connection(cnum,
			 lp_servicename(SNUM(cnum)),
			 lp_max_connections(SNUM(cnum)));
	if (lp_status(SNUM(cnum))) yield_connection(cnum,"STATUS.",MAXSTATUS);
      }
      return(-5);      
    }

  string_set(&pcon->origpath,pcon->connectpath);

#if SOFTLINK_OPTIMISATION
  /* resolve any soft links early */
  {
    pstring s;
    pstrcpy(s,pcon->connectpath);
    GetWd(s);
    string_set(&pcon->connectpath,s);
    ChDir(pcon->connectpath);
  }
#endif

  num_connections_open++;
  add_session_user(user);
  
  /* execute any "preexec = " line */
  if (*lp_preexec(SNUM(cnum)))
    {
      pstring cmd;
      pstrcpy(cmd,lp_preexec(SNUM(cnum)));
      standard_sub(cnum,cmd);
      smbrun(cmd,NULL,False);
    }
  
  /* we've finished with the sensitive stuff */
  unbecome_user();

  /* Add veto/hide lists */
  if (!IS_IPC(cnum) && !IS_PRINT(cnum))
  {
    set_namearray( &pcon->veto_list, lp_veto_files(SNUM(cnum)));
    set_namearray( &pcon->hide_list, lp_hide_files(SNUM(cnum)));
    set_namearray( &pcon->veto_oplock_list, lp_veto_oplocks(SNUM(cnum)));
  }

  {
    DEBUG(IS_IPC(cnum)?3:1,("%s %s (%s) connect to service %s as user %s (uid=%d,gid=%d) (pid %d)\n",
			    timestring(),
			    remote_machine,
			    client_addr(),
			    lp_servicename(SNUM(cnum)),user,
			    pcon->uid,
			    pcon->gid,
			    (int)getpid()));
  }

  return(cnum);
}

/****************************************************************************
  Attempt to break an oplock on a file (if oplocked).
  Returns True if the file was closed as a result of
  the oplock break, False otherwise.
  Used as a last ditch attempt to free a space in the 
  file table when we have run out.
****************************************************************************/

static BOOL attempt_close_oplocked_file(files_struct *fp)
{

  DEBUG(5,("attempt_close_oplocked_file: checking file %s.\n", fp->name));

  if (fp->open && fp->granted_oplock && !fp->sent_oplock_break) {

    /* Try and break the oplock. */
    file_fd_struct *fsp = fp->fd_ptr;
    if(oplock_break( fsp->dev, fsp->inode, &fp->open_time)) {
      if(!fp->open) /* Did the oplock break close the file ? */
        return True;
    }
  }

  return False;
}

/****************************************************************************
  find first available file slot
****************************************************************************/
int find_free_file(void )
{
	int i;
	static int first_file;

	/* we want to give out file handles differently on each new
	   connection because of a common bug in MS clients where they try to
	   reuse a file descriptor from an earlier smb connection. This code
	   increases the chance that the errant client will get an error rather
	   than causing corruption */
	if (first_file == 0) {
		first_file = (getpid() ^ (int)time(NULL)) % MAX_OPEN_FILES;
		if (first_file == 0) first_file = 1;
	}

	if (first_file >= MAX_OPEN_FILES)
		first_file = 1;

	for (i=first_file;i<MAX_OPEN_FILES;i++)
		if (!Files[i].open && !Files[i].reserved) {
			memset(&Files[i], 0, sizeof(Files[i]));
			first_file = i+1;
			Files[i].reserved = True;
			return(i);
		}

	/* returning a file handle of 0 is a bad idea - so we start at 1 */
	for (i=1;i<first_file;i++)
		if (!Files[i].open && !Files[i].reserved) {
			memset(&Files[i], 0, sizeof(Files[i]));
			first_file = i+1;
			Files[i].reserved = True;
			return(i);
		}

        /* 
         * Before we give up, go through the open files 
         * and see if there are any files opened with a
         * batch oplock. If so break the oplock and then
         * re-use that entry (if it becomes closed).
         * This may help as NT/95 clients tend to keep
         * files batch oplocked for quite a long time
         * after they have finished with them.
         */
        for (i=first_file;i<MAX_OPEN_FILES;i++) {
          if(attempt_close_oplocked_file( &Files[i])) {
            memset(&Files[i], 0, sizeof(Files[i]));
            first_file = i+1;
            Files[i].reserved = True;
            return(i);
          }
        }

        for (i=1;i<MAX_OPEN_FILES;i++) {
          if(attempt_close_oplocked_file( &Files[i])) {
            memset(&Files[i], 0, sizeof(Files[i]));
            first_file = i+1;
            Files[i].reserved = True;
            return(i);
          }
        }

	DEBUG(1,("ERROR! Out of file structures - perhaps increase MAX_OPEN_FILES?\n"));
	return(-1);
}

/****************************************************************************
  find first available connection slot, starting from a random position.
The randomisation stops problems with the server dieing and clients
thinking the server is still available.
****************************************************************************/
static int find_free_connection(int hash )
{
  int i;
  BOOL used=False;
  hash = (hash % (MAX_CONNECTIONS-2))+1;

 again:

  for (i=hash+1;i!=hash;)
    {
      if (!Connections[i].open && Connections[i].used == used) 
	{
	  DEBUG(3,("found free connection number %d\n",i));
	  return(i);
	}
      i++;
      if (i == MAX_CONNECTIONS)
	i = 1;
    }

  if (!used)
    {
      used = !used;
      goto again;
    }

  DEBUG(1,("ERROR! Out of connection structures\n"));
  return(-1);
}


/****************************************************************************
reply for the core protocol
****************************************************************************/
int reply_corep(char *outbuf)
{
  int outsize = set_message(outbuf,1,0,True);

  Protocol = PROTOCOL_CORE;

  return outsize;
}


/****************************************************************************
reply for the coreplus protocol
****************************************************************************/
int reply_coreplus(char *outbuf)
{
  int raw = (lp_readraw()?1:0) | (lp_writeraw()?2:0);
  int outsize = set_message(outbuf,13,0,True);
  SSVAL(outbuf,smb_vwv5,raw); /* tell redirector we support
				 readbraw and writebraw (possibly) */
  CVAL(outbuf,smb_flg) = 0x81; /* Reply, SMBlockread, SMBwritelock supported */
  SSVAL(outbuf,smb_vwv1,0x1); /* user level security, don't encrypt */	

  Protocol = PROTOCOL_COREPLUS;

  return outsize;
}


/****************************************************************************
reply for the lanman 1.0 protocol
****************************************************************************/
int reply_lanman1(char *outbuf)
{
  int raw = (lp_readraw()?1:0) | (lp_writeraw()?2:0);
  int secword=0;
  BOOL doencrypt = SMBENCRYPT();
  time_t t = time(NULL);

  if (lp_security()>=SEC_USER) secword |= 1;
  if (doencrypt) secword |= 2;

  set_message(outbuf,13,doencrypt?8:0,True);
  SSVAL(outbuf,smb_vwv1,secword); 
  /* Create a token value and add it to the outgoing packet. */
  if (doencrypt) 
    generate_next_challenge(smb_buf(outbuf));

  Protocol = PROTOCOL_LANMAN1;

  CVAL(outbuf,smb_flg) = 0x81; /* Reply, SMBlockread, SMBwritelock supported */
  SSVAL(outbuf,smb_vwv2,max_recv);
  SSVAL(outbuf,smb_vwv3,lp_maxmux()); /* maxmux */
  SSVAL(outbuf,smb_vwv4,1);
  SSVAL(outbuf,smb_vwv5,raw); /* tell redirector we support
				 readbraw writebraw (possibly) */
  SIVAL(outbuf,smb_vwv6,getpid());
  SSVAL(outbuf,smb_vwv10, TimeDiff(t)/60);

  put_dos_date(outbuf,smb_vwv8,t);

  return (smb_len(outbuf)+4);
}


/****************************************************************************
reply for the lanman 2.0 protocol
****************************************************************************/
int reply_lanman2(char *outbuf)
{
  int raw = (lp_readraw()?1:0) | (lp_writeraw()?2:0);
  int secword=0;
  BOOL doencrypt = SMBENCRYPT();
  time_t t = time(NULL);
  struct cli_state *cli = NULL;
  char cryptkey[8];
  char crypt_len = 0;

  if (lp_security() == SEC_SERVER) {
	  cli = server_cryptkey();
  }

  if (cli) {
	  DEBUG(3,("using password server validation\n"));
	  doencrypt = ((cli->sec_mode & 2) != 0);
  }

  if (lp_security()>=SEC_USER) secword |= 1;
  if (doencrypt) secword |= 2;

  if (doencrypt) {
	  crypt_len = 8;
	  if (!cli) {
		  generate_next_challenge(cryptkey);
	  } else {
		  memcpy(cryptkey, cli->cryptkey, 8);
		  set_challenge(cli->cryptkey);
	  }
  }

  set_message(outbuf,13,crypt_len,True);
  SSVAL(outbuf,smb_vwv1,secword); 
  SIVAL(outbuf,smb_vwv6,getpid());
  if (doencrypt) 
	  memcpy(smb_buf(outbuf), cryptkey, 8);

  Protocol = PROTOCOL_LANMAN2;

  CVAL(outbuf,smb_flg) = 0x81; /* Reply, SMBlockread, SMBwritelock supported */
  SSVAL(outbuf,smb_vwv2,max_recv);
  SSVAL(outbuf,smb_vwv3,lp_maxmux()); 
  SSVAL(outbuf,smb_vwv4,1);
  SSVAL(outbuf,smb_vwv5,raw); /* readbraw and/or writebraw */
  SSVAL(outbuf,smb_vwv10, TimeDiff(t)/60);
  put_dos_date(outbuf,smb_vwv8,t);

  return (smb_len(outbuf)+4);
}


/****************************************************************************
reply for the nt protocol
****************************************************************************/
int reply_nt1(char *outbuf)
{
  /* dual names + lock_and_read + nt SMBs + remote API calls */
  int capabilities = CAP_NT_FIND|CAP_LOCK_AND_READ;
/*
  other valid capabilities which we may support at some time...
                     CAP_LARGE_FILES|CAP_NT_SMBS|CAP_RPC_REMOTE_APIS;
                     CAP_LARGE_READX|CAP_STATUS32|CAP_LEVEL_II_OPLOCKS;
 */

  int secword=0;
  BOOL doencrypt = SMBENCRYPT();
  time_t t = time(NULL);
  int data_len;
  struct cli_state *cli = NULL;
  char cryptkey[8];
  char crypt_len = 0;

  if (lp_security() == SEC_SERVER) {
	  cli = server_cryptkey();
  }

  if (cli) {
	  DEBUG(3,("using password server validation\n"));
	  doencrypt = ((cli->sec_mode & 2) != 0);
  }

  if (doencrypt) {
	  crypt_len = 8;
	  if (!cli) {
		  generate_next_challenge(cryptkey);
	  } else {
		  memcpy(cryptkey, cli->cryptkey, 8);
		  set_challenge(cli->cryptkey);
	  }
  }

  if (lp_readraw() && lp_writeraw()) {
	  capabilities |= CAP_RAW_MODE;
  }

  if (lp_security() >= SEC_USER) secword |= 1;
  if (doencrypt) secword |= 2;

  /* decide where (if) to put the encryption challenge, and
     follow it with the OEM'd domain name
   */
  data_len = crypt_len + strlen(myworkgroup) + 1;

  set_message(outbuf,17,data_len,True);
  pstrcpy(smb_buf(outbuf)+crypt_len, myworkgroup);

  CVAL(outbuf,smb_vwv1) = secword;
  SSVALS(outbuf,smb_vwv16+1,crypt_len);
  if (doencrypt) 
	  memcpy(smb_buf(outbuf), cryptkey, 8);

  Protocol = PROTOCOL_NT1;

  SSVAL(outbuf,smb_vwv1+1,lp_maxmux()); /* maxmpx */
  SSVAL(outbuf,smb_vwv2+1,1); /* num vcs */
  SIVAL(outbuf,smb_vwv3+1,0xffff); /* max buffer. LOTS! */
  SIVAL(outbuf,smb_vwv5+1,0xffff); /* raw size. LOTS! */
  SIVAL(outbuf,smb_vwv7+1,getpid()); /* session key */
  SIVAL(outbuf,smb_vwv9+1,capabilities); /* capabilities */
  put_long_date(outbuf+smb_vwv11+1,t);
  SSVALS(outbuf,smb_vwv15+1,TimeDiff(t)/60);
  SSVAL(outbuf,smb_vwv17,data_len); /* length of challenge+domain strings */

  return (smb_len(outbuf)+4);
}

/* these are the protocol lists used for auto architecture detection:

WinNT 3.51:
protocol [PC NETWORK PROGRAM 1.0]
protocol [XENIX CORE]
protocol [MICROSOFT NETWORKS 1.03]
protocol [LANMAN1.0]
protocol [Windows for Workgroups 3.1a]
protocol [LM1.2X002]
protocol [LANMAN2.1]
protocol [NT LM 0.12]

Win95:
protocol [PC NETWORK PROGRAM 1.0]
protocol [XENIX CORE]
protocol [MICROSOFT NETWORKS 1.03]
protocol [LANMAN1.0]
protocol [Windows for Workgroups 3.1a]
protocol [LM1.2X002]
protocol [LANMAN2.1]
protocol [NT LM 0.12]

OS/2:
protocol [PC NETWORK PROGRAM 1.0]
protocol [XENIX CORE]
protocol [LANMAN1.0]
protocol [LM1.2X002]
protocol [LANMAN2.1]
*/

/*
  * Modified to recognize the architecture of the remote machine better.
  *
  * This appears to be the matrix of which protocol is used by which
  * MS product.
       Protocol                       WfWg    Win95   WinNT  OS/2
       PC NETWORK PROGRAM 1.0          1       1       1      1
       XENIX CORE                                      2      2
       MICROSOFT NETWORKS 3.0          2       2       
       DOS LM1.2X002                   3       3       
       MICROSOFT NETWORKS 1.03                         3
       DOS LANMAN2.1                   4       4       
       LANMAN1.0                                       4      3
       Windows for Workgroups 3.1a     5       5       5
       LM1.2X002                                       6      4
       LANMAN2.1                                       7      5
       NT LM 0.12                              6       8
  *
  *  tim@fsg.com 09/29/95
  */
  
#define ARCH_WFWG     0x3      /* This is a fudge because WfWg is like Win95 */
#define ARCH_WIN95    0x2
#define	ARCH_OS2      0xC      /* Again OS/2 is like NT */
#define ARCH_WINNT    0x8
#define ARCH_SAMBA    0x10
 
#define ARCH_ALL      0x1F
 
/* List of supported protocols, most desired first */
struct {
  char *proto_name;
  char *short_name;
  int (*proto_reply_fn)(char *);
  int protocol_level;
} supported_protocols[] = {
  {"NT LANMAN 1.0",           "NT1",      reply_nt1,      PROTOCOL_NT1},
  {"NT LM 0.12",              "NT1",      reply_nt1,      PROTOCOL_NT1},
  {"LM1.2X002",               "LANMAN2",  reply_lanman2,  PROTOCOL_LANMAN2},
  {"Samba",                   "LANMAN2",  reply_lanman2,  PROTOCOL_LANMAN2},
  {"DOS LM1.2X002",           "LANMAN2",  reply_lanman2,  PROTOCOL_LANMAN2},
  {"LANMAN1.0",               "LANMAN1",  reply_lanman1,  PROTOCOL_LANMAN1},
  {"MICROSOFT NETWORKS 3.0",  "LANMAN1",  reply_lanman1,  PROTOCOL_LANMAN1},
  {"MICROSOFT NETWORKS 1.03", "COREPLUS", reply_coreplus, PROTOCOL_COREPLUS},
  {"PC NETWORK PROGRAM 1.0",  "CORE",     reply_corep,    PROTOCOL_CORE}, 
  {NULL,NULL},
};


/****************************************************************************
  reply to a negprot
****************************************************************************/
static int reply_negprot(char *inbuf,char *outbuf, int size, int bufsize)
{
  int outsize = set_message(outbuf,1,0,True);
  int Index=0;
  int choice= -1;
  int protocol;
  char *p;
  int bcc = SVAL(smb_buf(inbuf),-2);
  int arch = ARCH_ALL;

  p = smb_buf(inbuf)+1;
  while (p < (smb_buf(inbuf) + bcc))
    { 
      Index++;
      DEBUG(3,("Requested protocol [%s]\n",p));
      if (strcsequal(p,"Windows for Workgroups 3.1a"))
	arch &= ( ARCH_WFWG | ARCH_WIN95 | ARCH_WINNT );
      else if (strcsequal(p,"DOS LM1.2X002"))
	arch &= ( ARCH_WFWG | ARCH_WIN95 );
      else if (strcsequal(p,"DOS LANMAN2.1"))
	arch &= ( ARCH_WFWG | ARCH_WIN95 );
      else if (strcsequal(p,"NT LM 0.12"))
	arch &= ( ARCH_WIN95 | ARCH_WINNT );
      else if (strcsequal(p,"LANMAN2.1"))
	arch &= ( ARCH_WINNT | ARCH_OS2 );
      else if (strcsequal(p,"LM1.2X002"))
	arch &= ( ARCH_WINNT | ARCH_OS2 );
      else if (strcsequal(p,"MICROSOFT NETWORKS 1.03"))
	arch &= ARCH_WINNT;
      else if (strcsequal(p,"XENIX CORE"))
	arch &= ( ARCH_WINNT | ARCH_OS2 );
      else if (strcsequal(p,"Samba")) {
	arch = ARCH_SAMBA;
	break;
      }
 
      p += strlen(p) + 2;
    }
    
  switch ( arch ) {
  case ARCH_SAMBA:
    set_remote_arch(RA_SAMBA);
    break;
  case ARCH_WFWG:
    set_remote_arch(RA_WFWG);
    break;
  case ARCH_WIN95:
    set_remote_arch(RA_WIN95);
    break;
  case ARCH_WINNT:
    set_remote_arch(RA_WINNT);
    break;
  case ARCH_OS2:
    set_remote_arch(RA_OS2);
    break;
  default:
    set_remote_arch(RA_UNKNOWN);
    break;
  }
 
  /* possibly reload - change of architecture */
  reload_services(True);      
    
  /* a special case to stop password server loops */
  if (Index == 1 && strequal(remote_machine,myhostname) && 
      lp_security()==SEC_SERVER)
    exit_server("Password server loop!");
  
  /* Check for protocols, most desirable first */
  for (protocol = 0; supported_protocols[protocol].proto_name; protocol++)
    {
      p = smb_buf(inbuf)+1;
      Index = 0;
      if (lp_maxprotocol() >= supported_protocols[protocol].protocol_level)
	while (p < (smb_buf(inbuf) + bcc))
	  { 
	    if (strequal(p,supported_protocols[protocol].proto_name))
	      choice = Index;
	    Index++;
	    p += strlen(p) + 2;
	  }
      if(choice != -1)
	break;
    }
  
  SSVAL(outbuf,smb_vwv0,choice);
  if(choice != -1) {
    extern fstring remote_proto;
    fstrcpy(remote_proto,supported_protocols[protocol].short_name);
    reload_services(True);          
    outsize = supported_protocols[protocol].proto_reply_fn(outbuf);
    DEBUG(3,("Selected protocol %s\n",supported_protocols[protocol].proto_name));
  }
  else {
    DEBUG(0,("No protocol supported !\n"));
  }
  SSVAL(outbuf,smb_vwv0,choice);
  
  DEBUG(5,("%s negprot index=%d\n",timestring(),choice));

  return(outsize);
}


/****************************************************************************
close all open files for a connection
****************************************************************************/
static void close_open_files(int cnum)
{
  int i;
  for (i=0;i<MAX_OPEN_FILES;i++)
    if( Files[i].cnum == cnum && Files[i].open) {
      close_file(i,False);
    }
}



/****************************************************************************
close a cnum
****************************************************************************/
void close_cnum(int cnum, uint16 vuid)
{
  DirCacheFlush(SNUM(cnum));

  unbecome_user();

  if (!OPEN_CNUM(cnum))
    {
      DEBUG(0,("Can't close cnum %d\n",cnum));
      return;
    }

  DEBUG(IS_IPC(cnum)?3:1,("%s %s (%s) closed connection to service %s\n",
			  timestring(),
			  remote_machine,client_addr(),
			  lp_servicename(SNUM(cnum))));

  yield_connection(cnum,
		   lp_servicename(SNUM(cnum)),
		   lp_max_connections(SNUM(cnum)));

  if (lp_status(SNUM(cnum)))
    yield_connection(cnum,"STATUS.",MAXSTATUS);

  close_open_files(cnum);
  dptr_closecnum(cnum);

  /* execute any "postexec = " line */
  if (*lp_postexec(SNUM(cnum)) && become_user(&Connections[cnum], cnum,vuid))
    {
      pstring cmd;
      pstrcpy(cmd,lp_postexec(SNUM(cnum)));
      standard_sub(cnum,cmd);
      smbrun(cmd,NULL,False);
      unbecome_user();
    }

  unbecome_user();
  /* execute any "root postexec = " line */
  if (*lp_rootpostexec(SNUM(cnum)))
    {
      pstring cmd;
      pstrcpy(cmd,lp_rootpostexec(SNUM(cnum)));
      standard_sub(cnum,cmd);
      smbrun(cmd,NULL,False);
    }

  Connections[cnum].open = False;
  num_connections_open--;
  if (Connections[cnum].ngroups && Connections[cnum].groups)
    {
      if (Connections[cnum].igroups != (int *)Connections[cnum].groups)
	free(Connections[cnum].groups);
      free(Connections[cnum].igroups);
      Connections[cnum].groups = NULL;
      Connections[cnum].igroups = NULL;
      Connections[cnum].ngroups = 0;
    }

  free_namearray(Connections[cnum].veto_list);
  free_namearray(Connections[cnum].hide_list);
  free_namearray(Connections[cnum].veto_oplock_list);

  string_set(&Connections[cnum].user,"");
  string_set(&Connections[cnum].dirpath,"");
  string_set(&Connections[cnum].connectpath,"");
}


/****************************************************************************
simple routines to do connection counting
****************************************************************************/
BOOL yield_connection(int cnum,char *name,int max_connections)
{
  struct connect_record crec;
  pstring fname;
  FILE *f;
  int mypid = getpid();
  int i;

  DEBUG(3,("Yielding connection to %d %s\n",cnum,name));

  if (max_connections <= 0)
    return(True);

  bzero(&crec,sizeof(crec));

  pstrcpy(fname,lp_lockdir());
  standard_sub(cnum,fname);
  trim_string(fname,"","/");

  pstrcat(fname,"/");
  pstrcat(fname,name);
  pstrcat(fname,".LCK");

  f = fopen(fname,"r+");
  if (!f)
    {
      DEBUG(2,("Couldn't open lock file %s (%s)\n",fname,strerror(errno)));
      return(False);
    }

  fseek(f,0,SEEK_SET);

  /* find a free spot */
  for (i=0;i<max_connections;i++)
    {
      if (fread(&crec,sizeof(crec),1,f) != 1)
	{
	  DEBUG(2,("Entry not found in lock file %s\n",fname));
	  fclose(f);
	  return(False);
	}
      if (crec.pid == mypid && crec.cnum == cnum)
	break;
    }

  if (crec.pid != mypid || crec.cnum != cnum)
    {
      fclose(f);
      DEBUG(2,("Entry not found in lock file %s\n",fname));
      return(False);
    }

  bzero((void *)&crec,sizeof(crec));
  
  /* remove our mark */
  if (fseek(f,i*sizeof(crec),SEEK_SET) != 0 ||
      fwrite(&crec,sizeof(crec),1,f) != 1)
    {
      DEBUG(2,("Couldn't update lock file %s (%s)\n",fname,strerror(errno)));
      fclose(f);
      return(False);
    }

  DEBUG(3,("Yield successful\n"));

  fclose(f);
  return(True);
}


/****************************************************************************
simple routines to do connection counting
****************************************************************************/
BOOL claim_connection(int cnum,char *name,int max_connections,BOOL Clear)
{
  struct connect_record crec;
  pstring fname;
  FILE *f;
  int snum = SNUM(cnum);
  int i,foundi= -1;
  int total_recs;

  if (max_connections <= 0)
    return(True);

  DEBUG(5,("trying claim %s %s %d\n",lp_lockdir(),name,max_connections));

  pstrcpy(fname,lp_lockdir());
  standard_sub(cnum,fname);
  trim_string(fname,"","/");

  if (!directory_exist(fname,NULL))
    mkdir(fname,0755);

  pstrcat(fname,"/");
  pstrcat(fname,name);
  pstrcat(fname,".LCK");

  if (!file_exist(fname,NULL))
    {
      int oldmask = umask(022);
      f = fopen(fname,"w");
      if (f) fclose(f);
      umask(oldmask);
    }

  total_recs = file_size(fname) / sizeof(crec);

  f = fopen(fname,"r+");

  if (!f)
    {
      DEBUG(1,("couldn't open lock file %s\n",fname));
      return(False);
    }

  /* find a free spot */
  for (i=0;i<max_connections;i++)
    {

      if (i>=total_recs || 
	  fseek(f,i*sizeof(crec),SEEK_SET) != 0 ||
	  fread(&crec,sizeof(crec),1,f) != 1)
	{
	  if (foundi < 0) foundi = i;
	  break;
	}

      if (Clear && crec.pid && !process_exists(crec.pid))
	{
	  fseek(f,i*sizeof(crec),SEEK_SET);
	  bzero((void *)&crec,sizeof(crec));
	  fwrite(&crec,sizeof(crec),1,f);
	  if (foundi < 0) foundi = i;
	  continue;
	}
      if (foundi < 0 && (!crec.pid || !process_exists(crec.pid)))
	{
	  foundi=i;
	  if (!Clear) break;
	}
    }  

  if (foundi < 0)
    {
      DEBUG(3,("no free locks in %s\n",fname));
      fclose(f);
      return(False);
    }      

  /* fill in the crec */
  bzero((void *)&crec,sizeof(crec));
  crec.magic = 0x280267;
  crec.pid = getpid();
  crec.cnum = cnum;
  crec.uid = Connections[cnum].uid;
  crec.gid = Connections[cnum].gid;
  StrnCpy(crec.name,lp_servicename(snum),sizeof(crec.name)-1);
  crec.start = time(NULL);

  StrnCpy(crec.machine,remote_machine,sizeof(crec.machine)-1);
  StrnCpy(crec.addr,client_addr(),sizeof(crec.addr)-1);
  
  /* make our mark */
  if (fseek(f,foundi*sizeof(crec),SEEK_SET) != 0 ||
      fwrite(&crec,sizeof(crec),1,f) != 1)
    {
      fclose(f);
      return(False);
    }

  fclose(f);
  return(True);
}

#if DUMP_CORE
/*******************************************************************
prepare to dump a core file - carefully!
********************************************************************/
static BOOL dump_core(void)
{
  char *p;
  pstring dname;
  pstrcpy(dname,debugf);
  if ((p=strrchr(dname,'/'))) *p=0;
  pstrcat(dname,"/corefiles");
  mkdir(dname,0700);
  sys_chown(dname,getuid(),getgid());
  chmod(dname,0700);
  if (chdir(dname)) return(False);
  umask(~(0700));

#ifndef NO_GETRLIMIT
#ifdef RLIMIT_CORE
  {
    struct rlimit rlp;
    getrlimit(RLIMIT_CORE, &rlp);
    rlp.rlim_cur = MAX(4*1024*1024,rlp.rlim_cur);
    setrlimit(RLIMIT_CORE, &rlp);
    getrlimit(RLIMIT_CORE, &rlp);
    DEBUG(3,("Core limits now %d %d\n",rlp.rlim_cur,rlp.rlim_max));
  }
#endif
#endif


  DEBUG(0,("Dumping core in %s\n",dname));
  return(True);
}
#endif

/****************************************************************************
exit the server
****************************************************************************/
void exit_server(char *reason)
{
  static int firsttime=1;
  int i;

  if (!firsttime) exit(0);
  firsttime = 0;

  unbecome_user();
  DEBUG(2,("Closing connections\n"));
  for (i=0;i<MAX_CONNECTIONS;i++)
    if (Connections[i].open)
      close_cnum(i,(uint16)-1);
#ifdef DFS_AUTH
  if (dcelogin_atmost_once)
    dfs_unlogin();
#endif
  if (!reason) {   
    int oldlevel = DEBUGLEVEL;
    DEBUGLEVEL = 10;
    DEBUG(0,("Last message was %s\n",smb_fn_name(last_message)));
    if (last_inbuf)
      show_msg(last_inbuf);
    DEBUGLEVEL = oldlevel;
    DEBUG(0,("===============================================================\n"));
#if DUMP_CORE
    if (dump_core()) return;
#endif
  }    

  locking_end();

  DEBUG(3,("%s Server exit  (%s)\n",timestring(),reason?reason:""));
  exit(0);
}

/****************************************************************************
do some standard substitutions in a string
****************************************************************************/
void standard_sub(int cnum,char *str)
{
  if (VALID_CNUM(cnum)) {
    char *p, *s, *home;

    for ( s=str ; (p=strchr(s, '%')) != NULL ; s=p ) {
      switch (*(p+1)) {
        case 'H' : if ((home = get_home_dir(Connections[cnum].user))!=NULL)
                     string_sub(p,"%H",home);
                   else
                     p += 2;
                   break;
        case 'P' : string_sub(p,"%P",Connections[cnum].connectpath); break;
        case 'S' : string_sub(p,"%S",lp_servicename(Connections[cnum].service)); break;
        case 'g' : string_sub(p,"%g",gidtoname(Connections[cnum].gid)); break;
        case 'u' : string_sub(p,"%u",Connections[cnum].user); break;
	/* 
         * Patch from jkf@soton.ac.uk
         * Left the %N (NIS server name) in standard_sub_basic as it
         * is a feature for logon servers, hence uses the username.
	 * The %p (NIS server path) code is here as it is used
	 * instead of the default "path =" string in [homes] and so
	 * needs the service name, not the username. 
         */
	case 'p' : string_sub(p,"%p",automount_path(lp_servicename(Connections[cnum].service))); break;
        case '\0' : p++; break; /* don't run off the end of the string */
        default  : p+=2; break;
      }
    }
  }
  standard_sub_basic(str);
}

/*
These flags determine some of the permissions required to do an operation 

Note that I don't set NEED_WRITE on some write operations because they
are used by some brain-dead clients when printing, and I don't want to
force write permissions on print services.
*/
#define AS_USER (1<<0)
#define NEED_WRITE (1<<1)
#define TIME_INIT (1<<2)
#define CAN_IPC (1<<3)
#define AS_GUEST (1<<5)
#define QUEUE_IN_OPLOCK (1<<6)

/* 
   define a list of possible SMB messages and their corresponding
   functions. Any message that has a NULL function is unimplemented -
   please feel free to contribute implementations!
*/

struct smb_message_struct
{
  int code;
  char *name;
  int (*fn)(char *, char *, int, int);
  int flags;
#if PROFILING
  unsigned long time;
#endif
}
 smb_messages[] = {

    /* CORE PROTOCOL */

   {SMBnegprot,"SMBnegprot",reply_negprot,0},
   {SMBtcon,"SMBtcon",reply_tcon,0},
   {SMBtdis,"SMBtdis",reply_tdis,0},
   {SMBexit,"SMBexit",reply_exit,0},
   {SMBioctl,"SMBioctl",reply_ioctl,0},
   {SMBecho,"SMBecho",reply_echo,0},
   {SMBsesssetupX,"SMBsesssetupX",reply_sesssetup_and_X,0},
   {SMBtconX,"SMBtconX",reply_tcon_and_X,0},
   {SMBulogoffX, "SMBulogoffX",reply_ulogoffX, 0}, /* ulogoff doesn't give a valid TID */
   {SMBgetatr,"SMBgetatr",reply_getatr,AS_USER},
   {SMBsetatr,"SMBsetatr",reply_setatr,AS_USER | NEED_WRITE},
   {SMBchkpth,"SMBchkpth",reply_chkpth,AS_USER},
   {SMBsearch,"SMBsearch",reply_search,AS_USER},
   {SMBopen,"SMBopen",reply_open,AS_USER | QUEUE_IN_OPLOCK },

   /* note that SMBmknew and SMBcreate are deliberately overloaded */   
   {SMBcreate,"SMBcreate",reply_mknew,AS_USER},
   {SMBmknew,"SMBmknew",reply_mknew,AS_USER}, 

   {SMBunlink,"SMBunlink",reply_unlink,AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK},
   {SMBread,"SMBread",reply_read,AS_USER},
   {SMBwrite,"SMBwrite",reply_write,AS_USER},
   {SMBclose,"SMBclose",reply_close,AS_USER | CAN_IPC},
   {SMBmkdir,"SMBmkdir",reply_mkdir,AS_USER | NEED_WRITE},
   {SMBrmdir,"SMBrmdir",reply_rmdir,AS_USER | NEED_WRITE},
   {SMBdskattr,"SMBdskattr",reply_dskattr,AS_USER},
   {SMBmv,"SMBmv",reply_mv,AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK},

   /* this is a Pathworks specific call, allowing the 
      changing of the root path */
   {pSETDIR,"pSETDIR",reply_setdir,AS_USER}, 

   {SMBlseek,"SMBlseek",reply_lseek,AS_USER},
   {SMBflush,"SMBflush",reply_flush,AS_USER},
   {SMBctemp,"SMBctemp",reply_ctemp,AS_USER | QUEUE_IN_OPLOCK },
   {SMBsplopen,"SMBsplopen",reply_printopen,AS_USER | QUEUE_IN_OPLOCK },
   {SMBsplclose,"SMBsplclose",reply_printclose,AS_USER},
   {SMBsplretq,"SMBsplretq",reply_printqueue,AS_USER|AS_GUEST},
   {SMBsplwr,"SMBsplwr",reply_printwrite,AS_USER},
   {SMBlock,"SMBlock",reply_lock,AS_USER},
   {SMBunlock,"SMBunlock",reply_unlock,AS_USER},
   
   /* CORE+ PROTOCOL FOLLOWS */
   
   {SMBreadbraw,"SMBreadbraw",reply_readbraw,AS_USER},
   {SMBwritebraw,"SMBwritebraw",reply_writebraw,AS_USER},
   {SMBwriteclose,"SMBwriteclose",reply_writeclose,AS_USER},
   {SMBlockread,"SMBlockread",reply_lockread,AS_USER},
   {SMBwriteunlock,"SMBwriteunlock",reply_writeunlock,AS_USER},
   
   /* LANMAN1.0 PROTOCOL FOLLOWS */
   
   {SMBreadBmpx,"SMBreadBmpx",reply_readbmpx,AS_USER},
   {SMBreadBs,"SMBreadBs",NULL,AS_USER},
   {SMBwriteBmpx,"SMBwriteBmpx",reply_writebmpx,AS_USER},
   {SMBwriteBs,"SMBwriteBs",reply_writebs,AS_USER},
   {SMBwritec,"SMBwritec",NULL,AS_USER},
   {SMBsetattrE,"SMBsetattrE",reply_setattrE,AS_USER | NEED_WRITE},
   {SMBgetattrE,"SMBgetattrE",reply_getattrE,AS_USER},
   {SMBtrans,"SMBtrans",reply_trans,AS_USER | CAN_IPC},
   {SMBtranss,"SMBtranss",NULL,AS_USER | CAN_IPC},
   {SMBioctls,"SMBioctls",NULL,AS_USER},
   {SMBcopy,"SMBcopy",reply_copy,AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK },
   {SMBmove,"SMBmove",NULL,AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK },
   
   {SMBopenX,"SMBopenX",reply_open_and_X,AS_USER | CAN_IPC | QUEUE_IN_OPLOCK },
   {SMBreadX,"SMBreadX",reply_read_and_X,AS_USER},
   {SMBwriteX,"SMBwriteX",reply_write_and_X,AS_USER},
   {SMBlockingX,"SMBlockingX",reply_lockingX,AS_USER},
   
   {SMBffirst,"SMBffirst",reply_search,AS_USER},
   {SMBfunique,"SMBfunique",reply_search,AS_USER},
   {SMBfclose,"SMBfclose",reply_fclose,AS_USER},

   /* LANMAN2.0 PROTOCOL FOLLOWS */
   {SMBfindnclose, "SMBfindnclose",reply_findnclose, AS_USER},
   {SMBfindclose, "SMBfindclose",reply_findclose,AS_USER},
   {SMBtrans2, "SMBtrans2",reply_trans2, AS_USER},
   {SMBtranss2, "SMBtranss2",reply_transs2, AS_USER},

   /* messaging routines */
   {SMBsends,"SMBsends",reply_sends,AS_GUEST},
   {SMBsendstrt,"SMBsendstrt",reply_sendstrt,AS_GUEST},
   {SMBsendend,"SMBsendend",reply_sendend,AS_GUEST},
   {SMBsendtxt,"SMBsendtxt",reply_sendtxt,AS_GUEST},

   /* NON-IMPLEMENTED PARTS OF THE CORE PROTOCOL */
   
   {SMBsendb,"SMBsendb",NULL,AS_GUEST},
   {SMBfwdname,"SMBfwdname",NULL,AS_GUEST},
   {SMBcancelf,"SMBcancelf",NULL,AS_GUEST},
   {SMBgetmac,"SMBgetmac",NULL,AS_GUEST}
 };

/****************************************************************************
return a string containing the function name of a SMB command
****************************************************************************/
char *smb_fn_name(int type)
{
  static char *unknown_name = "SMBunknown";
  static int num_smb_messages = 
    sizeof(smb_messages) / sizeof(struct smb_message_struct);
  int match;

  for (match=0;match<num_smb_messages;match++)
    if (smb_messages[match].code == type)
      break;

  if (match == num_smb_messages)
    return(unknown_name);

  return(smb_messages[match].name);
}


/****************************************************************************
do a switch on the message type, and return the response size
****************************************************************************/
static int switch_message(int type,char *inbuf,char *outbuf,int size,int bufsize)
{
  static int pid= -1;
  int outsize = 0;
  static int num_smb_messages = 
    sizeof(smb_messages) / sizeof(struct smb_message_struct);
  int match;

#if PROFILING
  struct timeval msg_start_time;
  struct timeval msg_end_time;
  static unsigned long total_time = 0;

  GetTimeOfDay(&msg_start_time);
#endif

  if (pid == -1)
    pid = getpid();

  errno = 0;
  last_message = type;

  /* make sure this is an SMB packet */
  if (strncmp(smb_base(inbuf),"\377SMB",4) != 0)
    {
      DEBUG(2,("Non-SMB packet of length %d\n",smb_len(inbuf)));
      return(-1);
    }

  for (match=0;match<num_smb_messages;match++)
    if (smb_messages[match].code == type)
      break;

  if (match == num_smb_messages)
    {
      DEBUG(0,("Unknown message type %d!\n",type));
      outsize = reply_unknown(inbuf,outbuf);
    }
  else
    {
      DEBUG(3,("switch message %s (pid %d)\n",smb_messages[match].name,pid));

      if(global_oplock_break && (smb_messages[match].flags & QUEUE_IN_OPLOCK))
      {
        /* 
         * Queue this message as we are the process of an oplock break.
         */

        DEBUG(2,("%s: switch_message: queueing message due to being in oplock break state.\n",
               timestring() ));

        push_smb_message( inbuf, size);
        return -1;
      }          

      if (smb_messages[match].fn)
	{
	  int cnum = SVAL(inbuf,smb_tid);
	  int flags = smb_messages[match].flags;
          static uint16 last_session_tag = UID_FIELD_INVALID;
          /* In share mode security we must ignore the vuid. */
	  uint16 session_tag = (lp_security() == SEC_SHARE) ? UID_FIELD_INVALID : SVAL(inbuf,smb_uid);
          /* Ensure this value is replaced in the incoming packet. */
          SSVAL(inbuf,smb_uid,session_tag);

          /*
           * Ensure the correct username is in sesssetup_user.
           * This is a really ugly bugfix for problems with
           * multiple session_setup_and_X's being done and
           * allowing %U and %G substitutions to work correctly.
           * There is a reason this code is done here, don't
           * move it unless you know what you're doing... :-).
           * JRA.
           */
          if(session_tag != last_session_tag ) {
            user_struct *vuser = NULL;

            last_session_tag = session_tag;
            if(session_tag != UID_FIELD_INVALID)
              vuser = get_valid_user_struct(session_tag);
            if(vuser != NULL)
              pstrcpy( sesssetup_user, vuser->requested_name);
          }

	  /* does this protocol need to be run as root? */
	  if (!(flags & AS_USER))
	    unbecome_user();

	  /* does this protocol need to be run as the connected user? */
	  if ((flags & AS_USER) && !become_user(&Connections[cnum], cnum,session_tag)) {
	    if (flags & AS_GUEST) 
	      flags &= ~AS_USER;
	    else
	      return(ERROR(ERRSRV,ERRinvnid));
	  }
	  /* this code is to work around a bug is MS client 3 without
	     introducing a security hole - it needs to be able to do
	     print queue checks as guest if it isn't logged in properly */
	  if (flags & AS_USER)
	    flags &= ~AS_GUEST;

	  /* does it need write permission? */
	  if ((flags & NEED_WRITE) && !CAN_WRITE(cnum))
	    return(ERROR(ERRSRV,ERRaccess));

	  /* ipc services are limited */
	  if (IS_IPC(cnum) && (flags & AS_USER) && !(flags & CAN_IPC))
	    return(ERROR(ERRSRV,ERRaccess));	    

	  /* load service specific parameters */
	  if (OPEN_CNUM(cnum) && !become_service(cnum,(flags & AS_USER)?True:False))
	    return(ERROR(ERRSRV,ERRaccess));

	  /* does this protocol need to be run as guest? */
	  if ((flags & AS_GUEST) && (!become_guest() || !check_access(-1)))
	    return(ERROR(ERRSRV,ERRaccess));

	  last_inbuf = inbuf;

	  outsize = smb_messages[match].fn(inbuf,outbuf,size,bufsize);
	}
      else
	{
	  outsize = reply_unknown(inbuf,outbuf);
	}
    }

#if PROFILING
  GetTimeOfDay(&msg_end_time);
  if (!(smb_messages[match].flags & TIME_INIT))
    {
      smb_messages[match].time = 0;
      smb_messages[match].flags |= TIME_INIT;
    }
  {
    unsigned long this_time =     
      (msg_end_time.tv_sec - msg_start_time.tv_sec)*1e6 +
	(msg_end_time.tv_usec - msg_start_time.tv_usec);
    smb_messages[match].time += this_time;
    total_time += this_time;
  }
  DEBUG(2,("TIME %s  %d usecs   %g pct\n",
	   smb_fn_name(type),smb_messages[match].time,
	(100.0*smb_messages[match].time) / total_time));
#endif

  return(outsize);
}


/****************************************************************************
  construct a chained reply and add it to the already made reply
  **************************************************************************/
int chain_reply(char *inbuf,char *outbuf,int size,int bufsize)
{
  static char *orig_inbuf;
  static char *orig_outbuf;
  int smb_com1, smb_com2 = CVAL(inbuf,smb_vwv0);
  unsigned smb_off2 = SVAL(inbuf,smb_vwv1);
  char *inbuf2, *outbuf2;
  int outsize2;
  char inbuf_saved[smb_wct];
  char outbuf_saved[smb_wct];
  extern int chain_size;
  int wct = CVAL(outbuf,smb_wct);
  int outsize = smb_size + 2*wct + SVAL(outbuf,smb_vwv0+2*wct);

  /* maybe its not chained */
  if (smb_com2 == 0xFF) {
    CVAL(outbuf,smb_vwv0) = 0xFF;
    return outsize;
  }

  if (chain_size == 0) {
    /* this is the first part of the chain */
    orig_inbuf = inbuf;
    orig_outbuf = outbuf;
  }

  /* we need to tell the client where the next part of the reply will be */
  SSVAL(outbuf,smb_vwv1,smb_offset(outbuf+outsize,outbuf));
  CVAL(outbuf,smb_vwv0) = smb_com2;

  /* remember how much the caller added to the chain, only counting stuff
     after the parameter words */
  chain_size += outsize - smb_wct;

  /* work out pointers into the original packets. The
     headers on these need to be filled in */
  inbuf2 = orig_inbuf + smb_off2 + 4 - smb_wct;
  outbuf2 = orig_outbuf + SVAL(outbuf,smb_vwv1) + 4 - smb_wct;

  /* remember the original command type */
  smb_com1 = CVAL(orig_inbuf,smb_com);

  /* save the data which will be overwritten by the new headers */
  memcpy(inbuf_saved,inbuf2,smb_wct);
  memcpy(outbuf_saved,outbuf2,smb_wct);

  /* give the new packet the same header as the last part of the SMB */
  memmove(inbuf2,inbuf,smb_wct);

  /* create the in buffer */
  CVAL(inbuf2,smb_com) = smb_com2;

  /* create the out buffer */
  bzero(outbuf2,smb_size);
  set_message(outbuf2,0,0,True);
  CVAL(outbuf2,smb_com) = CVAL(inbuf2,smb_com);
  
  memcpy(outbuf2+4,inbuf2+4,4);
  CVAL(outbuf2,smb_rcls) = SMB_SUCCESS;
  CVAL(outbuf2,smb_reh) = 0;
  CVAL(outbuf2,smb_flg) = 0x80 | (CVAL(inbuf2,smb_flg) & 0x8); /* bit 7 set 
								  means a reply */
  SSVAL(outbuf2,smb_flg2,1); /* say we support long filenames */
  SSVAL(outbuf2,smb_err,SMB_SUCCESS);
  SSVAL(outbuf2,smb_tid,SVAL(inbuf2,smb_tid));
  SSVAL(outbuf2,smb_pid,SVAL(inbuf2,smb_pid));
  SSVAL(outbuf2,smb_uid,SVAL(inbuf2,smb_uid));
  SSVAL(outbuf2,smb_mid,SVAL(inbuf2,smb_mid));

  DEBUG(3,("Chained message\n"));
  show_msg(inbuf2);

  /* process the request */
  outsize2 = switch_message(smb_com2,inbuf2,outbuf2,size-chain_size,
			    bufsize-chain_size);

  /* copy the new reply and request headers over the old ones, but
     preserve the smb_com field */
  memmove(orig_outbuf,outbuf2,smb_wct);
  CVAL(orig_outbuf,smb_com) = smb_com1;

  /* restore the saved data, being careful not to overwrite any
   data from the reply header */
  memcpy(inbuf2,inbuf_saved,smb_wct);
  {
    int ofs = smb_wct - PTR_DIFF(outbuf2,orig_outbuf);
    if (ofs < 0) ofs = 0;
    memmove(outbuf2+ofs,outbuf_saved+ofs,smb_wct-ofs);
  }

  return outsize2;
}



/****************************************************************************
  construct a reply to the incoming packet
****************************************************************************/
int construct_reply(char *inbuf,char *outbuf,int size,int bufsize)
{
  int type = CVAL(inbuf,smb_com);
  int outsize = 0;
  int msg_type = CVAL(inbuf,0);
  extern int chain_size;

  smb_last_time = time(NULL);

  chain_size = 0;
  chain_fnum = -1;
  reset_chain_pnum();

  bzero(outbuf,smb_size);

  if (msg_type != 0)
    return(reply_special(inbuf,outbuf));  

  CVAL(outbuf,smb_com) = CVAL(inbuf,smb_com);
  set_message(outbuf,0,0,True);
  
  memcpy(outbuf+4,inbuf+4,4);
  CVAL(outbuf,smb_rcls) = SMB_SUCCESS;
  CVAL(outbuf,smb_reh) = 0;
  CVAL(outbuf,smb_flg) = 0x80 | (CVAL(inbuf,smb_flg) & 0x8); /* bit 7 set 
							     means a reply */
  SSVAL(outbuf,smb_flg2,1); /* say we support long filenames */
  SSVAL(outbuf,smb_err,SMB_SUCCESS);
  SSVAL(outbuf,smb_tid,SVAL(inbuf,smb_tid));
  SSVAL(outbuf,smb_pid,SVAL(inbuf,smb_pid));
  SSVAL(outbuf,smb_uid,SVAL(inbuf,smb_uid));
  SSVAL(outbuf,smb_mid,SVAL(inbuf,smb_mid));

  outsize = switch_message(type,inbuf,outbuf,size,bufsize);

  outsize += chain_size;

  if(outsize > 4)
    smb_setlen(outbuf,outsize - 4);
  return(outsize);
}

/****************************************************************************
  process commands from the client
****************************************************************************/
static void process(void)
{
  extern int Client;

  InBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  OutBuffer = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  if ((InBuffer == NULL) || (OutBuffer == NULL)) 
    return;

  InBuffer += SMB_ALIGNMENT;
  OutBuffer += SMB_ALIGNMENT;

#if PRIME_NMBD
  DEBUG(3,("priming nmbd\n"));
  {
    struct in_addr ip;
    ip = *interpret_addr2("localhost");
    if (zero_ip(ip)) ip = *interpret_addr2("127.0.0.1");
    *OutBuffer = 0;
    send_one_packet(OutBuffer,1,ip,NMB_PORT,SOCK_DGRAM);
  }
#endif    

  /* re-initialise the timezone */
  TimeInit();

  while (True)
  {
    int deadtime = lp_deadtime()*60;
    int counter;
    int last_keepalive=0;
    int service_load_counter = 0;
    BOOL got_smb = False;

    if (deadtime <= 0)
      deadtime = DEFAULT_SMBD_TIMEOUT;

#if USE_READ_PREDICTION
    if (lp_readprediction())
      do_read_prediction();
#endif

    errno = 0;      

    for (counter=SMBD_SELECT_LOOP; 
          !receive_message_or_smb(Client,oplock_sock,
                      InBuffer,BUFFER_SIZE,SMBD_SELECT_LOOP*1000,&got_smb); 
          counter += SMBD_SELECT_LOOP)
    {
      int i;
      time_t t;
      BOOL allidle = True;
      extern int keepalive;

      if (counter > 365 * 3600) /* big number of seconds. */
      {
        counter = 0;
        service_load_counter = 0;
      }

      if (smb_read_error == READ_EOF) 
      {
        DEBUG(3,("end of file from client\n"));
        return;
      }

      if (smb_read_error == READ_ERROR) 
      {
        DEBUG(3,("receive_smb error (%s) exiting\n",
                  strerror(errno)));
        return;
      }

      t = time(NULL);

      /* become root again if waiting */
      unbecome_user();

      /* check for smb.conf reload */
      if (counter >= service_load_counter + SMBD_RELOAD_CHECK)
      {
        service_load_counter = counter;

        /* reload services, if files have changed. */
        reload_services(True);
      }

      /* automatic timeout if all connections are closed */      
      if (num_connections_open==0 && counter >= IDLE_CLOSED_TIMEOUT) 
      {
        DEBUG(2,("%s Closing idle connection\n",timestring()));
        return;
      }

      if (keepalive && (counter-last_keepalive)>keepalive) 
      {
	      struct cli_state *cli = server_client();
	      if (!send_keepalive(Client)) { 
		      DEBUG(2,("%s Keepalive failed - exiting\n",timestring()));
		      return;
	      }	    
	      /* also send a keepalive to the password server if its still
		 connected */
	      if (cli && cli->initialised)
		      send_keepalive(cli->fd);
	      last_keepalive = counter;
      }

      /* check for connection timeouts */
      for (i=0;i<MAX_CONNECTIONS;i++)
        if (Connections[i].open)
        {
          /* close dirptrs on connections that are idle */
          if ((t-Connections[i].lastused)>DPTR_IDLE_TIMEOUT)
            dptr_idlecnum(i);

          if (Connections[i].num_files_open > 0 ||
                     (t-Connections[i].lastused)<deadtime)
            allidle = False;
        }

      if (allidle && num_connections_open>0) 
      {
        DEBUG(2,("%s Closing idle connection 2\n",timestring()));
        return;
      }
    }

    if(got_smb)
      process_smb(InBuffer, OutBuffer);
    else
      process_local_message(oplock_sock, InBuffer, BUFFER_SIZE);
  }
}


/****************************************************************************
  initialise connect, service and file structs
****************************************************************************/
static void init_structs(void )
{
  int i;
  get_myname(myhostname,NULL);

  for (i=0;i<MAX_CONNECTIONS;i++)
    {
      Connections[i].open = False;
      Connections[i].num_files_open=0;
      Connections[i].lastused=0;
      Connections[i].used=False;
      string_init(&Connections[i].user,"");
      string_init(&Connections[i].dirpath,"");
      string_init(&Connections[i].connectpath,"");
      string_init(&Connections[i].origpath,"");
    }

  for (i=0;i<MAX_OPEN_FILES;i++)
    {
      Files[i].open = False;
      string_init(&Files[i].name,"");

    }

  for (i=0;i<MAX_OPEN_FILES;i++)
    {
      file_fd_struct *fd_ptr = &FileFd[i];
      fd_ptr->ref_count = 0;
      fd_ptr->dev = (int32)-1;
      fd_ptr->inode = (int32)-1;
      fd_ptr->fd = -1;
      fd_ptr->fd_readonly = -1;
      fd_ptr->fd_writeonly = -1;
      fd_ptr->real_open_flags = -1;
    }

  /* for RPC pipes */
  init_rpc_pipe_hnd();

#ifdef NTDOMAIN
  /* for LSA handles */
  init_lsa_policy_hnd();
#endif

  init_dptrs();
}

/****************************************************************************
usage on the program
****************************************************************************/
static void usage(char *pname)
{
  DEBUG(0,("Incorrect program usage - are you sure the command line is correct?\n"));

  printf("Usage: %s [-D] [-p port] [-d debuglevel] [-l log basename] [-s services file]\n",pname);
  printf("Version %s\n",VERSION);
  printf("\t-D                    become a daemon\n");
  printf("\t-p port               listen on the specified port\n");
  printf("\t-d debuglevel         set the debuglevel\n");
  printf("\t-l log basename.      Basename for log/debug files\n");
  printf("\t-s services file.     Filename of services file\n");
  printf("\t-P                    passive only\n");
  printf("\t-a                    overwrite log file, don't append\n");
  printf("\n");
}


/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
  extern BOOL append_log;
  /* shall I run as a daemon */
  BOOL is_daemon = False;
  int port = SMB_PORT;
  int opt;
  extern char *optarg;
  char pidFile[100];

  *pidFile = '\0';

#ifdef NEED_AUTH_PARAMETERS
  set_auth_parameters(argc,argv);
#endif

#ifdef SecureWare
  setluid(0);
#endif

  append_log = True;

  TimeInit();

  pstrcpy(debugf,SMBLOGFILE);  

  pstrcpy(remote_machine, "smb");

  setup_logging(argv[0],False);

  charset_initialise();

  /* make absolutely sure we run as root - to handle cases where people
     are crazy enough to have it setuid */
#ifdef USE_SETRES
  setresuid(0,0,0);
#else
  setuid(0);
  seteuid(0);
  setuid(0);
  seteuid(0);
#endif

  fault_setup((void (*)(void *))exit_server);
  signal(SIGTERM , SIGNAL_CAST dflt_sig);

  /* we want total control over the permissions on created files,
     so set our umask to 0 */
  umask(0);

  GetWd(OriginalDir);

  init_uid();

  /* this is for people who can't start the program correctly */
  while (argc > 1 && (*argv[1] != '-'))
    {
      argv++;
      argc--;
    }

  while ((opt = getopt(argc, argv, "O:i:l:s:d:Dp:hPaf:")) != EOF)
    switch (opt)
      {
      case 'f':
        strncpy(pidFile, optarg, sizeof(pidFile));
        break;
      case 'O':
	pstrcpy(user_socket_options,optarg);
	break;
      case 'i':
	pstrcpy(scope,optarg);
	break;
      case 'P':
	{
	  extern BOOL passive;
	  passive = True;
	}
	break;	
      case 's':
	pstrcpy(servicesf,optarg);
	break;
      case 'l':
	pstrcpy(debugf,optarg);
	break;
      case 'a':
	{
	  extern BOOL append_log;
	  append_log = !append_log;
	}
	break;
      case 'D':
	is_daemon = True;
	break;
      case 'd':
	if (*optarg == 'A')
	  DEBUGLEVEL = 10000;
	else
	  DEBUGLEVEL = atoi(optarg);
	break;
      case 'p':
	port = atoi(optarg);
	break;
      case 'h':
	usage(argv[0]);
	exit(0);
	break;
      default:
	usage(argv[0]);
	exit(1);
      }

  reopen_logs();

  DEBUG(2,("%s smbd version %s started\n",timestring(),VERSION));
  DEBUG(2,("Copyright Andrew Tridgell 1992-1997\n"));

#ifndef NO_GETRLIMIT
#ifdef RLIMIT_NOFILE
  {
    struct rlimit rlp;
    getrlimit(RLIMIT_NOFILE, &rlp);
    /*
     * Set the fd limit to be MAX_OPEN_FILES + 10 to account for the
     * extra fd we need to read directories, as well as the log files
     * and standard handles etc.
     */
    rlp.rlim_cur = (MAX_OPEN_FILES+10>rlp.rlim_max)? rlp.rlim_max:MAX_OPEN_FILES+10;
    setrlimit(RLIMIT_NOFILE, &rlp);
    getrlimit(RLIMIT_NOFILE, &rlp);
    DEBUG(3,("Maximum number of open files per session is %d\n",rlp.rlim_cur));
  }
#endif
#endif

  
  DEBUG(2,("uid=%d gid=%d euid=%d egid=%d\n",
	getuid(),getgid(),geteuid(),getegid()));

  if (sizeof(uint16) < 2 || sizeof(uint32) < 4)
    {
      DEBUG(0,("ERROR: Samba is not configured correctly for the word size on your machine\n"));
      exit(1);
    }

  init_structs();

  if (!reload_services(False))
    return(-1);	

  codepage_initialise(lp_client_code_page());

  pstrcpy(myworkgroup, lp_workgroup());

#ifndef NO_SIGNAL_TEST
  signal(SIGHUP,SIGNAL_CAST sig_hup);
#endif

  /* Setup the signals that allow the debug log level
     to by dynamically changed. */
 
  /* If we are using the malloc debug code we can't use
     SIGUSR1 and SIGUSR2 to do debug level changes. */

#ifndef MEM_MAN
#if defined(SIGUSR1)
  signal( SIGUSR1, SIGNAL_CAST sig_usr1 );
#endif /* SIGUSR1 */
   
#if defined(SIGUSR2)
  signal( SIGUSR2, SIGNAL_CAST sig_usr2 );
#endif /* SIGUSR2 */
#endif /* MEM_MAN */

  DEBUG(3,("%s loaded services\n",timestring()));

  if (!is_daemon && !is_a_socket(0))
    {
      DEBUG(0,("standard input is not a socket, assuming -D option\n"));
      is_daemon = True;
    }

  if (is_daemon)
    {
      DEBUG(3,("%s becoming a daemon\n",timestring()));
      become_daemon();
    }

  if (!directory_exist(lp_lockdir(), NULL)) {
	  mkdir(lp_lockdir(), 0755);
  }

  if (*pidFile)
    {
      int     fd;
      char    buf[20];

      if ((fd = open(pidFile,
#ifdef O_NONBLOCK
         O_NONBLOCK | 
#endif
         O_CREAT | O_WRONLY | O_TRUNC, 0644)) < 0)
        {
           DEBUG(0,("ERROR: can't open %s: %s\n", pidFile, strerror(errno)));
           exit(1);
        }
      if(fcntl_lock(fd,F_SETLK,0,1,F_WRLCK)==False)
        {
          DEBUG(0,("ERROR: smbd is already running\n"));
          exit(1);
        }
      slprintf(buf, sizeof(buf)-1, "%u\n", (unsigned int) getpid());
      if (write(fd, buf, strlen(buf)) < 0)
        {
          DEBUG(0,("ERROR: can't write to %s: %s\n", pidFile, strerror(errno)));
          exit(1);
        }
      /* Leave pid file open & locked for the duration... */
    }

  if (!open_sockets(is_daemon,port))
    exit(1);

  if (!locking_init(0))
    exit(1);

  /* possibly reload the services file. */
  reload_services(True);

  max_recv = MIN(lp_maxxmit(),BUFFER_SIZE);

  if (*lp_rootdir())
    {
      if (sys_chroot(lp_rootdir()) == 0)
	DEBUG(2,("%s changed root to %s\n",timestring(),lp_rootdir()));
    }

  /* Setup the oplock IPC socket. */
  if(!open_oplock_ipc())
    exit(1);

  process();
  close_sockets();

  exit_server("normal exit");
  return(0);
}


