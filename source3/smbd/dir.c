/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Directory handling routines
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

extern int DEBUGLEVEL;
extern connection_struct Connections[];

/*
   This module implements directory related functions for Samba.
*/



uint32 dircounter = 0;


#define NUMDIRPTRS 256


static struct dptr_struct
{
  int pid;
  int cnum;
  uint32 lastused;
  void *ptr;
  BOOL valid;
  BOOL finished;
  BOOL expect_close;
  char *wcard; /* Field only used for lanman2 trans2_findfirst/next searches */
  uint16 attr; /* Field only used for lanman2 trans2_findfirst/next searches */
  char *path;
}
dirptrs[NUMDIRPTRS];


static int dptrs_open = 0;

/****************************************************************************
initialise the dir array
****************************************************************************/
void init_dptrs(void)
{
  static BOOL dptrs_init=False;
  int i;

  if (dptrs_init) return;
  for (i=0;i<NUMDIRPTRS;i++)    
    {
      dirptrs[i].valid = False;
      dirptrs[i].wcard = NULL;
      dirptrs[i].ptr = NULL;
      string_init(&dirptrs[i].path,"");
    }
  dptrs_init = True;
}

/****************************************************************************
idle a dptr - the directory is closed but the control info is kept
****************************************************************************/
static void dptr_idle(int key)
{
  if (dirptrs[key].valid && dirptrs[key].ptr) {
    DEBUG(4,("Idling dptr key %d\n",key));
    dptrs_open--;
    CloseDir(dirptrs[key].ptr);
    dirptrs[key].ptr = NULL;
  }    
}

/****************************************************************************
idle the oldest dptr
****************************************************************************/
static void dptr_idleoldest(void)
{
  int i;
  uint32 old=dircounter+1;
  int oldi= -1;
  for (i=0;i<NUMDIRPTRS;i++)
    if (dirptrs[i].valid && dirptrs[i].ptr && dirptrs[i].lastused < old) {
      old = dirptrs[i].lastused;
      oldi = i;
    }
  if (oldi != -1)
    dptr_idle(oldi);
  else
    DEBUG(0,("No dptrs available to idle??\n"));
}

/****************************************************************************
get the dir ptr for a dir index
****************************************************************************/
static void *dptr_get(int key,uint32 lastused)
{
  struct dptr_struct *dp = &dirptrs[key];

  if (dp->valid) {
    if (lastused) dp->lastused = lastused;
    if (!dp->ptr) {
      if (dptrs_open >= MAXDIR)
	dptr_idleoldest();
      DEBUG(4,("Reopening dptr key %d\n",key));
      if ((dp->ptr = OpenDir(dp->cnum, dp->path, True)))
	dptrs_open++;
    }
    return(dp->ptr);
  }
  return(NULL);
}

/****************************************************************************
get the dir path for a dir index
****************************************************************************/
char *dptr_path(int key)
{
  if (dirptrs[key].valid)
    return(dirptrs[key].path);
  return(NULL);
}

/****************************************************************************
get the dir wcard for a dir index (lanman2 specific)
****************************************************************************/
char *dptr_wcard(int key)
{
  if (dirptrs[key].valid)
    return(dirptrs[key].wcard);
  return(NULL);
}

/****************************************************************************
set the dir wcard for a dir index (lanman2 specific)
Returns 0 on ok, 1 on fail.
****************************************************************************/
BOOL dptr_set_wcard(int key, char *wcard)
{
  if (dirptrs[key].valid) {
    dirptrs[key].wcard = wcard;
    return True;
  }
  return False;
}

/****************************************************************************
set the dir attrib for a dir index (lanman2 specific)
Returns 0 on ok, 1 on fail.
****************************************************************************/
BOOL dptr_set_attr(int key, uint16 attr)
{
  if (dirptrs[key].valid) {
    dirptrs[key].attr = attr;
    return True;
  }
  return False;
}

/****************************************************************************
get the dir attrib for a dir index (lanman2 specific)
****************************************************************************/
uint16 dptr_attr(int key)
{
  if (dirptrs[key].valid)
    return(dirptrs[key].attr);
  return(0);
}

/****************************************************************************
close a dptr
****************************************************************************/
void dptr_close(int key)
{
  /* OS/2 seems to use -1 to indicate "close all directories" */
  if (key == -1) {
    int i;
    for (i=0;i<NUMDIRPTRS;i++) 
      dptr_close(i);
    return;
  }

  if (key < 0 || key >= NUMDIRPTRS) {
    DEBUG(3,("Invalid key %d given to dptr_close\n",key));
    return;
  }

  if (dirptrs[key].valid) {
    DEBUG(4,("closing dptr key %d\n",key));
    if (dirptrs[key].ptr) {
      CloseDir(dirptrs[key].ptr);
      dptrs_open--;
    }
    /* Lanman 2 specific code */
    if (dirptrs[key].wcard)
      free(dirptrs[key].wcard);
    dirptrs[key].valid = False;
    string_set(&dirptrs[key].path,"");
  }
}

/****************************************************************************
close all dptrs for a cnum
****************************************************************************/
void dptr_closecnum(int cnum)
{
  int i;
  for (i=0;i<NUMDIRPTRS;i++)
    if (dirptrs[i].valid && dirptrs[i].cnum == cnum)
      dptr_close(i);
}

/****************************************************************************
idle all dptrs for a cnum
****************************************************************************/
void dptr_idlecnum(int cnum)
{
  int i;
  for (i=0;i<NUMDIRPTRS;i++)
    if (dirptrs[i].valid && dirptrs[i].cnum == cnum && dirptrs[i].ptr)
      dptr_idle(i);
}

/****************************************************************************
close a dptr that matches a given path, only if it matches the pid also
****************************************************************************/
void dptr_closepath(char *path,int pid)
{
  int i;
  for (i=0;i<NUMDIRPTRS;i++)
    if (dirptrs[i].valid && pid == dirptrs[i].pid &&
	strequal(dirptrs[i].path,path))
      dptr_close(i);
}

/****************************************************************************
  start a directory listing
****************************************************************************/
static BOOL start_dir(int cnum,char *directory)
{
  DEBUG(5,("start_dir cnum=%d dir=%s\n",cnum,directory));

  if (!check_name(directory,cnum))
    return(False);
  
  if (! *directory)
    directory = ".";

  Connections[cnum].dirptr = OpenDir(cnum, directory, True);
  if (Connections[cnum].dirptr) {    
    dptrs_open++;
    string_set(&Connections[cnum].dirpath,directory);
    return(True);
  }
  
  return(False);
}


/****************************************************************************
create a new dir ptr
****************************************************************************/
int dptr_create(int cnum,char *path, BOOL expect_close,int pid)
{
  int i;
  uint32 old;
  int oldi;

  if (!start_dir(cnum,path))
    return(-2); /* Code to say use a unix error return code. */

  if (dptrs_open >= MAXDIR)
    dptr_idleoldest();

  for (i=0;i<NUMDIRPTRS;i++)
    if (!dirptrs[i].valid)
      break;
  if (i == NUMDIRPTRS) i = -1;


  /* as a 2nd option, grab the oldest not marked for expect_close */
  if (i == -1) {
    old=dircounter+1;
    oldi= -1;
    for (i=0;i<NUMDIRPTRS;i++)
      if (!dirptrs[i].expect_close && dirptrs[i].lastused < old) {
	old = dirptrs[i].lastused;
	oldi = i;
      }
    i = oldi;
  }

  /* a 3rd option - grab the oldest one */
  if (i == -1) {
    old=dircounter+1;
    oldi= -1;
    for (i=0;i<NUMDIRPTRS;i++)
      if (dirptrs[i].lastused < old) {
	old = dirptrs[i].lastused;
	oldi = i;
      }
    i = oldi;
  }

  if (i == -1) {
    DEBUG(0,("Error - all dirptrs in use??\n"));
    return(-1);
  }

  if (dirptrs[i].valid)
    dptr_close(i);

  dirptrs[i].ptr = Connections[cnum].dirptr;
  string_set(&dirptrs[i].path,path);
  dirptrs[i].lastused = dircounter++;
  dirptrs[i].finished = False;
  dirptrs[i].cnum = cnum;
  dirptrs[i].pid = pid;
  dirptrs[i].expect_close = expect_close;
  dirptrs[i].wcard = NULL; /* Only used in lanman2 searches */
  dirptrs[i].attr = 0; /* Only used in lanman2 searches */
  dirptrs[i].valid = True;

  DEBUG(3,("creating new dirptr %d for path %s, expect_close = %d\n",
	   i,path,expect_close));  

  return(i);
}

#define DPTR_MASK ((uint32)(((uint32)1)<<31))

/****************************************************************************
fill the 5 byte server reserved dptr field
****************************************************************************/
BOOL dptr_fill(char *buf1,unsigned int key)
{
  unsigned char *buf = (unsigned char *)buf1;
  void *p = dptr_get(key,0);
  uint32 offset;
  if (!p) {
    DEBUG(1,("filling null dirptr %d\n",key));
    return(False);
  }
  offset = TellDir(p);
  DEBUG(6,("fill on key %d dirptr 0x%x now at %d\n",key,p,offset));
  buf[0] = key;
  SIVAL(buf,1,offset | DPTR_MASK);
  return(True);
}


/****************************************************************************
return True is the offset is at zero
****************************************************************************/
BOOL dptr_zero(char *buf)
{
  return((IVAL(buf,1)&~DPTR_MASK) == 0);
}

/****************************************************************************
fetch the dir ptr and seek it given the 5 byte server field
****************************************************************************/
void *dptr_fetch(char *buf,int *num)
{
  unsigned int key = *(unsigned char *)buf;
  void *p = dptr_get(key,dircounter++);
  uint32 offset;
  if (!p) {
    DEBUG(3,("fetched null dirptr %d\n",key));
    return(NULL);
  }
  *num = key;
  offset = IVAL(buf,1)&~DPTR_MASK;
  SeekDir(p,offset);
  DEBUG(3,("fetching dirptr %d for path %s at offset %d\n",
	   key,dptr_path(key),offset));
  return(p);
}

/****************************************************************************
fetch the dir ptr.
****************************************************************************/
void *dptr_fetch_lanman2(int dptr_num)
{
  void *p = dptr_get(dptr_num,dircounter++);

  if (!p) {
    DEBUG(3,("fetched null dirptr %d\n",dptr_num));
    return(NULL);
  }
  DEBUG(3,("fetching dirptr %d for path %s\n",dptr_num,dptr_path(dptr_num)));
  return(p);
}

/****************************************************************************
check a filetype for being valid
****************************************************************************/
BOOL dir_check_ftype(int cnum,int mode,struct stat *st,int dirtype)
{
  if (((mode & ~dirtype) & (aHIDDEN | aSYSTEM | aDIR)) != 0)
    return False;
  return True;
}

/****************************************************************************
  get a directory entry
****************************************************************************/
BOOL get_dir_entry(int cnum,char *mask,int dirtype,char *fname,int *size,int *mode,time_t *date,BOOL check_descend)
{
  char *dname;
  BOOL found = False;
  struct stat sbuf;
  pstring path;
  pstring pathreal;
  BOOL isrootdir;
  pstring filename;
  BOOL matched;
  BOOL needslash;

  *path = *pathreal = *filename = 0;

  isrootdir = (strequal(Connections[cnum].dirpath,"./") ||
	       strequal(Connections[cnum].dirpath,".") ||
	       strequal(Connections[cnum].dirpath,"/"));
  
  needslash = 
        ( Connections[cnum].dirpath[strlen(Connections[cnum].dirpath) -1] != '/');

  if (!Connections[cnum].dirptr)
    return(False);
  
  while (!found)
    {
      dname = ReadDirName(Connections[cnum].dirptr);

      DEBUG(6,("readdir on dirptr 0x%x now at offset %d\n",
	    Connections[cnum].dirptr,TellDir(Connections[cnum].dirptr)));
      
      if (dname == NULL) 
	return(False);
      
      matched = False;

      pstrcpy(filename,dname);      

      if ((strcmp(filename,mask) == 0) ||
	  (name_map_mangle(filename,True,SNUM(cnum)) &&
	   mask_match(filename,mask,False,False)))
	{
	  if (isrootdir && (strequal(filename,"..") || strequal(filename,".")))
	    continue;

	  pstrcpy(fname,filename);
	  *path = 0;
	  pstrcpy(path,Connections[cnum].dirpath);
          if(needslash)
  	    pstrcat(path,"/");
	  pstrcpy(pathreal,path);
	  pstrcat(path,fname);
	  pstrcat(pathreal,dname);
	  if (sys_stat(pathreal,&sbuf) != 0) 
	    {
	      DEBUG(5,("Couldn't stat 1 [%s]\n",path));
	      continue;
	    }

	  if (check_descend &&
	      !strequal(fname,".") && !strequal(fname,".."))
	    continue;
	  
	  *mode = dos_mode(cnum,pathreal,&sbuf);

	  if (!dir_check_ftype(cnum,*mode,&sbuf,dirtype)) {
	    DEBUG(5,("[%s] attribs didn't match %x\n",filename,dirtype));
	    continue;
	  }

	  *size = sbuf.st_size;
	  *date = sbuf.st_mtime;

	  DEBUG(5,("get_dir_entry found %s fname=%s\n",pathreal,fname));
	  
	  found = True;
	}
    }

  return(found);
}



typedef struct
{
  int pos;
  int numentries;
  int mallocsize;
  char *data;
  char *current;
} Dir;


/*******************************************************************
open a directory
********************************************************************/
void *OpenDir(int cnum, char *name, BOOL use_veto)
{
  Dir *dirp;
  char *n;
  void *p = sys_opendir(name);
  int used=0;

  if (!p) return(NULL);
  dirp = (Dir *)malloc(sizeof(Dir));
  if (!dirp) {
    closedir(p);
    return(NULL);
  }
  dirp->pos = dirp->numentries = dirp->mallocsize = 0;
  dirp->data = dirp->current = NULL;

  while ((n = readdirname(p)))
  {
    int l = strlen(n)+1;

    /* If it's a vetoed file, pretend it doesn't even exist */
    if (use_veto && IS_VETO_PATH(cnum, n)) continue;

    if (used + l > dirp->mallocsize) {
      int s = MAX(used+l,used+2000);
      char *r;
      r = (char *)Realloc(dirp->data,s);
      if (!r) {
	DEBUG(0,("Out of memory in OpenDir\n"));
	break;
      }
      dirp->data = r;
      dirp->mallocsize = s;
      dirp->current = dirp->data;
    }
    pstrcpy(dirp->data+used,n);
    used += l;
    dirp->numentries++;
  }

  closedir(p);
  return((void *)dirp);
}


/*******************************************************************
close a directory
********************************************************************/
void CloseDir(void *p)
{
  Dir *dirp = (Dir *)p;
  if (!dirp) return;    
  if (dirp->data) free(dirp->data);
  free(dirp);
}

/*******************************************************************
read from a directory
********************************************************************/
char *ReadDirName(void *p)
{
  char *ret;
  Dir *dirp = (Dir *)p;

  if (!dirp || !dirp->current || dirp->pos >= dirp->numentries) return(NULL);

  ret = dirp->current;
  dirp->current = skip_string(dirp->current,1);
  dirp->pos++;

  return(ret);
}


/*******************************************************************
seek a dir
********************************************************************/
BOOL SeekDir(void *p,int pos)
{
  Dir *dirp = (Dir *)p;

  if (!dirp) return(False);

  if (pos < dirp->pos) {
    dirp->current = dirp->data;
    dirp->pos = 0;
  }

  while (dirp->pos < pos && ReadDirName(p)) ;

  return(dirp->pos == pos);
}

/*******************************************************************
tell a dir position
********************************************************************/
int TellDir(void *p)
{
  Dir *dirp = (Dir *)p;

  if (!dirp) return(-1);
  
  return(dirp->pos);
}


/* -------------------------------------------------------------------------- **
 * This section manages a global directory cache.
 * (It should probably be split into a separate module.  crh)
 * -------------------------------------------------------------------------- **
 */

typedef struct
  {
  ubi_dlNode  node;
  char       *path;
  char       *name;
  char       *dname;
  int         snum;
  } dir_cache_entry;

static ubi_dlList dir_cache[1] = { { NULL, NULL, 0 } };

void DirCacheAdd( char *path, char *name, char *dname, int snum )
  /* ------------------------------------------------------------------------ **
   * Add an entry to the directory cache.
   *
   *  Input:  path  -
   *          name  -
   *          dname -
   *          snum  -
   *
   *  Output: None.
   *
   * ------------------------------------------------------------------------ **
   */
  {
  int               pathlen;
  int               namelen;
  dir_cache_entry  *entry;

  /* Allocate the structure & string space in one go so that it can be freed
   * in one call to free().
   */
  pathlen = strlen( path ) +1;  /* Bytes required to store path (with nul). */
  namelen = strlen( name ) +1;  /* Bytes required to store name (with nul). */
  entry = (dir_cache_entry *)malloc( sizeof( dir_cache_entry )
                                   + pathlen
                                   + namelen
                                   + strlen( dname ) +1 );
  if( NULL == entry )   /* Not adding to the cache is not fatal,  */
    return;             /* so just return as if nothing happened. */

  /* Set pointers correctly and load values. */
  entry->path  = pstrcpy( (char *)&entry[1],       path);
  entry->name  = pstrcpy( &(entry->path[pathlen]), name);
  entry->dname = pstrcpy( &(entry->name[namelen]), dname);
  entry->snum  = snum;

  /* Add the new entry to the linked list. */
  (void)ubi_dlAddHead( dir_cache, entry );
  DEBUG( 4, ("Added dir cache entry %s %s -> %s\n", path, name, dname ) );

  /* Free excess cache entries. */
  while( DIRCACHESIZE < dir_cache->count )
    free( ubi_dlRemTail( dir_cache ) );

  } /* DirCacheAdd */


char *DirCacheCheck( char *path, char *name, int snum )
  /* ------------------------------------------------------------------------ **
   * Search for an entry to the directory cache.
   *
   *  Input:  path  -
   *          name  -
   *          snum  -
   *
   *  Output: The dname string of the located entry, or NULL if the entry was
   *          not found.
   *
   *  Notes:  This uses a linear search, which is is okay because of
   *          the small size of the cache.  Use a splay tree or hash
   *          for large caches.
   *
   * ------------------------------------------------------------------------ **
   */
  {
  dir_cache_entry *entry;

  for( entry = (dir_cache_entry *)ubi_dlFirst( dir_cache );
       NULL != entry;
       entry = (dir_cache_entry *)ubi_dlNext( entry ) )
    {
    if( entry->snum == snum
        && 0 == strcmp( name, entry->name )
        && 0 == strcmp( path, entry->path ) )
      {
      DEBUG(4, ("Got dir cache hit on %s %s -> %s\n",path,name,entry->dname));
      return( entry->dname );
      }
    }

  return(NULL);
  } /* DirCacheCheck */

void DirCacheFlush( int snum )
  /* ------------------------------------------------------------------------ **
   * Remove all cache entries which have an snum that matches the input.
   *
   *  Input:  snum  -
   *
   *  Output: None.
   *
   * ------------------------------------------------------------------------ **
   */
  {
  dir_cache_entry *entry;
  ubi_dlNodePtr    next;

  for( entry = (dir_cache_entry *)ubi_dlFirst( dir_cache ); NULL != entry; )
    {
    next = ubi_dlNext( entry );
    if( entry->snum == snum )
      free( ubi_dlRemThis( dir_cache, entry ) );
    entry = (dir_cache_entry *)next;
    }
  } /* DirCacheFlush */

/* -------------------------------------------------------------------------- **
 * End of the section that manages the global directory cache.
 * -------------------------------------------------------------------------- **
 */


#ifdef REPLACE_GETWD
/* This is getcwd.c from bash.  It is needed in Interactive UNIX.  To
 * add support for another OS you need to determine which of the
 * conditional compilation macros you need to define.  All the options
 * are defined for Interactive UNIX.
 */
#ifdef ISC
#define HAVE_UNISTD_H
#define USGr3
#define USG
#endif

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#if defined (__STDC__)
#  define CONST const
#  define PTR void *
#else /* !__STDC__ */
#  define CONST
#  define PTR char *
#endif /* !__STDC__ */

#if !defined (PATH_MAX)
#  if defined (MAXPATHLEN)
#    define PATH_MAX MAXPATHLEN
#  else /* !MAXPATHLEN */
#    define PATH_MAX 1024
#  endif /* !MAXPATHLEN */
#endif /* !PATH_MAX */

#if defined (_POSIX_VERSION) || defined (USGr3) || defined (HAVE_DIRENT_H)
#  if !defined (HAVE_DIRENT)
#    define HAVE_DIRENT
#  endif /* !HAVE_DIRENT */
#endif /* _POSIX_VERSION || USGr3 || HAVE_DIRENT_H */

#if defined (HAVE_DIRENT)
#  define D_NAMLEN(d)	(strlen ((d)->d_name))
#else
#  define D_NAMLEN(d)	((d)->d_namlen)
#endif /* ! (_POSIX_VERSION || USGr3) */

#if defined (USG) || defined (USGr3)
#  define d_fileno d_ino
#endif

#if !defined (alloca)
extern char *alloca ();
#endif /* alloca */

/* Get the pathname of the current working directory,
   and put it in SIZE bytes of BUF.  Returns NULL if the
   directory couldn't be determined or SIZE was too small.
   If successful, returns BUF.  In GNU, if BUF is NULL,
   an array is allocated with `malloc'; the array is SIZE
   bytes long, unless SIZE <= 0, in which case it is as
   big as necessary.  */
#if defined (__STDC__)
char *
getcwd (char *buf, size_t size)
#else /* !__STDC__ */
char *
getcwd (buf, size)
     char *buf;
     int size;
#endif /* !__STDC__ */
{
  static CONST char dots[]
    = "../../../../../../../../../../../../../../../../../../../../../../../\
../../../../../../../../../../../../../../../../../../../../../../../../../../\
../../../../../../../../../../../../../../../../../../../../../../../../../..";
  CONST char *dotp, *dotlist;
  size_t dotsize;
  dev_t rootdev, thisdev;
  ino_t rootino, thisino;
  char path[PATH_MAX + 1];
  register char *pathp;
  char *pathbuf;
  size_t pathsize;
  struct stat st;

  if (buf != NULL && size == 0)
    {
      errno = EINVAL;
      return ((char *)NULL);
    }

  pathsize = sizeof (path);
  pathp = &path[pathsize];
  *--pathp = '\0';
  pathbuf = path;

  if (stat (".", &st) < 0)
    return ((char *)NULL);
  thisdev = st.st_dev;
  thisino = st.st_ino;

  if (stat ("/", &st) < 0)
    return ((char *)NULL);
  rootdev = st.st_dev;
  rootino = st.st_ino;

  dotsize = sizeof (dots) - 1;
  dotp = &dots[sizeof (dots)];
  dotlist = dots;
  while (!(thisdev == rootdev && thisino == rootino))
    {
      register DIR *dirstream;
      register struct dirent *d;
      dev_t dotdev;
      ino_t dotino;
      char mount_point;
      int namlen;

      /* Look at the parent directory.  */
      if (dotp == dotlist)
	{
	  /* My, what a deep directory tree you have, Grandma.  */
	  char *new;
	  if (dotlist == dots)
	    {
	      new = malloc (dotsize * 2 + 1);
	      if (new == NULL)
		goto lose;
	      memcpy (new, dots, dotsize);
	    }
	  else
	    {
	      new = realloc ((PTR) dotlist, dotsize * 2 + 1);
	      if (new == NULL)
		goto lose;
	    }
	  memcpy (&new[dotsize], new, dotsize);
	  dotp = &new[dotsize];
	  dotsize *= 2;
	  new[dotsize] = '\0';
	  dotlist = new;
	}

      dotp -= 3;

      /* Figure out if this directory is a mount point.  */
      if (stat (dotp, &st) < 0)
	goto lose;
      dotdev = st.st_dev;
      dotino = st.st_ino;
      mount_point = dotdev != thisdev;

      /* Search for the last directory.  */
      dirstream = opendir(dotp);
      if (dirstream == NULL)
	goto lose;
      while ((d = (struct dirent *)readdir(dirstream)) != NULL)
	{
	  if (d->d_name[0] == '.' &&
	      (d->d_name[1] == '\0' ||
		(d->d_name[1] == '.' && d->d_name[2] == '\0')))
	    continue;
	  if (mount_point || d->d_fileno == thisino)
	    {
	      char *name;

	      namlen = D_NAMLEN(d);
	      name = (char *)
		alloca (dotlist + dotsize - dotp + 1 + namlen + 1);
	      memcpy (name, dotp, dotlist + dotsize - dotp);
	      name[dotlist + dotsize - dotp] = '/';
	      memcpy (&name[dotlist + dotsize - dotp + 1],
		      d->d_name, namlen + 1);
	      if (lstat (name, &st) < 0)
		{
		  int save = errno;
		  closedir(dirstream);
		  errno = save;
		  goto lose;
		}
	      if (st.st_dev == thisdev && st.st_ino == thisino)
		break;
	    }
	}
      if (d == NULL)
	{
	  int save = errno;
	  closedir(dirstream);
	  errno = save;
	  goto lose;
	}
      else
	{
	  size_t space;

	  while ((space = pathp - pathbuf) <= namlen)
	    {
	      char *new;

	      if (pathbuf == path)
		{
		  new = malloc (pathsize * 2);
		  if (!new)
		    goto lose;
		}
	      else
		{
		  new = realloc ((PTR) pathbuf, (pathsize * 2));
		  if (!new)
		    goto lose;
		  pathp = new + space;
		}
	      (void) memcpy (new + pathsize + space, pathp, pathsize - space);
	      pathp = new + pathsize + space;
	      pathbuf = new;
	      pathsize *= 2;
	    }

	  pathp -= namlen;
	  (void) memcpy (pathp, d->d_name, namlen);
	  *--pathp = '/';
	  closedir(dirstream);
	}

      thisdev = dotdev;
      thisino = dotino;
    }

  if (pathp == &path[sizeof(path) - 1])
    *--pathp = '/';

  if (dotlist != dots)
    free ((PTR) dotlist);

  {
    size_t len = pathbuf + pathsize - pathp;
    if (buf == NULL)
      {
	if (len < (size_t) size)
	  len = size;
	buf = (char *) malloc (len);
	if (buf == NULL)
	  goto lose2;
      }
    else if ((size_t) size < len)
      {
	errno = ERANGE;
	goto lose2;
      }
    (void) memcpy((PTR) buf, (PTR) pathp, len);
  }

  if (pathbuf != path)
    free (pathbuf);

  return (buf);

 lose:
  if ((dotlist != dots) && dotlist)
    {
      int e = errno;
      free ((PTR) dotlist);
      errno = e;
    }

 lose2:
  if ((pathbuf != path) && pathbuf)
    {
      int e = errno;
      free ((PTR) pathbuf);
      errno = e;
    }
  return ((char *)NULL);
}
#endif
