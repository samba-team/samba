/*
 * Unix SMB/Netbios implementation. Version 1.9. SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998 Modified by Jeremy Allison 1995.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

extern int DEBUGLEVEL;

static int gotalarm;

/***************************************************************
 Signal function to tell us we timed out.
****************************************************************/

static void gotalarm_sig(void)
{
  gotalarm = 1;
}

/***************************************************************
 Lock or unlock a fd for a known lock type. Abandon after waitsecs 
 seconds.
****************************************************************/

BOOL do_file_lock(int fd, int waitsecs, int type)
{
  SMB_STRUCT_FLOCK lock;
  int             ret;

  gotalarm = 0;
  CatchSignal(SIGALRM, SIGNAL_CAST gotalarm_sig);

  lock.l_type = type;
  lock.l_whence = SEEK_SET;
  lock.l_start = 0;
  lock.l_len = 1;
  lock.l_pid = 0;

  alarm(5);
  ret = fcntl(fd, SMB_F_SETLKW, &lock);
  alarm(0);
  CatchSignal(SIGALRM, SIGNAL_CAST SIG_DFL);

  if (gotalarm) {
    DEBUG(0, ("do_file_lock: failed to %s file.\n",
                type == F_UNLCK ? "unlock" : "lock"));
    return False;
  }

  return (ret == 0);
}


/***************************************************************
 Lock an fd. Abandon after waitsecs seconds.
****************************************************************/

BOOL file_lock(int fd, int type, int secs, int *plock_depth)
{
  if (fd < 0)
    return False;

  (*plock_depth)++;

  if ((*plock_depth) == 0)
  {
    if (!do_file_lock(fd, secs, type)) {
      DEBUG(10,("file_lock: locking file failed, error = %s.\n",
                 strerror(errno)));
      return False;
    }
  }

  return True;
}

/***************************************************************
 Unlock an fd. Abandon after waitsecs seconds.
****************************************************************/

BOOL file_unlock(int fd, int *plock_depth)
{
  BOOL ret=True;

  if(*plock_depth == 1)
    ret = do_file_lock(fd, 5, F_UNLCK);

  (*plock_depth)--;

  if(!ret)
    DEBUG(10,("file_unlock: unlocking file failed, error = %s.\n",
                 strerror(errno)));
  return ret;
}

/****************************************************************************
routine to do file locking
****************************************************************************/
BOOL fcntl_lock(int fd, int op, SMB_OFF_T offset, SMB_OFF_T count, int type)
{
#if HAVE_FCNTL_LOCK
  SMB_STRUCT_FLOCK lock;
  int ret;

  if(lp_ole_locking_compat()) {
    SMB_OFF_T mask2= ((SMB_OFF_T)0x3) << (SMB_OFF_T_BITS-4);
    SMB_OFF_T mask = (mask2<<2);

    /* make sure the count is reasonable, we might kill the lockd otherwise */
    count &= ~mask;

    /* the offset is often strange - remove 2 of its bits if either of
       the top two bits are set. Shift the top ones by two bits. This
       still allows OLE2 apps to operate, but should stop lockd from
       dieing */
    if ((offset & mask) != 0)
      offset = (offset & ~mask) | (((offset & mask) >> 2) & mask2);
  } else {
    SMB_OFF_T mask2 = ((SMB_OFF_T)0x4) << (SMB_OFF_T_BITS-4);
    SMB_OFF_T mask = (mask2<<1);
    SMB_OFF_T neg_mask = ~mask;

    /* interpret negative counts as large numbers */
    if (count < 0)
      count &= ~mask;

    /* no negative offsets */
    if(offset < 0)
      offset &= ~mask;

    /* count + offset must be in range */
    while ((offset < 0 || (offset + count < 0)) && mask)
    {
      offset &= ~mask;
      mask = ((mask >> 1) & neg_mask);
    }
  }

  DEBUG(8,("fcntl_lock %d %d %.0f %.0f %d\n",fd,op,(double)offset,(double)count,type));

  lock.l_type = type;
  lock.l_whence = SEEK_SET;
  lock.l_start = offset;
  lock.l_len = count;
  lock.l_pid = 0;

  errno = 0;

  ret = fcntl(fd,op,&lock);
  if (errno == EFBIG)
  {
    if( DEBUGLVL( 0 ))
    {
      dbgtext("fcntl_lock: WARNING: lock request at offset %.0f, length %.0f returned\n", (double)offset,(double)count);
      dbgtext("a 'file too large' error. This can happen when using 64 bit lock offsets\n");
      dbgtext("on 32 bit NFS mounted file systems. Retrying with 32 bit truncated length.\n");
    }
    /* 32 bit NFS file system, retry with smaller offset */
    errno = 0;
    lock.l_len = count & 0xffffffff;
    ret = fcntl(fd,op,&lock);
  }

  if (errno != 0)
    DEBUG(3,("fcntl lock gave errno %d (%s)\n",errno,strerror(errno)));

  /* a lock query */
  if (op == SMB_F_GETLK)
  {
    if ((ret != -1) &&
        (lock.l_type != F_UNLCK) && 
        (lock.l_pid != 0) && 
        (lock.l_pid != getpid()))
    {
      DEBUG(3,("fd %d is locked by pid %d\n",fd,(int)lock.l_pid));
      return(True);
    }

    /* it must be not locked or locked by me */
    return(False);
  }

  /* a lock set or unset */
  if (ret == -1)
  {
    DEBUG(3,("lock failed at offset %.0f count %.0f op %d type %d (%s)\n",
          (double)offset,(double)count,op,type,strerror(errno)));

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
/***************************************************************
 locks a file for enumeration / modification.
 update to be set = True if modification is required.
****************************************************************/

void *startfileent(char *pfile, char *s_readbuf, int bufsize,
				int *file_lock_depth, BOOL update)
{
  FILE *fp = NULL;

  if (!*pfile)
 {
    DEBUG(0, ("startfileent: No file set\n"));
    return (NULL);
  }
  DEBUG(10, ("startfileent: opening file %s\n", pfile));

  fp = sys_fopen(pfile, update ? "r+b" : "rb");

  if (fp == NULL) {
    DEBUG(0, ("startfileent: unable to open file %s\n", pfile));
    return NULL;
  }

  /* Set a buffer to do more efficient reads */
  setvbuf(fp, s_readbuf, _IOFBF, bufsize);

  if (!file_lock(fileno(fp), (update ? F_WRLCK : F_RDLCK), 5, file_lock_depth))
  {
    DEBUG(0, ("startfileent: unable to lock file %s\n", pfile));
    fclose(fp);
    return NULL;
  }

  /* Make sure it is only rw by the owner */
  chmod(pfile, 0600);

  /* We have a lock on the file. */
  return (void *)fp;
}

/***************************************************************
 End enumeration of the file.
****************************************************************/
void endfileent(void *vp, int *file_lock_depth)
{
  FILE *fp = (FILE *)vp;

  file_unlock(fileno(fp), file_lock_depth);
  fclose(fp);
  DEBUG(7, ("endfileent: closed file.\n"));
}

/*************************************************************************
 Return the current position in the file list as an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/
SMB_BIG_UINT getfilepwpos(void *vp)
{
  return (SMB_BIG_UINT)sys_ftell((FILE *)vp);
}

/*************************************************************************
 Set the current position in the file list from an SMB_BIG_UINT.
 This must be treated as an opaque token.
*************************************************************************/
BOOL setfilepwpos(void *vp, SMB_BIG_UINT tok)
{
  return !sys_fseek((FILE *)vp, (SMB_OFF_T)tok, SEEK_SET);
}

/*************************************************************************
 gets a line out of a file.
 lines with "#" at the front are ignored.
*************************************************************************/
int getfileline(void *vp, char *linebuf, int linebuf_size)
{
	/* Static buffers we will return. */
	FILE *fp = (FILE *)vp;
	unsigned char   c;
	size_t            linebuf_len;

	if (fp == NULL)
	{
		DEBUG(0,("getfileline: Bad file pointer.\n"));
		return -1;
	}

	/*
	 * Scan the file, a line at a time.
	 */
	while (!feof(fp))
	{
		linebuf[0] = '\0';

		fgets(linebuf, linebuf_size, fp);
		if (ferror(fp))
		{
			return -1;
		}

		/*
		 * Check if the string is terminated with a newline - if not
		 * then we must keep reading and discard until we get one.
		 */

		linebuf_len = strlen(linebuf);
		if (linebuf[linebuf_len - 1] != '\n')
		{
			c = '\0';
			while (!ferror(fp) && !feof(fp))
			{
				c = fgetc(fp);
				if (c == '\n')
				{
					break;
				}
			}
		}
		else
		{
			linebuf[linebuf_len - 1] = '\0';
		}

#ifdef DEBUG_PASSWORD
		DEBUG(100, ("getfileline: got line |%s|\n", linebuf));
#endif
		if ((linebuf[0] == 0) && feof(fp))
		{
			DEBUG(4, ("getfileline: end of file reached\n"));
			return 0;
		}

		if (linebuf[0] == '#' || linebuf[0] == '\0')
		{
			DEBUG(6, ("getfileline: skipping comment or blank line\n"));
			continue;
		}

		return linebuf_len;
	}
	return -1;
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
checks if a file has changed since last read
****************************************************************************/
BOOL file_modified(const char *filename, time_t *lastmodified)
{
	SMB_STRUCT_STAT st;

	if (sys_stat(filename, &st) != 0)
	{
		DEBUG(0, ("file_changed: Unable to stat file %s. Error was %s\n",
			  filename, strerror(errno) ));
		return False;
	}

	if(st.st_mtime <= *lastmodified)
	{
		DEBUG(20, ("file_modified: %s not modified\n", filename));
		return False;
	}

	DEBUG(20, ("file_modified: %s modified\n", filename));
	*lastmodified = st.st_mtime;
	return True;
}

/***************************************************************************
opens a file if modified otherwise returns NULL
***************************************************************************/
void *open_file_if_modified(const char *filename, char *mode, time_t *lastmodified)
{
	FILE *f;

	if (!file_modified(filename, lastmodified))
	{
		return NULL;
	}

	if( (f = fopen(filename, mode)) == NULL)
	{
		DEBUG(0, ("open_file_if_modified: can't open file %s. Error was %s\n",
			  filename, strerror(errno)));
		return NULL;
	}

	return (void *)f;
}

