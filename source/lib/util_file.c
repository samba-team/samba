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

  alarm(waitsecs);
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
 Pathetically try and map a 64 bit lock offset into 31 bits. I hate Windows :-).
****************************************************************************/
uint32 map_lock_offset(uint32 high, uint32 low)
{
	unsigned int i;
	uint32 mask = 0;
	uint32 highcopy = high;

	/*
	 * Try and find out how many significant bits there are in high.
	 */

	for (i = 0; highcopy; i++)
		highcopy >>= 1;

	/*
	 * We use 31 bits not 32 here as POSIX
	 * lock offsets may not be negative.
	 */

	mask = (~0) << (31 - i);

	if (low & mask)
		return 0;	/* Fail. */

	high <<= (31 - i);

	return (high | low);
}

/****************************************************************************
 Get a lock count, dealing with large count requests.
****************************************************************************/
SMB_BIG_UINT get_lock_count(char *data, int data_offset,
			    BOOL large_file_format)
{
	SMB_BIG_UINT count = 0;

	if (!large_file_format)
	{
		count =
			(SMB_BIG_UINT) IVAL(data,
					    SMB_LKLEN_OFFSET(data_offset));
	}
	else
	{

#if defined(HAVE_LONGLONG)
		count =
			(((SMB_BIG_UINT)
			  IVAL(data,
			       SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset))) <<
			 32) | ((SMB_BIG_UINT)
				IVAL(data,
				     SMB_LARGE_LKLEN_OFFSET_LOW
				     (data_offset)));
#else /* HAVE_LONGLONG */

		/*
		 * NT4.x seems to be broken in that it sends large file (64 bit)
		 * lockingX calls even if the CAP_LARGE_FILES was *not*
		 * negotiated. For boxes without large unsigned ints truncate the
		 * lock count by dropping the top 32 bits.
		 */

		if (IVAL(data, SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset)) != 0)
		{
			DEBUG(3,
			      ("get_lock_count: truncating lock count (high)0x%x (low)0x%x to just low count.\n",
			       (unsigned int)IVAL(data,
						  SMB_LARGE_LKLEN_OFFSET_HIGH
						  (data_offset)),
			       (unsigned int)IVAL(data,
						  SMB_LARGE_LKLEN_OFFSET_LOW
						  (data_offset))));
			SIVAL(data, SMB_LARGE_LKLEN_OFFSET_HIGH(data_offset),
			      0);
		}

		count =
			(SMB_BIG_UINT) IVAL(data,
					    SMB_LARGE_LKLEN_OFFSET_LOW
					    (data_offset));
#endif /* HAVE_LONGLONG */
	}

	return count;
}

/****************************************************************************
 Get a lock offset, dealing with large offset requests.
****************************************************************************/

SMB_BIG_UINT get_lock_offset(char *data, int data_offset,
			     BOOL large_file_format, BOOL *err)
{
	SMB_BIG_UINT offset = 0;

	*err = False;

	if (!large_file_format)
	{
		offset =
			(SMB_BIG_UINT) IVAL(data,
					    SMB_LKOFF_OFFSET(data_offset));
	}
	else
	{

#if defined(HAVE_LONGLONG)
		offset =
			(((SMB_BIG_UINT)
			  IVAL(data,
			       SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset))) <<
			 32) | ((SMB_BIG_UINT)
				IVAL(data,
				     SMB_LARGE_LKOFF_OFFSET_LOW
				     (data_offset)));
#else /* HAVE_LONGLONG */

		/*
		 * NT4.x seems to be broken in that it sends large file (64 bit)
		 * lockingX calls even if the CAP_LARGE_FILES was *not*
		 * negotiated. For boxes without large unsigned ints mangle the
		 * lock offset by mapping the top 32 bits onto the lower 32.
		 */

		if (IVAL(data, SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset)) != 0)
		{
			uint32 low =
				IVAL(data,
				     SMB_LARGE_LKOFF_OFFSET_LOW(data_offset));
			uint32 high =
				IVAL(data,
				     SMB_LARGE_LKOFF_OFFSET_HIGH
				     (data_offset));
			uint32 new_low = 0;

			if ((new_low = map_lock_offset(high, low)) == 0)
			{
				*err = True;
				return (SMB_BIG_UINT) - 1;
			}

			DEBUG(3,
			      ("get_lock_offset: truncating lock offset (high)0x%x (low)0x%x to offset 0x%x.\n",
			       (unsigned int)high, (unsigned int)low,
			       (unsigned int)new_low));
			SIVAL(data, SMB_LARGE_LKOFF_OFFSET_HIGH(data_offset),
			      0);
			SIVAL(data, SMB_LARGE_LKOFF_OFFSET_LOW(data_offset),
			      new_low);
		}

		offset =
			(SMB_BIG_UINT) IVAL(data,
					    SMB_LARGE_LKOFF_OFFSET_LOW
					    (data_offset));
#endif /* HAVE_LONG_LONG */
	}

	return offset;
}

/****************************************************************************
routine to do file locking
****************************************************************************/

BOOL fcntl_lock(int fd, int op, SMB_OFF_T offset, SMB_OFF_T count, int type)
{
#if HAVE_FCNTL_LOCK
  SMB_STRUCT_FLOCK lock;
  int ret;

#if defined(LARGE_SMB_OFF_T)
  /*
   * In the 64 bit locking case we store the original
   * values in case we have to map to a 32 bit lock on
   * a filesystem that doesn't support 64 bit locks.
   */
  SMB_OFF_T orig_offset = offset;
  SMB_OFF_T orig_count = count;
#endif /* LARGE_SMB_OFF_T */

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
    lock.l_len = count & 0x7fffffff;
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

#if defined(LARGE_SMB_OFF_T)
      {
        /*
         * Ok - if we get here then we have a 64 bit lock request
         * that has returned EINVAL. Try and map to 31 bits for offset
         * and length and try again. This may happen if a filesystem
         * doesn't support 64 bit offsets (efs/ufs) although the underlying
         * OS does.
         */
        uint32 off_low = (orig_offset & 0xFFFFFFFF);
        uint32 off_high = ((orig_offset >> 32) & 0xFFFFFFFF);

        lock.l_len = (orig_count & 0x7FFFFFFF);
        lock.l_start = (SMB_OFF_T)map_lock_offset(off_high, off_low);
        ret = fcntl(fd,op,&lock);
        if (ret == -1)
        {
          if (errno == EINVAL)
          {
            DEBUG(3,("locking not supported? returning True\n"));
            return(True);
          }
          return False;
        }
        DEBUG(3,("64 -> 32 bit modified lock call successful\n"));
        return True;
      }
#else /* LARGE_SMB_OFF_T */
      DEBUG(3,("locking not supported? returning True\n"));
      return(True);
#endif /* LARGE_SMB_OFF_T */
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

/*******************************************************************
returns the size in bytes of the named file
********************************************************************/
SMB_OFF_T get_file_size(char *file_name)
{
	SMB_STRUCT_STAT buf;
	buf.st_size = 0;
	if (sys_stat(file_name, &buf) != 0)
		return (SMB_OFF_T) - 1;
	return (buf.st_size);
}

/***************************************************************
 Internal fn to enumerate the smbpasswd list. Returns a void pointer
 to ensure no modification outside this module. Checks for atomic
 rename of smbpasswd file on update or create once the lock has
 been granted to prevent race conditions. JRA.
****************************************************************/

void *startfilepw_race_condition_avoid(const char *pfile, enum pwf_access_type type, int *lock_depth)
{
  FILE *fp = NULL;
  const char *open_mode = NULL;
  int race_loop = 0;
  int lock_type;

  if (!*pfile) {
    DEBUG(0, ("startfilepw_race_condition_avoid: No SMB password file set\n"));
    return (NULL);
  }

  switch(type) {
  case PWF_READ:
    open_mode = "rb";
    lock_type = F_RDLCK;
    break;
  case PWF_UPDATE:
    open_mode = "r+b";
    lock_type = F_WRLCK;
    break;
  case PWF_CREATE:
    /*
     * Ensure atomic file creation.
     */
    {
      int i, fd = -1;

      for(i = 0; i < 5; i++) {
        if((fd = sys_open(pfile, O_CREAT|O_TRUNC|O_EXCL|O_RDWR, 0600))!=-1)
          break;
        sys_usleep(200); /* Spin, spin... */
      }
      if(fd == -1) {
        DEBUG(0,("startfilepw_race_condition_avoid: too many race conditions creating file %s\n", pfile));
        return NULL;
      }
      close(fd);
      open_mode = "r+b";
      lock_type = F_WRLCK;
      break;
    }
  }

  for(race_loop = 0; race_loop < 5; race_loop++) {
    DEBUG(10, ("startfilepw_race_condition_avoid: opening file %s\n", pfile));

    if((fp = sys_fopen(pfile, open_mode)) == NULL) {
      DEBUG(0, ("startfilepw_race_condition_avoid: unable to open file %s. Error was %s\n", pfile, strerror(errno) ));
      return NULL;
    }

    if (!file_lock(fileno(fp), lock_type, 5, lock_depth)) {
      DEBUG(0, ("startfilepw_race_condition_avoid: unable to lock file %s. Error was %s\n", pfile, strerror(errno) ));
      fclose(fp);
      return NULL;
    }

    /*
     * Only check for replacement races on update or create.
     * For read we don't mind if the data is one record out of date.
     */

    if(type == PWF_READ) {
      break;
    } else {
      SMB_STRUCT_STAT sbuf1, sbuf2;

      /*
       * Avoid the potential race condition between the open and the lock
       * by doing a stat on the filename and an fstat on the fd. If the
       * two inodes differ then someone did a rename between the open and
       * the lock. Back off and try the open again. Only do this 5 times to
       * prevent infinate loops. JRA.
       */

      if (sys_stat(pfile,&sbuf1) != 0) {
        DEBUG(0, ("startfilepw_race_condition_avoid: unable to stat file %s. Error was %s\n", pfile, strerror(errno)));
        file_unlock(fileno(fp), lock_depth);
        fclose(fp);
        return NULL;
      }

      if (sys_fstat(fileno(fp),&sbuf2) != 0) {
        DEBUG(0, ("startfilepw_race_condition_avoid: unable to fstat file %s. Error was %s\n", pfile, strerror(errno)));
        file_unlock(fileno(fp), lock_depth);
        fclose(fp);
        return NULL;
      }

      if( sbuf1.st_ino == sbuf2.st_ino) {
        /* No race. */
        break;
      }

      /*
       * Race occurred - back off and try again...
       */

      file_unlock(fileno(fp), lock_depth);
      fclose(fp);
    }
  }

  if(race_loop == 5) {
    DEBUG(0, ("startfilepw_race_condition_avoid: too many race conditions opening file %s\n", pfile));
    return NULL;
  }

  /* Set a buffer to do more efficient reads */
  setvbuf(fp, (char *)NULL, _IOFBF, 1024);

  /* Make sure it is only rw by the owner */
  if(fchmod(fileno(fp), S_IRUSR|S_IWUSR) == -1) {
    DEBUG(0, ("startfilepw_race_condition_avoid: failed to set 0600 permissions on password file %s. \
Error was %s\n.", pfile, strerror(errno) ));
    file_unlock(fileno(fp), lock_depth);
    fclose(fp);
    return NULL;
  }

  /* We have a lock on the file. */
  return (void *)fp;
}


/***************************************************************
 End enumeration of the smbpasswd list.
****************************************************************/

void endfilepw_race_condition_avoid(void *vp, int *lock_depth)
{
  FILE *fp = (FILE *)vp;

  file_unlock(fileno(fp), lock_depth);
  fclose(fp);
  DEBUG(7, ("endfilepw_race_condition_avoid: closed password file.\n"));
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
load from a pipe into memory
****************************************************************************/
char *file_pload(char *syscmd, size_t *size)
{
	int fd, n;
	char *p;
	pstring buf;
	size_t total;
	
	fd = sys_popen(syscmd);
	if (fd == -1) return NULL;

	p = NULL;
	total = 0;

	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		p = Realloc(p, total + n + 1);
		if (!p) {
			close(fd);
			return NULL;
		}
		memcpy(p+total, buf, n);
		total += n;
	}
	p[total] = 0;

	sys_pclose(fd);

	if (size) *size = total;

	return p;
}


/****************************************************************************
load a file into memory
****************************************************************************/
char *file_load(char *fname, size_t *size)
{
	int fd;
	SMB_STRUCT_STAT sbuf;
	char *p;

	if (!fname || !*fname) return NULL;
	
	fd = open(fname,O_RDONLY);
	if (fd == -1) return NULL;

	if (sys_fstat(fd, &sbuf) != 0) return NULL;

	if (sbuf.st_size == 0) return NULL;

	p = (char *)malloc(sbuf.st_size+1);
	if (!p) return NULL;

	if (read(fd, p, sbuf.st_size) != sbuf.st_size) {
		free(p);
		return NULL;
	}
	p[sbuf.st_size] = 0;

	close(fd);

	if (size) *size = sbuf.st_size;

	return p;
}


/****************************************************************************
parse a buffer into lines
****************************************************************************/
static char **file_lines_parse(char *p, size_t size, int *numlines)
{
	int i;
	char *s, **ret;

	if (!p) return NULL;

	for (s = p, i=0; s < p+size; s++) {
		if (s[0] == '\n') i++;
	}

	ret = (char **)malloc(sizeof(ret[0])*(i+2));
	if (!ret) {
		free(p);
		return NULL;
	}	
	memset(ret, 0, sizeof(ret[0])*(i+2));
	if (numlines) *numlines = i;

	ret[0] = p;
	for (s = p, i=0; s < p+size; s++) {
		if (s[0] == '\n') {
			s[0] = 0;
			i++;
			ret[i] = s+1;
		}
		if (s[0] == '\r') s[0] = 0;
	}

	return ret;
}


/****************************************************************************
load a file into memory and return an array of pointers to lines in the file
must be freed with file_lines_free()
****************************************************************************/
char **file_lines_load(char *fname, int *numlines)
{
	char *p;
	size_t size;

	p = file_load(fname, &size);
	if (!p) return NULL;

	return file_lines_parse(p, size, numlines);
}


/****************************************************************************
load a pipe into memory and return an array of pointers to lines in the data
must be freed with file_lines_free()
****************************************************************************/
char **file_lines_pload(char *syscmd, int *numlines)
{
	char *p;
	size_t size;

	p = file_pload(syscmd, &size);
	if (!p) return NULL;

	return file_lines_parse(p, size, numlines);
}

/****************************************************************************
free lines loaded with file_lines_load
****************************************************************************/
void file_lines_free(char **lines)
{
	if (!lines) return;
	free(lines[0]);
	free(lines);
}


/****************************************************************************
take a lislist of lines and modify them to produce a list where \ continues
a line
****************************************************************************/
void file_lines_slashcont(char **lines)
{
	int i, j;

	for (i=0; lines[i];) {
		int len = strlen(lines[i]);
		if (lines[i][len-1] == '\\') {
			lines[i][len-1] = ' ';
			if (lines[i+1]) {
				char *p = &lines[i][len];
				while (p < lines[i+1]) *p++ = ' ';
				for (j = i+1; lines[j]; j++) lines[j] = lines[j+1];
			}
		} else {
			i++;
		}
	}
}
