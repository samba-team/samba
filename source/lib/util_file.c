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
  /* Note we must *NOT* use sys_fcntl here ! JRA */
  ret = fcntl(fd, SMB_F_SETLKW, &lock);
  alarm(0);
  CatchSignal(SIGALRM, SIGNAL_CAST SIG_IGN);

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

/***************************************************************
 locks a file for enumeration / modification.
 update to be set = True if modification is required.
****************************************************************/

void *startfilepwent(char *pfile, char *s_readbuf, int bufsize,
				int *file_lock_depth, BOOL update)
{
  FILE *fp = NULL;

  if (!*pfile)
 {
    DEBUG(0, ("startfilepwent: No file set\n"));
    return (NULL);
  }
  DEBUG(10, ("startfilepwent: opening file %s\n", pfile));

  fp = sys_fopen(pfile, update ? "r+b" : "rb");

  if (fp == NULL) {
    DEBUG(0, ("startfilepwent: unable to open file %s\n", pfile));
    return NULL;
  }

  /* Set a buffer to do more efficient reads */
  setvbuf(fp, s_readbuf, _IOFBF, bufsize);

  if (!file_lock(fileno(fp), (update ? F_WRLCK : F_RDLCK), 5, file_lock_depth))
  {
    DEBUG(0, ("startfilepwent: unable to lock file %s\n", pfile));
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
void endfilepwent(void *vp, int *file_lock_depth)
{
  FILE *fp = (FILE *)vp;

  file_unlock(fileno(fp), file_lock_depth);
  fclose(fp);
  DEBUG(7, ("endfilepwent: closed file.\n"));
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
 line is of format "xxxx:xxxxxx:xxxxx:".
 lines with "#" at the front are ignored.
*************************************************************************/
int getfileline(void *vp, char *linebuf, int linebuf_size)
{
	/* Static buffers we will return. */
	FILE *fp = (FILE *)vp;
	unsigned char   c;
	unsigned char  *p;
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
		if (linebuf_len == 0)
		{
			linebuf[0] = '\0';
			return 0;
		}

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

		p = (unsigned char *) strchr(linebuf, ':');
		if (p == NULL)
		{
			DEBUG(0, ("getfileline: malformed line entry (no :)\n"));
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

  if (maxlen <2) return(NULL);

  if (!s2)
    {
      char *t;

      maxlen = MIN(maxlen,8);
      t = (char *)Realloc(s,maxlen);
      if (!t) {
        DEBUG(0,("fgets_slash: failed to expand buffer!\n"));
        SAFE_FREE(s);
        return(NULL);
      } else
        s = t;
    }

  if (!s)
    return(NULL);

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
	    SAFE_FREE(s);
	  return(len>0?s:NULL);
	case ' ':
	  if (start_of_line)
	    break;
	default:
	  start_of_line = False;
	  s[len++] = c;
	  s[len] = 0;
	}
      if (!s2 && len > maxlen-3) {
        char *t;

        maxlen *= 2;
        t = (char *)Realloc(s,maxlen);
        if (!t) {
          DEBUG(0,("fgets_slash: failed to expand buffer!\n"));
          SAFE_FREE(s);
          return(NULL);
        } else
          s = t;
      }
    }
  return(s);
}


/****************************************************************************
load from a pipe into memory
****************************************************************************/
char *file_pload(const char *syscmd, size_t *size)
{
	int fd, n;
	char *p, *tp;
	pstring buf;
	size_t total;
	
	fd = sys_popen(syscmd);
	if (fd == -1) return NULL;

	p = NULL;
	total = 0;

	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		tp = Realloc(p, total + n + 1);
		if (!tp) {
			DEBUG(0,("file_pload: failed to exand buffer!\n"));
			close(fd);
			SAFE_FREE(p);
			return NULL;
		} else
			p = tp;
		memcpy(p+total, buf, n);
		total += n;
	}
	if (p) p[total] = 0;

	sys_pclose(fd);

	if (size) *size = total;

	return p;
}

/****************************************************************************
load a file into memory from a fd.
****************************************************************************/ 

char *fd_load(int fd, size_t *size)
{
	SMB_STRUCT_STAT sbuf;
	char *p;

	if (sys_fstat(fd, &sbuf) != 0) return NULL;

	p = (char *)malloc(sbuf.st_size+1);
	if (!p) return NULL;

	if (read(fd, p, sbuf.st_size) != sbuf.st_size) {
		SAFE_FREE(p);
		return NULL;
	}
	p[sbuf.st_size] = 0;

	if (size) *size = sbuf.st_size;

	return p;
}

/****************************************************************************
load a file into memory
****************************************************************************/
char *file_load(const char *fname, size_t *size)
{
	int fd;
	char *p;

	if (!fname || !*fname) return NULL;
	
	fd = open(fname,O_RDONLY);
	if (fd == -1) return NULL;

	p = fd_load(fd, size);

	close(fd);

	return p;
}


/****************************************************************************
parse a buffer into lines
****************************************************************************/
static char **file_lines_parse(char *p, size_t size, int *numlines, BOOL convert)
{
	int i;
	char *s, **ret;

	if (!p) return NULL;

	for (s = p, i=0; s < p+size; s++) {
		if (s[0] == '\n') i++;
	}

	ret = (char **)malloc(sizeof(ret[0])*(i+2));
	if (!ret) {
		SAFE_FREE(p);
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

	if (convert) {
		for (i = 0; ret[i]; i++)
			unix_to_dos(ret[i]);
	}

	return ret;
}


/****************************************************************************
load a file into memory and return an array of pointers to lines in the file
must be freed with file_lines_free(). If convert is true calls unix_to_dos on
the list.
****************************************************************************/
char **file_lines_load(const char *fname, int *numlines, BOOL convert)
{
	char *p;
	size_t size;

	p = file_load(fname, &size);
	if (!p) return NULL;

	return file_lines_parse(p, size, numlines, convert);
}

/****************************************************************************
load a fd into memory and return an array of pointers to lines in the file
must be freed with file_lines_free(). If convert is true calls unix_to_dos on
the list.
****************************************************************************/
char **fd_lines_load(int fd, int *numlines, BOOL convert)
{
	char *p;
	size_t size;

	p = fd_load(fd, &size);
	if (!p) return NULL;

	return file_lines_parse(p, size, numlines, convert);
}


/****************************************************************************
load a pipe into memory and return an array of pointers to lines in the data
must be freed with file_lines_free(). If convert is true calls unix_to_dos on
the list.
****************************************************************************/
char **file_lines_pload(const char *syscmd, int *numlines, BOOL convert)
{
	char *p;
	size_t size;

	p = file_pload(syscmd, &size);
	if (!p) return NULL;

	return file_lines_parse(p, size, numlines, convert);
}

/****************************************************************************
free lines loaded with file_lines_load
****************************************************************************/
void file_lines_free(char **lines)
{
	if (!lines) return;
	SAFE_FREE(lines[0]);
	SAFE_FREE(lines);
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
