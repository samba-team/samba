/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   SMB client library implementation
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Richard Sharpe 2000
   Copyright (C) John Terpstra 2000
   
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
#include "libsmbclient.h"

/* Structure for servers ... Held here so we don't need an include ...
 * May be better to put in an include file
 */

struct smbc_server {
  struct smbc_server *next, *prev;
  struct cli_state cli;
  dev_t dev;
  char *server_name;
  char *share_name;
  char *workgroup;
  char *username;
  BOOL no_pathinfo2;
};

struct smbc_file {
  int cli_fd; 
  int smbc_fd;
  char *fname;
  off_t offset;
  struct smbc_server *srv;
  BOOL file;
};

static int smbc_initialized = 0;
static smbc_get_auth_data_fn smbc_auth_fn = NULL;
static int smbc_debug;
static int smbc_start_fd;
static int smbc_max_fd = 10000;
static struct smbc_file **smbc_file_table;

/*
 * Clean up a filename by removing redundent stuff 
 */

static void
clean_fname(char *name)
{
  char *p, *p2;
  int l;
  int modified = 1;

  if (!name) return;
  
  while (modified) {
    modified = 0;

    DEBUG(5,("cleaning %s\n", name));

    if ((p=strstr(name,"/./"))) {
      modified = 1;
      while (*p) {
	p[0] = p[2];
	p++;
      }
    }

    if ((p=strstr(name,"//"))) {
      modified = 1;
      while (*p) {
	p[0] = p[1];
	p++;
      }
    }

    if (strcmp(name,"/../")==0) {
      modified = 1;
      name[1] = 0;
    }
    
    if ((p=strstr(name,"/../"))) {
      modified = 1;
      for (p2=(p>name?p-1:p);p2>name;p2--) {
	if (p2[0] == '/') break;
      }
      while (*p2) {
	p2[0] = p2[3];
	p2++;
      }
    }

    if (strcmp(name,"/..")==0) {
      modified = 1;
      name[1] = 0;
    }

    l = strlen(name);
    p = l>=3?(name+l-3):name;
    if (strcmp(p,"/..")==0) {
      modified = 1;
      for (p2=p-1;p2>name;p2--) {
	if (p2[0] == '/') break;
      }
      if (p2==name) {
	p[0] = '/';
	p[1] = 0;
      } else {
	p2[0] = 0;
      }
    }
    
    l = strlen(name);
    p = l>=2?(name+l-2):name;
    if (strcmp(p,"/.")==0) {
      if (p == name) {
	p[1] = 0;
      } else {
	p[0] = 0;
      }
    }
    
    if (strncmp(p=name,"./",2) == 0) {      
      modified = 1;
      do {
	p[0] = p[2];
      } while (*p++);
    }
    
    l = strlen(p=name);
    if (l > 1 && p[l-1] == '/') {
      modified = 1;
      p[l-1] = 0;
    }
  }
}

/*
 * Function to parse a path and turn it into components
 *
 * We accept smb://server/share/path...
 * We also accept //server/share/path ...
 */

static const char *smbc_prefix = "smb:";

static int
smbc_parse_path(const char *fname, char *server, char *share, char *path)
{
  static pstring s;
  char *p;
  int len;
  fstring workgroup;

  pstrcpy(s, fname);

  /*  clean_fname(s);  causing problems ... */

  /* see if it has the right prefix */
  len = strlen(smbc_prefix);
  if (strncmp(s,smbc_prefix,len) || 
      (s[len] != '/' && s[len] != 0)) return -1; /* What about no smb: ? */

  p = s + len;

  /* Watch the test below, we are testing to see if we should exit */

  if (strncmp(p, "//", 2) && strncmp(p, "\\\\", 2)) {

    return -1;

  }

  p += 2;  /* Skip the // or \\ */

  /* ok, its for us. Now parse out the server, share etc. */

  if (!next_token(&p, server, "/", sizeof(fstring))) {

    return -1;

  }
  
  if (!next_token(&p, share, "/", sizeof(fstring))) {

    return -1;

  }
  
  pstrcpy(path, p);
  
  all_string_sub(path, "/", "\\", 0);

  return 0;
}

/*
 * Convert an SMB error into a UNIX error ...
 */

int smbc_errno(struct cli_state *c)
{
	uint8 eclass;
	uint32 ecode;
	int ret;

	ret = cli_error(c, &eclass, &ecode, NULL);

	if (ret) {
		DEBUG(3,("smbc_error %d %d (0x%x) -> %d\n", 
			 (int)eclass, (int)ecode, (int)ecode, ret));
	}
	return ret;
}

/*
 * Connect to a server, possibly on an existing connection
 */

static struct smbc_server *smbc_srvs;
static pstring  my_netbios_name;

struct smbc_server *smbc_server(char *server, char *share)
{
  struct smbc_server *srv=NULL;
  struct cli_state c;
  char *username = NULL;
  char *password = NULL;
  char *workgroup = NULL;
  struct nmb_name called, calling;
  char *p, *server_n = server;
  fstring group;
  pstring ipenv;
  struct in_addr ip;
  extern struct in_addr ipzero;
  
  ip = ipzero;
  ZERO_STRUCT(c);

  smbc_auth_fn(server, share, &workgroup, &username, &password);

  /* try to use an existing connection */
  for (srv=smbc_srvs;srv;srv=srv->next) {
    if (strcmp(server,srv->server_name)==0 &&
	strcmp(share,srv->share_name)==0 &&
	strcmp(workgroup,srv->workgroup)==0 &&
	strcmp(username, srv->username) == 0) 
      return srv;
  }

  if (server[0] == 0) {
    errno = EPERM;
    return NULL;
  }

  make_nmb_name(&calling, my_netbios_name, 0x0);
  make_nmb_name(&called , server, 0x20);

  DEBUG(4,("server_n=[%s] server=[%s]\n", server_n, server));
  
  if ((p=strchr(server_n,'#')) && 
      (strcmp(p+1,"1D")==0 || strcmp(p+1,"01")==0)) {
    struct in_addr sip;
    pstring s;
    
    fstrcpy(group, server_n);
    p = strchr(group,'#');
    *p = 0;
		
  }

  DEBUG(4,(" -> server_n=[%s] server=[%s]\n", server_n, server));

 again:
  slprintf(ipenv,sizeof(ipenv)-1,"HOST_%s", server_n);

  ip = ipzero;

  /* have to open a new connection */
  if (!cli_initialise(&c) || !cli_connect(&c, server_n, &ip)) {
    errno = ENOENT;
    return NULL;
  }

  if (!cli_session_request(&c, &calling, &called)) {
    cli_shutdown(&c);
    if (strcmp(called.name, "*SMBSERVER")) {
      make_nmb_name(&called , "*SMBSERVER", 0x20);
      goto again;
    }
    errno = ENOENT;
    return NULL;
  }
  
  DEBUG(4,(" session request ok\n"));
  
  if (!cli_negprot(&c)) {
    cli_shutdown(&c);
    errno = ENOENT;
    return NULL;
  }

  if (!cli_session_setup(&c, username, 
			 password, strlen(password),
			 password, strlen(password),
			 workgroup) &&
      /* try an anonymous login if it failed */
      !cli_session_setup(&c, "", "", 1,"", 0, workgroup)) {
    cli_shutdown(&c);
    errno = EPERM;
    return NULL;
  }

  DEBUG(4,(" session setup ok\n"));

  if (!cli_send_tconX(&c, share, "?????",
		      password, strlen(password)+1)) {
    errno = smbc_errno(&c);
    cli_shutdown(&c);
    return NULL;
  }
  
  DEBUG(4,(" tconx ok\n"));
  
  srv = (struct smbc_server *)malloc(sizeof(*srv));
  if (!srv) {
    errno = ENOMEM;
    goto failed;
  }

  ZERO_STRUCTP(srv);

  srv->cli = c;

  srv->dev = (dev_t)(str_checksum(server) ^ str_checksum(share));

  srv->server_name = strdup(server);
  if (!srv->server_name) {
    errno = ENOMEM;
    goto failed;
  }

  srv->share_name = strdup(share);
  if (!srv->share_name) {
    errno = ENOMEM;
    goto failed;
  }

  srv->workgroup = strdup(workgroup);
  if (!srv->workgroup) {
    errno = ENOMEM;
    goto failed;
  }

  srv->username = strdup(username);
  if (!srv->username) {
    errno = ENOMEM;
    goto failed;
  }

  DLIST_ADD(smbc_srvs, srv);

  return srv;

 failed:
  cli_shutdown(&c);
  if (!srv) return NULL;
  
  if (srv->server_name) free(srv->server_name);
  if (srv->share_name) free(srv->share_name);
  free(srv);
  return NULL;
}

/*
 *Initialise the library etc 
 */

int smbc_init(smbc_get_auth_data_fn fn, const char *wgroup, int debug)
{
  static pstring workgroup;
  int p, pid;
  char *user = NULL, *host = NULL;

  smbc_initialized = 1;
  smbc_auth_fn = fn;
  smbc_debug = debug;

  /*
   * We try to construct our netbios name from our hostname etc
   */

  user = getenv("USER");
  if (!user) user = "";

  pid = getpid();

  /*
   * Hmmm, I want to get hostname as well, but I am too lazy for the moment
   */

  slprintf(my_netbios_name, 16, "smbc%s%d", user, pid);
  pstrcpy(workgroup, wgroup);

  charset_initialise();

  /* Here we would open the smb.conf file if needed ... */

  /* To do soon ... try $HOME/.smb/smb.conf first ... */

  /* 
   * Now initialize the file descriptor array and figure out what the
   * max open files is, so we can return FD's that are above the max
   * open file, and separated by a guard band
   */

#if (defined(HAVE_GETRLIMIT) && defined(RLIMIT_NOFILE))
  do {
    struct rlimit rlp;

    if (getrlimit(RLIMIT_NOFILE, &rlp)) {

      DEBUG(0, ("smbc_init: getrlimit(1) for RLIMIT_NOFILE failed with error %s\n", strerror(errno)));

      smbc_start_fd = 1000000;
      smbc_max_fd = 10000;     /* FIXME, should be a define ... */

    }
    else {
      
      smbc_start_fd = rlp.rlim_max + 10000; /* Leave a guard space of 10,000 */
      smbc_max_fd = 10000;

    }
  } while ( 0 );
#else /* !defined(HAVE_GETRLIMIT) || !defined(RLIMIT_NOFILE) */

  smbc_start_fd = 1000000;
  smbc_max_fd = 10000;     /* FIXME, should be a define ... */

#endif

  smbc_file_table = malloc(smbc_max_fd * sizeof(struct smbc_file *));

  for (p = 0; p < smbc_max_fd; p++)
    smbc_file_table[p] = NULL;

  if (!smbc_file_table)
    return ENOMEM;

  smbc_start_fd = 100000;  /* FIXME: Figure it out */

  return 0;  /* Success */

}

/*
 * Routine to open() a file ...
 */

int smbc_open(const char *fname, int flags, mode_t mode)
{
  fstring server, share;
  pstring path;
  struct smbc_server *srv = NULL;
  struct smbc_file *file = NULL;
  int fd;

  if (!smbc_initialized) {

    errno = EUCLEAN;  /* Best I can think of ... */
    return -1;

  }

  if (!fname) {

    errno = EINVAL;
    return -1;

  }

  smbc_parse_path(fname, server, share, path); /* FIXME, check errors */

  srv = smbc_server(server, share);

  if (!srv) {

    return -1;  /* smbc_server sets errno */

  }

  if (path[strlen(path) - 1] == '\\') {
    
    fd = -1;

  }
  else {

    int slot = 0;

    /* Find a free slot first */

    while (smbc_file_table[slot])
      slot++;

    if (slot > smbc_max_fd) return ENOMEM; /* FIXME, is this best? */

    smbc_file_table[slot] = malloc(sizeof(struct smbc_file));

    if (!smbc_file_table[slot])
      return ENOMEM;

    fd = cli_open(&srv->cli, path, flags, DENY_NONE);

    /* Fill in file struct */

    smbc_file_table[slot]->cli_fd  = fd;
    smbc_file_table[slot]->smbc_fd = slot + smbc_start_fd;
    smbc_file_table[slot]->fname   = strdup(fname);
    smbc_file_table[slot]->srv     = srv;
    smbc_file_table[slot]->offset  = 0;
    smbc_file_table[slot]->file    = True;

    return smbc_file_table[slot]->smbc_fd;

  }

  /* Check if opendir needed ... */

  if (fd == -1) {
    int eno = 0;

    eno = smbc_errno(&srv->cli);
    fd = smbc_dir_open(fname);
    if (fd < 0) errno = eno;
    return fd;

  }

  return 1;  /* Success, with fd ... */

 failed:

  /*FIXME, clean up things ... */
  return -1;

}

/*
 * Routine to create a file 
 */

static int creat_bits = O_WRONLY | O_CREAT | O_TRUNC; /* FIXME: Do we need this */

int smbc_creat(const char *path, mode_t mode)
{
  return smbc_open(path, creat_bits, mode);
}

/*
 * Routine to read() a file ...
 */

ssize_t smbc_read(int fd, void *buf, size_t count)
{
  struct smbc_file *fe;
  int ret;

  DEBUG(4, ("smbc_read(%d, %d)\n", fd, (int)count));

  if (fd < smbc_start_fd || fd >= (smbc_start_fd + smbc_max_fd)) {

    errno = EBADF;
    return -1;

  }

  fe = smbc_file_table[fd - smbc_start_fd];

  if (!fe->file) {

    errno = EBADF;
    return -1;

  }

  ret = cli_read(&fe->srv->cli, fe->cli_fd, buf, fe->offset, count);

  if (ret < 0) {

    errno = smbc_errno(&fe->srv->cli);
    return -1;

  }

  fe->offset += ret;

  DEBUG(4, ("  --> %d\n", ret));

  return ret;  /* Success, ret bytes of data ... */

}

/*
 * Routine to write() a file ...
 */

ssize_t smbc_write(int fd, void *buf, size_t count)
{
  int ret;
  struct smbc_file *fe;

  if (fd < smbc_start_fd || fd >= (smbc_start_fd + smbc_max_fd)) {

    errno = EBADF;
    return -1;
    
  }

  fe = smbc_file_table[fd - smbc_start_fd];

  ret = cli_write(&fe->srv->cli, fe->cli_fd, 0, buf, fe->offset, count);

  if (ret < 0) {

    errno = smbc_errno(&fe->srv->cli);
    return -1;

  }

  fe->offset += ret;

  return ret;  /* Success, 0 bytes of data ... */
}

/*
 * Routine to close() a file ...
 */

int smbc_close(int fd)
{
  struct smbc_file *fe;

  if (fd < smbc_start_fd || fd >= (smbc_start_fd + smbc_max_fd)) {
   
    errno = EBADF;
    return -1;

  }

  fe = smbc_file_table[fd - smbc_start_fd];

  if (!fe->file) {

    return smbc_closedir(fd);

  }

  if (!cli_close(&fe->srv->cli, fe->cli_fd)) {

    errno = smbc_errno(&fe->srv->cli);  /* FIXME, should we deallocate slot? */
    return -1;

  }

  free(fe);
  smbc_file_table[fd - smbc_start_fd] = NULL;

  return 0;
}

/*
 * Routine to unlink() a file
 */

int smbc_unlink(const char *fname)
{
  fstring server, share;
  pstring path;
  struct smbc_server *srv = NULL;

  if (!smbc_initialized) {

    errno = EUCLEAN;  /* Best I can think of ... */
    return -1;

  }

  if (!fname) {

    errno = EINVAL;
    return -1;

  }

  smbc_parse_path(fname, server, share, path); /* FIXME, check errors */

  srv = smbc_server(server, share);

  if (!srv) {

    return -1;  /* smbc_server sets errno */

  }

  /*  if (strncmp(srv->cli.dev, "LPT", 3) == 0) {

    int job = smbc_stat_printjob(srv, path, NULL, NULL);
    if (job == -1) {

      return -1;

    }
    if (cli_printjob_del(&srv->cli, job) != 0) {

      return -1;

    }
    } else */

  if (!cli_unlink(&srv->cli, path)) {

    errno = smbc_errno(&srv->cli);
    return -1;

  }

  return 0;  /* Success ... */

}

/*
 * Routine to rename() a file
 */

int smbc_rename(const char *oname, const char *nname)
{
  fstring server1, share1, server2, share2;
  pstring path1, path2;
  struct smbc_server *srv = NULL;

  if (!smbc_initialized) {

    errno = EUCLEAN;  /* Best I can think of ... */
    return -1;

  }

  if (!oname || !nname) {

    errno = EINVAL;
    return -1;

  }
  
  DEBUG(4, ("smbc_rename(%s,%s)\n", oname, nname));

  smbc_parse_path(oname, server1, share1, path1);
  smbc_parse_path(nname, server2, share2, path2);

  if (strcmp(server1, server2) || strcmp(share1, share2)) {

    /* Can't rename across file systems */

    errno = EXDEV;
    return -1;

  }

  srv = smbc_server(server1, share1);
  if (!srv) {

    return -1;

  }

  if (!cli_rename(&srv->cli, path1, path2)) {
    int eno = smbc_errno(&srv->cli);

    if (eno != EEXIST ||
	!cli_unlink(&srv->cli, path2) ||
	!cli_rename(&srv->cli, path1, path2)) {

      errno = eno;
      return -1;

    }
  }

  return 0; /* Success */

}

/*
 * A routine to lseek() a file
 */

off_t smbc_lseek(int fd, off_t offset, int whence)
{
  struct smbc_file *fe;
  size_t size;

  if (fd < smbc_start_fd || fd >= (smbc_start_fd + smbc_max_fd)) {

    errno = EBADF;
    return -1;

  }

  fe = smbc_file_table[fd - smbc_start_fd];

  if (!fe->file) {

    return smbc_lseekdir(fd, offset, whence);

  }

  switch (whence) {
  case SEEK_SET:
    fe->offset = offset;
    break;

  case SEEK_CUR:
    fe->offset += offset;
    break;

  case SEEK_END:
    if (!cli_qfileinfo(&fe->srv->cli, fe->cli_fd, NULL, &size, NULL, NULL,
		       NULL, NULL, NULL) &&
	!cli_getattrE(&fe->srv->cli, fe->cli_fd, NULL, &size, NULL, NULL,
		      NULL)) {

      errno = EINVAL;
      return -1;
    }
    fe->offset = size + offset;
    break;

  default:
    errno = EINVAL;
    break;

  }

  return fe->offset;

}

/* 
 * Generate an inode number from file name for those things that need it
 */

static
ino_t smbc_inode(const char *name)
{

  if (!*name) return 2; /* FIXME, why 2 ??? */
  return (ino_t)str_checksum(name);

}

/*
 * Routine to put basic stat info into a stat structure ... Used by stat and
 * fstat below.
 */

static
int smbc_setup_stat(struct stat *st, char *fname, size_t size, int mode)
{

  st->st_mode = 0;

  if (IS_DOS_DIR(mode)) {
    st->st_mode = SMBC_DIR_MODE;
  } else {
    st->st_mode = SMBC_FILE_MODE;
  }

  if (IS_DOS_ARCHIVE(mode)) st->st_mode |= S_IXUSR;
  if (IS_DOS_SYSTEM(mode)) st->st_mode |= S_IXGRP;
  if (IS_DOS_HIDDEN(mode)) st->st_mode |= S_IXOTH;
  if (!IS_DOS_READONLY(mode)) st->st_mode |= S_IWUSR;

  st->st_size = size;
  st->st_blksize = 512;
  st->st_blocks = (size+511)/512;
  st->st_uid = getuid();
  st->st_gid = getgid();

  if (IS_DOS_DIR(mode)) {
    st->st_nlink = 2;
  } else {
    st->st_nlink = 1;
  }

  if (st->st_ino == 0) {
    st->st_ino = smbc_inode(fname);
  }
}

/*
 * Get info from an SMB server on a file. Use a qpathinfo call first
 * and if that fails, use getatr, as Win95 sometimes refuses qpathinfo
 */

BOOL smbc_getatr(struct smbc_server *srv, char *path, 
		 uint16 *mode, size_t *size, 
		 time_t *c_time, time_t *a_time, time_t *m_time,
		 SMB_INO_T *ino)
{
  DEBUG(4,("sending qpathinfo\n"));
  
  if (!srv->no_pathinfo2 &&
      cli_qpathinfo2(&srv->cli, path, c_time, a_time, m_time, NULL,
		     size, mode, ino)) return True;

  /* if this is NT then don't bother with the getatr */
  if (srv->cli.capabilities & CAP_NT_SMBS) return False;

  if (cli_getatr(&srv->cli, path, mode, size, m_time)) {
    a_time = c_time = m_time;
    srv->no_pathinfo2 = True;
    return True;
  }
  return False;
}

/*
 * Routine to stat a file given a name
 */

int smbc_stat(const char *fname, struct stat *st)
{
  struct smbc_server *srv;
  fstring server, share;
  pstring path;
  time_t m_time = 0, a_time = 0, c_time = 0;
  size_t size = 0;
  uint16 mode = 0;
  SMB_INO_T ino = 0;

  if (!smbc_initialized) {

    errno = EUCLEAN;  /* Best I can think of ... */
    return -1;

  }

  if (!fname) {

    errno = EINVAL;
    return -1;

  }
  
  DEBUG(4, ("stat(%s)\n", fname));

  smbc_parse_path(fname, server, share, path);

  srv = smbc_server(server, share);

  if (!srv) {

    return -1;  /* errno set by smbc_server */

  }

  /* if (strncmp(srv->cli.dev, "IPC", 3) == 0) {

     mode = aDIR | aRONLY;

     }
     else if (strncmp(srv->cli.dev, "LPT", 3) == 0) {

       if (strcmp(path, "\\") == 0) {

          mode = aDIR | aRONLY;

       }
       else {

         mode = aRONLY;
	 smbc_stat_printjob(srv, path, &size, &m_time);
	 c_time = a_time = m_time;

       }
       else { */

  if (!smbc_getatr(srv, path, &mode, &size, 
		   &c_time, &a_time, &m_time, &ino)) {

    errno = smbc_errno(&srv->cli);
    return -1;

  }

  /* } */

  st->st_ino = ino;

  smbc_setup_stat(st, path, size, mode);

  st->st_atime = a_time;
  st->st_ctime = c_time;
  st->st_mtime = m_time;
  st->st_dev   = srv->dev;

  return 0;

}

/*
 * Routine to stat a file given an fd
 */

int smbc_fstat(int fd, struct stat *st)
{
  struct smbc_file *fe;
  time_t c_time, a_time, m_time;
  size_t size;
  uint16 mode;
  SMB_INO_T ino = 0;

  if (fd < smbc_start_fd || fd >= (smbc_start_fd + smbc_max_fd)) {

    errno = EBADF;
    return -1;

  }

  fe = smbc_file_table[fd - smbc_start_fd];

  if (!fe->file) {

    return smbc_fstatdir(fd, st);

  }

  if (!cli_qfileinfo(&fe->srv->cli, fe->cli_fd,
		     &mode, &size, &c_time, &a_time, &m_time, NULL, &ino) &&
      !cli_getattrE(&fe->srv->cli, fe->cli_fd,
		    &mode, &size, &c_time, &a_time, &m_time)) {

    errno = EINVAL;
    return -1;

  }

  st->st_ino = ino;

  smbc_setup_stat(st, fe->fname, size, mode);

  st->st_atime = a_time;
  st->st_ctime = c_time;
  st->st_mtime = m_time;
  st->st_dev = fe->srv->dev;

  return 0;

}

/*
 * Routine to open a directory
 */

int smbc_dir_open(const char *fname)
{

  return 0;

}

/*
 * Routine to close a directory
 */

int smbc_closedir(int fd)
{

  return 0;

}

/*
 * Routine to get a directory entry
 */

int smbc_getdents(unsigned int fd, struct dirent *dirp, int count)
{

  return 0;

}

/*
 * Routine to create a directory ...
 */

int smbc_mkdir(const char *fname, mode_t mode)
{

}

/*
 * Routine to seek on a directory
 */

int smbc_lseekdir(int fd, off_t offset, int whence)
{

  return 0;

}

/*
 * Routine to fstat a dir
 */

int smbc_fstatdir(int fd, struct stat *st)
{

  return 0;

}
