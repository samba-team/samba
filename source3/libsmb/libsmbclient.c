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

/* Keep directory entries in a list */
struct smbc_dir_list {
  struct smbc_dir_list *next;
  struct smbc_dirent *dirent;
};

struct smbc_file {
  int cli_fd; 
  int smbc_fd;
  char *fname;
  off_t offset;
  struct smbc_server *srv;
  BOOL file;
  struct smbc_dir_list *dir_list, *dir_end, *dir_next;
  int dir_type, dir_error;
};

extern BOOL in_client;
static int smbc_initialized = 0;
static smbc_get_auth_data_fn smbc_auth_fn = NULL;
static int smbc_debug;
static int smbc_start_fd;
static int smbc_max_fd = 10000;
static struct smbc_file **smbc_file_table;
static struct smbc_server *smbc_srvs;
static pstring  my_netbios_name;

/*
 * Clean up a filename by removing redundent stuff 
 */

static void
smbc_clean_fname(char *name)
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
 * We accept smb://[[[domain;]user[:password@]]server[/share[/path[/file]]]]
 * 
 * smb://       means show all the workgroups
 * smb://name/  means, if name<1D> exists, list servers in workgroup,
 *              else, if name<20> exists, list all shares for server ...
 */

static const char *smbc_prefix = "smb:";

static int
smbc_parse_path(const char *fname, char *server, char *share, char *path)
{
  static pstring s;
  char *p;
  int len;
  fstring workgroup;

  server[0] = share[0] = path[0] = (char)0;
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

  p += 2;  /* Skip the // or \\  */

  if (*p == (char)0)
    return 0;

  if (*p == '/') {

    strncpy(server, lp_workgroup(), 16); /* FIXME: Danger here */
    return 0;

  }

  /* ok, its for us. Now parse out the server, share etc. */

  if (!next_token(&p, server, "/", sizeof(fstring))) {

    return -1;

  }

  if (*p == (char)0) return 0;  /* That's it ... */
  
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

  if (strncmp(share, "IPC$", 4))  /* IPC$ should not need a pwd ... */
    smbc_auth_fn(server, share, &workgroup, &username, &password);
  else {

    workgroup = lp_workgroup();  /* Is this relevant here? */
    username = "";
    password = "";

  }

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
  pstring conf;
  int p, pid;
  char *user = NULL, *host = NULL, *home = NULL;

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

  home = getenv("HOME");

  slprintf(conf, sizeof(conf), "%s/.smb/smb.conf", home);

    load_interfaces();  /* Load the list of interfaces ... */

  in_client = True; /* FIXME, make a param */

  

  if (!lp_load(conf, True, False, False)) {

    /*
     * Hmmm, what the hell do we do here ... we could not parse the
     * config file ... We must return an error ... and keep info around
     * about why we failed
     */
    /*
    errno = ENOENT; /* Hmmm, what error resp does lp_load return ? */
    return -1;

  }

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

    if (slot > smbc_max_fd) {

      errno = ENOMEM; /* FIXME, is this best? */
      return -1;

    }

    smbc_file_table[slot] = malloc(sizeof(struct smbc_file));

    if (!smbc_file_table[slot]) {

      errno = ENOMEM;
      return -1;

    }

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
    fd = smbc_opendir(fname);
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

  if (!smbc_initialized) {

    errno = EUCLEAN;
    return -1;

  }

  return smbc_open(path, creat_bits, mode);
}

/*
 * Routine to read() a file ...
 */

ssize_t smbc_read(int fd, void *buf, size_t count)
{
  struct smbc_file *fe;
  int ret;

  if (!smbc_initialized) {

    errno = EUCLEAN;
    return -1;

  }

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

  if (!smbc_initialized) {

    errno = EUCLEAN;
    return -1;

  }

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

  if (!smbc_initialized) {

    errno = EUCLEAN;
    return -1;

  }

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

  if (!smbc_initialized) {

    errno = EUCLEAN;
    return -1;

  }

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

  if (!smbc_initialized) {

    errno = EUCLEAN;
    return -1;

  }

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

  if (!smbc_initialized) {

    errno = EUCLEAN;
    return -1;

  }

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
 *
 * We want to allow:
 *
 * smb: which should list all the workgroups available
 * smb:workgroup
 * smb:workgroup//server
 * smb://server
 * smb://server/share
 */

static void smbc_remove_dir(struct smbc_file *dir)
{
  struct smbc_dir_list *d,*f;

  d = dir->dir_list;
  while (d) {

    f = d; d = d->next;

    if (f->dirent) free(f->dirent);
    free(f);

  }

  dir->dir_list = dir->dir_end = dir->dir_next = NULL;

}

static int add_dirent(struct smbc_file *dir, const char *name, const char *comment, uint32 type)
{
  struct smbc_dirent *dirent;
  int size;

  /*
   * Allocate space for the dirent, which must be increased by the 
   * size of the name and the comment and 1 for the null on the comment.
   * The null on the name is already accounted for.
   */

  size = sizeof(struct smbc_dirent) + (name?strlen(name):0) +
    (comment?strlen(comment):0) + 1; 
    
  dirent = malloc(size);

  if (!dirent) {

    dir->dir_error = ENOMEM;
    return -1;

  }

  if (dir->dir_list == NULL) {

    dir->dir_list = malloc(sizeof(struct smbc_dir_list));
    if (!dir->dir_list) {

      free(dirent);
      dir->dir_error = ENOMEM;
      return -1;

    }

    dir->dir_end = dir->dir_next = dir->dir_list;

  }
  else {

    dir->dir_end->next = malloc(sizeof(struct smbc_dir_list));

    if (!dir->dir_end) {

      free(dirent);
      dir->dir_error = ENOMEM;
      return -1;

    }

    dir->dir_end = dir->dir_end->next;
    dir->dir_end->next = NULL;

  }

  dir->dir_end->dirent = dirent;

  dirent->smbc_type = type;
  dirent->namelen = (name?strlen(name):0);
  dirent->commentlen = (comment?strlen(comment):0);
  dirent->dirlen = size;
  
  strncpy(dirent->name, (name?name:""), dirent->namelen + 1);

  dirent->comment = (char *)(&dirent->name + dirent->namelen + 1);
  strncpy(dirent->comment, (comment?comment:""), dirent->commentlen + 1);

  return 0;

}

static void
list_fn(const char *name, uint32 type, const char *comment, void *state)
{
  struct smbc_file *dir = (struct smbc_file *)state;
  int dirent_type;

  /* We need to process the type a little ... */

  if (dir->dir_type == SMBC_FILE_SHARE) {

    switch (type) {
    case 0: /* Directory tree */
      dirent_type = SMBC_FILE_SHARE;
      break;

    case 1:
      dirent_type = SMBC_PRINTER_SHARE;
      break;

    case 2:
      dirent_type = SMBC_COMMS_SHARE;
      break;

    case 3:
      dirent_type = SMBC_IPC_SHARE;
      break;

    default:
      dirent_type = SMBC_FILE_SHARE; /* FIXME, error? */
      break;
    }

  }
  else dirent_type = dir->dir_type;

  if (add_dirent(dir, name, comment, dirent_type) < 0) {

    /* An error occurred, what do we do? */

  }

}

static void
dir_list_fn(file_info *finfo, const char *mask, void *state)
{

  fprintf(stderr, "Finfo->name=%s, mask=%s\n", finfo->name, mask);
  if (add_dirent((struct smbc_file *)state, finfo->name, "", 
		 (finfo->mode&aDIR?SMBC_DIR:SMBC_FILE)) < 0) {

    /* Handle an error ... */

  } 

}

int smbc_opendir(const char *fname)
{
  struct in_addr addr;
  fstring server, share;
  pstring path;
  struct smbc_server *srv = NULL;
  struct in_addr rem_ip;
  int slot = 0;

  if (!smbc_initialized) {

    errno = EUCLEAN;
    return -1;

  }

  if (!fname) {
    
    errno = EINVAL;
    return -1;

  }

  if (smbc_parse_path(fname, server, share, path)) {

    errno = EINVAL;
    return -1;

  }

  /* Get a file entry ... */

  slot = 0;

  while (smbc_file_table[slot])
    slot++;

  if (slot > smbc_max_fd) {

    errno = ENOMEM;
    return -1; /* FIXME, ... move into a func */
      
  }

  smbc_file_table[slot] = malloc(sizeof(struct smbc_file));

  if (!smbc_file_table[slot]) {

    errno = ENOMEM;
    return -1;

  }

  smbc_file_table[slot]->cli_fd   = 0;
  smbc_file_table[slot]->smbc_fd  = slot + smbc_start_fd;
  smbc_file_table[slot]->fname    = strdup(fname);
  smbc_file_table[slot]->srv      = NULL;
  smbc_file_table[slot]->offset   = 0;
  smbc_file_table[slot]->file     = False;
  smbc_file_table[slot]->dir_list = NULL;

  if (server[0] == (char)0) {

    if (share[0] != (char)0 || path[0] != (char)0) {
    
      errno = EINVAL;
      if (smbc_file_table[slot]) free(smbc_file_table[slot]);
      smbc_file_table[slot] = NULL;
      return -1;

    }

    /* We have server and share and path empty ... so list the workgroups */

    /*    fprintf(stderr, "Workgroup is: %s\n", lp_workgroup()); */
    cli_get_backup_server(my_netbios_name, lp_workgroup(), server, sizeof(server));

    smbc_file_table[slot]->dir_type = SMBC_WORKGROUP;

  /*
   * Get a connection to IPC$ on the server if we do not already have one
   */

    srv = smbc_server(server, "IPC$");

    if (!srv) {

      if (smbc_file_table[slot]) free(smbc_file_table[slot]);
      smbc_file_table[slot] = NULL;
      return -1;

    }

    smbc_file_table[slot]->srv = srv;

    /* Now, list the stuff ... */

    if (!cli_NetServerEnum(&srv->cli, lp_workgroup(), 0x80000000, list_fn,
			   (void *)smbc_file_table[slot])) {

      if (smbc_file_table[slot]) free(smbc_file_table[slot]);
      smbc_file_table[slot] = NULL;
      return -1;

    }
  }
  else { /* Server not an empty string ... Check the rest and see what gives */

    if (share[0] == (char)0) {

      if (path[0] != (char)0) { /* Should not have empty share with path */

	errno = EINVAL;
	if (smbc_file_table[slot]) free(smbc_file_table[slot]);
	smbc_file_table[slot] = NULL;
	return -1;
	
      }

      /* Check to see if <server><1D> translates, or <server><20> translates */

      if (resolve_name(server, &rem_ip, 0x1d)) { /* Found LMB */
	pstring buserver;

	smbc_file_table[slot]->dir_type = SMBC_SERVER;

	/*
	 * Get the backup list ...
	 */

	cli_get_backup_server(my_netbios_name, server, buserver, sizeof(buserver));

	/*
	 * Get a connection to IPC$ on the server if we do not already have one
	 */

	srv = smbc_server(buserver, "IPC$");

	if (!srv) {

	  if (smbc_file_table[slot]) free(smbc_file_table[slot]);
	  smbc_file_table[slot] = NULL;  /* FIXME: Memory leaks ... */
	  return -1;

	}

	smbc_file_table[slot]->srv = srv;

	/* Now, list the servers ... */

	if (!cli_NetServerEnum(&srv->cli, server, 0x0000FFFE, list_fn,
			       (void *)smbc_file_table[slot])) {

	  if (smbc_file_table[slot]) free(smbc_file_table[slot]);
	  smbc_file_table[slot] = NULL;
	  return -1;

	}

      }
      else {

	if (resolve_name(server, &rem_ip, 0x20)) {

	  /* Now, list the shares ... */

	  smbc_file_table[slot]->dir_type = SMBC_FILE_SHARE;

	  srv = smbc_server(server, "IPC$");

	  if (!srv) {

	    if (smbc_file_table[slot]) free(smbc_file_table[slot]);
	    smbc_file_table[slot] = NULL;
	    return -1;

	  }

	  smbc_file_table[slot]->srv = srv;

	  /* Now, list the servers ... */

	  if (!cli_RNetShareEnum(&srv->cli, list_fn, 
				 (void *)smbc_file_table[slot])) {

	    if (smbc_file_table[slot]) free(smbc_file_table[slot]);
	    smbc_file_table[slot] = NULL;
	    return -1;

	  }

	}
	else {

	  errno = EINVAL;
	  if (smbc_file_table[slot]) free(smbc_file_table[slot]);
	  smbc_file_table[slot] = NULL;
	  return -1;

	}

      }

    }
    else { /* The server and share are specified ... work from there ... */

      /* Well, we connect to the server and list the directory */

      smbc_file_table[slot]->dir_type = SMBC_FILE_SHARE;

      srv = smbc_server(server, share);

      if (!srv) {

	if (smbc_file_table[slot]) free(smbc_file_table[slot]);
	smbc_file_table[slot] = NULL;
	return -1;

      }

      smbc_file_table[slot]->srv = srv;

      /* Now, list the files ... */

      pstrcat(path, "\\*");

      if (!cli_list(&srv->cli, path, aDIR | aSYSTEM | aHIDDEN, dir_list_fn, 
		    (void *)smbc_file_table[slot])) {

	if (smbc_file_table[slot]) free(smbc_file_table[slot]);
	smbc_file_table[slot] = NULL;
	errno = smbc_errno(&srv->cli);
	return -1;

      }
    }

  }

  return smbc_file_table[slot]->smbc_fd;

}

/*
 * Routine to close a directory
 */

int smbc_closedir(int fd)
{
  struct smbc_file *fe;

  if (!smbc_initialized) {

    errno = EUCLEAN;
    return -1;

  }

  if (fd < smbc_start_fd || fd >= (smbc_start_fd + smbc_max_fd)) {

    errno = EBADF;
    return -1;

  }

  fe = smbc_file_table[fd - smbc_start_fd];

  if (!fe) {

    errno = ENOENT;  /* FIXME: Is this correct */
    return -1;

  }

  smbc_remove_dir(fe); /* Clean it up */

  if (fe) free(fe);    /* Free the space too */

  smbc_file_table[fd - smbc_start_fd] = NULL;

  return 0;

}

/*
 * Routine to get a directory entry
 */

int smbc_getdents(unsigned int fd, struct smbc_dirent *dirp, int count)
{
  struct smbc_file *fe;
  struct smbc_dir_list *dir;
  int rem = count, reqd;

  /* Check that all is ok first ... */

  if (!smbc_initialized) {

    errno = EUCLEAN;
    return -1;

  }

  if (fd < smbc_start_fd || fd >= (smbc_start_fd + smbc_max_fd)) {

    errno = EBADF;
    return -1;

  }

  fe = smbc_file_table[fd - smbc_start_fd];

  if (fe->file != False) { /* FIXME, should be dir, perhaps */

    errno = ENOTDIR;
    return -1;

  }

  /* 
   * Now, retrieve the number of entries that will fit in what was passed
   * We have to figure out if the info is in the list, or we need to 
   * send a request to the server to get the info.
   */

  while ((dir = fe->dir_next)) {
    struct smbc_dirent *dirent;

    if (!dir->dirent) {

      errno = ENOENT;  /* Bad error */
      return -1;

    }

    if (rem < (reqd = (sizeof(struct smbc_dirent) + dir->dirent->namelen + 
			 dir->dirent->commentlen + 1))) {

      if (rem < count) { /* We managed to copy something */

	errno = 0;
	return count - rem;

      }
      else { /* Nothing copied ... */

	errno = EINVAL;  /* Not enough space ... */
	return -1;

      }

    }

    dirent = dir->dirent;

    bcopy(dirent, dirp, reqd); /* Copy the data in ... */
    
    dirp->comment = (char *)(&dirp->name + dirent->namelen + 1);

    (char *)dirp += reqd;

    rem -= reqd;

    fe->dir_next = dir = dir -> next;
  }

  if (rem == count)
    return 0;
  else 
    return count - rem;

}

/*
 * Routine to create a directory ...
 */

int smbc_mkdir(const char *fname, mode_t mode)
{

  if (!smbc_initialized) {

    errno = EUCLEAN;
    return -1;

  }

  return 0;

}

/*
 * Routine to seek on a directory
 */

int smbc_lseekdir(int fd, off_t offset, int whence)
{

  if (!smbc_initialized) {

    errno = EUCLEAN;
    return -1;

  }

  return 0;

}

/*
 * Routine to fstat a dir
 */

int smbc_fstatdir(int fd, struct stat *st)
{

  if (!smbc_initialized) {

    errno = EUCLEAN;
    return -1;

  }

  return 0;

}
