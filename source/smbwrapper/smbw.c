/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   SMB wrapper functions
   Copyright (C) Andrew Tridgell 1998
   
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
#include "smbw.h"
#include "wrapper.h"

static pstring smb_cwd;

struct smbw_server {
	struct smbw_server *next, *prev;
	struct cli_state cli;
	char *server_name;
	char *share_name;
};

struct smbw_file {
	struct smbw_file *next, *prev;
	int cli_fd, fd;
	char *fname;
	off_t offset;
	struct smbw_server *srv;
};

struct smbw_dir {
	struct smbw_dir *next, *prev;
	int fd;
	int offset, count, malloced;
	struct smbw_server *srv;
	struct file_info *list;
};

static struct smbw_file *smbw_files;
static struct smbw_dir *smbw_dirs;
static struct smbw_server *smbw_srvs;

static struct bitmap *file_bmap;
static pstring local_machine;
extern int DEBUGLEVEL;

/***************************************************** 
initialise structures
*******************************************************/
void smbw_init(void)
{
	extern BOOL in_client;
	static int initialised;
	static pstring servicesf = CONFIGFILE;
	extern FILE *dbf;
	char *p;

	if (initialised) return;
	initialised = 1;

	DEBUGLEVEL = 0;
	setup_logging("smbw",True);

	dbf = stderr;

	file_bmap = bitmap_allocate(SMBW_MAX_OPEN);
	if (!file_bmap) {
		exit(1);
	}

	charset_initialise();

	in_client = True;

	if (!lp_load(servicesf,True,False,False)) {
		exit(1);
	}

	get_myname(local_machine,NULL);

	if ((p=getenv("SMBW_DEBUG"))) {
		DEBUGLEVEL = atoi(p);
	}

	if ((p=getenv("SMBW_CWD"))) {
		pstrcpy(smb_cwd, p);
	} else {
		sys_getwd(smb_cwd);
	}
}

/***************************************************** 
determine if a file descriptor is a smb one
*******************************************************/
BOOL smbw_fd(int fd)
{
	return (fd >= SMBW_FD_OFFSET);
}


/***************************************************** 
remove redundent stuff from a filename
*******************************************************/
void clean_fname(char *name)
{
	char *p, *p2;
	int l;
	int modified = 1;

	if (!name) return;

	while (modified) {
		modified = 0;

		DEBUG(4,("cleaning %s\n", name));

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


/***************************************************** 
parse a smb path into its components. 
*******************************************************/
char *smbw_parse_path(char *fname, char **server, char **share, char **path)
{
	static fstring rshare, rserver;
	static pstring rpath, s;
	char *p, *p2;
	int len;

	(*server) = rserver;
	(*share) = rshare;
	(*path) = rpath;

	if (fname[0] == '/') {
		pstrcpy(s, fname);
	} else {
		slprintf(s,sizeof(s)-1, "%s/%s", smb_cwd, fname);
	}
	clean_fname(s);

	DEBUG(4,("cleaned %s (fname=%s cwd=%s)\n", 
		 s, fname, smb_cwd));

	if (strncmp(s,SMBW_PREFIX,strlen(SMBW_PREFIX))) return s;

	p = s + strlen(SMBW_PREFIX);
	p2 = strchr(p,'/');

	if (p2) {
		len = (int)(p2-p);
	} else {
		len = strlen(p);
	}

	strncpy(rserver, p, len);
	rserver[len] = 0;		

	p = p2;
	if (!p) {
		fstrcpy(rshare,"IPC$");
		fstrcpy(rpath,"");
		goto ok;
	}

	p++;
	p2 = strchr(p,'/');

	if (p2) {
		len = (int)(p2-p);
	} else {
		len = strlen(p);
	}
	
	fstrcpy(rshare, p);
	rshare[len] = 0;

	p = p2;
	if (!p) {
		pstrcpy(rpath,"\\");
		goto ok;
	}

	pstrcpy(rpath,p);

	string_sub(rpath, "/", "\\");

 ok:
	DEBUG(4,("parsed path name=%s cwd=%s [%s] [%s] [%s]\n", 
		 fname, smb_cwd,
		 *server, *share, *path));

	return s;
}

/***************************************************** 
determine if a path name (possibly relative) is in the 
smb name space
*******************************************************/
BOOL smbw_path(char *path)
{
	char *server, *share, *s;
	char *cwd;
	cwd = smbw_parse_path(path, &server, &share, &s);
	return strncmp(cwd,SMBW_PREFIX,strlen(SMBW_PREFIX)) == 0;
}

/***************************************************** 
return a unix errno from a SMB error pair
*******************************************************/
int smbw_errno(struct smbw_server *srv)
{
	int eclass=0, ecode=0;
	cli_error(&srv->cli, &eclass, &ecode);
	DEBUG(2,("eclass=%d ecode=%d\n", eclass, ecode));
	if (eclass == ERRDOS) {
		switch (ecode) {
		case ERRbadfile: return ENOENT;
		case ERRnoaccess: return EPERM;
		}
	}
	return EINVAL;
}

/***************************************************** 
return a connection to a server (existing or new)
*******************************************************/
struct smbw_server *smbw_server(char *server, char *share)
{
	struct smbw_server *srv=NULL;
	static struct cli_state c;
	char *username;
	char *password;
	char *workgroup;
	struct nmb_name called, calling;

	username = getenv("SMBW_USER");
	if (!username) username = getenv("USER");
	if (!username) username = "guest";

	workgroup = getenv("SMBW_WORKGROUP");
	if (!workgroup) workgroup = lp_workgroup();

	password = getenv("SMBW_PASSWORD");
	if (!password) password = "";

	/* try to use an existing connection */
	for (srv=smbw_srvs;srv;srv=srv->next) {
		if (strcmp(server,srv->server_name)==0 &&
		    strcmp(share,srv->share_name)==0) return srv;
	}

	/* have to open a new connection */
	if (!cli_initialise(&c) || !cli_connect(&c, server, NULL)) {
		errno = ENOENT;
		return NULL;
	}

	make_nmb_name(&calling, local_machine, 0x0, "");
	make_nmb_name(&called , server, 0x20, "");

	if (!cli_session_request(&c, &calling, &called)) {
		cli_shutdown(&c);
		errno = ENOENT;
		return NULL;
	}

	if (!cli_negprot(&c)) {
		cli_shutdown(&c);
		errno = ENOENT;
		return NULL;
	}

	if (!cli_session_setup(&c, username, 
			       password, strlen(password),
			       password, strlen(password),
			       workgroup)) {
		cli_shutdown(&c);
		errno = EPERM;
		return NULL;
	}

	if (!cli_send_tconX(&c, share, 
			    strstr(share,"IPC$")?"IPC":"A:", 
			    password, strlen(password)+1)) {
		cli_shutdown(&c);
		errno = ENOENT;
		return NULL;
	}

	srv = (struct smbw_server *)malloc(sizeof(*srv));
	if (!srv) {
		errno = ENOMEM;
		goto failed;
	}

	ZERO_STRUCTP(srv);

	srv->cli = c;

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

	DLIST_ADD(smbw_srvs, srv);

	return srv;

 failed:
	cli_shutdown(&c);
	if (!srv) return NULL;

	if (srv->server_name) free(srv->server_name);
	if (srv->share_name) free(srv->share_name);
	free(srv);
	return NULL;
}


/***************************************************** 
map a fd to a smbw_file structure
*******************************************************/
struct smbw_file *smbw_file(int fd)
{
	struct smbw_file *file;

	for (file=smbw_files;file;file=file->next) {
		if (file->fd == fd) return file;
	}
	return NULL;
}

/***************************************************** 
map a fd to a smbw_dir structure
*******************************************************/
struct smbw_dir *smbw_dir(int fd)
{
	struct smbw_dir *dir;

	for (dir=smbw_dirs;dir;dir=dir->next) {
		if (dir->fd == fd) return dir;
	}
	return NULL;
}

/***************************************************** 
setup basic info in a stat structure
*******************************************************/
void smbw_setup_stat(struct stat *st, char *fname, size_t size, int mode)
{
	ZERO_STRUCTP(st);

	if (IS_DOS_DIR(mode)) {
		st->st_mode = SMBW_DIR_MODE;
	} else {
		st->st_mode = SMBW_FILE_MODE;
	}

	st->st_size = size;
	st->st_blksize = 512;
	st->st_blocks = (size+511)/512;
	st->st_uid = getuid();
	st->st_gid = getgid();
}

/***************************************************** 
free a smbw_dir structure and all entries
*******************************************************/
static void free_dir(struct smbw_dir *dir)
{
	if (dir->list) {
		free(dir->list);
	}
	ZERO_STRUCTP(dir);
	free(dir);
}


static struct smbw_dir *cur_dir;

/***************************************************** 
add a entry to a directory listing
*******************************************************/
void smbw_dir_add(struct file_info *finfo)
{
	DEBUG(2,("%s\n", finfo->name));

	if (cur_dir->malloced == cur_dir->count) {
		cur_dir->list = (struct file_info *)Realloc(cur_dir->list, 
							    sizeof(cur_dir->list[0])*
							    (cur_dir->count+100));
		if (!cur_dir->list) {
			/* oops */
			return;
		}
		cur_dir->malloced += 100;
	}

	cur_dir->list[cur_dir->count] = *finfo;
	cur_dir->count++;
}

/***************************************************** 
open a directory on the server
*******************************************************/
int smbw_dir_open(const char *fname1, int flags)
{
	char *fname = strdup(fname1);
	char *server, *share, *path;
	struct smbw_server *srv=NULL;
	struct smbw_dir *dir=NULL;
	pstring mask;
	int fd;

	DEBUG(4,("%s\n", __FUNCTION__));

	if (!fname) {
		errno = EINVAL;
		return -1;
	}

	smbw_init();

	/* work out what server they are after */
	smbw_parse_path(fname, &server, &share, &path);

	/* get a connection to the server */
	srv = smbw_server(server, share);
	if (!srv) {
		/* smbw_server sets errno */
		goto failed;
	}

	dir = (struct smbw_dir *)malloc(sizeof(*dir));
	if (!dir) {
		errno = ENOMEM;
		goto failed;
	}

	ZERO_STRUCTP(dir);

	cur_dir = dir;

	slprintf(mask, sizeof(mask)-1, "%s\\*", path);
	string_sub(mask,"\\\\","\\");

	if (cli_list(&srv->cli, mask, aHIDDEN|aSYSTEM|aDIR, smbw_dir_add) <= 0) {
		errno = smbw_errno(srv);
		goto failed;
	}

	cur_dir = NULL;
	
	fd = bitmap_find(file_bmap, 0);
	if (fd == -1) {
		errno = EMFILE;
		goto failed;
	}

	DLIST_ADD(smbw_dirs, dir);
	
	bitmap_set(file_bmap, fd);

	dir->fd = fd + SMBW_FD_OFFSET;

	return dir->fd;

 failed:
	if (dir) {
		free_dir(dir);
	}
	if (fname) free(fname);

	return -1;
}


/***************************************************** 
a wrapper for open()
*******************************************************/
int smbw_open(const char *fname1, int flags, mode_t mode)
{
	char *fname = strdup(fname1);
	char *server, *share, *path;
	struct smbw_server *srv=NULL;
	int eno, fd = -1;
	struct smbw_file *file=NULL;

	DEBUG(4,("%s\n", __FUNCTION__));

	if (!fname) {
		errno = EINVAL;
		return -1;
	}

	smbw_init();

	/* work out what server they are after */
	smbw_parse_path(fname, &server, &share, &path);

	/* get a connection to the server */
	srv = smbw_server(server, share);
	if (!srv) {
		/* smbw_server sets errno */
		goto failed;
	}

	fd = cli_open(&srv->cli, path, flags, DENY_NONE);
	if (fd == -1) {
		if (fname) free(fname);
		/* it might be a directory. Maybe we should use chkpath? */
		return smbw_dir_open(fname1, flags);
	}
	if (fd == -1) {
		errno = eno;
		goto failed;
	}

	file = (struct smbw_file *)malloc(sizeof(*file));
	if (!file) {
		errno = ENOMEM;
		goto failed;
	}

	ZERO_STRUCTP(file);

	file->cli_fd = fd;
	file->fname = strdup(path);
	if (!file->fname) {
		errno = ENOMEM;
		goto failed;
	}
	file->srv = srv;
	file->fd = bitmap_find(file_bmap, 0);

	if (file->fd == -1) {
		errno = EMFILE;
		goto failed;
	}

	bitmap_set(file_bmap, file->fd);

	file->fd += SMBW_FD_OFFSET;

	DLIST_ADD(smbw_files, file);

	DEBUG(2,("opened %s\n", fname1));

	free(fname);

	return file->fd;

 failed:
	if (fname) {
		free(fname);
	}
	if (fd != -1) {
		cli_close(&srv->cli, fd);
	}
	if (file) {
		if (file->fname) {
			free(file->fname);
		}
		free(file);
	}
	return -1;
}


/***************************************************** 
a wrapper for fstat() on a directory
*******************************************************/
int smbw_dir_fstat(int fd, struct stat *st)
{
	struct smbw_dir *dir;

	DEBUG(4,("%s\n", __FUNCTION__));

	dir = smbw_dir(fd);
	if (!dir) {
		errno = EBADF;
		return -1;
	}

	ZERO_STRUCTP(st);

	smbw_setup_stat(st, "", dir->count*sizeof(struct dirent), aDIR);

	return 0;
}

/***************************************************** 
a wrapper for fstat()
*******************************************************/
int smbw_fstat(int fd, struct stat *st)
{
	struct smbw_file *file;
	time_t c_time, a_time, m_time;
	uint32 size;
	int mode;

	DEBUG(4,("%s\n", __FUNCTION__));

	file = smbw_file(fd);
	if (!file) {
		return smbw_dir_fstat(fd, st);
	}

	DEBUG(4,("%s - qfileinfo\n", __FUNCTION__));

	if (!cli_qfileinfo(&file->srv->cli, file->cli_fd, 
			   &c_time, &a_time, &m_time, &size, &mode)) {
		errno = EINVAL;
		return -1;
	}

	smbw_setup_stat(st, file->fname, size, mode);

	st->st_atime = a_time;
	st->st_ctime = c_time;
	st->st_mtime = m_time;

	DEBUG(4,("%s - OK\n", __FUNCTION__));

	return 0;
}

/***************************************************** 
a wrapper for stat()
*******************************************************/
int smbw_stat(char *fname1, struct stat *st)
{
	struct smbw_server *srv;
	char *server, *share, *path;
	char *fname = strdup(fname1);
	time_t c_time, a_time, m_time;
	uint32 size;
	int mode;

	DEBUG(4,("%s (%s)\n", __FUNCTION__, fname1));

	if (!fname) {
		errno = EINVAL;
		return -1;
	}

	smbw_init();

	/* work out what server they are after */
	smbw_parse_path(fname, &server, &share, &path);

	/* get a connection to the server */
	srv = smbw_server(server, share);
	if (!srv) {
		/* smbw_server sets errno */
		goto failed;
	}

	if (!cli_qpathinfo(&srv->cli, path, 
			   &c_time, &a_time, &m_time, &size, &mode)) {
		errno = smbw_errno(srv);
		goto failed;
	}

	smbw_setup_stat(st, path, size, mode);

	st->st_atime = a_time;
	st->st_ctime = c_time;
	st->st_mtime = m_time;

	return 0;

 failed:
	if (fname) free(fname);
	return -1;
}

/***************************************************** 
a wrapper for read()
*******************************************************/
ssize_t smbw_read(int fd, void *buf, size_t count)
{
	struct smbw_file *file;
	int ret;

	DEBUG(4,("%s\n", __FUNCTION__));

	file = smbw_file(fd);
	if (!file) {
		DEBUG(3,("bad fd in read\n"));
		errno = EBADF;
		return -1;
	}
	
	ret = cli_read(&file->srv->cli, file->cli_fd, buf, file->offset, count);

	if (ret == -1) {
		errno = smbw_errno(file->srv);
		return -1;
	}

	file->offset += ret;

	return ret;
}

/***************************************************** 
a wrapper for write()
*******************************************************/
ssize_t smbw_write(int fd, void *buf, size_t count)
{
	struct smbw_file *file;
	int ret;

	DEBUG(4,("%s\n", __FUNCTION__));

	file = smbw_file(fd);
	if (!file) {
		DEBUG(3,("bad fd in read\n"));
		errno = EBADF;
		return -1;
	}
	
	ret = cli_write(&file->srv->cli, file->cli_fd, buf, file->offset, count);

	if (ret == -1) {
		errno = smbw_errno(file->srv);
		return -1;
	}

	file->offset += ret;

	return ret;
}

/***************************************************** 
close a directory handle
*******************************************************/
int smbw_dir_close(int fd)
{
	struct smbw_dir *dir;

	DEBUG(4,("%s\n", __FUNCTION__));

	dir = smbw_dir(fd);
	if (!dir) {
		DEBUG(4,("%s(%d)\n", __FUNCTION__, __LINE__));
		errno = EBADF;
		return -1;
	}

	bitmap_clear(file_bmap, dir->fd - SMBW_FD_OFFSET);
	
	DLIST_REMOVE(smbw_dirs, dir);
	
	free_dir(dir);

	return 0;
}

/***************************************************** 
a wrapper for close()
*******************************************************/
int smbw_close(int fd)
{
	struct smbw_file *file;

	DEBUG(4,("%s\n", __FUNCTION__));

	file = smbw_file(fd);
	if (!file) {
		return smbw_dir_close(fd);
	}
	
	if (!cli_close(&file->srv->cli, file->cli_fd)) {
		errno = smbw_errno(file->srv);
		return -1;
	}


	bitmap_clear(file_bmap, file->fd - SMBW_FD_OFFSET);
	
	DLIST_REMOVE(smbw_files, file);

	free(file->fname);
	ZERO_STRUCTP(file);
	free(file);

	return 0;
}


/***************************************************** 
a wrapper for fcntl()
*******************************************************/
int smbw_fcntl(int fd, int cmd, long arg)
{
	DEBUG(4,("%s\n", __FUNCTION__));
	return 0;
}


/***************************************************** 
a wrapper for getdents()
*******************************************************/
int smbw_getdents(unsigned int fd, struct dirent *dirp, int count)
{
	struct smbw_dir *dir;
	int n=0;

	DEBUG(4,("%s\n", __FUNCTION__));

	dir = smbw_dir(fd);
	if (!dir) {
		errno = EBADF;
		return -1;
	}
	
	while (count>=sizeof(*dirp) && (dir->offset < dir->count)) {
		dirp->d_ino = dir->offset + 0x10000;
		dirp->d_off = (dir->offset+1)*sizeof(*dirp);
		dirp->d_reclen = sizeof(*dirp);
		/* what's going on with the -1 here? maybe d_type isn't really there? */
		safe_strcpy(&dirp->d_name[-1], dir->list[dir->offset].name, 
			    sizeof(dirp->d_name)-1);
		dir->offset++;
		count -= dirp->d_reclen;
		dirp++;
		n++;
	}

	return n*sizeof(*dirp);
}


/***************************************************** 
a wrapper for access()
*******************************************************/
int smbw_access(char *name, int mode)
{
	struct stat st;
	/* how do we map this properly ?? */
	return smbw_stat(name, &st) == 0;
}


/***************************************************** 
a wrapper for chdir()
*******************************************************/
int smbw_chdir(char *name)
{
	struct smbw_server *srv;
	char *server, *share, *path;
	int mode = aDIR;
	char *cwd;

	DEBUG(4,("%s (%s)\n", __FUNCTION__, name));

	if (!name) {
		errno = EINVAL;
		return -1;
	}

	smbw_init();

	DEBUG(2,("parsing\n"));

	/* work out what server they are after */
	cwd = smbw_parse_path(name, &server, &share, &path);

	DEBUG(2,("parsed\n"));

	if (strncmp(cwd,SMBW_PREFIX,strlen(SMBW_PREFIX))) {
		if (real_chdir(cwd) == 0) {
			pstrcpy(smb_cwd, cwd);
			setenv("SMB_CWD", smb_cwd, 1);
			return 0;
		}
		errno = ENOENT;
		return -1;
	}

	DEBUG(2,("doing server\n"));

	/* get a connection to the server */
	srv = smbw_server(server, share);
	if (!srv) {
		/* smbw_server sets errno */
		return -1;
	}

	DEBUG(2,("doing qpathinfo share=%s\n", share));

	if (strcmp(share,"IPC$") &&
	    !cli_qpathinfo(&srv->cli, path, 
			   NULL, NULL, NULL, NULL, &mode)) {
		errno = smbw_errno(srv);
		return -1;
	}

	if (!(mode & aDIR)) {
		errno = ENOTDIR;
		return -1;
	}

	pstrcpy(smb_cwd, cwd);
	setenv("SMB_CWD", smb_cwd, 1);

	return 0;
}

