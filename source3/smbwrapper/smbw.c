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
#include "wrapper.h"

pstring smb_cwd;

static struct smbw_file *smbw_files;
static struct smbw_server *smbw_srvs;

struct bitmap *smbw_file_bmap;
extern pstring global_myname;
extern int DEBUGLEVEL;

int smbw_busy=0;

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

	smbw_busy++;

	DEBUGLEVEL = 0;
	setup_logging("smbw",True);

	dbf = stderr;

	if ((p=getenv("SMBW_LOGFILE"))) {
		dbf = fopen(p, "a");
	}

	smbw_file_bmap = bitmap_allocate(SMBW_MAX_OPEN);
	if (!smbw_file_bmap) {
		exit(1);
	}

	charset_initialise();

	in_client = True;

	load_interfaces();

	if (!lp_load(servicesf,True,False,False)) {
		exit(1);
	}

	get_myname(global_myname,NULL);

	if ((p=getenv("SMBW_DEBUG"))) {
		DEBUGLEVEL = atoi(p);
	}

	if ((p=getenv(SMBW_PWD_ENV))) {
		pstrcpy(smb_cwd, p);
		DEBUG(4,("Initial cwd from smb_cwd is %s\n", smb_cwd));
	} else {
		sys_getwd(smb_cwd);
		DEBUG(4,("Initial cwd from getwd is %s\n", smb_cwd));
	}
	smbw_busy--;
}

/***************************************************** 
determine if a file descriptor is a smb one
*******************************************************/
int smbw_fd(int fd)
{
	if (smbw_busy) return 0;
	return smbw_file_bmap && bitmap_query(smbw_file_bmap, fd);
}

/***************************************************** 
a crude inode number generator
*******************************************************/
ino_t smbw_inode(const char *name)
{
	return (ino_t)str_checksum(name);
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


/***************************************************** 
parse a smb path into its components. 
*******************************************************/
char *smbw_parse_path(const char *fname, char *server, char *share, char *path)
{
	static pstring s;
	char *p, *p2;
	int len;

	*server = *share = *path = 0;

	if (fname[0] == '/') {
		pstrcpy(s, fname);
	} else {
		slprintf(s,sizeof(s)-1, "%s/%s", smb_cwd, fname);
	}
	clean_fname(s);

	DEBUG(5,("cleaned %s (fname=%s cwd=%s)\n", 
		 s, fname, smb_cwd));

	if (strncmp(s,SMBW_PREFIX,strlen(SMBW_PREFIX))) return s;

	p = s + strlen(SMBW_PREFIX);
	p2 = strchr(p,'/');

	if (p2) {
		len = (int)(p2-p);
	} else {
		len = strlen(p);
	}

	len = MIN(len,sizeof(fstring)-1);

	strncpy(server, p, len);
	server[len] = 0;		

	p = p2;
	if (!p) {
		fstrcpy(share,"IPC$");
		pstrcpy(path,"");
		goto ok;
	}

	p++;
	p2 = strchr(p,'/');

	if (p2) {
		len = (int)(p2-p);
	} else {
		len = strlen(p);
	}

	len = MIN(len,sizeof(fstring)-1);
	
	strncpy(share, p, len);
	share[len] = 0;

	p = p2;
	if (!p) {
		pstrcpy(path,"\\");
		goto ok;
	}

	pstrcpy(path,p);

	string_sub(path, "/", "\\");

 ok:
	DEBUG(5,("parsed path name=%s cwd=%s [%s] [%s] [%s]\n", 
		 fname, smb_cwd,
		 server, share, path));

	return s;
}

/***************************************************** 
determine if a path name (possibly relative) is in the 
smb name space
*******************************************************/
int smbw_path(const char *path)
{
	fstring server, share;
	pstring s;
	char *cwd;
	int l=strlen(SMBW_PREFIX)-1;

	if (path[0] == '/' && strncmp(path,SMBW_PREFIX,l)) {
		return 0;
	}

	if (smbw_busy) return 0;

	smbw_init();

	DEBUG(3,("smbw_path(%s)\n", path));

	cwd = smbw_parse_path(path, server, share, s);

	if (strncmp(cwd,SMBW_PREFIX,l) == 0 &&
	    (cwd[l] == '/' || cwd[l] == 0)) {
		return 1;
	}

	return 0;
}

/***************************************************** 
return a unix errno from a SMB error pair
*******************************************************/
int smbw_errno(struct cli_state *c)
{
	uint8 eclass;
	uint32 ecode;
	int ret;

	ret = cli_error(c, &eclass, &ecode);

	if (ret) {
		DEBUG(3,("smbw_error %d %d (0x%x) -> %d\n", 
			 (int)eclass, (int)ecode, (int)ecode, ret));
	}
	return ret;
}

/***************************************************** 
return a connection to a server (existing or new)
*******************************************************/
struct smbw_server *smbw_server(char *server, char *share)
{
	struct smbw_server *srv=NULL;
	struct cli_state c;
	char *username;
	char *password;
	char *workgroup;
	struct nmb_name called, calling;

	ZERO_STRUCT(c);

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

	if (server[0] == 0) {
		errno = EPERM;
		return NULL;
	}

	make_nmb_name(&calling, global_myname, 0x0, "");
	make_nmb_name(&called , server, 0x20, "");

 again:
	/* have to open a new connection */
	if (!cli_initialise(&c) || !cli_connect(&c, server, NULL)) {
		errno = ENOENT;
		return NULL;
	}

	if (!cli_session_request(&c, &calling, &called)) {
		cli_shutdown(&c);
		if (strcmp(called.name, "*SMBSERVER")) {
			make_nmb_name(&called , "*SMBSERVER", 0x20, "");
			goto again;
		}
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

	if (!cli_send_tconX(&c, share, "?????",
			    password, strlen(password)+1)) {
		errno = smbw_errno(&c);
		cli_shutdown(&c);
		return NULL;
	}

	srv = (struct smbw_server *)malloc(sizeof(*srv));
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

	/* some programs play with file descriptors fairly intimately. We
	   try to get out of the way by duping to a high fd number */
	if (fcntl(SMBW_CLI_FD + srv->cli.fd, F_GETFD) && errno == EBADF) {
		if (dup2(srv->cli.fd,SMBW_CLI_FD+srv->cli.fd) == 
		    srv->cli.fd+SMBW_CLI_FD) {
			close(srv->cli.fd);
			srv->cli.fd += SMBW_CLI_FD;
		}
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
a wrapper for open()
*******************************************************/
int smbw_open(const char *fname, int flags, mode_t mode)
{
	fstring server, share;
	pstring path;
	struct smbw_server *srv=NULL;
	int eno, fd = -1;
	struct smbw_file *file=NULL;

	DEBUG(4,("%s\n", __FUNCTION__));

	smbw_init();

	if (!fname) {
		errno = EINVAL;
		return -1;
	}

	smbw_busy++;	

	/* work out what server they are after */
	smbw_parse_path(fname, server, share, path);

	/* get a connection to the server */
	srv = smbw_server(server, share);
	if (!srv) {
		/* smbw_server sets errno */
		goto failed;
	}

	if (path[strlen(path)-1] == '\\') {
		fd = -1;
	} else {
		fd = cli_open(&srv->cli, path, flags, DENY_NONE);
	}
	if (fd == -1) {
		/* it might be a directory. Maybe we should use chkpath? */
		fd = smbw_dir_open(fname);
		smbw_busy--;
		return fd;
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

	file->f = (struct smbw_filedes *)malloc(sizeof(*(file->f)));
	if (!file->f) {
		errno = ENOMEM;
		goto failed;
	}

	ZERO_STRUCTP(file->f);

	file->f->cli_fd = fd;
	file->f->fname = strdup(path);
	if (!file->f->fname) {
		errno = ENOMEM;
		goto failed;
	}
	file->srv = srv;
	file->fd = open(SMBW_DUMMY, O_WRONLY);
	if (file->fd == -1) {
		errno = EMFILE;
		goto failed;
	}

	if (bitmap_query(smbw_file_bmap, file->fd)) {
		DEBUG(0,("ERROR: fd used in smbw_open\n"));
		errno = EIO;
		goto failed;
	}

	file->f->ref_count=1;

	bitmap_set(smbw_file_bmap, file->fd);

	DLIST_ADD(smbw_files, file);

	DEBUG(4,("opened %s\n", fname));

	smbw_busy--;
	return file->fd;

 failed:
	if (fd != -1) {
		cli_close(&srv->cli, fd);
	}
	if (file) {
		if (file->f) {
			if (file->f->fname) {
				free(file->f->fname);
			}
			free(file->f);
		}
		free(file);
	}
	smbw_busy--;
	return -1;
}


/***************************************************** 
a wrapper for read()
*******************************************************/
ssize_t smbw_read(int fd, void *buf, size_t count)
{
	struct smbw_file *file;
	int ret;

	DEBUG(4,("%s %d\n", 
		 __FUNCTION__, (int)count));

	smbw_busy++;

	file = smbw_file(fd);
	if (!file) {
		errno = EBADF;
		smbw_busy--;
		return -1;
	}
	
	ret = cli_read(&file->srv->cli, file->f->cli_fd, buf, file->f->offset, count);

	if (ret == -1) {
		errno = smbw_errno(&file->srv->cli);
		smbw_busy--;
		return -1;
	}

	file->f->offset += ret;

	smbw_busy--;
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

	smbw_busy++;

	file = smbw_file(fd);
	if (!file) {
		DEBUG(3,("bad fd in read\n"));
		errno = EBADF;
		smbw_busy--;
		return -1;
	}
	
	ret = cli_write(&file->srv->cli, file->f->cli_fd, buf, file->f->offset, count);

	if (ret == -1) {
		errno = smbw_errno(&file->srv->cli);
		smbw_busy--;
		return -1;
	}

	file->f->offset += ret;

	smbw_busy--;
	return ret;
}

/***************************************************** 
a wrapper for close()
*******************************************************/
int smbw_close(int fd)
{
	struct smbw_file *file;

	DEBUG(4,("%s\n", __FUNCTION__));

	smbw_busy++;

	file = smbw_file(fd);
	if (!file) {
		int ret = smbw_dir_close(fd);
		smbw_busy--;
		return ret;
	}
	
	if (file->f->ref_count == 1 &&
	    !cli_close(&file->srv->cli, file->f->cli_fd)) {
		errno = smbw_errno(&file->srv->cli);
		smbw_busy--;
		return -1;
	}


	bitmap_clear(smbw_file_bmap, file->fd);
	close(file->fd);
	
	DLIST_REMOVE(smbw_files, file);

	file->f->ref_count--;
	if (file->f->ref_count == 0) {
		free(file->f->fname);
		free(file->f);
	}
	ZERO_STRUCTP(file);
	free(file);
	
	smbw_busy--;

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
a wrapper for access()
*******************************************************/
int smbw_access(const char *name, int mode)
{
	struct stat st;
	/* how do we map this properly ?? */
	return smbw_stat(name, &st);
}

/***************************************************** 
a wrapper for realink() - needed for correct errno setting
*******************************************************/
int smbw_readlink(const char *path, char *buf, size_t bufsize)
{
	struct stat st;
	int ret;

	ret = smbw_stat(path, &st);
	if (ret != 0) {
		DEBUG(4,("readlink(%s) failed\n", path));
		return -1;
	}
	
	/* it exists - say it isn't a link */
	DEBUG(4,("readlink(%s) not a link\n", path));

	errno = EINVAL;
	return -1;
}


/***************************************************** 
a wrapper for unlink()
*******************************************************/
int smbw_unlink(const char *fname)
{
	struct smbw_server *srv;
	fstring server, share;
	pstring path;

	DEBUG(4,("%s (%s)\n", __FUNCTION__, fname));

	if (!fname) {
		errno = EINVAL;
		return -1;
	}

	smbw_init();

	smbw_busy++;

	/* work out what server they are after */
	smbw_parse_path(fname, server, share, path);

	/* get a connection to the server */
	srv = smbw_server(server, share);
	if (!srv) {
		/* smbw_server sets errno */
		goto failed;
	}

	if (strncmp(srv->cli.dev, "LPT", 3) == 0) {
		int job = smbw_stat_printjob(srv, path, NULL, NULL);
		if (job == -1) {
			goto failed;
		}
		if (cli_printjob_del(&srv->cli, job) != 0) {
			goto failed;
		}
	} else if (!cli_unlink(&srv->cli, path)) {
		errno = smbw_errno(&srv->cli);
		goto failed;
	}

	smbw_busy--;
	return 0;

 failed:
	smbw_busy--;
	return -1;
}


/***************************************************** 
a wrapper for rename()
*******************************************************/
int smbw_rename(const char *oldname, const char *newname)
{
	struct smbw_server *srv;
	fstring server1, share1;
	pstring path1;
	fstring server2, share2;
	pstring path2;

	DEBUG(4,("%s (%s, %s)\n", __FUNCTION__, oldname, newname));

	if (!oldname || !newname) {
		errno = EINVAL;
		return -1;
	}

	smbw_init();

	smbw_busy++;

	/* work out what server they are after */
	smbw_parse_path(oldname, server1, share1, path1);
	smbw_parse_path(newname, server2, share2, path2);

	if (strcmp(server1, server2) || strcmp(share1, share2)) {
		/* can't cross filesystems */
		errno = EXDEV;
		return -1;
	}

	/* get a connection to the server */
	srv = smbw_server(server1, share1);
	if (!srv) {
		/* smbw_server sets errno */
		goto failed;
	}

	if (!cli_rename(&srv->cli, path1, path2)) {
		errno = smbw_errno(&srv->cli);
		goto failed;
	}

	smbw_busy--;
	return 0;

 failed:
	smbw_busy--;
	return -1;
}


/***************************************************** 
a wrapper for utime()
*******************************************************/
int smbw_utime(const char *fname, void *buf)
{
	struct utimbuf *tbuf = (struct utimbuf *)buf;
	struct smbw_server *srv;
	fstring server, share;
	pstring path;
	uint32 mode;

	DEBUG(4,("%s (%s)\n", __FUNCTION__, fname));

	if (!fname) {
		errno = EINVAL;
		return -1;
	}

	smbw_init();

	smbw_busy++;

	/* work out what server they are after */
	smbw_parse_path(fname, server, share, path);

	/* get a connection to the server */
	srv = smbw_server(server, share);
	if (!srv) {
		/* smbw_server sets errno */
		goto failed;
	}

	if (!cli_getatr(&srv->cli, path, &mode, NULL, NULL)) {
		errno = smbw_errno(&srv->cli);
		goto failed;
	}

	if (!cli_setatr(&srv->cli, path, mode, tbuf->modtime)) {
		errno = smbw_errno(&srv->cli);
		goto failed;
	}

	smbw_busy--;
	return 0;

 failed:
	smbw_busy--;
	return -1;
}

/***************************************************** 
a wrapper for chown()
*******************************************************/
int smbw_chown(const char *fname, uid_t owner, gid_t group)
{
	struct smbw_server *srv;
	fstring server, share;
	pstring path;
	uint32 mode;

	DEBUG(4,("%s (%s)\n", __FUNCTION__, fname));

	if (!fname) {
		errno = EINVAL;
		return -1;
	}

	smbw_init();

	smbw_busy++;

	/* work out what server they are after */
	smbw_parse_path(fname, server, share, path);

	/* get a connection to the server */
	srv = smbw_server(server, share);
	if (!srv) {
		/* smbw_server sets errno */
		goto failed;
	}

	if (!cli_getatr(&srv->cli, path, &mode, NULL, NULL)) {
		errno = smbw_errno(&srv->cli);
		goto failed;
	}
	
	/* assume success */

	smbw_busy--;
	return 0;

 failed:
	smbw_busy--;
	return -1;
}

/***************************************************** 
a wrapper for chmod()
*******************************************************/
int smbw_chmod(const char *fname, mode_t newmode)
{
	struct smbw_server *srv;
	fstring server, share;
	pstring path;
	uint32 mode;

	DEBUG(4,("%s (%s)\n", __FUNCTION__, fname));

	if (!fname) {
		errno = EINVAL;
		return -1;
	}

	smbw_init();

	smbw_busy++;

	/* work out what server they are after */
	smbw_parse_path(fname, server, share, path);

	/* get a connection to the server */
	srv = smbw_server(server, share);
	if (!srv) {
		/* smbw_server sets errno */
		goto failed;
	}

	if (!cli_getatr(&srv->cli, path, &mode, NULL, NULL)) {
		errno = smbw_errno(&srv->cli);
		goto failed;
	}
	
	/* assume success for the moment - need to add attribute mapping */

	smbw_busy--;
	return 0;

 failed:
	smbw_busy--;
	return -1;
}

/***************************************************** 
a wrapper for lseek()
*******************************************************/
off_t smbw_lseek(int fd, off_t offset, int whence)
{
	struct smbw_file *file;
	uint32 size;

	DEBUG(4,("%s\n", __FUNCTION__));

	smbw_busy++;

	file = smbw_file(fd);
	if (!file) {
		off_t ret = smbw_dir_lseek(fd, offset, whence);
		smbw_busy--;
		return ret;
	}

	switch (whence) {
	case SEEK_SET:
		file->f->offset = offset;
		break;
	case SEEK_CUR:
		file->f->offset += offset;
		break;
	case SEEK_END:
		if (!cli_qfileinfo(&file->srv->cli, file->f->cli_fd, 
				   NULL, &size, NULL, NULL, NULL) &&
		    !cli_getattrE(&file->srv->cli, file->f->cli_fd, 
				  NULL, &size, NULL, NULL, NULL)) {
			errno = EINVAL;
			smbw_busy--;
			return -1;
		}
		file->f->offset = size + offset;
		break;
	}

	smbw_busy--;
	return file->f->offset;
}


/***************************************************** 
a wrapper for dup()
*******************************************************/
int smbw_dup(int fd)
{
	int fd2;
	struct smbw_file *file, *file2;

	DEBUG(4,("%s\n", __FUNCTION__));

	smbw_busy++;

	file = smbw_file(fd);
	if (!file) {
		errno = EBADF;
		goto failed;
	}

	fd2 = dup(file->fd);
	if (fd2 == -1) {
		goto failed;
	}

	if (bitmap_query(smbw_file_bmap, fd2)) {
		DEBUG(0,("ERROR: fd already open in dup!\n"));
		errno = EIO;
		goto failed;
	}

	file2 = (struct smbw_file *)malloc(sizeof(*file2));
	if (!file2) {
		close(fd2);
		errno = ENOMEM;
		goto failed;
	}

	ZERO_STRUCTP(file2);

	*file2 = *file;
	file2->fd = fd2;

	file->f->ref_count++;

	bitmap_set(smbw_file_bmap, fd2);
	
	DLIST_ADD(smbw_files, file2);
	
	smbw_busy--;
	return fd2;

 failed:
	smbw_busy--;
	return -1;
}


/***************************************************** 
a wrapper for dup2()
*******************************************************/
int smbw_dup2(int fd, int fd2)
{
	struct smbw_file *file, *file2;

	DEBUG(4,("%s\n", __FUNCTION__));

	smbw_busy++;

	file = smbw_file(fd);
	if (!file) {
		errno = EBADF;
		goto failed;
	}

	if (bitmap_query(smbw_file_bmap, fd2)) {
		DEBUG(0,("ERROR: fd already open in dup2!\n"));
		errno = EIO;
		goto failed;
	}

	if (dup2(file->fd, fd2) != fd2) {
		goto failed;
	}

	file2 = (struct smbw_file *)malloc(sizeof(*file2));
	if (!file2) {
		close(fd2);
		errno = ENOMEM;
		goto failed;
	}

	ZERO_STRUCTP(file2);

	*file2 = *file;
	file2->fd = fd2;

	file->f->ref_count++;

	bitmap_set(smbw_file_bmap, fd2);
	
	DLIST_ADD(smbw_files, file2);
	
	smbw_busy--;
	return fd2;

 failed:
	smbw_busy--;
	return -1;
}

