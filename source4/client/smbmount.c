/* 
   Unix SMB/CIFS implementation.
   SMBFS mount program
   Copyright (C) Andrew Tridgell 1999
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/passwd.h"

#include <mntent.h>
#include <asm/types.h>
#include <linux/smb_fs.h>

#define pstrcpy(d,s) safe_strcpy((d),(s),sizeof(pstring)-1)
#define pstrcat(d,s) safe_strcat((d),(s),sizeof(pstring)-1)

static pstring credentials;
static pstring my_netbios_name;
static pstring password;
static pstring username;
static pstring workgroup;
static pstring mpoint;
static pstring service;
static pstring options;

static struct in_addr dest_ip;
static bool have_ip;
static int smb_port = 0;
static bool got_user;
static bool got_pass;
static uid_t mount_uid;
static gid_t mount_gid;
static int mount_ro;
static uint_t mount_fmask;
static uint_t mount_dmask;
static bool use_kerberos;
/* TODO: Add code to detect smbfs version in kernel */
static bool status32_smbfs = false;

static void usage(void);

static void exit_parent(int sig)
{
	/* parent simply exits when child says go... */
	exit(0);
}

static void daemonize(void)
{
	int j, status;
	pid_t child_pid;

	signal( SIGTERM, exit_parent );

	if ((child_pid = sys_fork()) < 0) {
		DEBUG(0,("could not fork\n"));
	}

	if (child_pid > 0) {
		while( 1 ) {
			j = waitpid( child_pid, &status, 0 );
			if( j < 0 ) {
				if( EINTR == errno ) {
					continue;
				}
				status = errno;
			}
			break;
		}

		/* If we get here - the child exited with some error status */
		if (WIFSIGNALED(status))
			exit(128 + WTERMSIG(status));
		else
			exit(WEXITSTATUS(status));
	}

	signal( SIGTERM, SIG_DFL );
	chdir("/");
}

static void close_our_files(int client_fd)
{
	int i;
	struct rlimit limits;

	getrlimit(RLIMIT_NOFILE,&limits);
	for (i = 0; i< limits.rlim_max; i++) {
		if (i == client_fd)
			continue;
		close(i);
	}
}

static void usr1_handler(int x)
{
	return;
}


/***************************************************** 
return a connection to a server
*******************************************************/
static struct smbcli_state *do_connection(const char *the_service, bool unicode, int maxprotocol,
					  struct smbcli_session_options session_options)
{
	struct smbcli_state *c;
	struct nmb_name called, calling;
	char *server_n;
	struct in_addr ip;
	pstring server;
	char *share;

	if (the_service[0] != '\\' || the_service[1] != '\\') {
		usage();
		exit(1);
	}

	pstrcpy(server, the_service+2);
	share = strchr_m(server,'\\');
	if (!share) {
		usage();
		exit(1);
	}
	*share = 0;
	share++;

	server_n = server;

	make_nmb_name(&calling, my_netbios_name, 0x0);
	choose_called_name(&called, server, 0x20);

 again:
        zero_ip(&ip);
	if (have_ip) ip = dest_ip;

	/* have to open a new connection */
	if (!(c=smbcli_initialise(NULL)) || (smbcli_set_port(c, smb_port) != smb_port) ||
	    !smbcli_connect(c, server_n, &ip)) {
		DEBUG(0,("%d: Connection to %s failed\n", sys_getpid(), server_n));
		if (c) {
			talloc_free(c);
		}
		return NULL;
	}

	/* SPNEGO doesn't work till we get NTSTATUS error support */
	/* But it is REQUIRED for kerberos authentication */
	if(!use_kerberos) c->use_spnego = false;

	/* The kernel doesn't yet know how to sign it's packets */
	c->sign_info.allow_smb_signing = false;

	/* Use kerberos authentication if specified */
	c->use_kerberos = use_kerberos;

	if (!smbcli_session_request(c, &calling, &called)) {
		char *p;
		DEBUG(0,("%d: session request to %s failed (%s)\n", 
			 sys_getpid(), called.name, smbcli_errstr(c)));
		talloc_free(c);
		if ((p=strchr_m(called.name, '.'))) {
			*p = 0;
			goto again;
		}
		if (strcmp(called.name, "*SMBSERVER")) {
			make_nmb_name(&called , "*SMBSERVER", 0x20);
			goto again;
		}
		return NULL;
	}

	DEBUG(4,("%d: session request ok\n", sys_getpid()));

	if (!smbcli_negprot(c, unicode, maxprotocol)) {
		DEBUG(0,("%d: protocol negotiation failed\n", sys_getpid()));
		talloc_free(c);
		return NULL;
	}

	if (!got_pass) {
		char *pass = getpass("Password: ");
		if (pass) {
			pstrcpy(password, pass);
		}
	}

	/* This should be right for current smbfs. Future versions will support
	  large files as well as unicode and oplocks. */
	if (status32_smbfs) {
	    c->capabilities &= ~(CAP_UNICODE | CAP_LARGE_FILES | CAP_NT_SMBS |
                                 CAP_NT_FIND | CAP_LEVEL_II_OPLOCKS);
	}
	else {
	    c->capabilities &= ~(CAP_UNICODE | CAP_LARGE_FILES | CAP_NT_SMBS |
				 CAP_NT_FIND | CAP_STATUS32 |
				 CAP_LEVEL_II_OPLOCKS);
	    c->force_dos_errors = true;
	}

	if (!smbcli_session_setup(c, username, 
			       password, strlen(password),
			       password, strlen(password),
			       workgroup, session_options)) {
		/* if a password was not supplied then try again with a
			null username */
		if (password[0] || !username[0] ||
				!smbcli_session_setup(c, "", "", 0, "", 0, workgroup, 
						      session_options)) {
			DEBUG(0,("%d: session setup failed: %s\n",
				sys_getpid(), smbcli_errstr(c)));
			talloc_free(c);
			return NULL;
		}
		DEBUG(0,("Anonymous login successful\n"));
	}

	DEBUG(4,("%d: session setup ok\n", sys_getpid()));

	if (!smbcli_tconX(c, share, "?????", password, strlen(password)+1)) {
		DEBUG(0,("%d: tree connect failed: %s\n",
			 sys_getpid(), smbcli_errstr(c)));
		talloc_free(c);
		return NULL;
	}

	DEBUG(4,("%d: tconx ok\n", sys_getpid()));

	got_pass = true;

	return c;
}


/****************************************************************************
unmount smbfs  (this is a bailout routine to clean up if a reconnect fails)
	Code blatently stolen from smbumount.c
		-mhw-
****************************************************************************/
static void smb_umount(const char *mount_point)
{
	int fd;
        struct mntent *mnt;
        FILE* mtab;
        FILE* new_mtab;

	/* Programmers Note:
		This routine only gets called to the scene of a disaster
		to shoot the survivors...  A connection that was working
		has now apparently failed.  We have an active mount point
		(presumably) that we need to dump.  If we get errors along
		the way - make some noise, but we are already turning out
		the lights to exit anyways...
	*/
        if (umount(mount_point) != 0) {
                DEBUG(0,("%d: Could not umount %s: %s\n",
			 sys_getpid(), mount_point, strerror(errno)));
                return;
        }

        if ((fd = open(MOUNTED"~", O_RDWR|O_CREAT|O_EXCL, 0600)) == -1) {
                DEBUG(0,("%d: Can't get "MOUNTED"~ lock file", sys_getpid()));
                return;
        }

        close(fd);
	
        if ((mtab = setmntent(MOUNTED, "r")) == NULL) {
                DEBUG(0,("%d: Can't open " MOUNTED ": %s\n",
			 sys_getpid(), strerror(errno)));
                return;
        }

#define MOUNTED_TMP MOUNTED".tmp"

        if ((new_mtab = setmntent(MOUNTED_TMP, "w")) == NULL) {
                DEBUG(0,("%d: Can't open " MOUNTED_TMP ": %s\n",
			 sys_getpid(), strerror(errno)));
                endmntent(mtab);
                return;
        }

        while ((mnt = getmntent(mtab)) != NULL) {
                if (strcmp(mnt->mnt_dir, mount_point) != 0) {
                        addmntent(new_mtab, mnt);
                }
        }

        endmntent(mtab);

        if (fchmod (fileno (new_mtab), S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH) < 0) {
                DEBUG(0,("%d: Error changing mode of %s: %s\n",
			 sys_getpid(), MOUNTED_TMP, strerror(errno)));
                return;
        }

        endmntent(new_mtab);

        if (rename(MOUNTED_TMP, MOUNTED) < 0) {
                DEBUG(0,("%d: Cannot rename %s to %s: %s\n",
			 sys_getpid(), MOUNTED, MOUNTED_TMP, strerror(errno)));
                return;
        }

        if (unlink(MOUNTED"~") == -1) {
                DEBUG(0,("%d: Can't remove "MOUNTED"~", sys_getpid()));
                return;
        }
}


/*
 * Call the smbfs ioctl to install a connection socket,
 * then wait for a signal to reconnect. Note that we do
 * not exit after open_sockets() or send_login() errors,
 * as the smbfs mount would then have no way to recover.
 */
static void send_fs_socket(struct loadparm_context *lp_ctx,
			   const char *the_service, const char *mount_point, struct smbcli_state *c)
{
	int fd, closed = 0, res = 1;
	pid_t parentpid = getppid();
	struct smb_conn_opt conn_options;
	struct smbcli_session_options session_options;

	lp_smbcli_session_options(lp_ctx, &session_options);

	memset(&conn_options, 0, sizeof(conn_options));

	while (1) {
		if ((fd = open(mount_point, O_RDONLY)) < 0) {
			DEBUG(0,("mount.smbfs[%d]: can't open %s\n",
				 sys_getpid(), mount_point));
			break;
		}

		conn_options.fd = c->fd;
		conn_options.protocol = c->protocol;
		conn_options.case_handling = SMB_CASE_DEFAULT;
		conn_options.max_xmit = c->max_xmit;
		conn_options.server_uid = c->vuid;
		conn_options.tid = c->cnum;
		conn_options.secmode = c->sec_mode;
		conn_options.rawmode = 0;
		conn_options.sesskey = c->sesskey;
		conn_options.maxraw = 0;
		conn_options.capabilities = c->capabilities;
		conn_options.serverzone = c->serverzone/60;

		res = ioctl(fd, SMB_IOC_NEWCONN, &conn_options);
		if (res != 0) {
			DEBUG(0,("mount.smbfs[%d]: ioctl failed, res=%d\n",
				 sys_getpid(), res));
			close(fd);
			break;
		}

		if (parentpid) {
			/* Ok...  We are going to kill the parent.  Now
				is the time to break the process group... */
			setsid();
			/* Send a signal to the parent to terminate */
			kill(parentpid, SIGTERM);
			parentpid = 0;
		}

		close(fd);

		/* This looks wierd but we are only closing the userspace
		   side, the connection has already been passed to smbfs and 
		   it has increased the usage count on the socket.

		   If we don't do this we will "leak" sockets and memory on
		   each reconnection we have to make. */
		talloc_free(c);
		c = NULL;

		if (!closed) {
			/* redirect stdout & stderr since we can't know that
			   the library functions we use are using DEBUG. */
			if ( (fd = open("/dev/null", O_WRONLY)) < 0)
				DEBUG(2,("mount.smbfs: can't open /dev/null\n"));
			close_our_files(fd);
			if (fd >= 0) {
				dup2(fd, STDOUT_FILENO);
				dup2(fd, STDERR_FILENO);
				close(fd);
			}

			/* here we are no longer interactive */
			set_remote_machine_name("smbmount");	/* sneaky ... */
			setup_logging("mount.smbfs", DEBUG_STDERR);
			reopen_logs();
			DEBUG(0, ("mount.smbfs: entering daemon mode for service %s, pid=%d\n", the_service, sys_getpid()));

			closed = 1;
		}

		/* Wait for a signal from smbfs ... but don't continue
                   until we actually get a new connection. */
		while (!c) {
			CatchSignal(SIGUSR1, &usr1_handler);
			pause();
			DEBUG(2,("mount.smbfs[%d]: got signal, getting new socket\n", sys_getpid()));
			c = do_connection(the_service, 
					  lp_unicode(lp_ctx), 
					  lp_cli_maxprotocol(lp_ctx),
					  session_options);
		}
	}

	smb_umount(mount_point);
	DEBUG(2,("mount.smbfs[%d]: exit\n", sys_getpid()));
	exit(1);
}


/**
 * Mount a smbfs
 **/
static void init_mount(struct loadparm_context *lp_ctx)
{
	char mount_point[MAXPATHLEN+1];
	pstring tmp;
	pstring svc2;
	struct smbcli_state *c;
	char *args[20];
	int i, status;
	struct smbcli_session_options session_options;

	if (realpath(mpoint, mount_point) == NULL) {
		fprintf(stderr, "Could not resolve mount point %s\n", mpoint);
		return;
	}

	lp_smbcli_session_options(lp_ctx, &session_options);

	c = do_connection(service, lp_unicode(lp_ctx), lp_cli_maxprotocol(lp_ctx),
			  session_options);
	if (!c) {
		fprintf(stderr,"SMB connection failed\n");
		exit(1);
	}

	/*
		Set up to return as a daemon child and wait in the parent
		until the child say it's ready...
	*/
	daemonize();

	pstrcpy(svc2, service);
	string_replace(svc2, '\\','/');
	string_replace(svc2, ' ','_');

	memset(args, 0, sizeof(args[0])*20);

	i=0;
	args[i++] = "smbmnt";

	args[i++] = mount_point;
	args[i++] = "-s";
	args[i++] = svc2;

	if (mount_ro) {
		args[i++] = "-r";
	}
	if (mount_uid) {
		slprintf(tmp, sizeof(tmp)-1, "%d", mount_uid);
		args[i++] = "-u";
		args[i++] = smb_xstrdup(tmp);
	}
	if (mount_gid) {
		slprintf(tmp, sizeof(tmp)-1, "%d", mount_gid);
		args[i++] = "-g";
		args[i++] = smb_xstrdup(tmp);
	}
	if (mount_fmask) {
		slprintf(tmp, sizeof(tmp)-1, "0%o", mount_fmask);
		args[i++] = "-f";
		args[i++] = smb_xstrdup(tmp);
	}
	if (mount_dmask) {
		slprintf(tmp, sizeof(tmp)-1, "0%o", mount_dmask);
		args[i++] = "-d";
		args[i++] = smb_xstrdup(tmp);
	}
	if (options) {
		args[i++] = "-o";
		args[i++] = options;
	}

	if (sys_fork() == 0) {
		char *smbmnt_path;

		asprintf(&smbmnt_path, "%s/smbmnt", dyn_BINDIR);
		
		if (file_exist(smbmnt_path)) {
			execv(smbmnt_path, args);
			fprintf(stderr,
				"smbfs/init_mount: execv of %s failed. Error was %s.",
				smbmnt_path, strerror(errno));
		} else {
			execvp("smbmnt", args);
			fprintf(stderr,
				"smbfs/init_mount: execv of %s failed. Error was %s.",
				"smbmnt", strerror(errno));
		}
		free(smbmnt_path);
		exit(1);
	}

	if (waitpid(-1, &status, 0) == -1) {
		fprintf(stderr,"waitpid failed: Error was %s", strerror(errno) );
		/* FIXME: do some proper error handling */
		exit(1);
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
		fprintf(stderr,"smbmnt failed: %d\n", WEXITSTATUS(status));
		/* FIXME: do some proper error handling */
		exit(1);
	} else if (WIFSIGNALED(status)) {
		fprintf(stderr, "smbmnt killed by signal %d\n", WTERMSIG(status));
		exit(1);
	}

	/* Ok...  This is the rubicon for that mount point...  At any point
	   after this, if the connections fail and can not be reconstructed
	   for any reason, we will have to unmount the mount point.  There
	   is no exit from the next call...
	*/
	send_fs_socket(lp_ctx, service, mount_point, c);
}


/****************************************************************************
get a password from a a file or file descriptor
exit on failure (from smbclient, move to libsmb or shared .c file?)
****************************************************************************/
static void get_password_file(void)
{
	int fd = -1;
	char *p;
	bool close_it = false;
	pstring spec;
	char pass[128];

	if ((p = getenv("PASSWD_FD")) != NULL) {
		pstrcpy(spec, "descriptor ");
		pstrcat(spec, p);
		sscanf(p, "%d", &fd);
		close_it = false;
	} else if ((p = getenv("PASSWD_FILE")) != NULL) {
		fd = open(p, O_RDONLY, 0);
		pstrcpy(spec, p);
		if (fd < 0) {
			fprintf(stderr, "Error opening PASSWD_FILE %s: %s\n",
				spec, strerror(errno));
			exit(1);
		}
		close_it = true;
	}

	for(p = pass, *p = '\0'; /* ensure that pass is null-terminated */
	    p && p - pass < sizeof(pass);) {
		switch (read(fd, p, 1)) {
		case 1:
			if (*p != '\n' && *p != '\0') {
				*++p = '\0'; /* advance p, and null-terminate pass */
				break;
			}
		case 0:
			if (p - pass) {
				*p = '\0'; /* null-terminate it, just in case... */
				p = NULL; /* then force the loop condition to become false */
				break;
			} else {
				fprintf(stderr, "Error reading password from file %s: %s\n",
					spec, "empty password\n");
				exit(1);
			}

		default:
			fprintf(stderr, "Error reading password from file %s: %s\n",
				spec, strerror(errno));
			exit(1);
		}
	}
	pstrcpy(password, pass);
	if (close_it)
		close(fd);
}

/****************************************************************************
get username and password from a credentials file
exit on failure (from smbclient, move to libsmb or shared .c file?)
****************************************************************************/
static void read_credentials_file(char *filename)
{
	FILE *auth;
	fstring buf;
	uint16_t len = 0;
	char *ptr, *val, *param;

	if ((auth=sys_fopen(filename, "r")) == NULL)
	{
		/* fail if we can't open the credentials file */
		DEBUG(0,("ERROR: Unable to open credentials file!\n"));
		exit (-1);
	}

	while (!feof(auth))
	{
		/* get a line from the file */
		if (!fgets (buf, sizeof(buf), auth))
			continue;
		len = strlen(buf);

		if ((len) && (buf[len-1]=='\n'))
		{
			buf[len-1] = '\0';
			len--;
		}
		if (len == 0)
			continue;

		/* break up the line into parameter & value.
		   will need to eat a little whitespace possibly */
		param = buf;
		if (!(ptr = strchr (buf, '=')))
			continue;
		val = ptr+1;
		*ptr = '\0';

		/* eat leading white space */
		while ((*val!='\0') && ((*val==' ') || (*val=='\t')))
			val++;

		if (strwicmp("password", param) == 0)
		{
			pstrcpy(password, val);
			got_pass = true;
		}
		else if (strwicmp("username", param) == 0) {
			pstrcpy(username, val);
		}

		memset(buf, 0, sizeof(buf));
	}
	fclose(auth);
}


/****************************************************************************
usage on the program
****************************************************************************/
static void usage(void)
{
	printf("Usage: mount.smbfs service mountpoint [-o options,...]\n");

	printf("Version %s\n\n",VERSION);

	printf(
"Options:\n\
      username=<arg>                  SMB username\n\
      password=<arg>                  SMB password\n\
      credentials=<filename>          file with username/password\n\
      krb                             use kerberos (active directory)\n\
      netbiosname=<arg>               source NetBIOS name\n\
      uid=<arg>                       mount uid or username\n\
      gid=<arg>                       mount gid or groupname\n\
      port=<arg>                      remote SMB port number\n\
      fmask=<arg>                     file umask\n\
      dmask=<arg>                     directory umask\n\
      debug=<arg>                     debug level\n\
      ip=<arg>                        destination host or IP address\n\
      workgroup=<arg>                 workgroup on destination\n\
      sockopt=<arg>                   TCP socket options\n\
      scope=<arg>                     NetBIOS scope\n\
      iocharset=<arg>                 Linux charset (iso8859-1, utf8)\n\
      codepage=<arg>                  server codepage (cp850)\n\
      ttl=<arg>                       dircache time to live\n\
      guest                           don't prompt for a password\n\
      ro                              mount read-only\n\
      rw                              mount read-write\n\
\n\
This command is designed to be run from within /bin/mount by giving\n\
the option '-t smbfs'. For example:\n\
  mount -t smbfs -o username=tridge,password=foobar //fjall/test /data/test\n\
");
}


/****************************************************************************
  Argument parsing for mount.smbfs interface
  mount will call us like this:
    mount.smbfs device mountpoint -o <options>
  
  <options> is never empty, containing at least rw or ro
 ****************************************************************************/
static void parse_mount_smb(int argc, char **argv)
{
	int opt;
	char *opts;
	char *opteq;
	extern char *optarg;
	int val;
	char *p;

	/* FIXME: This function can silently fail if the arguments are
	 * not in the expected order.

	> The arguments syntax of smbmount 2.2.3a (smbfs of Debian stable)
	> requires that one gives "-o" before further options like username=...
	> . Without -o, the username=.. setting is *silently* ignored. I've
	> spent about an hour trying to find out why I couldn't log in now..

	*/


	if (argc < 2 || argv[1][0] == '-') {
		usage();
		exit(1);
	}
	
	pstrcpy(service, argv[1]);
	pstrcpy(mpoint, argv[2]);

	/* Convert any '/' characters in the service name to
	   '\' characters */
	string_replace(service, '/','\\');
	argc -= 2;
	argv += 2;

	opt = getopt(argc, argv, "o:");
	if(opt != 'o') {
		return;
	}

	options[0] = 0;
	p = options;

	/*
	 * option parsing from nfsmount.c (util-linux-2.9u)
	 */
        for (opts = strtok(optarg, ","); opts; opts = strtok(NULL, ",")) {
		DEBUG(3, ("opts: %s\n", opts));
                if ((opteq = strchr_m(opts, '='))) {
                        val = atoi(opteq + 1);
                        *opteq = '\0';

                        if (!strcmp(opts, "username") || 
			    !strcmp(opts, "logon")) {
				char *lp;
				got_user = true;
				pstrcpy(username,opteq+1);
				if ((lp=strchr_m(username,'%'))) {
					*lp = 0;
					pstrcpy(password,lp+1);
					got_pass = true;
					memset(strchr_m(opteq+1,'%')+1,'X',strlen(password));
				}
				if ((lp=strchr_m(username,'/'))) {
					*lp = 0;
					pstrcpy(workgroup,lp+1);
				}
			} else if(!strcmp(opts, "passwd") ||
				  !strcmp(opts, "password")) {
				pstrcpy(password,opteq+1);
				got_pass = true;
				memset(opteq+1,'X',strlen(password));
			} else if(!strcmp(opts, "credentials")) {
				pstrcpy(credentials,opteq+1);
			} else if(!strcmp(opts, "netbiosname")) {
				pstrcpy(my_netbios_name,opteq+1);
			} else if(!strcmp(opts, "uid")) {
				mount_uid = nametouid(opteq+1);
			} else if(!strcmp(opts, "gid")) {
				mount_gid = nametogid(opteq+1);
			} else if(!strcmp(opts, "port")) {
				smb_port = val;
			} else if(!strcmp(opts, "fmask")) {
				mount_fmask = strtol(opteq+1, NULL, 8);
			} else if(!strcmp(opts, "dmask")) {
				mount_dmask = strtol(opteq+1, NULL, 8);
			} else if(!strcmp(opts, "debug")) {
				DEBUGLEVEL = val;
			} else if(!strcmp(opts, "ip")) {
				dest_ip = interpret_addr2(opteq+1);
				if (is_zero_ip_v4(dest_ip)) {
					fprintf(stderr,"Can't resolve address %s\n", opteq+1);
					exit(1);
				}
				have_ip = true;
			} else if(!strcmp(opts, "workgroup")) {
				pstrcpy(workgroup,opteq+1);
			} else if(!strcmp(opts, "sockopt")) {
				lp_set_cmdline("socket options", opteq+1);
			} else if(!strcmp(opts, "scope")) {
				lp_set_cmdline("netbios scope", opteq+1);
			} else {
				slprintf(p, sizeof(pstring) - (p - options) - 1, "%s=%s,", opts, opteq+1);
				p += strlen(p);
			}
		} else {
			val = 1;
			if(!strcmp(opts, "nocaps")) {
				fprintf(stderr, "Unhandled option: %s\n", opteq+1);
				exit(1);
			} else if(!strcmp(opts, "guest")) {
				*password = '\0';
				got_pass = true;
			} else if(!strcmp(opts, "krb")) {
#ifdef HAVE_KRB5

				use_kerberos = true;
				if(!status32_smbfs)
					fprintf(stderr, "Warning: kerberos support will only work for samba servers\n");
#else
				fprintf(stderr,"No kerberos support compiled in\n");
				exit(1);
#endif
			} else if(!strcmp(opts, "rw")) {
				mount_ro = 0;
			} else if(!strcmp(opts, "ro")) {
				mount_ro = 1;
			} else {
				strncpy(p, opts, sizeof(pstring) - (p - options) - 1);
				p += strlen(opts);
				*p++ = ',';
				*p = 0;
			}
		}
	}

	if (!*service) {
		usage();
		exit(1);
	}

	if (p != options) {
		*(p-1) = 0;	/* remove trailing , */
		DEBUG(3,("passthrough options '%s'\n", options));
	}
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	extern char *optarg;
	extern int optind;
	char *p;
	struct loadparm_context *lp_ctx;

	DEBUGLEVEL = 1;

	/* here we are interactive, even if run from autofs */
	setup_logging("mount.smbfs",DEBUG_STDERR);

#if 0 /* JRA - Urban says not needed ? */
	/* CLI_FORCE_ASCII=false makes smbmount negotiate unicode. The default
	   is to not announce any unicode capabilities as current smbfs does
	   not support it. */
	p = getenv("CLI_FORCE_ASCII");
	if (p && !strcmp(p, "false"))
		unsetenv("CLI_FORCE_ASCII");
	else
		setenv("CLI_FORCE_ASCII", "true", 1);
#endif

	if (getenv("USER")) {
		pstrcpy(username,getenv("USER"));

		if ((p=strchr_m(username,'%'))) {
			*p = 0;
			pstrcpy(password,p+1);
			got_pass = true;
			memset(strchr_m(getenv("USER"),'%')+1,'X',strlen(password));
		}
		strupper(username);
	}

	if (getenv("PASSWD")) {
		pstrcpy(password, getenv("PASSWD"));
		got_pass = true;
	}

	if (getenv("PASSWD_FD") || getenv("PASSWD_FILE")) {
		get_password_file();
		got_pass = true;
	}

	if (*username == 0 && getenv("LOGNAME")) {
		pstrcpy(username,getenv("LOGNAME"));
	}

	lp_ctx = loadparm_init(talloc_autofree_context());

	if (!lp_load(lp_ctx, dyn_CONFIGFILE)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", 
			lp_config_file());
	}

	parse_mount_smb(argc, argv);

	if (use_kerberos && !got_user) {
		got_pass = true;
	}

	if (*credentials != 0) {
		read_credentials_file(credentials);
	}

	DEBUG(3,("mount.smbfs started (version %s)\n", VERSION));

	if (*workgroup == 0) {
		pstrcpy(workgroup, lp_workgroup());
	}

	if (!*my_netbios_name) {
		pstrcpy(my_netbios_name, myhostname());
	}
	strupper(my_netbios_name);

	init_mount(lp_ctx);
	return 0;
}
