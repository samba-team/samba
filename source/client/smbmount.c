/* 
   Unix SMB/Netbios implementation.
   Version 2.0.
   SMBFS mount program
   Copyright (C) Andrew Tridgell 1999
   
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

#define NO_SYSLOG

#include "includes.h"

#include <mntent.h>
#include <asm/types.h>
#include <linux/smb_fs.h>

/* Uncomment this to allow debug the mount.smb daemon */
/* WARNING!  This option is incompatible with autofs/automount because
	it does not close the stdout pipe back to the automount
	process, which automount depends on.  This will cause automount
	to hang!  Use with caution! */
/* #define SMBFS_DEBUG 1 */

extern struct in_addr ipzero;
extern int DEBUGLEVEL;

extern BOOL in_client;
extern pstring user_socket_options;

static pstring my_netbios_name;
static pstring password;
static pstring username;
static pstring workgroup;
static pstring mpoint;
static pstring service;

static struct in_addr dest_ip;
static BOOL have_ip;
static int smb_port = 139;
static BOOL got_pass;
static uid_t mount_uid;
static gid_t mount_gid;
static int mount_ro;
static unsigned mount_fmask;
static unsigned mount_dmask;

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

	if ((child_pid = fork()) < 0) {
		fprintf(stderr,"could not fork\n");
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
		exit(status);
	}

	signal( SIGTERM, SIG_DFL );
	chdir("/");
}

static void close_our_files(int client_fd)
{
	int i;
	for (i = 0; i < 256; i++) {
		if (i == client_fd) continue;
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
static struct cli_state *do_connection(char *service)
{
	struct cli_state *c;
	struct nmb_name called, calling;
	char *server_n;
	struct in_addr ip;
	extern struct in_addr ipzero;
	pstring server;
	char *share;

	if (service[0] != '\\' || service[1] != '\\') {
		usage();
		exit(1);
	}

	pstrcpy(server, service+2);
	share = strchr(server,'\\');
	if (!share) {
		usage();
		exit(1);
	}
	*share = 0;
	share++;

	server_n = server;
	
	ip = ipzero;

	make_nmb_name(&calling, my_netbios_name, 0x0);
	make_nmb_name(&called , server, 0x20);

 again:
	ip = ipzero;
	if (have_ip) ip = dest_ip;

	/* have to open a new connection */
	if (!(c=cli_initialise(NULL)) || (cli_set_port(c, smb_port) == 0) ||
	    !cli_connect(c, server_n, &ip)) {
		fprintf(stderr,"Connection to %s failed\n", server_n);
		return NULL;
	}

	if (!cli_session_request(c, &calling, &called)) {
		fprintf(stderr, "session request to %s failed\n", called.name);
		cli_shutdown(c);
		if (strcmp(called.name, "*SMBSERVER")) {
			make_nmb_name(&called , "*SMBSERVER", 0x20);
			goto again;
		}
		return NULL;
	}

	DEBUG(4,(" session request ok\n"));

	if (!cli_negprot(c)) {
		fprintf(stderr, "protocol negotiation failed\n");
		cli_shutdown(c);
		return NULL;
	}

	if (!got_pass) {
		char *pass = getpass("Password: ");
		if (pass) {
			pstrcpy(password, pass);
		}
	}

	if (!cli_session_setup(c, username, 
			       password, strlen(password),
			       password, strlen(password),
			       workgroup)) {
		fprintf(stderr, "session setup failed: %s\n", cli_errstr(c));
		return NULL;
	}

	DEBUG(4,(" session setup ok\n"));

	if (!cli_send_tconX(c, share, "?????",
			    password, strlen(password)+1)) {
		fprintf(stderr,"tree connect failed: %s\n", cli_errstr(c));
		cli_shutdown(c);
		return NULL;
	}

	DEBUG(4,(" tconx ok\n"));

	got_pass = True;

	return c;
}


/****************************************************************************
unmount smbfs  (this is a bailout routine to clean up if a reconnect fails)
	Code blatently stolen from smbumount.c
		-mhw-
****************************************************************************/
static void smb_umount(char *mount_point)
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
                fprintf(stderr, "Could not umount %s: %s\n",
                        mount_point, strerror(errno));
                return;
        }

        if ((fd = open(MOUNTED"~", O_RDWR|O_CREAT|O_EXCL, 0600)) == -1) {
                fprintf(stderr, "Can't get "MOUNTED"~ lock file");
                return;
        }

        close(fd);
	
        if ((mtab = setmntent(MOUNTED, "r")) == NULL) {
                fprintf(stderr, "Can't open " MOUNTED ": %s\n",
                        strerror(errno));
                return;
        }

#define MOUNTED_TMP MOUNTED".tmp"

        if ((new_mtab = setmntent(MOUNTED_TMP, "w")) == NULL) {
                fprintf(stderr, "Can't open " MOUNTED_TMP ": %s\n",
                        strerror(errno));
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
                fprintf(stderr, "Error changing mode of %s: %s\n",
                        MOUNTED_TMP, strerror(errno));
                return;
        }

        endmntent(new_mtab);

        if (rename(MOUNTED_TMP, MOUNTED) < 0) {
                fprintf(stderr, "Cannot rename %s to %s: %s\n",
                        MOUNTED, MOUNTED_TMP, strerror(errno));
                return;
        }

        if (unlink(MOUNTED"~") == -1) {
                fprintf(stderr, "Can't remove "MOUNTED"~");
                return;
        }
}


/*
 * Call the smbfs ioctl to install a connection socket,
 * then wait for a signal to reconnect. Note that we do
 * not exit after open_sockets() or send_login() errors,
 * as the smbfs mount would then have no way to recover.
 */
static void send_fs_socket(char *service, char *mount_point, struct cli_state *c)
{
	int fd, closed = 0, res = 1;
	pid_t parentpid = getppid();
	struct smb_conn_opt conn_options;

	memset(&conn_options, 0, sizeof(conn_options));

	while (1) {
		if ((fd = open(mount_point, O_RDONLY)) < 0) {
			fprintf(stderr, "mount.smbfs: can't open %s\n", mount_point);
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
			fprintf(stderr, "mount.smbfs: ioctl failed, res=%d\n", res);
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

#ifndef SMBFS_DEBUG
		/* Close all open files if we haven't done so yet. */
		if (!closed) {
			extern FILE *dbf;
			closed = 1;
			dbf = NULL;
			close_our_files(c?c->fd:-1);
		}
#endif

		/* Wait for a signal from smbfs ... */
		CatchSignal(SIGUSR1, &usr1_handler);
		pause();
#ifdef SMBFS_DEBUG
		DEBUG(2,("mount.smbfs: got signal, getting new socket\n"));
#endif
		c = do_connection(service);
	}

	smb_umount(mount_point);
	DEBUG(2,("mount.smbfs: exit\n"));
	exit(1);
}

/*********************************************************
a strdup with exit
**********************************************************/
static char *xstrdup(char *s)
{
	s = strdup(s);
	if (!s) {
		fprintf(stderr,"out of memory\n");
		exit(1);
	}
	return s;
}


/****************************************************************************
mount smbfs
****************************************************************************/
static void init_mount(void)
{
	char mount_point[MAXPATHLEN+1];
	pstring tmp;
	pstring svc2;
	struct cli_state *c;
	char *args[20];
	int i, status;

	if (realpath(mpoint, mount_point) == NULL) {
		fprintf(stderr, "Could not resolve mount point %s\n", mpoint);
		return;
	}


	c = do_connection(service);
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
		slprintf(tmp, sizeof(tmp), "%d", mount_uid);
		args[i++] = "-u";
		args[i++] = xstrdup(tmp);
	}
	if (mount_gid) {
		slprintf(tmp, sizeof(tmp), "%d", mount_gid);
		args[i++] = "-g";
		args[i++] = xstrdup(tmp);
	}
	if (mount_fmask) {
		slprintf(tmp, sizeof(tmp), "0%o", mount_fmask);
		args[i++] = "-f";
		args[i++] = xstrdup(tmp);
	}
	if (mount_dmask) {
		slprintf(tmp, sizeof(tmp), "0%o", mount_dmask);
		args[i++] = "-d";
		args[i++] = xstrdup(tmp);
	}

	if (fork() == 0) {
		if (file_exist(BINDIR "/smbmnt", NULL)) {
			execv(BINDIR "/smbmnt", args);
			fprintf(stderr,"execv of %s failed. Error was %s.", BINDIR "/smbmnt", strerror(errno));
		} else {
			execvp("smbmnt", args);
			fprintf(stderr,"execvp of smbmnt failed. Error was %s.", strerror(errno) );
		}
		exit(1);
	}

	if (waitpid(-1, &status, 0) == -1) {
		fprintf(stderr,"waitpid failed: Error was %s", strerror(errno) );
		/* FIXME: do some proper error handling */
		exit(1);
	}	

	if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
		fprintf(stderr,"smbmnt failed: %d\n", WEXITSTATUS(status));
	}

	/* Ok...  This is the rubicon for that mount point...  At any point
	   after this, if the connections fail and can not be reconstructed
	   for any reason, we will have to unmount the mount point.  There
	   is no exit from the next call...
	*/
	send_fs_socket(service, mount_point, c);
}


/****************************************************************************
usage on the program
****************************************************************************/
static void usage(void)
{
	printf("Usage: mount.smbfs service mountpoint [-o options,...]\n");

	printf("Version %s\n\n",VERSION);

	printf(
"Options:
      username=<arg>                  SMB username
      password=<arg>                  SMB password
      netbiosname=<arg>               source NetBIOS name
      uid=<arg>                       mount uid or username
      gid=<arg>                       mount gid or groupname
      port=<arg>                      remote SMB port number
      fmask=<arg>                     file umask
      dmask=<arg>                     directory umask
      debug=<arg>                     debug level
      ip=<arg>                        destination host or IP address
      workgroup=<arg>                 workgroup on destination
      sockopt=<arg>                   TCP socket options
      scope=<arg>                     NetBIOS scope
      guest                           don't prompt for a password
      ro                              mount read-only
      rw                              mount read-write

This command is designed to be run from within /bin/mount by giving
the option '-t smbfs'. For example:
  mount -t smbfs -o username=tridge,password=foobar //fjall/test /data/test
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
	extern pstring global_scope;

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

	/*
	 * option parsing from nfsmount.c (util-linux-2.9u)
	 */
        for (opts = strtok(optarg, ","); opts; opts = strtok(NULL, ",")) {
		DEBUG(3, ("opts: %s\n", opts));
                if ((opteq = strchr(opts, '='))) {
                        val = atoi(opteq + 1);
                        *opteq = '\0';

                        if (!strcmp(opts, "username") || 
			    !strcmp(opts, "logon")) {
				char *lp;
				pstrcpy(username,opteq+1);
				if ((lp=strchr(username,'%'))) {
					*lp = 0;
					pstrcpy(password,lp+1);
					got_pass = True;
					memset(strchr(opteq+1,'%')+1,'X',strlen(password));
				}
				if ((lp=strchr(username,'/'))) {
					*lp = 0;
					pstrcpy(workgroup,lp+1);
				}
			} else if(!strcmp(opts, "passwd") ||
				  !strcmp(opts, "password")) {
				pstrcpy(password,opteq+1);
				got_pass = True;
				memset(opteq+1,'X',strlen(password));
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
				dest_ip = *interpret_addr2(opteq+1);
				if (zero_ip(dest_ip)) {
					fprintf(stderr,"Can't resolve address %s\n", opteq+1);
					exit(1);
				}
				have_ip = True;
			} else if(!strcmp(opts, "workgroup")) {
				pstrcpy(workgroup,opteq+1);
			} else if(!strcmp(opts, "sockopt")) {
				pstrcpy(user_socket_options,opteq+1);
			} else if(!strcmp(opts, "scope")) {
				pstrcpy(global_scope,opteq+1);
			} else {
				usage();
				exit(1);
			}
		} else {
			val = 1;
			if(!strcmp(opts, "nocaps")) {
				fprintf(stderr, "Unhandled option: %s\n", opteq+1);
				exit(1);
			} else if(!strcmp(opts, "guest")) {
				got_pass = True;
			} else if(!strcmp(opts, "rw")) {
				mount_ro = 0;
			} else if(!strcmp(opts, "ro")) {
				mount_ro = 1;
			}
		}
	}

	if (!*service) {
		usage();
		exit(1);
	}
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	extern char *optarg;
	extern int optind;
	static pstring servicesf = CONFIGFILE;
	char *p;

	DEBUGLEVEL = 1;
	
	setup_logging("mount.smbfs",True);

	TimeInit();
	charset_initialise();
	
	in_client = True;   /* Make sure that we tell lp_load we are */

	if (getenv("USER")) {
		pstrcpy(username,getenv("USER"));

		if ((p=strchr(username,'%'))) {
			*p = 0;
			pstrcpy(password,p+1);
			got_pass = True;
		}
	}

	if (getenv("PASSWD")) {
		pstrcpy(password,getenv("PASSWD"));
	}

	if (*username == 0 && getenv("LOGNAME")) {
		pstrcpy(username,getenv("LOGNAME"));
	}

	parse_mount_smb(argc, argv);

	DEBUG(3,("mount.smbfs started (version %s)\n", VERSION));

	if (!lp_load(servicesf,True,False,False)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", 
			servicesf);
	}

	codepage_initialise(lp_client_code_page());

	if (*workgroup == 0) {
		pstrcpy(workgroup,lp_workgroup());
	}

	load_interfaces();
	if (!*my_netbios_name) {
		pstrcpy(my_netbios_name, myhostname());
	}
	strupper(my_netbios_name);

	init_mount();
	return 0;
}
