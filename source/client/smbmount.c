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

#ifndef REGISTER
#define REGISTER 0
#endif

/* Uncomment this to allow debug the smbmount daemon */
/* WARNING!  This option is incompatible with autofs/automount because
	it does not close the stdout pipe back to the automount
	process, which automount depends on.  This will cause automount
	to hang!  Use with caution! */
/* #define SMBFS_DEBUG 1 */

extern struct in_addr ipzero;
extern int DEBUGLEVEL;

extern pstring scope;
extern pstring global_myname;
extern BOOL in_client;
extern pstring user_socket_options;
extern pstring myhostname;

static pstring password;
static pstring username;
static pstring workgroup;

static struct in_addr dest_ip;
static BOOL have_ip;
static int port = 139;
static BOOL got_pass;

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
		DEBUG(0, ("could not fork\n"));
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

	make_nmb_name(&calling, global_myname, 0x0, "");
	make_nmb_name(&called , server, 0x20, "");

 again:
	ip = ipzero;
	if (have_ip) ip = dest_ip;

	/* have to open a new connection */
	if (!(c=cli_initialise(NULL)) || (cli_set_port(c, port) == 0) ||
	    !cli_connect(c, server_n, &ip)) {
		DEBUG(0,("Connection to %s failed\n", server_n));
		return NULL;
	}

	if (!cli_session_request(c, &calling, &called)) {
		DEBUG(0,("session request to %s failed\n", called.name));
		cli_shutdown(c);
		if (strcmp(called.name, "*SMBSERVER")) {
			make_nmb_name(&called , "*SMBSERVER", 0x20, "");
			goto again;
		}
		return NULL;
	}

	DEBUG(4,(" session request ok\n"));

	if (!cli_negprot(c)) {
		DEBUG(0,("protocol negotiation failed\n"));
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
		DEBUG(0,("session setup failed: %s\n", cli_errstr(c)));
		return NULL;
	}

	DEBUG(4,(" session setup ok\n"));

	if (!cli_send_tconX(c, share, "?????",
			    password, strlen(password)+1)) {
		DEBUG(0,("tree connect failed: %s\n", cli_errstr(c)));
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
                DEBUG(0, ("Could not umount %s: %s\n",
                        mount_point, strerror(errno)));
                return;
        }

        if ((fd = open(MOUNTED"~", O_RDWR|O_CREAT|O_EXCL, 0600)) == -1) {
                DEBUG(0, ("Can't get "MOUNTED"~ lock file"));
                return;
        }

        close(fd);
	
        if ((mtab = setmntent(MOUNTED, "r")) == NULL) {
                DEBUG(0, ("Can't open " MOUNTED ": %s\n",
                        strerror(errno)));
                return;
        }

#define MOUNTED_TMP MOUNTED".tmp"

        if ((new_mtab = setmntent(MOUNTED_TMP, "w")) == NULL) {
                DEBUG(0, ("Can't open " MOUNTED_TMP ": %s\n",
                        strerror(errno)));
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
                DEBUG(0, ("Error changing mode of %s: %s\n",
                        MOUNTED_TMP, strerror(errno)));
                return;
        }

        endmntent(new_mtab);

        if (rename(MOUNTED_TMP, MOUNTED) < 0) {
                DEBUG(0, ("Cannot rename %s to %s: %s\n",
                        MOUNTED, MOUNTED_TMP, strerror(errno)));
                return;
        }

        if (unlink(MOUNTED"~") == -1) {
                DEBUG(0, ("Can't remove "MOUNTED"~"));
                return;
        }
}


/*
 * Call the smbfs ioctl to install a connection socket,
 * then wait for a signal to reconnect. Note that we do
 * not exit after open_sockets() or send_login() errors,
 * as the smbfs mount would then have no way to recover.
 */
static void send_fs_socket(char *service, char *mount_point)
{
	int fd, closed = 0, res = 1;
	pid_t parentpid = getppid();
	struct cli_state *c = NULL;
	struct smb_conn_opt conn_options;

	memset(&conn_options, 0, sizeof(conn_options));

	while (1) {
		if ((fd = open(mount_point, O_RDONLY)) < 0) {
			DEBUG(0, ("smbmount: can't open %s\n", mount_point));
			break;
		}		

		c = do_connection(service);

		if (!c) {
			DEBUG(0, ("smbmount: login failed\n"));
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
			DEBUG(0,("smbmount: ioctl failed, res=%d\n", res));
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
			closed = 1;
			close_our_files(c?c->fd:-1);
		}
#endif

		/* Wait for a signal from smbfs ... */
		CatchSignal(SIGUSR1, &usr1_handler);
		pause();
#ifndef SMBFS_DEBUG
		DEBUG(0,("smbmount: got signal, getting new socket\n"));
#endif
	}

	smb_umount(mount_point);
	DEBUG(0,("smbmount: exit\n"));
	exit(1);
}


/****************************************************************************
mount smbfs
****************************************************************************/
static void init_mount(char *service, char *mpoint,char *options)
{
	int retval;
	char mount_point[MAXPATHLEN+1];
	pstring mount_command;
	pstring svc2;

	if (realpath(mpoint, mount_point) == NULL) {
		DEBUG(0, ("Could not resolve mount point %s\n", mpoint));
		return;
	}

	/*
		Set up to return as a daemon child and wait in the parent
		until the child say it's ready...
	*/
	daemonize();

	pstrcpy(svc2, service);
	string_replace(svc2, '\\','/');
	string_replace(svc2, ' ','_');

	slprintf(mount_command,sizeof(mount_command),
		 "smbmnt %s -s %s", mount_point, svc2);

	if ((retval = system(mount_command)) != 0) {
		DEBUG(0,("mount failed\n"));
		exit(1);
	}

	/* Ok...  This is the rubicon for that mount point...  At any point
	   after this, if the connections fail and can not be reconstructed
	   for any reason, we will have to unmount the mount point.  There
	   is no exit from the next call...
	*/
	send_fs_socket(service, mount_point);
}




/****************************************************************************
usage on the program
****************************************************************************/
static void usage(void)
{
	DEBUG(0,("Usage: smbmount //server/share mountpoint [options ...]"));

	DEBUG(0,("\nVersion %s\n",VERSION));
	DEBUG(0,("\t-d debuglevel         set the debuglevel\n"));
	DEBUG(0,("\t-n netbios name.      Use this name as my netbios name\n"));
	DEBUG(0,("\t-N                    don't ask for a password\n"));
	DEBUG(0,("\t-I dest IP            use this IP to connect to\n"));
	DEBUG(0,("\t-E                    write messages to stderr instead of stdout\n"));
	DEBUG(0,("\t-U username           set the network username\n"));
	DEBUG(0,("\t-W workgroup          set the workgroup name\n"));
	DEBUG(0,("\t-t terminal code      terminal i/o code {sjis|euc|jis7|jis8|junet|hex}\n"));
	DEBUG(0,("\n"));
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	int opt;
	extern FILE *dbf;
	extern char *optarg;
	extern int optind;
	static pstring servicesf = CONFIGFILE;
	pstring term_code;
	char *p;
	pstring mpoint;
	pstring service;

#ifdef KANJI
	pstrcpy(term_code, KANJI);
#else /* KANJI */
	*term_code = 0;
#endif /* KANJI */

	DEBUGLEVEL = 2;
	
	setup_logging("smbmount",True);

	TimeInit();
	charset_initialise();
	
	in_client = True;   /* Make sure that we tell lp_load we are */

	if (getenv("USER")) {
		pstrcpy(username,getenv("USER"));

		if ((p=strchr(username,'%'))) {
			*p = 0;
			pstrcpy(password,p+1);
			got_pass = True;
			memset(strchr(getenv("USER"),'%')+1,'X',strlen(password));
		}
		strupper(username);
	}

	if (getenv("PASSWD")) {
		pstrcpy(password,getenv("PASSWD"));
	}

	if (*username == 0 && getenv("LOGNAME")) {
		pstrcpy(username,getenv("LOGNAME"));
		strupper(username);
	}

	if (argc < 3 || *argv[1] == '-' || *argv[2] == '-') {
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

	while ((opt = 
		getopt(argc, argv,"O:i:U:W:EI:n:Nd:h")) != EOF)
		switch (opt) {
		case 'O':
			pstrcpy(user_socket_options,optarg);
			break;	
		case 'i':
			pstrcpy(scope,optarg);
			break;
		case 'U':
			{
				char *lp;
				pstrcpy(username,optarg);
				if ((lp=strchr(username,'%'))) {
					*lp = 0;
					pstrcpy(password,lp+1);
					got_pass = True;
					memset(strchr(optarg,'%')+1,'X',strlen(password));
				}
			}
			break;
		case 'W':
			pstrcpy(workgroup,optarg);
			break;
		case 'E':
			dbf = stderr;
			break;
		case 'I':
			dest_ip = *interpret_addr2(optarg);
			if (zero_ip(dest_ip)) {
				fprintf(stderr,"Can't resolve address %s\n", optarg);
				exit(1);
			}
			have_ip = True;
			break;
		case 'n':
			pstrcpy(global_myname,optarg);
			break;
		case 'N':
			got_pass = True;
			break;
		case 'd':
			DEBUGLEVEL = atoi(optarg);
			break;
		case 'h':
			usage();
			exit(0);
			break;
		default:
			usage();
			exit(1);
		}
	
	if (!*service) {
		usage();
		exit(1);
	}


	DEBUG(3,("smbmount started (version %s)\n", VERSION));

	if (!get_myname(myhostname)) {
		DEBUG(0,("Failed to get my hostname.\n"));
	}

	if (!lp_load(servicesf,True,False,False)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", 
			servicesf);
	}

	codepage_initialise(lp_client_code_page());

	interpret_coding_system(term_code);

	if (*workgroup == 0)
		pstrcpy(workgroup,lp_workgroup());

	load_interfaces();
	get_myname((*global_myname)?NULL:global_myname);  
	strupper(global_myname);

	init_mount(service, mpoint, "");
	return 0;
}
