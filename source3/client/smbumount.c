/*
 *  smbumount.c
 *
 *  Copyright (C) 1995-1998 by Volker Lendecke
 *
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>
/* #include <sys/wait.h> */  /* generates a warning here */
extern pid_t waitpid(pid_t, int *, int);
#include <sys/errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <mntent.h>

#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/smb.h>
#include <linux/smb_mount.h>
#include <linux/smb_fs.h>

#include "includes.h"

static char *progname;

static void
usage(void)
{
        printf("usage: %s mount-point\n", progname);
}

static int
umount_ok(const char *mount_point)
{
        int fid = open(mount_point, O_RDONLY, 0);
        uid_t mount_uid;

        if (fid == -1) {
                fprintf(stderr, "Could not open %s: %s\n",
                        mount_point, strerror(errno));
                return -1;
        }
        
        if (ioctl(fid, SMB_IOC_GETMOUNTUID, &mount_uid) != 0) {
                fprintf(stderr, "%s probably not smb-filesystem\n",
                        mount_point);
                return -1;
        }

        if (   (getuid() != 0)
            && (mount_uid != getuid())) {
                fprintf(stderr, "You are not allowed to umount %s\n",
                        mount_point);
                return -1;
        }

        close(fid);
        return 0;
}

/* Make a canonical pathname from PATH.  Returns a freshly malloced string.
   It is up the *caller* to ensure that the PATH is sensible.  i.e.
   canonicalize ("/dev/fd0/.") returns "/dev/fd0" even though ``/dev/fd0/.''
   is not a legal pathname for ``/dev/fd0.''  Anything we cannot parse
   we return unmodified.   */
char *
canonicalize (const char *path)
{
	char *canonical = malloc (PATH_MAX + 1);

	if (strlen(path) > PATH_MAX)
	{
		fprintf(stderr, "Mount point string too long\n");
		return NULL;
	}

	if (path == NULL)
		return NULL;
  
	if (realpath (path, canonical))
		return canonical;

	pstrcpy (canonical, path);
	return canonical;
}


int 
main(int argc, char *argv[])
{
        int fd;

        char* mount_point;

        struct mntent *mnt;
        FILE* mtab;
        FILE* new_mtab;

        progname = argv[0];

        if (argc != 2) {
                usage();
                exit(1);
        }

        if (geteuid() != 0) {
                fprintf(stderr, "%s must be installed suid root\n", progname);
                exit(1);
        }

        mount_point = canonicalize(argv[1]);

	if (mount_point == NULL)
	{
		exit(1);
	}

        if (umount_ok(mount_point) != 0) {
                exit(1);
        }

        if (umount(mount_point) != 0) {
                fprintf(stderr, "Could not umount %s: %s\n",
                        mount_point, strerror(errno));
                exit(1);
        }

        if ((fd = open(MOUNTED"~", O_RDWR|O_CREAT|O_EXCL, 0600)) == -1)
        {
                fprintf(stderr, "Can't get "MOUNTED"~ lock file");
                return 1;
        }
        close(fd);
	
        if ((mtab = setmntent(MOUNTED, "r")) == NULL) {
                fprintf(stderr, "Can't open " MOUNTED ": %s\n",
                        strerror(errno));
                return 1;
        }

#define MOUNTED_TMP MOUNTED".tmp"

        if ((new_mtab = setmntent(MOUNTED_TMP, "w")) == NULL) {
                fprintf(stderr, "Can't open " MOUNTED_TMP ": %s\n",
                        strerror(errno));
                endmntent(mtab);
                return 1;
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
                exit(1);
        }

        endmntent(new_mtab);

        if (rename(MOUNTED_TMP, MOUNTED) < 0) {
                fprintf(stderr, "Cannot rename %s to %s: %s\n",
                        MOUNTED, MOUNTED_TMP, strerror(errno));
                exit(1);
        }

        if (unlink(MOUNTED"~") == -1)
        {
                fprintf(stderr, "Can't remove "MOUNTED"~");
                return 1;
        }

	return 0;
}	
