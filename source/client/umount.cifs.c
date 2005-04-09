/* 
   Unmount utility program for Linux CIFS VFS (virtual filesystem) client
   Copyright (C) 2005 Steve French  (sfrench@us.ibm.com)

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
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <mntent.h>

#define UNMOUNT_CIFS_VERSION_MAJOR "0"
#define UNMOUNT_CIFS_VERSION_MINOR "1"

#ifndef UNMOUNT_CIFS_VENDOR_SUFFIX
#define UNMOUNT_CIFS_VENDOR_SUFFIX ""
#endif

#ifndef MNT_DETACH
#define MNT_DETACH 0x02
#endif

#ifndef MNT_EXPIRE
#define MNT_EXPIRE 0x04
#endif

#define CIFS_IOC_CHECKUMOUNT _IO('c', 2)
   
static struct option longopts[] = {
	{ "all", 0, NULL, 'a' },
	{ "help",0, NULL, 'h' },
	{ "read-only", 0, NULL, 'r' },
	{ "ro", 0, NULL, 'r' },
	{ "verbose", 0, NULL, 'v' },
	{ "version", 0, NULL, 'V' },
	{ "expire", 0, NULL, 'e' },
	{ "force", 0, 0, 'f' },
	{ "lazy", 0, 0, 'l' },
	{ "no-mtab", 0, 0, 'n' },
	{ NULL, 0, NULL, 0 }
};

char * thisprogram;
int verboseflg = 0;

static void umount_cifs_usage(void)
{
	printf("\nUsage:  %s <remotetarget> <dir>\n", thisprogram);
	printf("\nUnmount the specified directory\n");
	printf("\nLess commonly used options:");
	printf("\n\t-r\tIf mount fails, retry with readonly remount.");
	printf("\n\t-n\tDo not write to mtab.");
	printf("\n\t-f\tAttempt a forced unmount, even if the fs is busy.");
	printf("\n\t-l\tAttempt lazy unmount, Unmount now, cleanup later.");
	printf("\n\t-v\tEnable verbose mode (may be useful for debugging).");
	printf("\n\t-h\tDisplay this help.");
	printf("\n\nOptions are described in more detail in the manual page");
	printf("\n\tman 8 umount.cifs\n");
	printf("\nTo display the version number of the cifs umount utility:");
	printf("\n\t%s -V\n",thisprogram);
}

static int umount_check_perm(char * dir)
{
	int fileid;
	int rc;

	/* presumably can not chdir into the target as we do on mount */

	fileid = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
	if(fileid == -1) {
		if(verboseflg)
			printf("error opening mountpoint %d %s",errno,strerror(errno));
		return errno;
	}

	rc = ioctl(fileid, CIFS_IOC_CHECKUMOUNT, NULL);

	if(verboseflg)
		printf("ioctl returned %d with errno %d %s\n",rc,errno,strerror(errno));

	if(rc == ENOTTY)
		printf("user unmounting via %s is an optional feature of the cifs filesystem driver (cifs.ko)\n\tand requires cifs.ko version 1.32 or later\n",thisprogram);
	else if (rc > 0)
		printf("user unmount of %s failed with %d %s",dir,errno,strerror(errno));
	close(fileid);

	return rc;
}

int main(int argc, char ** argv)
{
	int c;
	int rc;
	int flags = 0;
	int nomtab = 0;
	int retry_remount = 0;
	struct mntent mountent;
	char * mountpoint;
	FILE * pmntfile;

	if(argc && argv) {
		thisprogram = argv[0];
	} else {
		umount_cifs_usage();
		return -EINVAL;
	}

	if(argc < 2) {
		umount_cifs_usage();
		return -EINVAL;
	}

	if(thisprogram == NULL)
		thisprogram = "umount.cifs";

	/* add sharename in opts string as unc= parm */

	while ((c = getopt_long (argc, argv, "afhilnrvV",
			 longopts, NULL)) != -1) {
		switch (c) {
/* No code to do the following  option yet */
/*		case 'a':	       
			++umount_all;
			break; */
		case '?':
		case 'h':   /* help */
			umount_cifs_usage();
			exit(1);
		case 'n':
			++nomtab;
			break;
		case 'f':
			flags |= MNT_FORCE;
			break;
		case 'l':
			flags |= MNT_DETACH; /* lazy unmount */
			break;
		case 'e':
			flags |= MNT_EXPIRE; /* gradually timeout */
			break;
		case 'r':
			++retry_remount;
			break;
		case 'v':
			++verboseflg;
			break;
		case 'V':	   
			printf ("umount.cifs version: %s.%s%s\n",
				UNMOUNT_CIFS_VERSION_MAJOR,
				UNMOUNT_CIFS_VERSION_MINOR,
				UNMOUNT_CIFS_VENDOR_SUFFIX);
			exit (0);
		default:
			printf("unknown unmount option %c\n",c);
			umount_cifs_usage();
			exit(1);
		}
	}

	/* move past the umount options */
	argv += optind;
	argc -= optind;

	mountpoint = argv[0];

	if((argc < 1) || (argv[0] == NULL)) {
		printf("\nMissing name of unmount directory\n");
		umount_cifs_usage();
		return -EINVAL;
	}

	if(verboseflg)
		printf("optind %d unmount dir %s\n",optind, mountpoint);

	/* check if running effectively root */
	if(geteuid() != 0)
		printf("Trying to unmount when %s not installed suid\n",thisprogram);

	/* fixup path if needed */

	/* check if our uid was the one who mounted */
	rc = umount_check_perm(mountpoint);
	if (rc) {
		return rc;
	}

	if(umount2(mountpoint, flags)) {
	/* remember to kill daemon on error */

		switch (errno) {
		case 0:
			printf("mount failed but no error number set\n");
			break;
		default:
			
			printf("mount error %d = %s\n",errno,strerror(errno));
		}
		printf("Refer to the umount.cifs(8) manual page (e.g.man 8 umount.cifs)\n");
		return -1;
	} else {
		pmntfile = setmntent(MOUNTED, "a+");
		if(pmntfile) {
/*			mountent.mnt_fsname = share_name;
			mountent.mnt_dir = mountpoint; 
			mountent.mnt_type = "cifs"; 
			mountent.mnt_opts = malloc(220);
			if(mountent.mnt_opts) {
				char * mount_user = getusername();
				memset(mountent.mnt_opts,0,200);
				if(flags & MS_RDONLY)
					strcat(mountent.mnt_opts,"ro");
				else
					strcat(mountent.mnt_opts,"rw");
				if(flags & MS_MANDLOCK)
					strcat(mountent.mnt_opts,",mand");
				else
					strcat(mountent.mnt_opts,",nomand");
				if(flags & MS_NOEXEC)
					strcat(mountent.mnt_opts,",noexec");
				if(flags & MS_NOSUID)
					strcat(mountent.mnt_opts,",nosuid");
				if(flags & MS_NODEV)
					strcat(mountent.mnt_opts,",nodev");
				if(flags & MS_SYNCHRONOUS)
					strcat(mountent.mnt_opts,",synch");
				if(mount_user) {
					if(getuid() != 0) {
						strcat(mountent.mnt_opts,",user=");
						strcat(mountent.mnt_opts,mount_user);
					}
					free(mount_user);
				}
			}
			mountent.mnt_freq = 0;
			mountent.mnt_passno = 0;
			rc = addmntent(pmntfile,&mountent);
			endmntent(pmntfile);
			if(mountent.mnt_opts)
				free(mountent.mnt_opts);*/
		} else {
		    printf("could not update mount table\n");
		}
	}

	return 0;
}

