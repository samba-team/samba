/*
 *  smbmount.c
 *
 *  Copyright (C) 1995-1998 by Paal-Kr. Engstad and Volker Lendecke
 *
 */

#include "includes.h"

#include <mntent.h>

#include <asm/types.h>
#include <asm/posix_types.h>
#include <linux/smb.h>
#include <linux/smb_mount.h>
#include <asm/unistd.h>

#ifndef	MS_MGC_VAL
/* This may look strange but MS_MGC_VAL is what we are looking for and
	is what we need from <linux/fs.h> under libc systems and is
	provided in standard includes on glibc systems.  So...  We
	switch on what we need...  */
#include <linux/fs.h>
#endif

static void
help(void)
{
        printf("\n");
        printf("usage: smbmnt mount-point [options]\n");
        printf("-s share       share name on server\n"
               "-h             print this help text\n");
}

static int
parse_args(int argc, char *argv[], struct smb_mount_data *data, char **share)
{
        int opt;

        while ((opt = getopt (argc, argv, "s:")) != EOF)
	{
                switch (opt)
		{
                case 's':
                        *share = optarg;
                        break;
                default:
                        return -1;
                }
        }
        return 0;
        
}

static char *
fullpath(const char *p)
{
        char path[MAXPATHLEN];

	if (strlen(p) > MAXPATHLEN-1) {
		return NULL;
	}

        if (realpath(p, path) == NULL) {
		fprintf(stderr,"Failed to find real path for mount point\n");
		exit(1);
	}
	return strdup(path);
}

/* Check whether user is allowed to mount on the specified mount point. If it's
   OK then we change into that directory - this prevents race conditions */
static int mount_ok(char *mount_point)
{
	SMB_STRUCT_STAT st;

	if (chdir(mount_point) != 0) {
		return -1;
	}

        if (sys_stat(".", &st) != 0) {
		return -1;
        }

        if (!S_ISDIR(st.st_mode)) {
                errno = ENOTDIR;
                return -1;
        }
	
        if ((getuid() != 0) && 
	    ((getuid() != st.st_uid) || 
	     ((st.st_mode & S_IRWXU) != S_IRWXU))) {
                errno = EPERM;
                return -1;
        }

        return 0;
}

 int main(int argc, char *argv[])
{
	char *mount_point, *share_name = NULL;
	FILE *mtab;
	int fd, um;
	unsigned int flags;
	struct smb_mount_data data;
	struct mntent ment;

	memset(&data, 0, sizeof(struct smb_mount_data));

	if (argv[1][0] == '-') {
		help();
		exit(1);
	}

        if (geteuid() != 0) {
                fprintf(stderr, "smbmnt must be installed suid root\n");
                exit(1);
        }

	if (argc < 2) {
		help();
		exit(1);
	}

        mount_point = fullpath(argv[1]);

        argv += 1;
        argc -= 1;

        if (mount_ok(mount_point) != 0) {
                fprintf(stderr, "cannot mount on %s: %s\n",
                        mount_point, strerror(errno));
                exit(1);
        }

	data.version = SMB_MOUNT_VERSION;

        /* getuid() gives us the real uid, who may umount the fs */
        data.mounted_uid = getuid();

        data.uid = getuid();
        data.gid = getgid();
        um = umask(0);
        umask(um);
        data.file_mode = (S_IRWXU|S_IRWXG|S_IRWXO) & ~um;
        data.dir_mode  = 0;

        if (parse_args(argc, argv, &data, &share_name) != 0) {
                help();
                return -1;
        }

        if (data.dir_mode == 0) {
                data.dir_mode = data.file_mode;
                if ((data.dir_mode & S_IRUSR) != 0)
                        data.dir_mode |= S_IXUSR;
                if ((data.dir_mode & S_IRGRP) != 0)
                        data.dir_mode |= S_IXGRP;
                if ((data.dir_mode & S_IROTH) != 0)
                        data.dir_mode |= S_IXOTH;
        }

	flags = MS_MGC_VAL;

	if (mount(share_name, ".", "smbfs", flags, (char *)&data) < 0)
	{
		perror("mount error");
		printf("Please refer to the smbmnt(8) manual page\n");
		return -1;
	}

        ment.mnt_fsname = share_name ? share_name : "none";
        ment.mnt_dir = mount_point;
        ment.mnt_type = "smbfs";
        ment.mnt_opts = "";
        ment.mnt_freq = 0;
        ment.mnt_passno= 0;

        mount_point = ment.mnt_dir;

	if (mount_point == NULL)
	{
		fprintf(stderr, "Mount point too long\n");
		return -1;
	}
	
        if ((fd = open(MOUNTED"~", O_RDWR|O_CREAT|O_EXCL, 0600)) == -1)
        {
                fprintf(stderr, "Can't get "MOUNTED"~ lock file");
                return 1;
        }
        close(fd);
	
        if ((mtab = setmntent(MOUNTED, "a+")) == NULL)
        {
                fprintf(stderr, "Can't open " MOUNTED);
                return 1;
        }

        if (addmntent(mtab, &ment) == 1)
        {
                fprintf(stderr, "Can't write mount entry");
                return 1;
        }
        if (fchmod(fileno(mtab), 0644) == -1)
        {
                fprintf(stderr, "Can't set perms on "MOUNTED);
                return 1;
        }
        endmntent(mtab);

        if (unlink(MOUNTED"~") == -1)
        {
                fprintf(stderr, "Can't remove "MOUNTED"~");
                return 1;
        }

	return 0;
}	
