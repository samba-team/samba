/*
 *  smbmount.c
 *
 *  Copyright (C) 1995-1998 by Paal-Kr. Engstad and Volker Lendecke
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

#include <linux/fs.h>
#include <linux/smb.h>
#include <linux/smb_mount.h>

#include <asm/unistd.h>

static char *progname;


static void
usage(void)
{
        printf("usage: %s mount-point [options]\n", progname);
        printf("Try `%s -h' for more information\n", progname);
}

static void
help(void)
{
        printf("\n");
        printf("usage: %s mount-point [options]\n", progname);
        printf("-u uid         uid the mounted files get\n"
               "-g gid         gid the mounted files get\n"
               "-f mode        permission the files get (octal notation)\n"
               "-d mode        permission the dirs get (octal notation)\n"
	       "-P pid         connection handler's pid\n\n"
	       "-s share       share name on server\n\n"
               "-h             print this help text\n");
}

static int
parse_args(int argc, char *argv[], struct smb_mount_data *data, char **share)
{
        int opt;
        struct passwd *pwd;
        struct group  *grp;

        while ((opt = getopt (argc, argv, "u:g:f:d:s:")) != EOF)
	{
                switch (opt)
		{
                case 'u':
                        if (isdigit(optarg[0]))
			{
                                data->uid = atoi(optarg);
                        }
			else
			{
                                pwd = getpwnam(optarg);
                                if (pwd == NULL)
				{
                                        fprintf(stderr, "Unknown user: %s\n",
                                                optarg);
                                        return 1;
                                }
                                data->uid = pwd->pw_uid;
                        }
                        break;
                case 'g':
                        if (isdigit(optarg[0]))
			{
                                data->gid = atoi(optarg);
                        }
			else
			{
                                grp = getgrnam(optarg);
                                if (grp == NULL)
				{
                                        fprintf(stderr, "Unknown group: %s\n",
                                                optarg);
                                        return 1;
                                }
                                data->gid = grp->gr_gid;
                        }
                        break;
                case 'f':
                        data->file_mode = strtol(optarg, NULL, 8);
                        break;
                case 'd':
                        data->dir_mode = strtol(optarg, NULL, 8);
                        break;
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

	if (strlen(p) > MAXPATHLEN-1)
	{
		return NULL;
	}

        if (realpath(p, path) == NULL)
	{
                return strdup(p);
	}
	return strdup(path);
}

/* Check whether user is allowed to mount on the specified mount point */
static int
mount_ok(struct stat *st)
{
        if (!S_ISDIR(st->st_mode))
        {
                errno = ENOTDIR;
                return -1;
        }
	
        if (   (getuid() != 0)
            && (   (getuid() != st->st_uid)
                || ((st->st_mode & S_IRWXU) != S_IRWXU)))
        {
                errno = EPERM;
                return -1;
        }

        return 0;
}

int 
main(int argc, char *argv[])
{
	char *mount_point, *share_name = NULL;
	FILE *mtab;
	int fd, um;
	unsigned int flags;
	struct smb_mount_data data;
	struct stat st;
	struct mntent ment;

        progname = argv[0];

	memset(&data, 0, sizeof(struct smb_mount_data));

	if (   (argc == 2)
	       && (argv[1][0] == '-')
	       && (argv[1][1] == 'h')
	       && (argv[1][2] == '\0'))
	{
		help();
		return 0;
	}

        if (geteuid() != 0) {
                fprintf(stderr, "%s must be installed suid root\n", progname);
                exit(1);
        }

	if (argc < 2)
	{
		usage();
		return 1;
	}

        mount_point = argv[1];

        argv += 1;
        argc -= 1;

        if (stat(mount_point, &st) == -1) {
                fprintf(stderr, "could not find mount point %s: %s\n",
                        mount_point, strerror(errno));
                exit(1);
        }

        if (mount_ok(&st) != 0) {
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
                usage();
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

	if (mount(share_name, mount_point, "smbfs", flags, (char *)&data) < 0)
	{
		perror("mount error");
		printf("Please refer to the smbmnt(8) manual page\n");
		return -1;
	}

        ment.mnt_fsname = share_name ? share_name : "none";
        ment.mnt_dir = fullpath(mount_point);
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
