/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   SMB wrapper functions - frontend
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Derrell Lipman 2003-2005
   
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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <libsmbclient.h>

#ifndef FALSE
# define        FALSE   (0)
# define        TRUE    (! FALSE)
#endif

static void smbsh_usage(void)
{
	printf("smbsh [options] [command [args] ...]\n\n");
        printf(" -p prepend library name\n");
        printf(" -a append library name\n");
        printf(" -n");
	printf(" -W workgroup\n");
	printf(" -U username\n");
	printf(" -P prefix\n");
	printf(" -R resolve order\n");
	printf(" -d debug level\n");
	printf(" -l logfile\n");
	printf(" -L libdir\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	char *p, *u;
	char *libd = ".";
	char line[PATH_MAX], pre[PATH_MAX], post[PATH_MAX];
	int opt;
        int no_ask = 0;
        struct stat statbuf;
	extern char *optarg;
	extern int optind;

        *pre = *post = '\0';

	while ((opt = getopt(argc, argv, "p:a:d:nL:W:U:h")) != -1) {
		switch (opt) {
                case 'p':       /* prepend library before smbwrapper.so */
                        if (*pre != '\0')
                                strncat(pre, " ", PATH_MAX - strlen(pre));
                        strncat(pre, optarg, PATH_MAX - strlen(pre));
                        break;
                        
                case 'a':       /* append library after smbwrapper.so */
                        strncat(post, " ", PATH_MAX - strlen(post));
                        strncat(post, optarg, PATH_MAX - strlen(post));
                        break;
                        
                case 'd':
                        setenv("DEBUG", optarg, TRUE);
                        break;

                case 'n':       /* don't ask for username/password */
                        no_ask++;
                        break;

		case 'L':
			libd = optarg;
			break;

		case 'W':
			setenv("WORKGROUP", optarg, TRUE);
			break;

		case 'U':
			p = strchr(optarg,'%');
			if (p) {
				*p=0;
				setenv("PASSWORD", p+1, TRUE);
			}
			setenv("USER", optarg, TRUE);
			break;

		case 'h':
		default:
			smbsh_usage();
		}
	}


        if (! no_ask) {
                if (!getenv("USER")) {
                        printf("Username: ");
                        u = fgets(line, sizeof(line)-1, stdin);
                        setenv("USER", u, TRUE);
                }
                
                if (!getenv("PASSWORD")) {
                        p = getpass("Password: ");
                        setenv("PASSWORD", p, TRUE);
                }
        }

        strncpy(line, pre, PATH_MAX - strlen(line));
        strncat(line, " ", PATH_MAX - strlen(line));
        strncat(line, libd, PATH_MAX - strlen(line));
        strncat(line, "/smbwrapper.so", PATH_MAX - strlen(line));
        strncat(line, post, PATH_MAX - strlen(line));
	setenv("LD_PRELOAD", line, TRUE);
        setenv("LD_BIND_NOW", "true", TRUE);

	snprintf(line,sizeof(line)-1,"%s/smbwrapper.32.so", libd);

	if (stat(line, &statbuf) == 0 && S_ISREG(statbuf.st_mode)) {
		snprintf(line,sizeof(line)-1,"%s/smbwrapper.32.so:DEFAULT", libd);
		setenv("_RLD_LIST", line, TRUE);
		snprintf(line,sizeof(line)-1,"%s/smbwrapper.so:DEFAULT", libd);
		setenv("_RLDN32_LIST", line, TRUE);
	} else {
		snprintf(line,sizeof(line)-1,"%s/smbwrapper.so:DEFAULT", libd);
		setenv("_RLD_LIST", line, TRUE);
	}

        if (optind < argc) {
                execvp(argv[optind], &argv[optind]);
        } else {
                char *shellpath = getenv("SHELL");

                setenv("PS1", "smbsh$ ", TRUE);

                if(shellpath) {
			execl(shellpath,"smbsh", NULL);
                } else {
                        setenv("SHELL", "/bin/sh", TRUE);
			execl("/bin/sh", "smbsh", NULL);
                }
	}
	printf("launch failed!\n");
	return 1;
}	
