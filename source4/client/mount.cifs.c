#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <mntent.h>

#define MOUNT_CIFS_VERSION "1"

extern char *getusername(void);

char * thisprogram;
int verboseflag = 0;
static int got_password = 0;
static int got_user = 0;
static int got_domain = 0;
static int got_ip = 0;
static int got_unc = 0;
static int got_uid = 0;
static int got_gid = 0;
static char * user_name = NULL;
char * mountpassword = NULL;


void mount_cifs_usage()
{
	printf("\nUsage:  %s remotetarget dir\n", thisprogram);
	printf("\nMount the remotetarget, specified as either a UNC name or ");
	printf(" CIFS URL, to the local directory, dir.\n");

	exit(1);
}

/* caller frees username if necessary */
char * getusername() {
	char *username = NULL;
	struct passwd *password = getpwuid(getuid());

	if (password) {
		username = password->pw_name;
	}
	return username;
}

char * parse_cifs_url(unc_name)
{
	printf("\ncifs url %s\n",unc_name);
}

int parse_options(char * options)
{
	char * data;
	char * value = 0;

	if (!options)
		return 1;

	while ((data = strsep(&options, ",")) != NULL) {
		if (!*data)
			continue;
		if ((value = strchr(data, '=')) != NULL) {
			*value++ = '\0';
		}
		if (strncmp(data, "user", 4) == 0) {
			if (!value || !*value) {
				printf("invalid or missing username\n");
				return 1;	/* needs_arg; */
			}
			if (strnlen(value, 260) < 260) {
				got_user=1;
				/* BB add check for format user%pass */
				/* if(strchr(username%passw) got_password = 1) */
			} else {
				printf("username too long\n");
				return 1;
			}
	} else if (strncmp(data, "pass", 4) == 0) {
		if (!value || !*value) {
			if(got_password) {
				printf("password specified twice, ignoring second\n");
			} else
				got_password = 1;
		} else if (strnlen(value, 17) < 17) {
			got_password = 1;
		} else {
			printf("password too long\n");
			return 1;
		}
	} else if (strncmp(data, "ip", 2) == 0) {
		if (!value || !*value) {
			printf("target ip address argument missing");
		} else if (strnlen(value, 35) < 35) {
			got_ip = 1;
		} else {
			printf("ip address too long\n");
			return 1;
		}
	} else if ((strncmp(data, "unc", 3) == 0)
		   || (strncmp(data, "target", 6) == 0)
		   || (strncmp(data, "path", 4) == 0)) {
		if (!value || !*value) {
			printf("invalid path to network resource\n");
			return 1;  /* needs_arg; */
		} else if(strnlen(value,5) < 5) {
			printf("UNC name too short");
		}

		if (strnlen(value, 300) < 300) {
			got_unc = 1;
			if (strncmp(value, "//", 2) == 0) {
				if(got_unc)
					printf("unc name specified twice, ignoring second\n");
				else
					got_unc = 1;
			} else if (strncmp(value, "\\\\", 2) != 0) {	                   
				printf("UNC Path does not begin with // or \\\\ \n");
				return 1;
			} else {
				if(got_unc)
					printf("unc name specified twice, ignoring second\n");
				else
					got_unc = 1;
			}
		} else {
			printf("CIFS: UNC name too long\n");
			return 1;
		}
	} else if ((strncmp(data, "domain", 3) == 0)
		   || (strncmp(data, "workgroup", 5) == 0)) {
		if (!value || !*value) {
			printf("CIFS: invalid domain name\n");
			return 1;	/* needs_arg; */
		}
		if (strnlen(value, 65) < 65) {
			got_domain = 1;
		} else {
			printf("domain name too long\n");
			return 1;
		}
	} else if (strncmp(data, "uid", 3) == 0) {
		if (value && *value) {
			got_uid = 1;
		}
	} else if (strncmp(data, "gid", 3) == 0) {
		if (value && *value) {
			got_gid = 1;
		}
	} /* else if (strnicmp(data, "file_mode", 4) == 0) {
		if (value && *value) {
			vol->file_mode =
				simple_strtoul(value, &value, 0);
		}
	} else if (strnicmp(data, "dir_mode", 3) == 0) {
		if (value && *value) {
			vol->dir_mode =
				simple_strtoul(value, &value, 0);
		}
	} else if (strnicmp(data, "port", 4) == 0) {
		if (value && *value) {
			vol->port =
				simple_strtoul(value, &value, 0);
		}
	} else if (strnicmp(data, "rsize", 5) == 0) {
		if (value && *value) {
			vol->rsize =
				simple_strtoul(value, &value, 0);
		}
	} else if (strnicmp(data, "wsize", 5) == 0) {
		if (value && *value) {
			vol->wsize =
				simple_strtoul(value, &value, 0);
		}
	} else if (strnicmp(data, "version", 3) == 0) {
		
	} else if (strnicmp(data, "rw", 2) == 0) {
		
	} else
		printf("CIFS: Unknown mount option %s\n",data); */
	}
	return 0;
}

/* Note that caller frees the returned buffer if necessary */
char * parse_server(char * unc_name)
{
	int length = strnlen(unc_name,1024);
	char * share;
	char * ipaddress_string = NULL;
	struct hostent * host_entry;
	struct in_addr server_ipaddr;
	int rc,j;
	char temp[64];

	if(length > 1023) {
		printf("mount error: UNC name too long");
		return 0;
	}
	if (strncasecmp("cifs://",unc_name,7) == 0)
		return parse_cifs_url(unc_name+7);
	if (strncasecmp("smb://",unc_name,6) == 0) {
		return parse_cifs_url(unc_name+6);
	}

	if(length < 3) {
		/* BB add code to find DFS root here */
		printf("\nMounting the DFS root for domain not implemented yet");
		return 0;
	} else {
		/* BB add support for \\\\ not just // */
		if(strncmp(unc_name,"//",2) && strncmp(unc_name,"\\\\",2)) {
			printf("mount error: improperly formatted UNC name.");
			printf(" %s does not begin with \\\\ or //\n",unc_name);
			return 0;
		} else {
			unc_name[0] = '\\';
			unc_name[1] = '\\';
			unc_name += 2;
			if ((share = strchr(unc_name, '/')) || 
				(share = strchr(unc_name,'\\'))) {
				*share = 0;  /* temporarily terminate the string */
				share += 1;
				host_entry = gethostbyname(unc_name);
				*(share - 1) = '\\'; /* put the slash back */
/*				rc = getipnodebyname(unc_name, AF_INET, AT_ADDRCONFIG ,&rc);*/
				if(host_entry == NULL) {
					printf("mount error: could not find target server. TCP name %s not found ", unc_name);
					printf(" rc = %d\n",rc);
					return 0;
				}
				else {
					/* BB should we pass an alternate version of the share name as Unicode */
					/* BB what about ipv6? BB */
					/* BB add retries with alternate servers in list */

					memcpy(&server_ipaddr.s_addr, host_entry->h_addr, 4);

					ipaddress_string = inet_ntoa(server_ipaddr);                                                                                     
					if(ipaddress_string == NULL) {
						printf("mount error: could not get valid ip address for target server\n");
						return 0;
					}
					return ipaddress_string; 
				}
			} else {
				/* BB add code to find DFS root (send null path on get DFS Referral to specified server here */
				printf("Mounting the DFS root for a particular server not implemented yet\n");
				return 0;
			}
		}
	}
}

static struct option longopts[] = {
	{ "all", 0, 0, 'a' },
	{ "help", 0, 0, 'h' },
	{ "read-only", 0, 0, 'r' },
	{ "ro", 0, 0, 'r' },
	{ "verbose", 0, 0, 'v' },
	{ "version", 0, 0, 'V' },
	{ "read-write", 0, 0, 'w' },
	{ "rw", 0, 0, 'w' },
	{ "options", 1, 0, 'o' },
	{ "types", 1, 0, 't' },
	{ "replace", 0, 0, 129 },
	{ "after", 0, 0, 130 },
	{ "before", 0, 0, 131 },
	{ "over", 0, 0, 132 },
	{ "move", 0, 0, 133 },
	{ "rsize",1, 0, 136 },
	{ "wsize",1, 0, 137 },
	{ "uid", 1, 0, 138},
	{ "gid", 1, 0, 139},
	{ "uuid",1,0,'U' },
	{ "user",1,0,140},
	{ "username",1,0,140},
	{ "dom",1,0,141},
	{ "domain",1,0,141},
	{ "password",1,0,142},
	{ NULL, 0, 0, 0 }
};

int main(int argc, char ** argv)
{
	int c;
	int flags = MS_MANDLOCK | MS_MGC_VAL;
	char * orgoptions = NULL;
	char * share_name = NULL;
	char * domain_name = NULL;
	char * ipaddr = NULL;
	char * uuid = NULL;
	char * mountpoint;
	char * options;
	int rc,i;
	int rsize = 0;
	int wsize = 0;
	int nomtab = 0;
	int uid = 0;
	int gid = 0;
	int optlen = 0;
	struct stat statbuf;
	struct utsname sysinfo;
	struct mntent mountent;
	FILE * pmntfile;

	/* setlocale(LC_ALL, "");
#if defined(LOCALEDIR)
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE); */
#endif

	if(argc && argv) {
		thisprogram = argv[0];
	}
	if(thisprogram == NULL)
		thisprogram = "mount.cifs";

	uname(&sysinfo);
	/* BB add workstation name and domain and pass down */
/*#ifdef _GNU_SOURCE
	printf(" node: %s machine: %s\n", sysinfo.nodename,sysinfo.machine);
#endif*/
	if(argc < 3)
		mount_cifs_usage();
	share_name = argv[1];
	mountpoint = argv[2];
	/* add sharename in opts string as unc= parm */

	while ((c = getopt_long (argc, argv, "afFhilL:no:O:rsU:vVwt:",
			 longopts, NULL)) != -1) {
		switch (c) {
/*	case 'a':	       
		++mount_all;
		break;
	case 'f':	       
		++fake;
		break;
	case 'F':
		++optfork;
		break; */
		case 'h':	 /* help */
			mount_cifs_usage ();
			break;
/*	case 'i':
		external_allowed = 0;
		break;
	case 'l':
		list_with_volumelabel = 1;
		break;
	case 'L':
		volumelabel = optarg;
		break; */
	case 'n':
		++nomtab;
		break;
	case 'o':
		if (orgoptions) {
			orgoptions = strcat(orgoptions, ",");
			orgoptions = strcat(orgoptions,optarg);
		} else
			orgoptions = strdup(optarg);
		break;

/*	case 'O':
		if (test_opts)
			test_opts = xstrconcat3(test_opts, ",", optarg);
		else
			test_opts = xstrdup(optarg);
		break;*/
		case 'r':  /* mount readonly */
			flags |= MS_RDONLY;;
			break;
		case 'U':
			uuid = optarg;
			break;
		case 'v':
			++verboseflag;
			break;
/*	case 'V':	   
		printf ("mount: %s\n", version);
		exit (0);*/
		case 'w':
			flags &= ~MS_RDONLY;;
			break;
/*	case 0:
		break;

	case 128: 
		mounttype = MS_BIND;
		break;
	case 129: 
		mounttype = MS_REPLACE;
		break;
	case 130: 
		mounttype = MS_AFTER;
		break;
	case 131: 
		mounttype = MS_BEFORE;
		break;
	case 132: 
		mounttype = MS_OVER;
		break;
	case 133: 
		mounttype = MS_MOVE;
		break;
	case 135:
		mounttype = (MS_BIND | MS_REC);
		break; */
		case 136:
			rsize = atoi(optarg) ;
			break;
		case 137:
			wsize = atoi(optarg);
			break;
		case 138:
			uid = atoi(optarg);
			break;
		case 139:
			gid = atoi(optarg);
			break;
		case 140:
			got_user = 1;
			user_name = optarg;
			break;
		case 141:
			domain_name = optarg;
			break;
		case 142:
			got_password = 1;
			 mountpassword = optarg;
			break;
		case '?':
		default:
			mount_cifs_usage ();
		}
	}

	/* canonicalize the path in argv[1]? */

	if(stat (mountpoint, &statbuf)) {
		printf("mount error: mount point %s does not exist\n",mountpoint);
		return -1;
	}
	if (S_ISDIR(statbuf.st_mode) == 0) {
		printf("mount error: mount point %s is not a directory\n",mountpoint);
		return -1;
	}

	if(geteuid()) {
		printf("mount error: permission denied, not superuser and cifs.mount not installed SUID\n"); 
		return -1;
	}

	ipaddr = parse_server(share_name);
/*	if(share_name == NULL)
		return 1; */
	if (parse_options(strdup(orgoptions)))
		return 1;

	if(got_user == 0)
		user_name = getusername();
       
/*	check username for user%password format */

	if(got_password == 0) {
		if (getenv("PASSWD")) {
			mountpassword = malloc(33);
			if(mountpassword) {
				strncpy(mountpassword,getenv("PASSWD"),32);
				got_password = 1;
			}
/*		} else if (getenv("PASSWD_FD") || getenv("PASSWD_FILE")) {
			get_password_file();
			got_password = 1;*/ /* BB add missing function */
		} else {
			mountpassword = getpass("Password: "); /* BB obsolete */
			got_password = 1;
		}
	}
	/* FIXME launch daemon (handles dfs name resolution and credential change) 
	   remember to clear parms and overwrite password field before launching */
	if(orgoptions) {
		optlen = strlen(orgoptions);
	} else
		optlen = 0;
	if(share_name)
		optlen += strlen(share_name) + 4;
	if(user_name)
		optlen += strlen(user_name) + 6;
	if(ipaddr)
		optlen += strlen(ipaddr) + 4;
	if(mountpassword)
		optlen += strlen(mountpassword) + 6;
	options = malloc(optlen + 10);

    options[0] = 0;
	strncat(options,"unc=",4);
	strcat(options,share_name);
	if(ipaddr) {
		strncat(options,",ip=",4);
		strcat(options,ipaddr);
	} 
	if(user_name) {
		strncat(options,",user=",6);
		strcat(options,user_name);
	} 
	if(mountpassword) {
		strncat(options,",pass=",6);
		strcat(options,mountpassword);
	}
	strncat(options,",ver=",5);
	strcat(options,MOUNT_CIFS_VERSION);

	if(orgoptions) {
		strcat(options,",");
		strcat(options,orgoptions);
	}
	/* printf("\noptions %s \n",options);*/
	if(mount(share_name, mountpoint, "cifs", flags, options)) {
	/* remember to kill daemon on error */
		switch (errno) {
		case 0:
			printf("mount failed but no error number set\n");
			return 0;
		case ENODEV:
			printf("mount error: cifs filesystem not supported by the system\n");
			break;
		default:
			printf("mount error %d = %s",errno,strerror(errno));
		}
		printf("Refer to the mount.cifs(8) manual page (e.g.man mount.cifs)\n");
		return -1;
	} else {
		pmntfile = setmntent(MOUNTED, "a+");
		if(pmntfile) {
			mountent.mnt_fsname = share_name;
			mountent.mnt_dir = mountpoint; 
			mountent.mnt_type = "cifs"; 
			mountent.mnt_opts = "";
			mountent.mnt_freq = 0;
			mountent.mnt_passno = 0;
			rc = addmntent(pmntfile,&mountent);
			endmntent(pmntfile);
		} else {
		    printf("could not update mount table\n");
		}
	}
	return 0;
}

