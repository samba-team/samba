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

#define MOUNT_CIFS_VERSION "1"

extern char *getusername(void);

char * thisprogram;
int verboseflag = 0;
static int got_password = 0;
static int got_user = 0;
static char * user_name = NULL;
char * mountpassword = NULL;


void mount_cifs_usage()
{
	printf("\nUsage:  %s remotetarget dir\n", thisprogram);
	printf("\nMount the remotetarget, specified as either a UNC name or ");
	printf(" CIFS URL, to the local directory, dir.\n");

	return;
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

char * parse_options(char * options)
{
	/* BB add missing code BB */
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
			unc_name += 2;
			if (share = strchr(unc_name, '/')) {
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
					printf("Target server %s %x found\n",host_entry->h_name,host_entry->h_addr);	/* BB removeme */
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
	char * options;
	char * share_name;
	char * domain_name = NULL;
	char * ipaddr;
	char * mount_point;
	char * uuid = NULL;
	int rc,i;
	int rsize = 0;
	int wsize = 0;
	int nomtab = 0;
	int uid = 0;
	int gid = 0;
	int optlen = 0;
	struct stat statbuf;
	struct utsname sysinfo;

	/* setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE); */

	if(argc && argv) {
		thisprogram = argv[0];
	}
	if(thisprogram == NULL)
		thisprogram = "mount.cifs";

	uname(&sysinfo);
#ifdef _GNU_SOURCE
	printf(" node: %s machine: %s\n", sysinfo.nodename,sysinfo.machine);
#endif
	mount_cifs_usage();
	share_name = argv[1];
	mount_point = argv[2];
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

	for(i = 0;i < argc;i++)  /* BB remove */
		printf("\narg %d is %s",i,argv[i]);  /* BB remove */
	printf("\n");  /* BB removeme */

	/* canonicalize the path in argv[1]? */

	if(stat (mount_point, &statbuf)) {
		printf("mount error: mount point %s does not exist\n",mount_point);
		return -1;
	}
	if (S_ISDIR(statbuf.st_mode) == 0) {
		printf("mount error: mount point %s is not a directory\n",mount_point);
		return -1;
	}

	if(geteuid()) {
		printf("mount error: permission denied, not superuser and cifs.mount not installed SUID\n"); 
		return -1;
	}

	ipaddr = parse_server(share_name);
/*	if(share_name == NULL)
		return 1; */
	parse_options(orgoptions);

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

	/* launch daemon (handles dfs name resolution and credential change) */
	if(orgoptions)
		optlen = strlen(orgoptions);
	else
		optlen = 0;
	options = malloc(optlen + 25 + strlen(share_name) + strlen(user_name)
			+ strlen(ipaddr) + 1);
	strcpy(options,"unc=");
	strcat(options,share_name);
	strncat(options,",ip=",4);
	strcat(options,ipaddr);
	strncat(options,",user=",6);
	strcat(options,user_name);
	strncat(options,",pass=",6);
	strcat(options,mountpassword);
	strncat(options,",ver=",5);
	strcat(options,MOUNT_CIFS_VERSION);
	if(optlen)
		strcat(options,orgoptions);
	printf("\noptions %s \n",options);
	if(mount(share_name, mount_point, "cifs", flags, options)) {
	/* remember to kill daemon on error */
		switch (errno) {
		case 0:
			printf(" success\n"); /* BB removeme */
			return 0;
		case ENODEV:
			printf("mount error: cifs filesystem not supported by the system\n");
			break;
		default:
			printf("mount error %d = %s",errno,strerror(errno));
		}
		printf("\nRefer to the mount.cifs(8) manual page (e.g.man mount.cifs)\n");
		return -1;
	} else
		printf(" mount succeeded\n"); /* BB removeme */
}

