#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

extern DIR *smbw_opendir(const char *fname);
extern struct dirent *smbw_readdir(DIR *dirp);

static void usage(void)
{
	printf("\n \
smbw_sample - a sample program that uses smbw\n \
\n \
smbw_sample <options> path\n \
\n \
  options:\n \
     -W workgroup\n \
     -l logfile\n \
     -P prefix\n \
     -d debuglevel\n \
     -U username%%password\n \
     -R resolve order\n \
\n \
note that path must start with /smb/\n \
");
}

int main(int argc, char *argv[])
{
	DIR *dir;
	struct dirent *dent;
	int opt;
	char *p;
	extern char *optarg;
	extern int optind;
	char *path;

	charset_initialise();
	lp_load(CONFIGFILE,1,0,0);
	codepage_initialise(lp_client_code_page());
	smbw_setup_shared();

	while ((opt = getopt(argc, argv, "W:U:R:d:P:l:hL:")) != EOF) {
		switch (opt) {
		case 'W':
			smbw_setshared("WORKGROUP", optarg);
			break;
		case 'l':
			smbw_setshared("LOGFILE", optarg);
			break;
		case 'P':
			smbw_setshared("PREFIX", optarg);
			break;
		case 'd':
			smbw_setshared("DEBUG", optarg);
			break;
		case 'U':
			p = strchr(optarg,'%');
			if (p) {
				*p=0;
				smbw_setshared("PASSWORD",p+1);
			}
			smbw_setshared("USER", optarg);
			break;
		case 'R':
			smbw_setshared("RESOLVE_ORDER",optarg);
			break;
		case 'h':
		default:
			usage();
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		usage();
		exit(1);
	}

	path = argv[0];

	smbw_init();

	dir = smbw_opendir(path);
	if (!dir) {
		printf("failed to open %s\n", path);
		exit(1);
	}
	
	while ((dent = smbw_readdir(dir))) {
		printf("%s\n", dent->d_name);
	}
	smbw_closedir(dir);
	return 0;
}
